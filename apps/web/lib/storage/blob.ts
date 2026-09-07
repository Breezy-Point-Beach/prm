import type {
  ArtifactKind, ArtifactRef, ArtifactStore, MetadataStore, PolicyRecord, Storage
} from './types'
import { ArtifactNotFoundError, DigestMismatchError, StorageError } from './types'
import { artifactKey, byteDigestOf, byteDigestMatches } from './digest'
import { contentTypeFor } from './memory'

/**
 * Vercel Blob adapter — production artifact storage.
 *
 * Artifacts are written at digest-derived keys, which makes the storage address itself an integrity
 * claim: anyone who fetched `artifacts/policy/uEiDy…` can hash what came back and know whether the
 * backend lied. Every read is verified against the requested digest before it is returned, so a
 * compromised or buggy blob store cannot serve altered bytes without this adapter noticing.
 *
 * The blob client is INJECTED rather than imported directly. That is not indirection for its own
 * sake: it is what allows the hostile-backend contract to run against this adapter's real logic with
 * a corrupting fake underneath. The integrity behaviour is what needs testing, and it is testable
 * without network access.
 */

/** The slice of @vercel/blob this adapter needs. Matches the published API. */
export interface BlobClient {
  put (
    pathname: string,
    body: Uint8Array | string,
    options: {
      access: 'public'
      contentType?: string
      addRandomSuffix?: boolean
      cacheControlMaxAge?: number
      allowOverwrite?: boolean
      token?: string
    }
  ): Promise<{ url: string; pathname: string }>
  head (pathname: string, options?: { token?: string }): Promise<{ url: string; size: number } | null>
}

/** Fetches blob content. Injected so tests can corrupt what comes back. */
export type BlobFetcher = (url: string) => Promise<Uint8Array>

export interface BlobArtifactStoreOptions {
  client: BlobClient
  fetcher: BlobFetcher
  token?: string
  /** Cache lifetime for immutable artifacts. A year: the content can never change. */
  cacheSeconds?: number
}

export class BlobArtifactStore implements ArtifactStore {
  private readonly urls = new Map<string, string>()

  constructor (private readonly opts: BlobArtifactStoreOptions) {}

  async put (kind: ArtifactKind, bytes: Uint8Array, declaredByteDigest: string): Promise<ArtifactRef> {
    if (!byteDigestMatches(bytes, declaredByteDigest)) {
      throw new DigestMismatchError(declaredByteDigest, byteDigestOf(bytes), 'write refused')
    }
    const pathname = artifactKey(kind, declaredByteDigest)

    // Write-once. An existing object at a digest-derived key already holds these exact bytes, so a
    // second write is a no-op rather than an overwrite. allowOverwrite stays false so that a bug
    // which did try to replace an artifact fails loudly instead of quietly rewriting history.
    const existing = await this.head(pathname)
    if (existing) {
      this.urls.set(declaredByteDigest, existing.url)
      return {
        kind, byteDigest: declaredByteDigest, location: pathname,
        byteLength: bytes.length, contentType: contentTypeFor(kind)
      }
    }

    const result = await this.opts.client.put(pathname, bytes, {
      access: 'public',
      contentType: contentTypeFor(kind),
      addRandomSuffix: false,
      allowOverwrite: false,
      cacheControlMaxAge: this.opts.cacheSeconds ?? 31_536_000,
      ...(this.opts.token ? { token: this.opts.token } : {})
    })
    this.urls.set(declaredByteDigest, result.url)

    return {
      kind,
      byteDigest: declaredByteDigest,
      location: result.pathname,
      byteLength: bytes.length,
      contentType: contentTypeFor(kind)
    }
  }

  async get (byteDigest: string): Promise<Uint8Array> {
    const url = await this.resolveUrl(byteDigest)
    if (!url) throw new ArtifactNotFoundError(byteDigest)

    let bytes: Uint8Array
    try {
      bytes = await this.opts.fetcher(url)
    } catch (e) {
      throw new StorageError(`could not read artifact ${byteDigest}: ${(e as Error).message}`)
    }

    // The load-bearing line of this adapter. Everything the blob store returns is suspect until it
    // hashes to the address it was requested from.
    if (!byteDigestMatches(bytes, byteDigest)) {
      throw new DigestMismatchError(byteDigest, byteDigestOf(bytes), 'read verification')
    }
    return bytes
  }

  async has (byteDigest: string): Promise<boolean> {
    return (await this.resolveUrl(byteDigest)) !== null
  }

  private async resolveUrl (byteDigest: string): Promise<string | null> {
    const cached = this.urls.get(byteDigest)
    if (cached) return cached
    for (const kind of ['policy', 'key-event-log'] as const) {
      const found = await this.head(artifactKey(kind, byteDigest))
      if (found) { this.urls.set(byteDigest, found.url); return found.url }
    }
    return null
  }

  private async head (pathname: string): Promise<{ url: string; size: number } | null> {
    try {
      return await this.opts.client.head(pathname, this.opts.token ? { token: this.opts.token } : {})
    } catch {
      // @vercel/blob throws BlobNotFoundError rather than returning null.
      return null
    }
  }
}

/**
 * Postgres metadata store.
 *
 * Holds ONLY the alias layer: which digest a handle's version N points at. The signed artifact never
 * enters the database, which is what keeps decision D51 (no jsonb) structurally impossible to
 * violate rather than merely discouraged — there is no column that could hold a policy.
 */
export type SqlQuery = <T = Record<string, unknown>>(
  text: string,
  values?: unknown[]
) => Promise<T[]>

export const SCHEMA_SQL = `
create table if not exists published_policies (
  handle             text        not null,
  version            integer     not null,
  account_id         text        not null,
  policy_chain_id    text        not null,
  policy_digest      text        not null,
  policy_byte_digest text        not null,
  policy_location    text        not null,
  policy_byte_length integer     not null,
  kel_byte_digest    text        not null,
  kel_location       text        not null,
  content_type       text        not null,
  published_at       timestamptz not null default now(),
  primary key (handle, version)
);
create index if not exists published_policies_account
  on published_policies (account_id);
`

export class PostgresMetadataStore implements MetadataStore {
  constructor (private readonly sql: SqlQuery) {}

  async publish (record: PolicyRecord): Promise<void> {
    await this.sql(
      `insert into published_policies
         (handle, version, account_id, policy_chain_id, policy_digest, policy_byte_digest,
          policy_location, policy_byte_length, kel_byte_digest, kel_location, content_type, published_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       on conflict (handle, version) do nothing`,
      [
        record.handle, record.version, record.accountId, record.policyChainId,
        record.policyDigest, record.policyByteDigest, record.policyLocation,
        record.policyByteLength, record.kelByteDigest, record.kelLocation,
        record.contentType, record.publishedAt
      ]
    )
  }

  async currentVersion (handle: string): Promise<PolicyRecord | null> {
    const rows = await this.sql(
      'select * from published_policies where handle = $1 order by version desc limit 1', [handle])
    return rows[0] ? toRecord(rows[0]) : null
  }

  async version (handle: string, version: number): Promise<PolicyRecord | null> {
    const rows = await this.sql(
      'select * from published_policies where handle = $1 and version = $2', [handle, version])
    return rows[0] ? toRecord(rows[0]) : null
  }

  async versions (handle: string): Promise<PolicyRecord[]> {
    const rows = await this.sql(
      'select * from published_policies where handle = $1 order by version asc', [handle])
    return rows.map(toRecord)
  }

  async handleOwner (handle: string): Promise<string | null> {
    const rows = await this.sql<{ account_id: string }>(
      'select account_id from published_policies where handle = $1 limit 1', [handle])
    return rows[0]?.account_id ?? null
  }
}

function toRecord (row: Record<string, unknown>): PolicyRecord {
  const at = row.published_at
  return {
    handle: String(row.handle),
    accountId: String(row.account_id),
    policyChainId: String(row.policy_chain_id),
    version: Number(row.version),
    policyDigest: String(row.policy_digest),
    policyByteDigest: String(row.policy_byte_digest),
    policyLocation: String(row.policy_location),
    policyByteLength: Number(row.policy_byte_length),
    kelByteDigest: String(row.kel_byte_digest),
    kelLocation: String(row.kel_location),
    publishedAt: at instanceof Date
      ? at.toISOString().replace(/\.\d{3}Z$/, 'Z')
      : String(at),
    contentType: String(row.content_type)
  }
}

export function createBlobStorage (opts: {
  artifacts: BlobArtifactStoreOptions
  metadata: MetadataStore
}): Storage {
  return {
    name: 'blob',
    artifacts: new BlobArtifactStore(opts.artifacts),
    metadata: opts.metadata
  }
}
