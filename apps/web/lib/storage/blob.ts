import type {
  ArtifactKind, ArtifactRef, ArtifactStore, LogLeaf, LogStore, MetadataStore, PolicyLogLink,
  PolicyRecord, Storage, TimestampRecord, TreeHeadRecord
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
  /**
   * Prepended to every object path, e.g. "preview/". Environment isolation (docs/16 §4): a preview
   * deployment writes under its own prefix and can neither see nor overwrite production objects,
   * whatever credentials it was given.
   */
  pathPrefix?: string
}

export class BlobArtifactStore implements ArtifactStore {
  private readonly urls = new Map<string, string>()

  constructor (private readonly opts: BlobArtifactStoreOptions) {}

  private key (kind: ArtifactKind, byteDigest: string): string {
    return (this.opts.pathPrefix ?? '') + artifactKey(kind, byteDigest)
  }

  async put (kind: ArtifactKind, bytes: Uint8Array, declaredByteDigest: string): Promise<ArtifactRef> {
    if (!byteDigestMatches(bytes, declaredByteDigest)) {
      throw new DigestMismatchError(declaredByteDigest, byteDigestOf(bytes), 'write refused')
    }
    const pathname = this.key(kind, declaredByteDigest)

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
      const found = await this.head(this.key(kind, byteDigest))
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
create table if not exists log_leaves (
  leaf_index  integer     primary key,
  leaf_hash   text        not null unique,
  appended_at timestamptz not null default now()
);
create table if not exists log_tree_heads (
  tree_size  integer     primary key,
  sth_json   text        not null,
  created_at timestamptz not null default now()
);
create table if not exists log_timestamps (
  tree_size   integer     not null,
  tsa         text        not null,
  token_b64   text        not null,
  gen_time    timestamptz not null,
  chain_pem   text,
  acquired_at timestamptz not null default now(),
  primary key (tree_size, tsa)
);
create table if not exists published_policy_log (
  policy_digest text        primary key,
  account_id    text        not null,
  entry_digest  text        not null,
  leaf_index    integer     not null,
  linked_at     timestamptz not null default now()
);
`

/** Every relation the Postgres adapters touch. Kept in one place so namespacing cannot miss one. */
export const TABLES = ['published_policies', 'published_policy_log', 'log_leaves', 'log_tree_heads', 'log_timestamps'] as const

/**
 * Rewrite a statement to address prefixed relations: `log_leaves` -> `preview_log_leaves`.
 *
 * Applied to every statement, DDL included, so a namespaced store creates and uses its own tables
 * and can never name a production one. Index and constraint names that embed a table name are
 * rewritten by the same pass (`published_policies_account`, `log_leaves_pkey`).
 */
export function namespaceSql (text: string, tablePrefix: string): string {
  if (!tablePrefix) return text
  let out = text
  for (const table of TABLES) out = out.replace(new RegExp(`\\b${table}`, 'g'), `${tablePrefix}${table}`)
  return out
}

/** A SqlQuery that transparently addresses prefixed relations. */
export function namespaced (sql: SqlQuery, tablePrefix: string): SqlQuery {
  if (!tablePrefix) return sql
  return ((text, values) => sql(namespaceSql(text, tablePrefix), values)) as SqlQuery
}

/**
 * Apply the schema once per process. Every statement is `if not exists`, so this is the same thing
 * scripts/migrate.mjs does, run lazily — a deployment whose migration has not been run yet must not
 * fail its first append with "relation does not exist".
 */
const ensured = new WeakMap<object, Promise<void>>()
export function ensureSchema (sql: SqlQuery): Promise<void> {
  let p = ensured.get(sql)
  if (!p) {
    p = (async () => {
      for (const statement of SCHEMA_SQL.split(';').map((x) => x.trim()).filter(Boolean)) await sql(statement)
    })()
    ensured.set(sql, p)
  }
  return p
}

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

  async recordLogLink (link: PolicyLogLink): Promise<void> {
    await ensureSchema(this.sql)
    await this.sql(
      `insert into published_policy_log (policy_digest, account_id, entry_digest, leaf_index, linked_at)
       values ($1,$2,$3,$4,$5) on conflict (policy_digest) do nothing`,
      [link.policyDigest, link.accountId, link.entryDigest, link.leafIndex, link.linkedAt])
  }

  async logLink (policyDigest: string): Promise<PolicyLogLink | null> {
    await ensureSchema(this.sql)
    const rows = await this.sql(
      'select * from published_policy_log where policy_digest = $1', [policyDigest])
    const r = rows[0]
    return r
      ? {
          policyDigest: String(r.policy_digest),
          accountId: String(r.account_id),
          entryDigest: String(r.entry_digest),
          leafIndex: Number(r.leaf_index),
          linkedAt: instant(r.linked_at)
        }
      : null
  }
}

const instant = (v: unknown): string =>
  v instanceof Date ? v.toISOString().replace(/\.\d{3}Z$/, 'Z') : String(v)

/**
 * Postgres transparency log.
 *
 * APPEND SERIALIZATION. docs/07 §3.2 specifies an advisory lock, which needs a transaction spanning
 * two statements. The serverless HTTP driver issues one statement per request, so the equivalent
 * here is a single INSERT that computes its own index, with the primary key as the arbiter: two
 * concurrent appends that compute the same index collide, one fails, and the loser retries with the
 * new maximum. Correct at any concurrency, and lock-free. The unique leaf_hash makes a retried
 * append of the same leaf a no-op rather than a duplicate.
 */
export class PostgresLogStore implements LogStore {
  constructor (private readonly sql: SqlQuery) {}

  async append (leafHash: string, appendedAt: string): Promise<LogLeaf> {
    await ensureSchema(this.sql)
    for (let attempt = 0; attempt < 8; attempt++) {
      try {
        const rows = await this.sql<{ leaf_index: number }>(
          `insert into log_leaves (leaf_index, leaf_hash, appended_at)
           select coalesce(max(leaf_index) + 1, 0), $1, $2 from log_leaves
           on conflict (leaf_hash) do nothing
           returning leaf_index`,
          [leafHash, appendedAt])
        if (rows[0]) return { leafIndex: Number(rows[0].leaf_index), leafHash, appendedAt }
        // Nothing returned: the leaf already existed. Return it.
        const existing = await this.sql(
          'select * from log_leaves where leaf_hash = $1', [leafHash])
        if (existing[0]) return toLeaf(existing[0])
        throw new StorageError('append returned no row and the leaf is not present')
      } catch (e) {
        // A primary-key collision on leaf_index means another append won the race. Retry.
        if (!/duplicate key|unique constraint|log_leaves_pkey/i.test(String((e as Error).message))) throw e
        await new Promise((r) => setTimeout(r, 5 + Math.random() * 20))
      }
    }
    throw new StorageError('could not append to the log after repeated collisions')
  }

  async leaves (): Promise<LogLeaf[]> {
    await ensureSchema(this.sql)
    return (await this.sql('select * from log_leaves order by leaf_index asc')).map(toLeaf)
  }

  async size (): Promise<number> {
    await ensureSchema(this.sql)
    const rows = await this.sql<{ n: unknown }>('select count(*) as n from log_leaves')
    return Number(rows[0]?.n ?? 0)
  }

  async putTreeHead (record: TreeHeadRecord): Promise<void> {
    await ensureSchema(this.sql)
    await this.sql(
      `insert into log_tree_heads (tree_size, sth_json, created_at) values ($1,$2,$3)
       on conflict (tree_size) do nothing`,
      [record.treeSize, record.sthJson, record.createdAt])
  }

  async treeHead (treeSize: number): Promise<TreeHeadRecord | null> {
    await ensureSchema(this.sql)
    const rows = await this.sql('select * from log_tree_heads where tree_size = $1', [treeSize])
    return rows[0] ? toHead(rows[0]) : null
  }

  async latestTreeHead (): Promise<TreeHeadRecord | null> {
    await ensureSchema(this.sql)
    const rows = await this.sql('select * from log_tree_heads order by tree_size desc limit 1')
    return rows[0] ? toHead(rows[0]) : null
  }

  async putTimestamp (record: TimestampRecord): Promise<void> {
    await ensureSchema(this.sql)
    await this.sql(
      `insert into log_timestamps (tree_size, tsa, token_b64, gen_time, chain_pem, acquired_at)
       values ($1,$2,$3,$4,$5,$6)
       on conflict (tree_size, tsa) do update
         set token_b64 = excluded.token_b64, gen_time = excluded.gen_time,
             chain_pem = excluded.chain_pem, acquired_at = excluded.acquired_at`,
      [record.treeSize, record.tsa, record.tokenBase64, record.genTime, record.chainPem ?? null, record.acquiredAt])
  }

  async timestamps (treeSize: number): Promise<TimestampRecord[]> {
    await ensureSchema(this.sql)
    return (await this.sql('select * from log_timestamps where tree_size = $1 order by tsa asc', [treeSize])).map(toTimestamp)
  }

  async latestTimestamp (): Promise<TimestampRecord | null> {
    await ensureSchema(this.sql)
    const rows = await this.sql('select * from log_timestamps order by acquired_at desc, tree_size desc limit 1')
    return rows[0] ? toTimestamp(rows[0]) : null
  }
}

const toLeaf = (r: Record<string, unknown>): LogLeaf =>
  ({ leafIndex: Number(r.leaf_index), leafHash: String(r.leaf_hash), appendedAt: instant(r.appended_at) })
const toHead = (r: Record<string, unknown>): TreeHeadRecord =>
  ({ treeSize: Number(r.tree_size), sthJson: String(r.sth_json), createdAt: instant(r.created_at) })
const toTimestamp = (r: Record<string, unknown>): TimestampRecord => ({
  treeSize: Number(r.tree_size),
  tsa: String(r.tsa),
  tokenBase64: String(r.token_b64),
  genTime: instant(r.gen_time),
  acquiredAt: instant(r.acquired_at),
  ...(r.chain_pem ? { chainPem: String(r.chain_pem) } : {})
})

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
  log: LogStore
}): Storage {
  return {
    name: 'blob',
    artifacts: new BlobArtifactStore(opts.artifacts),
    metadata: opts.metadata,
    log: opts.log
  }
}
