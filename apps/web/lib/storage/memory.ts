import type {
  ArtifactKind, ArtifactRef, ArtifactStore, LogLeaf, LogStore, MetadataStore, PolicyLogLink,
  PolicyRecord, Storage, TimestampRecord, TreeHeadRecord
} from './types'
import { ArtifactNotFoundError, DigestMismatchError } from './types'
import { artifactKey, byteDigestOf, byteDigestMatches } from './digest'

/**
 * In-memory adapter, for tests.
 *
 * `backing` is exposed so a test can corrupt what is stored WITHOUT going through the adapter — the
 * shape a hostile object store takes. The adapter's read verification must catch it.
 */
export class MemoryArtifactStore implements ArtifactStore {
  readonly backing = new Map<string, Uint8Array>()

  /** Applied to stored bytes on the way out. Identity unless a test replaces it. */
  constructor (private readonly tamper: (bytes: Uint8Array) => Uint8Array = (b) => b) {}

  async put (kind: ArtifactKind, bytes: Uint8Array, declaredByteDigest: string): Promise<ArtifactRef> {
    if (!byteDigestMatches(bytes, declaredByteDigest)) {
      throw new DigestMismatchError(declaredByteDigest, byteDigestOf(bytes), 'write refused')
    }
    const location = artifactKey(kind, declaredByteDigest)
    // Content-addressed and write-once: identical bytes make this a no-op, and different bytes
    // cannot reach here because the digest check above would have rejected them.
    if (!this.backing.has(location)) this.backing.set(location, new Uint8Array(bytes))
    return {
      kind,
      byteDigest: declaredByteDigest,
      location,
      byteLength: bytes.length,
      contentType: contentTypeFor(kind)
    }
  }

  async get (byteDigest: string): Promise<Uint8Array> {
    const found = this.find(byteDigest)
    if (!found) throw new ArtifactNotFoundError(byteDigest)
    const returned = this.tamper(found)
    if (!byteDigestMatches(returned, byteDigest)) {
      throw new DigestMismatchError(byteDigest, byteDigestOf(returned), 'read verification')
    }
    return returned
  }

  async has (byteDigest: string): Promise<boolean> {
    return this.find(byteDigest) !== undefined
  }

  private find (byteDigest: string): Uint8Array | undefined {
    for (const kind of ['policy', 'key-event-log'] as const) {
      const bytes = this.backing.get(artifactKey(kind, byteDigest))
      if (bytes) return bytes
    }
    return undefined
  }
}

export class MemoryMetadataStore implements MetadataStore {
  readonly rows = new Map<string, Map<number, PolicyRecord>>()

  async publish (record: PolicyRecord): Promise<void> {
    const versions = this.rows.get(record.handle) ?? new Map<number, PolicyRecord>()
    versions.set(record.version, record)
    this.rows.set(record.handle, versions)
  }

  async currentVersion (handle: string): Promise<PolicyRecord | null> {
    const versions = this.rows.get(handle)
    if (!versions || versions.size === 0) return null
    return versions.get(Math.max(...versions.keys())) ?? null
  }

  async version (handle: string, version: number): Promise<PolicyRecord | null> {
    return this.rows.get(handle)?.get(version) ?? null
  }

  async versions (handle: string): Promise<PolicyRecord[]> {
    return [...(this.rows.get(handle)?.values() ?? [])].sort((a, b) => a.version - b.version)
  }

  async handleOwner (handle: string): Promise<string | null> {
    return (await this.currentVersion(handle))?.accountId ?? null
  }

  readonly links = new Map<string, PolicyLogLink>()

  async recordLogLink (link: PolicyLogLink): Promise<void> {
    // Write-once: a policy's entry is logged once. A second link for the same digest is ignored.
    if (!this.links.has(link.policyDigest)) this.links.set(link.policyDigest, link)
  }

  async logLink (policyDigest: string): Promise<PolicyLogLink | null> {
    return this.links.get(policyDigest) ?? null
  }
}

/**
 * In-memory transparency log.
 *
 * Append is serialized through a promise chain — the in-process equivalent of the advisory lock the
 * Postgres adapter needs — so the contract's concurrent-append test means the same thing here.
 */
export class MemoryLogStore implements LogStore {
  readonly leafList: LogLeaf[] = []
  readonly heads = new Map<number, TreeHeadRecord>()
  readonly tokens: TimestampRecord[] = []
  private chain: Promise<unknown> = Promise.resolve()

  append (leafHash: string, appendedAt: string): Promise<LogLeaf> {
    const run = async (): Promise<LogLeaf> => {
      const existing = this.leafList.find((l) => l.leafHash === leafHash)
      if (existing) return existing
      const leaf = { leafIndex: this.leafList.length, leafHash, appendedAt }
      this.leafList.push(leaf)
      return leaf
    }
    const next = this.chain.then(run, run)
    this.chain = next.catch(() => undefined)
    return next
  }

  async leaves (): Promise<LogLeaf[]> { return [...this.leafList] }
  async size (): Promise<number> { return this.leafList.length }

  async putTreeHead (record: TreeHeadRecord): Promise<void> {
    if (!this.heads.has(record.treeSize)) this.heads.set(record.treeSize, record)
  }

  async treeHead (treeSize: number): Promise<TreeHeadRecord | null> {
    return this.heads.get(treeSize) ?? null
  }

  async latestTreeHead (): Promise<TreeHeadRecord | null> {
    if (this.heads.size === 0) return null
    return this.heads.get(Math.max(...this.heads.keys())) ?? null
  }

  async putTimestamp (record: TimestampRecord): Promise<void> {
    const i = this.tokens.findIndex((t) => t.treeSize === record.treeSize && t.tsa === record.tsa)
    if (i >= 0) this.tokens[i] = record
    else this.tokens.push(record)
  }

  async timestamps (treeSize: number): Promise<TimestampRecord[]> {
    return this.tokens.filter((t) => t.treeSize === treeSize)
  }

  async latestTimestamp (): Promise<TimestampRecord | null> {
    return [...this.tokens].sort((a, b) =>
      b.acquiredAt.localeCompare(a.acquiredAt) || b.treeSize - a.treeSize)[0] ?? null
  }
}

export function createMemoryStorage (
  tamper?: (bytes: Uint8Array) => Uint8Array
): Storage {
  return {
    name: 'memory',
    artifacts: new MemoryArtifactStore(tamper),
    metadata: new MemoryMetadataStore(),
    log: new MemoryLogStore()
  }
}

export function contentTypeFor (kind: ArtifactKind): string {
  return kind === 'policy'
    ? 'application/prm-policy+json'
    : 'application/json'
}
