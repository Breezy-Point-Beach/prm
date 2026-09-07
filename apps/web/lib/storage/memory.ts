import type {
  ArtifactKind, ArtifactRef, ArtifactStore, MetadataStore, PolicyRecord, Storage
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
}

export function createMemoryStorage (
  tamper?: (bytes: Uint8Array) => Uint8Array
): Storage {
  return {
    name: 'memory',
    artifacts: new MemoryArtifactStore(tamper),
    metadata: new MemoryMetadataStore()
  }
}

export function contentTypeFor (kind: ArtifactKind): string {
  return kind === 'policy'
    ? 'application/prm-policy+json'
    : 'application/json'
}
