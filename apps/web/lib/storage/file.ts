import { mkdir, readFile, writeFile, readdir, access } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import type {
  ArtifactKind, ArtifactRef, ArtifactStore, MetadataStore, PolicyRecord, Storage
} from './types'
import { ArtifactNotFoundError, DigestMismatchError } from './types'
import { artifactKey, byteDigestOf, byteDigestMatches } from './digest'
import { contentTypeFor } from './memory'

/**
 * Filesystem adapter — local development only.
 *
 * Vercel's filesystem is read-only outside an ephemeral /tmp, so this cannot be the production
 * store. It exists so a fresh clone runs with `pnpm dev` and no configuration at all, and it passes
 * the identical StorageAdapterContract as the production adapter.
 */
export class FileArtifactStore implements ArtifactStore {
  constructor (private readonly root: string) {}

  private pathFor (kind: ArtifactKind, byteDigest: string): string {
    const key = artifactKey(kind, byteDigest)
    const full = resolve(this.root, key)
    // artifactKey validates the digest shape, but a path traversal in the one component that writes
    // files is not worth trusting upstream validation for.
    if (!full.startsWith(resolve(this.root) + '/')) throw new Error('invalid artifact key')
    return full
  }

  async put (kind: ArtifactKind, bytes: Uint8Array, declaredByteDigest: string): Promise<ArtifactRef> {
    if (!byteDigestMatches(bytes, declaredByteDigest)) {
      throw new DigestMismatchError(declaredByteDigest, byteDigestOf(bytes), 'write refused')
    }
    const file = this.pathFor(kind, declaredByteDigest)
    await mkdir(dirname(file), { recursive: true })
    try {
      await access(file)
      // Already present. Content-addressed, so the bytes are the same by construction.
    } catch {
      await writeFile(file, bytes)
    }
    return {
      kind,
      byteDigest: declaredByteDigest,
      location: artifactKey(kind, declaredByteDigest),
      byteLength: bytes.length,
      contentType: contentTypeFor(kind)
    }
  }

  async get (byteDigest: string): Promise<Uint8Array> {
    for (const kind of ['policy', 'key-event-log'] as const) {
      try {
        const bytes = new Uint8Array(await readFile(this.pathFor(kind, byteDigest)))
        if (!byteDigestMatches(bytes, byteDigest)) {
          throw new DigestMismatchError(byteDigest, byteDigestOf(bytes), 'read verification')
        }
        return bytes
      } catch (e) {
        if (e instanceof DigestMismatchError) throw e
      }
    }
    throw new ArtifactNotFoundError(byteDigest)
  }

  async has (byteDigest: string): Promise<boolean> {
    for (const kind of ['policy', 'key-event-log'] as const) {
      try {
        await access(this.pathFor(kind, byteDigest))
        return true
      } catch { /* try the next kind */ }
    }
    return false
  }
}

/** Metadata as one JSON file per handle. Aliases only; artifacts live elsewhere. */
export class FileMetadataStore implements MetadataStore {
  constructor (private readonly root: string) {}

  private pathFor (handle: string): string {
    const full = resolve(this.root, 'handles', `${handle}.json`)
    if (!full.startsWith(resolve(this.root, 'handles') + '/')) throw new Error('invalid handle')
    return full
  }

  private async read (handle: string): Promise<PolicyRecord[]> {
    try {
      return JSON.parse(await readFile(this.pathFor(handle), 'utf8')) as PolicyRecord[]
    } catch {
      return []
    }
  }

  async publish (record: PolicyRecord): Promise<void> {
    const rows = (await this.read(record.handle)).filter((r) => r.version !== record.version)
    rows.push(record)
    rows.sort((a, b) => a.version - b.version)
    const file = this.pathFor(record.handle)
    await mkdir(dirname(file), { recursive: true })
    await writeFile(file, JSON.stringify(rows, null, 2), 'utf8')
  }

  async currentVersion (handle: string): Promise<PolicyRecord | null> {
    const rows = await this.read(handle)
    return rows.length === 0 ? null : (rows[rows.length - 1] as PolicyRecord)
  }

  async version (handle: string, version: number): Promise<PolicyRecord | null> {
    return (await this.read(handle)).find((r) => r.version === version) ?? null
  }

  async versions (handle: string): Promise<PolicyRecord[]> {
    return this.read(handle)
  }

  async handleOwner (handle: string): Promise<string | null> {
    return (await this.currentVersion(handle))?.accountId ?? null
  }
}

export function createFileStorage (root: string): Storage {
  return {
    name: 'file',
    artifacts: new FileArtifactStore(root),
    metadata: new FileMetadataStore(root)
  }
}
