import { mkdir, readFile, writeFile, readdir, access } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import type {
  ArtifactKind, ArtifactRef, ArtifactStore, LogLeaf, LogStore, MetadataStore, PolicyLogLink,
  PolicyRecord, Storage, TimestampRecord, TreeHeadRecord
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

  private linkPath (policyDigest: string): string {
    if (!/^u[A-Za-z0-9_-]{40,}$/.test(policyDigest)) throw new Error('invalid policy digest')
    return resolve(this.root, 'log-links', `${policyDigest}.json`)
  }

  async recordLogLink (link: PolicyLogLink): Promise<void> {
    const file = this.linkPath(link.policyDigest)
    await mkdir(dirname(file), { recursive: true })
    try {
      await access(file)
    } catch {
      await writeFile(file, JSON.stringify(link, null, 2), 'utf8')
    }
  }

  async logLink (policyDigest: string): Promise<PolicyLogLink | null> {
    try {
      return JSON.parse(await readFile(this.linkPath(policyDigest), 'utf8')) as PolicyLogLink
    } catch {
      return null
    }
  }
}

/**
 * Filesystem transparency log — development only.
 *
 * leaves.json is the whole leaf list; tree heads and tokens are one file each. Append is serialized
 * in-process; there is no cross-process lock, which is fine for `pnpm dev` and nothing else.
 */
export class FileLogStore implements LogStore {
  private chain: Promise<unknown> = Promise.resolve()
  constructor (private readonly root: string) {}

  private path (...parts: string[]): string {
    const full = resolve(this.root, 'log', ...parts)
    if (!full.startsWith(resolve(this.root, 'log') + '/')) throw new Error('invalid log path')
    return full
  }

  private async readLeaves (): Promise<LogLeaf[]> {
    try {
      return JSON.parse(await readFile(this.path('leaves.json'), 'utf8')) as LogLeaf[]
    } catch {
      return []
    }
  }

  private async writeJson (file: string, value: unknown): Promise<void> {
    await mkdir(dirname(file), { recursive: true })
    await writeFile(file, JSON.stringify(value, null, 2), 'utf8')
  }

  append (leafHash: string, appendedAt: string): Promise<LogLeaf> {
    const run = async (): Promise<LogLeaf> => {
      const leaves = await this.readLeaves()
      const existing = leaves.find((l) => l.leafHash === leafHash)
      if (existing) return existing
      const leaf = { leafIndex: leaves.length, leafHash, appendedAt }
      await this.writeJson(this.path('leaves.json'), [...leaves, leaf])
      return leaf
    }
    const next = this.chain.then(run, run)
    this.chain = next.catch(() => undefined)
    return next
  }

  async leaves (): Promise<LogLeaf[]> { return this.readLeaves() }
  async size (): Promise<number> { return (await this.readLeaves()).length }

  async putTreeHead (record: TreeHeadRecord): Promise<void> {
    const file = this.path('tree-heads', `${record.treeSize}.json`)
    try { await access(file) } catch { await this.writeJson(file, record) }
  }

  async treeHead (treeSize: number): Promise<TreeHeadRecord | null> {
    try {
      return JSON.parse(await readFile(this.path('tree-heads', `${treeSize}.json`), 'utf8')) as TreeHeadRecord
    } catch {
      return null
    }
  }

  async latestTreeHead (): Promise<TreeHeadRecord | null> {
    const sizes = await this.listNumbers('tree-heads')
    return sizes.length === 0 ? null : this.treeHead(Math.max(...sizes))
  }

  async putTimestamp (record: TimestampRecord): Promise<void> {
    await this.writeJson(this.path('timestamps', `${record.treeSize}-${record.tsa}.json`), record)
  }

  async timestamps (treeSize: number): Promise<TimestampRecord[]> {
    return (await this.allTimestamps()).filter((t) => t.treeSize === treeSize)
  }

  async latestTimestamp (): Promise<TimestampRecord | null> {
    return (await this.allTimestamps()).sort((a, b) =>
      b.acquiredAt.localeCompare(a.acquiredAt) || b.treeSize - a.treeSize)[0] ?? null
  }

  private async allTimestamps (): Promise<TimestampRecord[]> {
    let names: string[]
    try { names = await readdir(this.path('timestamps')) } catch { return [] }
    const out: TimestampRecord[] = []
    for (const n of names) {
      if (!n.endsWith('.json')) continue
      try { out.push(JSON.parse(await readFile(this.path('timestamps', n), 'utf8')) as TimestampRecord) } catch { /* skip */ }
    }
    return out
  }

  private async listNumbers (dir: string): Promise<number[]> {
    try {
      return (await readdir(this.path(dir)))
        .map((n) => /^(\d+)\.json$/.exec(n)?.[1])
        .filter((n): n is string => n !== undefined)
        .map(Number)
    } catch {
      return []
    }
  }
}

export function createFileStorage (root: string): Storage {
  return {
    name: 'file',
    artifacts: new FileArtifactStore(root),
    metadata: new FileMetadataStore(root),
    log: new FileLogStore(root)
  }
}
