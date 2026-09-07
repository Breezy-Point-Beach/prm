import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'

/**
 * Published-artifact storage.
 *
 * ONE RULE GOVERNS THIS FILE: what the browser signed is what gets stored, byte for byte, and what
 * gets served back. The server validates and refuses; it never edits.
 *
 * That is why records hold the RAW REQUEST TEXT as a string and not a parsed object. Parsing and
 * re-serializing would reorder keys, normalize numbers, collapse duplicate keys, and rewrite unicode
 * escapes. Most of those survive JCS canonicalization and would still verify — but "most" is not a
 * property worth resting on, and the strong version is simpler to reason about and to test:
 *
 *     bytes in === bytes out, or the publish fails visibly.
 *
 * DEVIATION FROM docs/13-mvp.md: that document specifies `document jsonb` for the policies table.
 * jsonb explicitly does not preserve key order, insignificant whitespace, duplicate keys, or numeric
 * formatting, so it cannot satisfy the rule above. Production storage must use `text` (or `bytea`)
 * for the canonical bytes, with an optional jsonb column alongside for indexing only. Recorded in
 * docs/decisions.md as D51.
 */

export interface PublishedPolicy {
  handle: string
  accountId: string
  policyChainId: string
  version: number
  digest: string
  /** The exact bytes received from the client. Never re-serialized. */
  policyJson: string
  /** The exact key event log bytes received from the client. */
  keyEventLogJson: string
  publishedAt: string
}

export interface PolicyStore {
  publish (record: PublishedPolicy): Promise<void>
  getCurrent (handle: string): Promise<PublishedPolicy | null>
  getVersion (handle: string, version: number): Promise<PublishedPolicy | null>
  listVersions (handle: string): Promise<number[]>
  /** Returns the account that owns a handle, or null if it is free. */
  handleOwner (handle: string): Promise<string | null>
}

/**
 * Filesystem-backed store.
 *
 * Used for local development, where it needs no configuration at all — a fresh clone runs with
 * `pnpm dev` and nothing else. It is NOT suitable for Vercel, whose filesystem is read-only outside
 * an ephemeral /tmp. The Postgres driver and deployment land with PR 6; this interface exists so
 * that swap touches one file.
 */
export class FileStore implements PolicyStore {
  constructor (private readonly root: string) {}

  private path (handle: string, ...rest: string[]): string {
    // Handles are validated before reaching here, but resolve and re-check anyway: a path traversal
    // in the one endpoint that writes files is not a mistake worth risking on upstream validation.
    const base = resolve(this.root, handle)
    if (!base.startsWith(resolve(this.root) + '/')) throw new Error('invalid handle')
    return join(base, ...rest)
  }

  async publish (record: PublishedPolicy): Promise<void> {
    const file = this.path(record.handle, `v${record.version}.json`)
    await mkdir(dirname(file), { recursive: true })
    // The record wrapper is JSON, but policyJson inside it is the untouched original string.
    await writeFile(file, JSON.stringify(record, null, 2), 'utf8')
    await writeFile(this.path(record.handle, 'current.txt'), String(record.version), 'utf8')
  }

  async getVersion (handle: string, version: number): Promise<PublishedPolicy | null> {
    try {
      return JSON.parse(await readFile(this.path(handle, `v${version}.json`), 'utf8')) as PublishedPolicy
    } catch {
      return null
    }
  }

  async getCurrent (handle: string): Promise<PublishedPolicy | null> {
    try {
      const v = Number.parseInt(await readFile(this.path(handle, 'current.txt'), 'utf8'), 10)
      return await this.getVersion(handle, v)
    } catch {
      return null
    }
  }

  async listVersions (handle: string): Promise<number[]> {
    try {
      const files = await readdir(this.path(handle))
      return files
        .map((f) => /^v(\d+)\.json$/.exec(f)?.[1])
        .filter((v): v is string => v !== undefined)
        .map(Number)
        .sort((a, b) => a - b)
    } catch {
      return []
    }
  }

  async handleOwner (handle: string): Promise<string | null> {
    const current = await this.getCurrent(handle)
    return current?.accountId ?? null
  }
}

/** In-memory store, for tests. Same contract, no filesystem. */
export class MemoryStore implements PolicyStore {
  private readonly data = new Map<string, Map<number, PublishedPolicy>>()

  async publish (record: PublishedPolicy): Promise<void> {
    const versions = this.data.get(record.handle) ?? new Map()
    versions.set(record.version, record)
    this.data.set(record.handle, versions)
  }

  async getVersion (handle: string, version: number): Promise<PublishedPolicy | null> {
    return this.data.get(handle)?.get(version) ?? null
  }

  async getCurrent (handle: string): Promise<PublishedPolicy | null> {
    const versions = this.data.get(handle)
    if (!versions || versions.size === 0) return null
    return versions.get(Math.max(...versions.keys())) ?? null
  }

  async listVersions (handle: string): Promise<number[]> {
    return [...(this.data.get(handle)?.keys() ?? [])].sort((a, b) => a - b)
  }

  async handleOwner (handle: string): Promise<string | null> {
    return (await this.getCurrent(handle))?.accountId ?? null
  }
}

let singleton: PolicyStore | undefined

export function getStore (): PolicyStore {
  if (!singleton) {
    singleton = new FileStore(process.env.PRM_STORE_DIR ?? resolve(process.cwd(), '.prm-store'))
  }
  return singleton
}

/** Test hook. Never called in production code paths. */
export function __setStore (store: PolicyStore | undefined): void {
  singleton = store
}

export const HANDLE_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$/

export function isValidHandle (handle: string): boolean {
  return HANDLE_PATTERN.test(handle) && !RESERVED_HANDLES.has(handle)
}

const RESERVED_HANDLES = new Set([
  'api', 'app', 'admin', 'status', 'log', 'well-known', 'u', 'p', 'create', 'author', 'publish',
  'about', 'docs', 'verify', 'help', 'settings', 'login', 'signup', 'prm'
])
