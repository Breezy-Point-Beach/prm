import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runStorageContract, runHostileBackendContract, runLogContract } from '../lib/storage/contract'
import { createMemoryStorage, MemoryArtifactStore, MemoryMetadataStore, MemoryLogStore } from '../lib/storage/memory'
import { createFileStorage } from '../lib/storage/file'
import { BlobArtifactStore, PostgresLogStore, PostgresMetadataStore, type BlobClient, type SqlQuery } from '../lib/storage/blob'
import { byteDigestOf, utf8 } from '../lib/storage/digest'
import type { Storage } from '../lib/storage/types'

/**
 * Every adapter passes the identical contract.
 *
 * This is the guard rail against a future maintainer swapping Vercel Blob for S3 or Postgres and
 * accidentally breaking PRM's core property. A new adapter is not finished until it appears here.
 */

// ---- memory ----------------------------------------------------------------
runStorageContract('MemoryStore', {
  create: () => createMemoryStorage(),
  // A "restart" for the in-memory adapter means new instances over the same maps.
  reopen: (storage) => ({
    name: 'memory',
    artifacts: reuseMemoryArtifacts(storage),
    metadata: storage.metadata,
    log: storage.log
  })
})
runLogContract('MemoryLog', { create: () => createMemoryStorage() })
runHostileBackendContract('MemoryStore', (mutate) => createMemoryStorage(mutate))

// ---- filesystem (development) ----------------------------------------------
// The genuinely meaningful durability case: bytes on disk, read by a new process.
const fileRoots: string[] = []
const newFileRoot = () => {
  const root = mkdtempSync(join(tmpdir(), 'prm-file-store-'))
  fileRoots.push(root)
  return root
}
const fileRootOf = new WeakMap<Storage, string>()
runStorageContract('FileStore', {
  create: () => {
    const root = newFileRoot()
    const storage = createFileStorage(root)
    fileRootOf.set(storage, root)
    return storage
  },
  reopen: (storage) => createFileStorage(fileRootOf.get(storage) as string)
})
runLogContract('FileLog', {
  create: () => {
    const root = newFileRoot()
    const storage = createFileStorage(root)
    fileRootOf.set(storage, root)
    return storage
  },
  reopen: (storage) => createFileStorage(fileRootOf.get(storage) as string)
})

// ---- Vercel Blob (production), against a fake backend ----------------------

/**
 * A stand-in for @vercel/blob.
 *
 * Exercises the adapter's real integrity logic — digest-derived keys, write-once behaviour, and
 * read verification — without network access. What it does NOT cover is @vercel/blob's own wire
 * behaviour; that is what the deployment smoke check is for.
 */
function fakeBlobBackend (tamper: (bytes: Uint8Array) => Uint8Array = (b) => b) {
  const objects = new Map<string, Uint8Array>()
  const client: BlobClient = {
    async put (pathname, body, options) {
      const bytes = typeof body === 'string' ? utf8(body) : body
      if (options.allowOverwrite === false && objects.has(pathname)) {
        throw new Error('blob already exists')
      }
      objects.set(pathname, new Uint8Array(bytes))
      return { url: `https://blob.test/${pathname}`, pathname }
    },
    async head (pathname) {
      const bytes = objects.get(pathname)
      if (!bytes) throw new Error('BlobNotFoundError')
      return { url: `https://blob.test/${pathname}`, size: bytes.length }
    }
  }
  const fetcher = async (url: string): Promise<Uint8Array> => {
    const pathname = url.replace('https://blob.test/', '')
    const bytes = objects.get(pathname)
    if (!bytes) throw new Error('404')
    return tamper(bytes)
  }
  return { client, fetcher, objects }
}

/** A second MemoryArtifactStore sharing the first's backing map. */
function reuseMemoryArtifacts (storage: Storage): MemoryArtifactStore {
  const fresh = new MemoryArtifactStore()
  for (const [k, v] of (storage.artifacts as MemoryArtifactStore).backing) fresh.backing.set(k, v)
  return fresh
}

function blobStorage (tamper?: (b: Uint8Array) => Uint8Array): Storage {
  const { client, fetcher } = fakeBlobBackend(tamper)
  return {
    name: 'blob',
    artifacts: new BlobArtifactStore({ client, fetcher }),
    metadata: new MemoryMetadataStore(),
    log: new MemoryLogStore()
  }
}

/**
 * A stand-in for Neon's HTTP driver: one statement per call, no transactions. It understands only
 * the statements PostgresLogStore and the log-link methods issue, and it reproduces the one
 * behaviour that matters for correctness — a primary-key collision on leaf_index raises, so the
 * adapter's retry loop is what makes concurrent appends safe. The SQL is matched on shape, not
 * parsed; if the adapter's statements change, this fake must too, and the contract will say so.
 */
type Row = Record<string, unknown>
interface FakeTables { log_leaves: Row[]; log_tree_heads: Row[]; log_timestamps: Row[]; published_policy_log: Row[] }
function fakePostgres (): { sql: SqlQuery; tables: FakeTables } {
  const tables: FakeTables = { log_leaves: [], log_tree_heads: [], log_timestamps: [], published_policy_log: [] }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const sql = (async (text: string, values: unknown[] = []): Promise<any[]> => {
    const q = text.replace(/\s+/g, ' ').trim().toLowerCase()
    if (q.startsWith('create table') || q.startsWith('create index')) return []
    if (q.startsWith('insert into log_leaves')) {
      const [leafHash, appendedAt] = values as [string, string]
      if (tables.log_leaves.some((r) => r.leaf_hash === leafHash)) return []
      const index = tables.log_leaves.length === 0 ? 0 : Math.max(...tables.log_leaves.map((r) => Number(r.leaf_index))) + 1
      // Simulate the race the real database would expose: yield, then check the key again.
      await new Promise((r) => setTimeout(r, Math.random() * 3))
      if (tables.log_leaves.some((r) => r.leaf_index === index)) {
        throw new Error('duplicate key value violates unique constraint "log_leaves_pkey"')
      }
      tables.log_leaves.push({ leaf_index: index, leaf_hash: leafHash, appended_at: appendedAt })
      return [{ leaf_index: index }]
    }
    if (q.startsWith('select * from log_leaves where leaf_hash')) return tables.log_leaves.filter((r) => r.leaf_hash === values[0])
    if (q.startsWith('select * from log_leaves')) return [...tables.log_leaves].sort((a, b) => Number(a.leaf_index) - Number(b.leaf_index))
    if (q.startsWith('select count(*)')) return [{ n: tables.log_leaves.length }]
    if (q.startsWith('insert into log_tree_heads')) {
      const [tree_size, sth_json, created_at] = values
      if (!tables.log_tree_heads.some((r) => r.tree_size === tree_size)) tables.log_tree_heads.push({ tree_size, sth_json, created_at })
      return []
    }
    if (q.startsWith('select * from log_tree_heads where')) return tables.log_tree_heads.filter((r) => r.tree_size === values[0])
    if (q.startsWith('select * from log_tree_heads order')) return [...tables.log_tree_heads].sort((a, b) => Number(b.tree_size) - Number(a.tree_size)).slice(0, 1)
    if (q.startsWith('insert into log_timestamps')) {
      const [tree_size, tsa, token_b64, gen_time, chain_pem, acquired_at] = values
      const row = { tree_size, tsa, token_b64, gen_time, chain_pem, acquired_at }
      const i = tables.log_timestamps.findIndex((r) => r.tree_size === tree_size && r.tsa === tsa)
      if (i >= 0) tables.log_timestamps[i] = row; else tables.log_timestamps.push(row)
      return []
    }
    if (q.startsWith('select * from log_timestamps where')) return tables.log_timestamps.filter((r) => r.tree_size === values[0]).sort((a, b) => String(a.tsa).localeCompare(String(b.tsa)))
    if (q.startsWith('select * from log_timestamps order')) return [...tables.log_timestamps].sort((a, b) => String(b.acquired_at).localeCompare(String(a.acquired_at)) || Number(b.tree_size) - Number(a.tree_size)).slice(0, 1)
    if (q.startsWith('insert into published_policy_log')) {
      const [policy_digest, account_id, entry_digest, leaf_index, linked_at] = values
      if (!tables.published_policy_log.some((r) => r.policy_digest === policy_digest)) tables.published_policy_log.push({ policy_digest, account_id, entry_digest, leaf_index, linked_at })
      return []
    }
    if (q.startsWith('select * from published_policy_log')) return tables.published_policy_log.filter((r) => r.policy_digest === values[0])
    throw new Error(`fakePostgres: unhandled statement: ${q.slice(0, 80)}`)
  }) as SqlQuery
  return { sql, tables }
}

const pgBackends = new WeakMap<Storage, ReturnType<typeof fakePostgres>>()
runLogContract('PostgresLog (fake driver)', {
  create: () => {
    const backend = fakePostgres()
    const storage: Storage = {
      name: 'blob',
      artifacts: new MemoryArtifactStore(),
      metadata: new PostgresMetadataStore(backend.sql),
      log: new PostgresLogStore(backend.sql)
    }
    pgBackends.set(storage, backend)
    return storage
  },
  reopen: (storage) => {
    const backend = pgBackends.get(storage) as ReturnType<typeof fakePostgres>
    return { ...storage, metadata: new PostgresMetadataStore(backend.sql), log: new PostgresLogStore(backend.sql) }
  }
})

const blobBackends = new WeakMap<Storage, ReturnType<typeof fakeBlobBackend>>()
runStorageContract('BlobStore (fake backend)', {
  create: () => {
    const backend = fakeBlobBackend()
    const storage: Storage = {
      name: 'blob',
      artifacts: new BlobArtifactStore({ client: backend.client, fetcher: backend.fetcher }),
      metadata: new MemoryMetadataStore(),
      log: new MemoryLogStore()
    }
    blobBackends.set(storage, backend)
    return storage
  },
  // New adapter instance, same object store: exactly what a Vercel cold start looks like, and the
  // case where an adapter that cached URLs in memory without re-resolving would break.
  reopen: (storage) => {
    const backend = blobBackends.get(storage) as ReturnType<typeof fakeBlobBackend>
    return {
      name: 'blob',
      artifacts: new BlobArtifactStore({ client: backend.client, fetcher: backend.fetcher }),
      metadata: storage.metadata,
      log: storage.log
    }
  }
})
runHostileBackendContract('BlobStore', (mutate) => blobStorage(mutate))

// ---- adapter-specific behaviour --------------------------------------------

describe('BlobStore specifics', () => {
  it('writes at a digest-derived key, not a random one', async () => {
    const { client, fetcher, objects } = fakeBlobBackend()
    const store = new BlobArtifactStore({ client, fetcher })
    const bytes = utf8('{"a":1}')
    const digest = byteDigestOf(bytes)
    await store.put('policy', bytes, digest)
    expect([...objects.keys()]).toEqual([`artifacts/policy/${digest}`])
  })

  it('never asks the backend to overwrite', async () => {
    const calls: Array<boolean | undefined> = []
    const { client, fetcher } = fakeBlobBackend()
    const spying: BlobClient = {
      put: async (p, b, o) => { calls.push(o.allowOverwrite); return client.put(p, b, o) },
      head: client.head
    }
    const store = new BlobArtifactStore({ client: spying, fetcher })
    const bytes = utf8('{"a":1}')
    await store.put('policy', bytes, byteDigestOf(bytes))
    expect(calls).toEqual([false])
  })

  it('treats a repeat write as a no-op instead of a failed overwrite', async () => {
    const { client, fetcher, objects } = fakeBlobBackend()
    const store = new BlobArtifactStore({ client, fetcher })
    const bytes = utf8('{"a":1}')
    const digest = byteDigestOf(bytes)
    await store.put('policy', bytes, digest)
    await expect(store.put('policy', bytes, digest)).resolves.toMatchObject({ byteDigest: digest })
    expect(objects.size).toBe(1)
  })
})

describe('FileStore cleanup', () => {
  it('removes its temporary roots', () => {
    for (const root of fileRoots) rmSync(root, { recursive: true, force: true })
    expect(true).toBe(true)
  })
})
