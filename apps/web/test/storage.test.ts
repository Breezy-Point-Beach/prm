import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runStorageContract, runHostileBackendContract } from '../lib/storage/contract'
import { createMemoryStorage, MemoryArtifactStore, MemoryMetadataStore } from '../lib/storage/memory'
import { createFileStorage } from '../lib/storage/file'
import { BlobArtifactStore, type BlobClient } from '../lib/storage/blob'
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
    metadata: storage.metadata
  })
})
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
    metadata: new MemoryMetadataStore()
  }
}

const blobBackends = new WeakMap<Storage, ReturnType<typeof fakeBlobBackend>>()
runStorageContract('BlobStore (fake backend)', {
  create: () => {
    const backend = fakeBlobBackend()
    const storage: Storage = {
      name: 'blob',
      artifacts: new BlobArtifactStore({ client: backend.client, fetcher: backend.fetcher }),
      metadata: new MemoryMetadataStore()
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
      metadata: storage.metadata
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
