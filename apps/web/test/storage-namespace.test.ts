import { describe, expect, it } from 'vitest'
import { storageNamespace } from '../lib/storage'
import { BlobArtifactStore, PostgresLogStore, PostgresMetadataStore, namespaceSql, namespaced, SCHEMA_SQL, TABLES, type BlobClient } from '../lib/storage/blob'
import { MemoryArtifactStore } from '../lib/storage/memory'
import { runStorageContract, runLogContract } from '../lib/storage/contract'
import { byteDigestOf, utf8 } from '../lib/storage/digest'
import type { Storage } from '../lib/storage/types'
import { fakePostgres } from './helpers/fake-postgres'

/**
 * Environment isolation, enforced — docs/16 §4: a preview must never write to production data.
 *
 * The failure this guards: a preview deployment given production credentials (it happened) publishes
 * a test policy straight into the production tables and blob store. Isolation here is by
 * construction, not configuration: on a preview every relation is `preview_*` and every object is
 * under `preview/`, whatever DATABASE_URL and BLOB_READ_WRITE_TOKEN say.
 */
describe('the namespace is decided by VERCEL_ENV alone', () => {
  it('confines a preview to its own tables and paths', () => {
    expect(storageNamespace({ VERCEL_ENV: 'preview' })).toEqual({ environment: 'preview', tablePrefix: 'preview_', blobPrefix: 'preview/' })
  })
  it('leaves production and development on the plain names', () => {
    expect(storageNamespace({ VERCEL_ENV: 'production' })).toMatchObject({ tablePrefix: '', blobPrefix: '' })
    expect(storageNamespace({})).toMatchObject({ environment: 'development', tablePrefix: '', blobPrefix: '' })
  })
})

describe('namespaceSql', () => {
  it('rewrites every relation the adapters use, DDL included, and nothing else', () => {
    const ddl = namespaceSql(SCHEMA_SQL, 'preview_')
    for (const t of TABLES) {
      expect(ddl).toContain(`create table if not exists preview_${t}`)
      expect(ddl).not.toMatch(new RegExp(`(?<!preview_)\\b${t}\\b`))
    }
    expect(ddl).toContain('preview_published_policies_account')
    // A column that merely resembles a table name is untouched.
    expect(namespaceSql('select policy_digest from published_policy_log where policy_digest = $1', 'preview_'))
      .toBe('select policy_digest from preview_published_policy_log where policy_digest = $1')
    expect(namespaceSql('select * from log_leaves', '')).toBe('select * from log_leaves')
  })

  it('a namespaced SqlQuery addresses prefixed relations and passes values through untouched', async () => {
    const { sql, statements, tables } = fakePostgres()
    const preview = namespaced(sql, 'preview_')
    const meta = new PostgresMetadataStore(preview)
    await meta.recordLogLink({ policyDigest: 'uEiA'.padEnd(47, 'A'), accountId: 'prm:x', entryDigest: 'uEiB'.padEnd(47, 'B'), leafIndex: 3, linkedAt: '2026-09-15T10:00:00Z' })
    expect(statements.some((s) => s.includes('into preview_published_policy_log'))).toBe(true)
    expect(statements.some((s) => /\bpublished_policy_log\b/.test(s) && !s.includes('preview_'))).toBe(false)
    expect(tables.has('preview_published_policy_log')).toBe(true)
    expect(tables.has('published_policy_log')).toBe(false)
  })
})

describe('a preview and production over the SAME credentials cannot see each other', () => {
  function fakeBlob () {
    const objects = new Map<string, Uint8Array>()
    const client: BlobClient = {
      async put (pathname, body) { objects.set(pathname, new Uint8Array(typeof body === 'string' ? utf8(body) : body)); return { url: `https://blob.test/${pathname}`, pathname } },
      async head (pathname) { const b = objects.get(pathname); if (!b) throw new Error('BlobNotFoundError'); return { url: `https://blob.test/${pathname}`, size: b.length } }
    }
    const fetcher = async (url: string) => { const b = objects.get(url.replace('https://blob.test/', '')); if (!b) throw new Error('404'); return b }
    return { client, fetcher, objects }
  }

  it('blob objects: the preview writes under preview/, production never finds them, and vice versa', async () => {
    const backend = fakeBlob()
    const production = new BlobArtifactStore({ client: backend.client, fetcher: backend.fetcher })
    const preview = new BlobArtifactStore({ client: backend.client, fetcher: backend.fetcher, pathPrefix: 'preview/' })
    const bytes = utf8('{"from":"preview"}'); const digest = byteDigestOf(bytes)
    const ref = await preview.put('policy', bytes, digest)
    expect(ref.location).toBe(`preview/artifacts/policy/${digest}`)
    expect([...backend.objects.keys()]).toEqual([`preview/artifacts/policy/${digest}`])
    expect(await preview.has(digest)).toBe(true)
    expect(await production.has(digest)).toBe(false)
    await expect(production.get(digest)).rejects.toThrow(/No artifact/)

    const prodBytes = utf8('{"from":"production"}'); const prodDigest = byteDigestOf(prodBytes)
    await production.put('policy', prodBytes, prodDigest)
    expect(await preview.has(prodDigest)).toBe(false)
  })

  it('database rows: the same driver, disjoint relations', async () => {
    const backend = fakePostgres()
    const production = new PostgresMetadataStore(backend.sql)
    const preview = new PostgresMetadataStore(namespaced(backend.sql, 'preview_'))
    const record = (handle: string) => ({
      handle, accountId: 'prm:x', policyChainId: 'urn:prm:chain:x', version: 1, policyDigest: 'uEiA'.padEnd(47, 'A'),
      policyByteDigest: 'uEiB'.padEnd(47, 'B'), policyLocation: 'l', policyByteLength: 1, kelByteDigest: 'uEiC'.padEnd(47, 'C'),
      kelLocation: 'k', publishedAt: '2026-09-15T10:00:00Z', contentType: 'application/prm-policy+json'
    })
    await preview.publish(record('previewtest'))
    expect(await production.currentVersion('previewtest')).toBeNull()
    expect(await production.handleOwner('previewtest')).toBeNull()
    expect((await preview.currentVersion('previewtest'))?.handle).toBe('previewtest')
    expect(backend.tables.get('preview_published_policies')).toHaveLength(1)
    // The production relation was only ever read, never written.
    expect(backend.tables.get('published_policies') ?? []).toEqual([])
  })
})

// The namespaced adapters must behave exactly like the plain ones. Same contracts, prefixed.
const pgBackends = new WeakMap<Storage, ReturnType<typeof fakePostgres>>()
function previewStorage (backend = fakePostgres()): Storage {
  const sql = namespaced(backend.sql, 'preview_')
  const storage: Storage = {
    name: 'blob (preview namespace)',
    artifacts: new MemoryArtifactStore(),
    metadata: new PostgresMetadataStore(sql),
    log: new PostgresLogStore(sql)
  }
  pgBackends.set(storage, backend)
  return storage
}
runStorageContract('Postgres metadata (fake driver, preview namespace)', {
  create: () => previewStorage(),
  reopen: (storage) => ({ ...previewStorage(pgBackends.get(storage) as ReturnType<typeof fakePostgres>), artifacts: storage.artifacts })
})
runLogContract('Postgres log (fake driver, preview namespace)', {
  create: () => previewStorage(),
  reopen: (storage) => previewStorage(pgBackends.get(storage) as ReturnType<typeof fakePostgres>)
})
