import { resolve } from 'node:path'
import type { Storage } from './types'
import { createFileStorage } from './file'
import { BlobArtifactStore, PostgresMetadataStore, PostgresLogStore, namespaced, type BlobClient, type SqlQuery } from './blob'

export * from './types'
export * from './digest'
export { createFileStorage } from './file'
export { createMemoryStorage, MemoryArtifactStore, MemoryMetadataStore, MemoryLogStore, contentTypeFor } from './memory'
export {
  BlobArtifactStore, PostgresMetadataStore, PostgresLogStore, createBlobStorage, SCHEMA_SQL, ensureSchema,
  namespaceSql, namespaced, TABLES,
  type BlobClient, type BlobFetcher, type SqlQuery
} from './blob'

let singleton: Storage | undefined

export interface StorageNamespace {
  environment: 'development' | 'preview' | 'production'
  /** Prepended to every Postgres relation name. */
  tablePrefix: string
  /** Prepended to every blob object path. */
  blobPrefix: string
}

/**
 * Where an environment's data lives, decided by VERCEL_ENV alone.
 *
 * A preview must never write to production data (docs/16 §4). Rather than trusting that the
 * Preview environment was given different credentials — it was not, once — a preview is confined
 * by construction: its tables are `preview_*` and its objects live under `preview/`, so the same
 * DATABASE_URL and BLOB_READ_WRITE_TOKEN cannot reach a production row or object from a preview,
 * and production code never names a preview relation. A separate Neon branch per preview remains
 * the stronger setup and composes with this; this is the floor, not the ceiling.
 */
export function storageNamespace (env: Record<string, string | undefined> = process.env): StorageNamespace {
  const environment = (env.VERCEL_ENV as StorageNamespace['environment'] | undefined) ?? 'development'
  return environment === 'preview'
    ? { environment, tablePrefix: 'preview_', blobPrefix: 'preview/' }
    : { environment, tablePrefix: '', blobPrefix: '' }
}

/**
 * Select a storage adapter.
 *
 * Production (BLOB_READ_WRITE_TOKEN + DATABASE_URL present) uses Vercel Blob for artifacts and
 * Postgres for the alias layer. Anything else falls back to the filesystem, so local development
 * needs no configuration.
 *
 * Fails LOUDLY on a partial production configuration. Silently falling back to the filesystem on
 * Vercel would appear to work — publishes would succeed, and every artifact would vanish on the next
 * cold start.
 */
export async function getStorage (): Promise<Storage> {
  if (singleton) return singleton

  const blobToken = process.env.BLOB_READ_WRITE_TOKEN
  const databaseUrl = process.env.DATABASE_URL
  const onVercel = process.env.VERCEL === '1'

  if (blobToken && databaseUrl) {
    singleton = await createProductionStorage(blobToken, databaseUrl)
    return singleton
  }

  if (onVercel || blobToken || databaseUrl) {
    const missing = [
      blobToken ? null : 'BLOB_READ_WRITE_TOKEN',
      databaseUrl ? null : 'DATABASE_URL'
    ].filter(Boolean)
    throw new Error(
      `Incomplete production storage configuration: missing ${missing.join(' and ')}. ` +
      'Refusing to fall back to filesystem storage, which is ephemeral on Vercel and would lose ' +
      'every published artifact on the next cold start.')
  }

  singleton = createFileStorage(process.env.PRM_STORE_DIR ?? resolve(process.cwd(), '.prm-store'))
  return singleton
}

async function createProductionStorage (token: string, databaseUrl: string): Promise<Storage> {
  // Imported dynamically so local development does not need these packages resolved at all.
  const blob = (await import('@vercel/blob')) as unknown as BlobClient
  const { neon } = await import('@neondatabase/serverless')
  const client = neon(databaseUrl)

  const raw: SqlQuery = async <T>(text: string, values: unknown[] = []) =>
    (await client.query(text, values)) as T[]
  const ns = storageNamespace()
  // One namespaced connection shared by both stores, so the schema is ensured once and both
  // address the same relations.
  const sql = namespaced(raw, ns.tablePrefix)

  return {
    name: ns.environment === 'preview' ? 'blob (preview namespace)' : 'blob',
    artifacts: new BlobArtifactStore({
      client: blob,
      fetcher: async (url) => {
        const response = await fetch(url, { cache: 'no-store' })
        if (!response.ok) throw new Error(`blob fetch failed: ${response.status}`)
        return new Uint8Array(await response.arrayBuffer())
      },
      token,
      ...(ns.blobPrefix ? { pathPrefix: ns.blobPrefix } : {})
    }),
    metadata: new PostgresMetadataStore(sql),
    log: new PostgresLogStore(sql)
  }
}

/** Test hook. Never used by application code paths. */
export function __setStorage (storage: Storage | undefined): void {
  singleton = storage
}

export { HANDLE_PATTERN, isValidHandle } from '../handle'
