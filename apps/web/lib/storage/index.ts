import { resolve } from 'node:path'
import type { Storage } from './types'
import { createFileStorage } from './file'
import { BlobArtifactStore, PostgresMetadataStore, type BlobClient, type SqlQuery } from './blob'

export * from './types'
export * from './digest'
export { createFileStorage } from './file'
export { createMemoryStorage, MemoryArtifactStore, MemoryMetadataStore, contentTypeFor } from './memory'
export {
  BlobArtifactStore, PostgresMetadataStore, createBlobStorage, SCHEMA_SQL,
  type BlobClient, type BlobFetcher, type SqlQuery
} from './blob'

let singleton: Storage | undefined

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

  const sql: SqlQuery = async <T>(text: string, values: unknown[] = []) =>
    (await client.query(text, values)) as T[]

  return {
    name: 'blob',
    artifacts: new BlobArtifactStore({
      client: blob,
      fetcher: async (url) => {
        const response = await fetch(url, { cache: 'no-store' })
        if (!response.ok) throw new Error(`blob fetch failed: ${response.status}`)
        return new Uint8Array(await response.arrayBuffer())
      },
      token
    }),
    metadata: new PostgresMetadataStore(sql)
  }
}

/** Test hook. Never used by application code paths. */
export function __setStorage (storage: Storage | undefined): void {
  singleton = storage
}

export const HANDLE_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$/

const RESERVED_HANDLES = new Set([
  'api', 'app', 'admin', 'status', 'log', 'well-known', 'u', 'p', 'create', 'author', 'publish',
  'about', 'docs', 'verify', 'help', 'settings', 'login', 'signup', 'prm', 'share', 'v'
])

export function isValidHandle (handle: string): boolean {
  return HANDLE_PATTERN.test(handle) && !RESERVED_HANDLES.has(handle)
}
