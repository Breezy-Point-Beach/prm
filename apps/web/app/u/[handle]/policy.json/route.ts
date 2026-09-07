import { artifactResponse, readPolicyBytes } from '../../../../lib/publish'
import { getStorage, isValidHandle } from '../../../../lib/storage'

export const runtime = 'nodejs'

/**
 * GET /u/{handle}/policy.json — the CURRENT version.
 *
 * An alias that moves when a new version is published, so it is cached briefly. For a stable
 * reference use /u/{handle}/v/{n}.json, which is immutable.
 */
export async function GET (
  _request: Request,
  context: { params: Promise<{ handle: string }> }
): Promise<Response> {
  const { handle } = await context.params
  if (!isValidHandle(handle)) return new Response('Not found', { status: 404 })

  const storage = await getStorage()
  const record = await storage.metadata.currentVersion(handle)
  if (!record) return new Response('Not found', { status: 404 })

  try {
    return artifactResponse(await readPolicyBytes(storage, record), record)
  } catch (e) {
    // A digest mismatch here means the storage backend returned different bytes than were written.
    // Serving them anyway would defeat the point, so refuse loudly.
    return new Response(`Artifact integrity check failed: ${(e as Error).message}`, { status: 502 })
  }
}
