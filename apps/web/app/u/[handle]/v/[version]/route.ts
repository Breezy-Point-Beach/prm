import { artifactResponse, readPolicyBytes } from '../../../../../lib/publish'
import { getStorage, isValidHandle } from '../../../../../lib/storage'

export const runtime = 'nodejs'

/**
 * GET /u/{handle}/v/{n}.json — an IMMUTABLE version.
 *
 * Once published, a version never changes: a new policy is a new artifact at a new address, and the
 * old one remains forever. That makes this endpoint safe to cache for a year, and makes it the
 * reference to cite in a notice or a filing.
 */
export async function GET (
  _request: Request,
  context: { params: Promise<{ handle: string; version: string }> }
): Promise<Response> {
  const { handle, version } = await context.params
  if (!isValidHandle(handle)) return new Response('Not found', { status: 404 })

  const match = /^(\d{1,6})\.json$/.exec(version)
  if (!match) return new Response('Not found', { status: 404 })
  const n = Number.parseInt(match[1] as string, 10)

  const storage = await getStorage()
  const record = await storage.metadata.version(handle, n)
  if (!record) return new Response('Not found', { status: 404 })

  try {
    return artifactResponse(await readPolicyBytes(storage, record), record, { immutable: true })
  } catch (e) {
    return new Response(`Artifact integrity check failed: ${(e as Error).message}`, { status: 502 })
  }
}
