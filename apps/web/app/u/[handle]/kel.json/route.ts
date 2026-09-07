import { artifactResponse, readKelBytes } from '../../../../lib/publish'
import { getStorage, isValidHandle } from '../../../../lib/storage'

export const runtime = 'nodejs'

/** GET /u/{handle}/kel.json — the public key history a verifier needs to check issuer authority. */
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
    const bytes = await readKelBytes(storage, record)
    return artifactResponse(bytes, record, { contentType: 'application/json' })
  } catch (e) {
    return new Response(`Artifact integrity check failed: ${(e as Error).message}`, { status: 502 })
  }
}
