import { handlePublish, type PublishRequest } from '../../../../lib/publish'
import { getStorage } from '../../../../lib/storage'

// Node runtime: the store touches the filesystem in development, and verification uses Node crypto
// paths in @noble. The public read routes stay cacheable and could move to Edge later.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * POST /api/v1/publish
 *
 * Accepts ONLY an already-signed policy and the public key event log, both as exact strings. There
 * is deliberately no endpoint that accepts a draft, an identifier, or anything the server could use
 * to author a document on a user's behalf.
 */
export async function POST (request: Request): Promise<Response> {
  let body: PublishRequest
  try {
    body = (await request.json()) as PublishRequest
  } catch {
    return json({ ok: false, error: 'Request body is not valid JSON.' }, 400)
  }

  const origin = new URL(request.url).origin
  const result = await handlePublish(body, await getStorage(), origin)
  return json(result, result.ok ? 200 : 400)
}

function json (payload: unknown, status: number): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  })
}
