import { anchorLatest, proofForLeaf, LogNotConfiguredError } from '../../../../lib/log'
import { getStorage } from '../../../../lib/storage'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * GET /log/proof/{leafIndex}.json — inclusion proof, signed tree head, and any RFC 3161 tokens.
 *
 * Public and cross-origin: this is what a third party fetches to check a leaf without asking PRM
 * anything else. If the newest head has no token yet and an hour has passed since the last one,
 * this request also anchors it — the cron is the schedule, but a reader who arrives first should
 * not have to wait for it.
 */
export async function GET (
  _request: Request,
  context: { params: Promise<{ leaf: string }> }
): Promise<Response> {
  const { leaf } = await context.params
  const match = /^(\d{1,9})\.json$/.exec(leaf)
  if (!match) return new Response('Not found', { status: 404 })
  const leafIndex = Number.parseInt(match[1] as string, 10)

  try {
    const storage = await getStorage()
    await anchorLatest(storage).catch(() => undefined)
    const proof = await proofForLeaf(storage, leafIndex)
    if (!proof) return new Response('Not found', { status: 404 })
    return new Response(JSON.stringify(proof, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        // A proof against a given head never changes; a NEWER head may add a token. Short cache.
        'Cache-Control': proof.timestampedAt ? 'public, max-age=300' : 'public, max-age=30',
        'Access-Control-Allow-Origin': '*',
        'Cross-Origin-Resource-Policy': 'cross-origin'
      }
    })
  } catch (e) {
    if (e instanceof LogNotConfiguredError) return new Response(e.message, { status: 503 })
    return new Response(`Could not produce a proof: ${(e as Error).message}`, { status: 500 })
  }
}
