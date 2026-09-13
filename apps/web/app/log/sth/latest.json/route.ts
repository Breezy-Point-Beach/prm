import { LogNotConfiguredError, timestampArtifacts } from '../../../../lib/log'
import { getStorage } from '../../../../lib/storage'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/** GET /log/sth/latest.json — the newest signed tree head, as the exact bytes that were signed. */
export async function GET (): Promise<Response> {
  try {
    const storage = await getStorage()
    const head = await storage.log.latestTreeHead()
    if (!head) return new Response('Not found', { status: 404 })
    const tokens = await storage.log.timestamps(head.treeSize)
    const { timestampedAt, authorities } = timestampArtifacts(tokens)
    return new Response(head.sthJson, {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'public, max-age=30',
        'Access-Control-Allow-Origin': '*',
        'Cross-Origin-Resource-Policy': 'cross-origin',
        'X-PRM-Tree-Size': String(head.treeSize),
        'X-PRM-Timestamped-At': timestampedAt ?? 'pending',
        'X-PRM-Timestamp-Authorities': authorities.map((a) => a.tsa).join(',')
      }
    })
  } catch (e) {
    if (e instanceof LogNotConfiguredError) return new Response(e.message, { status: 503 })
    return new Response((e as Error).message, { status: 500 })
  }
}
