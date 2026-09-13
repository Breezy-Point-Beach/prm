import { anchorLatest, LogNotConfiguredError } from '../../../../lib/log'
import { getStorage } from '../../../../lib/storage'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
export const maxDuration = 60

/**
 * /api/cron/timestamp — hourly RFC 3161 over the newest tree head (docs/08 §3, docs/16 §6).
 *
 * Guarded by CRON_SECRET, which Vercel sends as a bearer token. Idempotent: an authority that has
 * already issued a token for this head is not asked again, so a cron that fires twice is harmless.
 * Outside Vercel with no secret configured the guard is off, so `pnpm dev` can exercise it.
 */
async function run (request: Request): Promise<Response> {
  const secret = process.env.CRON_SECRET
  if (secret) {
    if (request.headers.get('authorization') !== `Bearer ${secret}`) {
      return json({ ok: false, error: 'unauthorized' }, 401)
    }
  } else if (process.env.VERCEL === '1') {
    return json({ ok: false, error: 'CRON_SECRET is not set; refusing to run unauthenticated on Vercel.' }, 503)
  }

  try {
    const result = await anchorLatest(await getStorage(), { force: true })
    const failed = result.results.filter((r) => !r.ok)
    if (failed.length > 0 && failed.length === result.results.length) {
      // Every authority failed: say so with a status that monitoring will notice (docs/16 §12).
      return json({ ok: false, ...result }, 502)
    }
    return json({ ok: true, ...result }, 200)
  } catch (e) {
    if (e instanceof LogNotConfiguredError) return json({ ok: false, error: e.message }, 503)
    return json({ ok: false, error: (e as Error).message }, 500)
  }
}

export const GET = run
export const POST = run

function json (payload: unknown, status: number): Response {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  })
}
