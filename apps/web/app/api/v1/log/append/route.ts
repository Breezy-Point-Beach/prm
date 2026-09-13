import { appendEntryDigest, isMultihash, LogNotConfiguredError } from '../../../../../lib/log'
import { getStorage } from '../../../../../lib/storage'
import { isValidHandle } from '../../../../../lib/handle'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * POST /api/v1/log/append — { entryDigest, handle? }
 *
 * Appends the DIGEST of a ledger entry the client signed. The entry itself never arrives (docs/07
 * §1): the server learns a 32-byte hash and nothing else. With `handle`, the digest is also linked
 * to the handle's current published policy so the public page can show the leaf and its evidence.
 *
 * Idempotent: appending the same digest twice yields the same leaf.
 */
export async function POST (request: Request): Promise<Response> {
  let body: { entryDigest?: unknown; handle?: unknown }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return json({ ok: false, error: 'Request body is not valid JSON.' }, 400)
  }
  if (!isMultihash(body.entryDigest)) {
    return json({ ok: false, error: 'entryDigest must be a multibase multihash (base64url SHA-256).' }, 400)
  }
  if (body.handle !== undefined && (typeof body.handle !== 'string' || !isValidHandle(body.handle))) {
    return json({ ok: false, error: 'Invalid handle.' }, 400)
  }

  try {
    const storage = await getStorage()
    const result = await appendEntryDigest(storage, body.entryDigest)

    if (typeof body.handle === 'string') {
      const current = await storage.metadata.currentVersion(body.handle)
      if (current) {
        await storage.metadata.recordLogLink({
          policyDigest: current.policyDigest,
          accountId: current.accountId,
          entryDigest: body.entryDigest,
          leafIndex: result.leafIndex,
          linkedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
        })
      }
    }

    return json({
      ok: true,
      logId: result.logId,
      leafIndex: result.leafIndex,
      treeSize: result.head.treeSize,
      rootHash: result.head.sth.rootHash,
      proofUrl: `/log/proof/${result.leafIndex}.json`
    }, 200)
  } catch (e) {
    if (e instanceof LogNotConfiguredError) return json({ ok: false, error: e.message }, 503)
    return json({ ok: false, error: `Could not append to the log: ${(e as Error).message}` }, 500)
  }
}

function json (payload: unknown, status: number): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  })
}
