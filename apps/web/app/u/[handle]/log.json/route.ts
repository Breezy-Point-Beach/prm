import { anchorLatest, proofForLeaf, LogNotConfiguredError } from '../../../../lib/log'
import { getStorage, isValidHandle } from '../../../../lib/storage'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * GET /u/{handle}/log.json — the transparency-log evidence for the handle's current policy.
 *
 * Everything a third party needs to check the policy's place in the log and the time an
 * independent authority attests for it: the entry digest the issuer appended, the leaf, the
 * inclusion proof, the signed tree head, and the RFC 3161 token(s) over that head.
 */
export async function GET (
  _request: Request,
  context: { params: Promise<{ handle: string }> }
): Promise<Response> {
  const { handle } = await context.params
  if (!isValidHandle(handle)) return new Response('Not found', { status: 404 })

  try {
    const storage = await getStorage()
    const record = await storage.metadata.currentVersion(handle)
    if (!record) return new Response('Not found', { status: 404 })
    const link = await storage.metadata.logLink(record.policyDigest)
    if (!link) return new Response('Not logged', { status: 404 })

    await anchorLatest(storage).catch(() => undefined)
    const proof = await proofForLeaf(storage, link.leafIndex)
    if (!proof) return new Response('Not found', { status: 404 })

    return new Response(JSON.stringify({
      handle,
      policyVersion: record.version,
      policyDigest: record.policyDigest,
      entryDigest: link.entryDigest,
      ...proof
    }, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': proof.timestampedAt ? 'public, max-age=300' : 'public, max-age=30',
        'Access-Control-Allow-Origin': '*',
        'Cross-Origin-Resource-Policy': 'cross-origin'
      }
    })
  } catch (e) {
    if (e instanceof LogNotConfiguredError) return new Response(e.message, { status: 503 })
    return new Response((e as Error).message, { status: 500 })
  }
}
