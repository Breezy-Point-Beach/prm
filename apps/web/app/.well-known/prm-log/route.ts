import { logIdentity, LogNotConfiguredError } from '../../../lib/log'
import { configuredAuthorities } from '../../../lib/tsa'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * GET /.well-known/prm-log — the log's identity and how to use it (docs/07 §3).
 *
 * The public key here is what verifies every signed tree head. Anyone mirroring the log or
 * checking a .prmproof bundle takes it from this address, not from the bundle.
 */
export async function GET (request: Request): Promise<Response> {
  try {
    const id = logIdentity()
    const origin = new URL(request.url).origin
    const body = {
      logId: id.logId,
      publicKeyMultibase: id.publicKeyMultibase,
      keys: [{ publicKeyMultibase: id.publicKeyMultibase, alg: 'Ed25519' }],
      hashing: 'RFC 6962: leaf = SHA-256(0x00 || entryDigest), node = SHA-256(0x01 || left || right)',
      treeHeadSignature: 'Ed25519 over PRM-STH-v1 || SHA-256(PRM-JCS(head without signature))',
      timestampImprint: 'SHA-256 over the 32 raw bytes of rootHash (spec/NORMATIVE.md §9.1)',
      endpoints: {
        latestTreeHead: `${origin}/log/sth/latest.json`,
        inclusionProof: `${origin}/log/proof/{leafIndex}.json`,
        append: `${origin}/api/v1/log/append`
      },
      timestampAuthorities: configuredAuthorities().map((a) => ({ tsa: a.tsa, url: a.url, ...(a.caUrl ? { chain: a.caUrl } : {}) })),
      specification: 'https://rightsroot.org/spec/prm'
    }
    return new Response(JSON.stringify(body, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'public, max-age=300',
        'Access-Control-Allow-Origin': '*'
      }
    })
  } catch (e) {
    if (e instanceof LogNotConfiguredError) return new Response(e.message, { status: 503 })
    return new Response((e as Error).message, { status: 500 })
  }
}
