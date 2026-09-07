import QRCode from 'qrcode'
import { getStorage, isValidHandle } from '../../../../lib/storage'

export const runtime = 'nodejs'

/**
 * GET /u/{handle}/qr.svg
 *
 * Encodes the canonical URL WITH the policy digest in the fragment:
 *
 *     https://host/u/{handle}#sha256=uEiDy...
 *
 * The digest travels with the share mechanism, which is what makes substitution by the hosting layer
 * detectable. A scanner lands on the page, the page fetches the policy, recomputes the digest, and
 * compares it against the value that came from the QR — so a server that swapped the document is
 * caught by a code printed on a card in the holder's hand.
 *
 * A fragment, not a query parameter, because fragments are never sent to the server: the expectation
 * is carried by the reader, and the server cannot see which digest they were told to expect.
 *
 * Error correction level M (15%): enough for a printed card that gets folded and scanned in poor
 * light, without inflating the code so much that it stops scanning at business-card size.
 */
export async function GET (
  request: Request,
  context: { params: Promise<{ handle: string }> }
): Promise<Response> {
  const { handle } = await context.params
  if (!isValidHandle(handle)) return new Response('Not found', { status: 404 })

  const storage = await getStorage()
  const record = await storage.metadata.currentVersion(handle)
  if (!record) return new Response('Not found', { status: 404 })

  const origin = new URL(request.url).origin
  const target = `${origin}/u/${handle}#sha256=${record.policyDigest}`

  const svg = await QRCode.toString(target, {
    type: 'svg',
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 512,
    color: { dark: '#000000ff', light: '#ffffffff' }
  })

  return new Response(svg, {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      // Tied to the current version, so it must not outlive a new publish.
      'Cache-Control': 'public, max-age=60, stale-while-revalidate=600',
      'X-PRM-Encoded-Url': target
    }
  })
}
