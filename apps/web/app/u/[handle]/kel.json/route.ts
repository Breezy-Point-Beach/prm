import { keyEventLogResponse } from '../../../../lib/publish'
import { getStore, isValidHandle } from '../../../../lib/store'

export const runtime = 'nodejs'

/** GET /u/{handle}/kel.json — the public key history a verifier needs to check issuer authority. */
export async function GET (
  _request: Request,
  context: { params: Promise<{ handle: string }> }
): Promise<Response> {
  const { handle } = await context.params
  if (!isValidHandle(handle)) return new Response('Not found', { status: 404 })

  const record = await getStore().getCurrent(handle)
  if (!record) return new Response('Not found', { status: 404 })
  return keyEventLogResponse(record)
}
