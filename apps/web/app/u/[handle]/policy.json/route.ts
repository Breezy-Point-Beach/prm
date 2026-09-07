import { policyResponse } from '../../../../lib/publish'
import { getStore, isValidHandle } from '../../../../lib/store'

export const runtime = 'nodejs'

/**
 * GET /u/{handle}/policy.json
 *
 * Returns the stored bytes verbatim. No re-serialization, no added fields, no reordering — the
 * publish flow's byte comparison depends on this handler being a pass-through.
 */
export async function GET (
  _request: Request,
  context: { params: Promise<{ handle: string }> }
): Promise<Response> {
  const { handle } = await context.params
  if (!isValidHandle(handle)) return new Response('Not found', { status: 404 })

  const record = await getStore().getCurrent(handle)
  if (!record) return new Response('Not found', { status: 404 })
  return policyResponse(record)
}
