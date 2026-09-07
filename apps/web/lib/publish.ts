import type { KeyEvent, Policy } from '@prm/schema'
import { validatePolicy, validateKeyEvent } from '@prm/schema'
import { digest, deriveAccountId } from '@prm/crypto'
import { verifyPolicy, verifyKeyEventLog } from '@prm/verify'
import { isValidHandle, type PolicyStore, type PublishedPolicy } from './store'

/**
 * The publish contract.
 *
 * The client sends the signed documents as RAW STRINGS, not as nested objects. That is deliberate: if
 * they arrived as objects, the server would have to re-serialize them to store them, and the exact
 * bytes the user signed would be gone before anything was written down. Sending strings means the
 * server can store precisely what it received.
 */
export interface PublishRequest {
  handle: string
  /** The exact JSON text of the signed policy, as produced on the user's device. */
  policyJson: string
  /** The exact JSON text of the key event log array. */
  keyEventLogJson: string
}

export interface PublishSuccess {
  ok: true
  handle: string
  digest: string
  version: number
  policyUrl: string
  canonicalUrl: string
}

export interface PublishFailure {
  ok: false
  error: string
  detail?: string[]
}

export type PublishResult = PublishSuccess | PublishFailure

const fail = (error: string, detail?: string[]): PublishFailure =>
  detail ? { ok: false, error, detail } : { ok: false, error }

/**
 * Validate and store a published policy.
 *
 * Everything here is a REFUSAL check. There is no code path that alters the submitted bytes, and
 * there must never be one: the server's job is to say yes or no, not to interpret.
 */
export async function handlePublish (
  request: PublishRequest,
  store: PolicyStore,
  origin: string
): Promise<PublishResult> {
  const { handle, policyJson, keyEventLogJson } = request

  if (typeof handle !== 'string' || !isValidHandle(handle)) {
    return fail('Invalid handle. Use 3-32 lowercase letters, digits, or hyphens.')
  }
  if (typeof policyJson !== 'string' || typeof keyEventLogJson !== 'string') {
    return fail('policyJson and keyEventLogJson must be strings containing the exact signed bytes.')
  }
  if (policyJson.length > 512_000 || keyEventLogJson.length > 512_000) {
    return fail('Document too large.')
  }

  let policy: Policy
  let keyEventLog: KeyEvent[]
  try {
    policy = JSON.parse(policyJson) as Policy
  } catch {
    return fail('policyJson is not valid JSON.')
  }
  try {
    const parsed = JSON.parse(keyEventLogJson)
    keyEventLog = Array.isArray(parsed) ? parsed : [parsed]
  } catch {
    return fail('keyEventLogJson is not valid JSON.')
  }

  const policySchema = validatePolicy(policy)
  if (!policySchema.valid) return fail('Policy failed schema validation.', policySchema.errors)
  for (const event of keyEventLog) {
    const r = validateKeyEvent(event)
    if (!r.valid) return fail('Key event failed schema validation.', r.errors)
  }

  const kel = verifyKeyEventLog(keyEventLog)
  if (!kel.valid) return fail('Key event log did not verify.', kel.errors)

  const genesis = [...keyEventLog].sort((a, b) => a.sequence - b.sequence)[0]
  if (!genesis || deriveAccountId(genesis) !== policy.issuer.id) {
    return fail('The policy issuer does not match the account its key event log certifies.')
  }

  // The full verification the client already ran, repeated server-side. Not because the client's
  // result is trusted — it is not sent — but because PRM should refuse to publish something a
  // third party would reject.
  const verification = verifyPolicy(policy, { keyEventLog })
  if (verification.summary === 'failed') {
    return fail('Policy did not verify.', verification.errors)
  }

  const owner = await store.handleOwner(handle)
  if (owner !== null && owner !== policy.issuer.id) {
    return fail('That handle belongs to another account.')
  }

  const existing = await store.getCurrent(handle)
  if (existing) {
    if (existing.policyChainId !== policy.policyChainId) {
      return fail('This handle already publishes a different policy chain.')
    }
    if (policy.version <= existing.version) {
      return fail(`Version ${policy.version} is not newer than the published version ${existing.version}.`)
    }
    if (policy.previousPolicyHash !== existing.digest) {
      return fail(
        'This version does not chain to the currently published one.',
        [`expected previousPolicyHash ${existing.digest}, got ${String(policy.previousPolicyHash)}`])
    }
  } else if (policy.version !== 1) {
    return fail('The first policy published under a handle must be version 1.')
  }

  const policyDigest = digest(policy, 'policy')

  await store.publish({
    handle,
    accountId: policy.issuer.id,
    policyChainId: policy.policyChainId,
    version: policy.version,
    digest: policyDigest,
    // VERBATIM. The whole design rests on these two lines not being "improved" into
    // JSON.stringify(policy).
    policyJson,
    keyEventLogJson,
    publishedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  })

  return {
    ok: true,
    handle,
    digest: policyDigest,
    version: policy.version,
    policyUrl: `${origin}/u/${handle}/policy.json`,
    canonicalUrl: `${origin}/u/${handle}`
  }
}

/** Serve the stored bytes back untouched. */
export function policyResponse (record: PublishedPolicy): Response {
  return new Response(record.policyJson, {
    status: 200,
    headers: {
      'Content-Type': 'application/prm-policy+json; charset=utf-8',
      // The digest IS the content address, so it is the natural strong ETag.
      ETag: `"${record.digest}"`,
      'Cache-Control': 'public, max-age=60, stale-while-revalidate=600',
      'Access-Control-Allow-Origin': '*',
      Link: `<${'/u/' + record.handle}>; rel="canonical"`,
      'X-PRM-Policy-Digest': record.digest,
      'X-PRM-Policy-Version': String(record.version)
    }
  })
}

export function keyEventLogResponse (record: PublishedPolicy): Response {
  return new Response(record.keyEventLogJson, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=60, stale-while-revalidate=600',
      'Access-Control-Allow-Origin': '*'
    }
  })
}
