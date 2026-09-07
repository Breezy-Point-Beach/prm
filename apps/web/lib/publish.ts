import type { KeyEvent, Policy } from '@prm/schema'
import { validatePolicy, validateKeyEvent } from '@prm/schema'
import { digest, deriveAccountId } from '@prm/crypto'
import { verifyPolicy, verifyKeyEventLog } from '@prm/verify'
import { isValidHandle } from './storage'
import { byteDigestOf, utf8, contentTypeFor } from './storage'
import type { PolicyRecord, Storage } from './storage'

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
  versionUrl: string
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
  storage: Storage,
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

  const owner = await storage.metadata.handleOwner(handle)
  if (owner !== null && owner !== policy.issuer.id) {
    return fail('That handle belongs to another account.')
  }

  const existing = await storage.metadata.currentVersion(handle)
  if (existing) {
    if (existing.policyChainId !== policy.policyChainId) {
      return fail('This handle already publishes a different policy chain.')
    }
    if (policy.version <= existing.version) {
      return fail(`Version ${policy.version} is not newer than the published version ${existing.version}.`)
    }
    if (policy.previousPolicyHash !== existing.policyDigest) {
      return fail(
        'This version does not chain to the currently published one.',
        [`expected previousPolicyHash ${existing.policyDigest}, got ${String(policy.previousPolicyHash)}`])
    }
  } else if (policy.version !== 1) {
    return fail('The first policy published under a handle must be version 1.')
  }

  const policyDigest = digest(policy, 'policy')

  // Two digests, deliberately distinct (see lib/storage/types.ts):
  //   policyDigest is the PROTOCOL identity, stable across reserialization
  //   byteDigest   is the STORAGE address, and changes if a single space moves
  const policyBytes = utf8(policyJson)
  const kelBytes = utf8(keyEventLogJson)
  const policyByteDigest = byteDigestOf(policyBytes)
  const kelByteDigest = byteDigestOf(kelBytes)

  let policyRef, kelRef
  try {
    // Write-once and content-addressed. The store refuses bytes that do not hash to the declared
    // digest, so a corrupted upload cannot be persisted even if everything above passed.
    policyRef = await storage.artifacts.put('policy', policyBytes, policyByteDigest)
    kelRef = await storage.artifacts.put('key-event-log', kelBytes, kelByteDigest)
  } catch (e) {
    return fail('Storage refused the artifact.', [(e as Error).message])
  }

  await storage.metadata.publish({
    handle,
    accountId: policy.issuer.id,
    policyChainId: policy.policyChainId,
    version: policy.version,
    policyDigest,
    policyByteDigest,
    policyLocation: policyRef.location,
    policyByteLength: policyRef.byteLength,
    kelByteDigest,
    kelLocation: kelRef.location,
    publishedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    contentType: contentTypeFor('policy')
  })

  return {
    ok: true,
    handle,
    digest: policyDigest,
    version: policy.version,
    policyUrl: `${origin}/u/${handle}/policy.json`,
    versionUrl: `${origin}/u/${handle}/v/${policy.version}.json`,
    // The digest travels with the share link, so a recipient can check what they received against
    // what they were told to expect. See app/u/[handle]/IntegrityCheck.tsx.
    canonicalUrl: `${origin}/u/${handle}#sha256=${policyDigest}`
  }
}

/** Read a published artifact's bytes, verified against its storage digest on the way out. */
export async function readPolicyBytes (
  storage: Storage,
  record: PolicyRecord
): Promise<string> {
  const bytes = await storage.artifacts.get(record.policyByteDigest)
  return new TextDecoder().decode(bytes)
}

export async function readKelBytes (
  storage: Storage,
  record: PolicyRecord
): Promise<string> {
  const bytes = await storage.artifacts.get(record.kelByteDigest)
  return new TextDecoder().decode(bytes)
}

/**
 * Serve stored bytes back untouched.
 *
 * `immutable` marks a version endpoint, whose content is addressed by version number and can never
 * change. The current-policy alias must stay short-lived, because it moves when v2 is published.
 */
export function artifactResponse (
  bytes: string,
  record: PolicyRecord,
  opts: { immutable?: boolean; contentType?: string } = {}
): Response {
  return new Response(bytes, {
    status: 200,
    headers: {
      'Content-Type': `${opts.contentType ?? record.contentType}; charset=utf-8`,
      // The protocol digest is the content address, so it is the natural strong ETag.
      ETag: `"${record.policyDigest}"`,
      'Cache-Control': opts.immutable
        ? 'public, max-age=31536000, immutable'
        : 'public, max-age=60, stale-while-revalidate=600',
      'Access-Control-Allow-Origin': '*',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'X-PRM-Policy-Digest': record.policyDigest,
      'X-PRM-Policy-Version': String(record.version),
      // The storage address, so a reader can independently confirm the bytes they received are the
      // bytes that were stored, not merely a document that happens to verify.
      'X-PRM-Byte-Digest': record.policyByteDigest
    }
  })
}
