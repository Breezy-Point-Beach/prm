import type {
  DeliveryMethod, DeliveryRecord, Notice, Policy, Recipient, ResponseRecord, ResponseStatus,
  DisclosedIdentifier, UtcInstant
} from '@prm/schema'
import {
  PRM_CONTEXT, REQUESTED_TREATMENT, LEGAL_EFFECT_DISCLAIMER, findForbiddenAssertions
} from '@prm/schema'
import { buildProof, digest, hash, encodeMultihash, type KeyPair } from '@prm/crypto'

/**
 * Building the three recipient-facing records.
 *
 * All three are signed on the user's device. None of them is ever constructed server-side, because
 * a notice a server could author is a notice the user did not send.
 */

export const iso = (d: Date): UtcInstant =>
  d.toISOString().replace(/\.\d{3}Z$/, 'Z') as UtcInstant

const byteDigest = (text: string): string =>
  encodeMultihash(hash(new TextEncoder().encode(text)))

export interface BuildNoticeInput {
  /** The signed policy, parsed. Used for its identity only; never re-derived semantically. */
  policy: Policy
  /**
   * The EXACT policy bytes being delivered. Recorded as policyByteDigest so a recipient can later
   * prove which serialization they received, not merely which document.
   */
  policyJson: string
  recipient: Recipient
  purpose?: string
  /**
   * PRIVATE matching identifiers. Included only where the recipient genuinely needs them to find
   * the right records. These never enter the published policy or any public surface.
   */
  matchingIdentifiers?: DisclosedIdentifier[]
  policyUrl?: string
  requestedTreatment?: string
  legalEffect?: string
  note?: string
  issued?: Date
}

export interface SignedRecord<T> {
  document: T
  /** THE bytes. Store and deliver exactly this string; do not re-serialize the document. */
  json: string
  digest: string
}

function freeze<T extends object> (document: T, kind: 'notice' | 'delivery' | 'response'): SignedRecord<T> {
  return {
    document,
    json: JSON.stringify(document, null, 2),
    digest: digest(document, kind)
  }
}

/**
 * Build and sign a recipient-specific notice.
 *
 * The notice is deliberately separate from the policy. The policy is public and general; a notice is
 * targeted, and may carry a private identifier that must never appear in the published document.
 * Keeping them as distinct artifacts is what makes that separation enforceable rather than a habit.
 */
export function buildNotice (input: BuildNoticeInput, key: KeyPair): SignedRecord<Notice> {
  const requestedTreatment = input.requestedTreatment ?? REQUESTED_TREATMENT
  const legalEffect = input.legalEffect ?? LEGAL_EFFECT_DISCLAIMER

  // Refuse to sign a notice that asserts an obligation PRM cannot support. Failing here beats
  // discovering it after the notice has been delivered and quoted back.
  const offending = findForbiddenAssertions(`${requestedTreatment}\n${legalEffect}\n${input.note ?? ''}`)
  if (offending.length > 0) {
    throw new Error(
      `Refusing to sign a notice containing: ${offending.join(', ')}. PRM records instructions and ` +
      'objections; it does not assert legal obligations that have not been established.')
  }

  const issued = iso(input.issued ?? new Date())
  const unsigned: Omit<Notice, 'proof'> = {
    '@context': [...PRM_CONTEXT],
    type: ['VerifiableCredential', 'PRMNotice'],
    policyChainId: input.policy.policyChainId,
    policyDigest: digest(input.policy, 'policy'),
    policyByteDigest: byteDigest(input.policyJson),
    policyVersion: input.policy.version,
    ...(input.policyUrl ? { policyUrl: input.policyUrl } : {}),
    issuer: input.policy.issuer,
    recipient: input.recipient,
    ...(input.purpose ? { purpose: input.purpose } : {}),
    issued,
    ...(input.matchingIdentifiers?.length ? { matchingIdentifiers: input.matchingIdentifiers } : {}),
    requestedTreatment,
    legalEffect,
    ...(input.note ? { note: input.note } : {})
  }

  const proof = buildProof(unsigned, {
    privateKey: key.privateKey, publicKey: key.publicKey, kind: 'notice', created: issued
  })
  const withProof = { ...unsigned, proof } as Notice
  withProof.id = `urn:prm:notice:${digest(unsigned, 'notice')}`
  return freeze(withProof, 'notice')
}

export interface BuildDeliveryInput {
  notice: Notice
  noticeDigest: string
  recipient: { name: string; id?: string; domain?: string; contact?: string }
  method: DeliveryMethod
  /** What the user says happened. PRM does not witness delivery and never claims to. */
  deliveredAt: Date
  manifestDigest?: string
  packetDigest?: string
  reference?: string
  notes?: string
  evidence?: Array<{ kind: string; digest: string; note?: string }>
  recorded?: Date
}

export function buildDeliveryRecord (
  input: BuildDeliveryInput,
  key: KeyPair
): SignedRecord<DeliveryRecord> {
  const recorded = iso(input.recorded ?? new Date())
  const unsigned: Omit<DeliveryRecord, 'proof'> = {
    '@context': [...PRM_CONTEXT],
    type: ['VerifiableCredential', 'PRMDeliveryRecord'],
    noticeDigest: input.noticeDigest,
    policyDigest: input.notice.policyDigest,
    ...(input.manifestDigest ? { manifestDigest: input.manifestDigest } : {}),
    ...(input.packetDigest ? { packetDigest: input.packetDigest } : {}),
    recipient: input.recipient,
    method: input.method,
    deliveredAt: iso(input.deliveredAt),
    recorded,
    ...(input.reference ? { reference: input.reference } : {}),
    ...(input.notes ? { notes: input.notes } : {}),
    ...(input.evidence?.length ? { evidence: input.evidence } : {})
  }
  const proof = buildProof(unsigned, {
    privateKey: key.privateKey, publicKey: key.publicKey, kind: 'delivery', created: recorded
  })
  const withProof = { ...unsigned, proof } as DeliveryRecord
  withProof.id = `urn:prm:delivery:${digest(unsigned, 'delivery')}`
  return freeze(withProof, 'delivery')
}

export interface BuildResponseInput {
  noticeDigest: string
  deliveryDigest?: string
  recipient?: { name: string; id?: string; domain?: string; contact?: string }
  status: ResponseStatus
  receivedAt?: Date
  responseDigest?: string
  responseMediaType?: string
  notes?: string
  recorded?: Date
}

/**
 * Record a response.
 *
 * PRM preserves what came back and the issuer's own characterisation of it. It does NOT decide
 * whether the recipient's legal position is correct — that judgement belongs to a lawyer and a
 * court, and a system that pretended otherwise would be producing confidently wrong legal claims.
 */
export function buildResponseRecord (
  input: BuildResponseInput,
  key: KeyPair
): SignedRecord<ResponseRecord> {
  if (input.status === 'no-response' && input.receivedAt) {
    throw new Error('a "no-response" record cannot carry a receipt time')
  }
  if (input.status !== 'no-response' && !input.receivedAt) {
    throw new Error(`status "${input.status}" requires the date the response was received`)
  }

  const recorded = iso(input.recorded ?? new Date())
  const unsigned: Omit<ResponseRecord, 'proof'> = {
    '@context': [...PRM_CONTEXT],
    type: ['VerifiableCredential', 'PRMResponseRecord'],
    noticeDigest: input.noticeDigest,
    ...(input.deliveryDigest ? { deliveryDigest: input.deliveryDigest } : {}),
    ...(input.recipient ? { recipient: input.recipient } : {}),
    status: input.status,
    ...(input.receivedAt ? { receivedAt: iso(input.receivedAt) } : {}),
    recorded,
    ...(input.responseDigest ? { responseDigest: input.responseDigest } : {}),
    ...(input.responseMediaType ? { responseMediaType: input.responseMediaType } : {}),
    ...(input.notes ? { notes: input.notes } : {})
  }
  const proof = buildProof(unsigned, {
    privateKey: key.privateKey, publicKey: key.publicKey, kind: 'response', created: recorded
  })
  const withProof = { ...unsigned, proof } as ResponseRecord
  withProof.id = `urn:prm:response:${digest(unsigned, 'response')}`
  return freeze(withProof, 'response')
}

export { byteDigest }
