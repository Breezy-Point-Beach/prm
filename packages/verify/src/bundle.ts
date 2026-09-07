import type { Authorization, KeyEvent, LedgerEntry, Policy, SignedTreeHead } from '@prm/schema'
import { verifyPolicy, verifyPolicyChain } from './policy.js'
import { verifyKeyEventLog } from './kel.js'
import { verifyLedgerChain, verifyLogInclusion, verifySignedTreeHead } from './ledger.js'
import { verifyAuthorization } from './authorization.js'
import { digest } from '@prm/crypto'
import type { VerificationResult } from './types.js'

export const PRMPROOF_VERSION = 1
export const PRMPROOF_MEDIA_TYPE = 'application/prm-proof+json'

/**
 * A portable evidence bundle — docs/07 §4.
 *
 * Everything a third party needs to verify a claim about a policy, in ONE file, with PRM offline and
 * forever. A proof you cannot hand to a lawyer as a single attachment is a proof that will not get
 * used, so portability and long-term verifiability are functional requirements, not niceties.
 */
export interface PrmProofBundle {
  prmproof: number
  mediaType: typeof PRMPROOF_MEDIA_TYPE
  generatedAt: string
  subject: {
    accountId: string
    policyChainId: string
    policyDigest: string
    version: number
  }
  /** The policy version this bundle is about. */
  policy: Policy
  /** Prior versions, so a verifier can walk the chain without fetching anything. */
  policyChain?: Policy[]
  /** The issuer's key events — how issuer authority is established offline. */
  keyEventLog: KeyEvent[]
  /** Ledger entries relevant to the claim, with their inclusion proofs attached. */
  ledgerEntries?: LedgerEntry[]
  signedTreeHead?: SignedTreeHead
  /** Public key of the log that signed the tree head, so the STH can be checked. */
  logPublicKeyMultibase?: string
  /** RFC 3161 token over the tree head root, base64. */
  timestampToken?: string
  timestamp?: { notLaterThan: string; source: 'rfc3161' | 'ots' | 'log-only'; authority?: string }
  authorizations?: Authorization[]
  /** Free-text context from the issuer. Not authenticated; displayed as a claim, not a fact. */
  note?: string
}

export interface BundleVerification {
  valid: boolean
  policy: VerificationResult
  chain?: { valid: boolean; errors: string[] }
  keyEventLog: { valid: boolean; errors: string[]; accountId?: string }
  ledger?: { valid: boolean; errors: string[] }
  inclusion?: Array<{ sequence: number; valid: boolean; errors: string[] }>
  signedTreeHead?: { valid: boolean; checked: boolean }
  authorizations?: Array<{ valid: boolean; errors: string[] }>
  errors: string[]
  warnings: string[]
  /** One-line plain-language conclusion, suitable for showing a non-technical reader. */
  conclusion: string
}

/**
 * Verify a bundle. PURE — no network, no filesystem.
 *
 * The chain of reasoning it establishes, when everything is present:
 *   the timestamp authority (independent) says this root existed by T;
 *   the root commits to this leaf; the leaf is the hash of this signed ledger entry;
 *   the entry names this policy digest; the policy verifies under a key the key event log
 *   shows was authorized at the time. No step requires trusting PRM.
 */
export function verifyBundle (bundle: unknown, opts: { now?: Date } = {}): BundleVerification {
  const out: BundleVerification = {
    valid: false,
    policy: {} as VerificationResult,
    keyEventLog: { valid: false, errors: [] },
    errors: [], warnings: [], conclusion: ''
  }

  if (typeof bundle !== 'object' || bundle === null) {
    out.errors.push('not a PRM proof bundle')
    out.conclusion = 'This file is not a PRM proof bundle.'
    return out
  }
  const b = bundle as PrmProofBundle

  if (b.prmproof !== PRMPROOF_VERSION) {
    out.errors.push(`unsupported bundle version: ${String(b.prmproof)}`)
    out.conclusion = 'This bundle was produced by an incompatible version of PRM.'
    return out
  }

  const kel = verifyKeyEventLog(b.keyEventLog ?? [])
  out.keyEventLog = { valid: kel.valid, errors: kel.errors, accountId: kel.accountId }
  if (!kel.valid) out.errors.push(...kel.errors.map((e) => `key event log: ${e}`))

  out.policy = verifyPolicy(b.policy, {
    keyEventLog: b.keyEventLog,
    ...(b.timestamp ? { timestamp: b.timestamp } : {}),
    ...(opts.now ? { now: opts.now } : {})
  })
  if (out.policy.summary === 'failed') out.errors.push(...out.policy.errors)
  out.warnings.push(...out.policy.warnings)

  if (b.policyChain && b.policyChain.length > 0) {
    out.chain = verifyPolicyChain(b.policyChain)
    if (!out.chain.valid) out.errors.push(...out.chain.errors.map((e) => `policy chain: ${e}`))
  }

  if (b.ledgerEntries && b.ledgerEntries.length > 0) {
    out.ledger = verifyLedgerChain(b.ledgerEntries)
    if (!out.ledger.valid) out.errors.push(...out.ledger.errors.map((e) => `ledger: ${e}`))

    out.inclusion = b.ledgerEntries
      .filter((e) => e.logInclusion)
      .map((e) => {
        const r = verifyLogInclusion(e, b.signedTreeHead)
        return { sequence: e.sequence, valid: r.valid, errors: r.errors }
      })
    for (const i of out.inclusion) {
      if (!i.valid) out.errors.push(...i.errors.map((e) => `inclusion: ${e}`))
    }

    // The bundle must actually be about the policy it carries.
    const pd = out.policy.checked.digest
    if (pd && !b.ledgerEntries.some((e) => e.subjectHash === pd)) {
      out.warnings.push('no ledger entry in this bundle refers to the policy it contains')
    }
  }

  if (b.signedTreeHead) {
    if (b.logPublicKeyMultibase) {
      const ok = verifySignedTreeHead(b.signedTreeHead, b.logPublicKeyMultibase)
      out.signedTreeHead = { valid: ok, checked: true }
      if (!ok) out.errors.push('the signed tree head signature is not valid')
    } else {
      out.signedTreeHead = { valid: false, checked: false }
      out.warnings.push('no log public key supplied; the signed tree head was not checked')
    }
  }

  if (b.authorizations && b.authorizations.length > 0) {
    out.authorizations = b.authorizations.map((a) => {
      const r = verifyAuthorization(a, {
        boundPolicy: b.policy,
        ...(opts.now ? { now: opts.now } : {})
      })
      return { valid: r.valid, errors: r.errors }
    })
    for (const a of out.authorizations) {
      if (!a.valid) out.warnings.push(...a.errors.map((e) => `authorization: ${e}`))
    }
  }

  if (b.subject?.policyDigest && out.policy.checked.digest &&
      b.subject.policyDigest !== out.policy.checked.digest) {
    out.errors.push('the bundle header does not match the policy it contains')
  }

  out.valid = out.errors.length === 0 && out.policy.summary !== 'failed'
  out.conclusion = describe(b, out)
  return out
}

function describe (b: PrmProofBundle, r: BundleVerification): string {
  if (!r.valid) return 'This proof did NOT verify. See the errors below.'

  const who = r.keyEventLog.accountId ?? b.subject?.accountId ?? 'an unidentified account'
  const when = b.timestamp?.notLaterThan
  const v = b.policy?.version ?? r.policy.checked.version

  let s = `Verified: PRM account ${who} signed version ${v} of this policy`
  if (when) {
    const auth = b.timestamp?.authority ? ` by ${b.timestamp.authority}` : ''
    s += `, and it is independently proven${auth} to have existed no later than ${when}`
  }
  s += '.'
  if (r.warnings.length > 0) s += ` ${r.warnings.length} note(s) below.`
  return s
}

/** Assemble a bundle. Callers supply already-signed artifacts; this adds no authority of its own. */
export function buildBundle (input: Omit<PrmProofBundle, 'prmproof' | 'mediaType' | 'subject' | 'generatedAt'> & {
  generatedAt?: string
}): PrmProofBundle {
  const { generatedAt, ...rest } = input
  return {
    prmproof: PRMPROOF_VERSION,
    mediaType: PRMPROOF_MEDIA_TYPE,
    generatedAt: generatedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    subject: {
      accountId: rest.policy.issuer.id,
      policyChainId: rest.policy.policyChainId,
      policyDigest: digest(rest.policy, 'policy'),
      version: rest.policy.version
    },
    ...rest
  }
}
