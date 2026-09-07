import type { KeyEvent, Policy } from '@prm/schema'
import { validatePolicy, policyWarnings, unknownCategories } from '@prm/schema'
import {
  digest, policyId, policyChainId, encodePublicKey, publicKeyFromVerificationMethod,
  verifyProofSelfContained
} from '@prm/crypto'
import { verifyKeyEventLog } from './kel.js'
import { emptyResult, grade, type VerificationResult } from './types.js'

export interface VerifyPolicyOptions {
  /** The issuer's key event log. Without it, issuer authority cannot be established offline. */
  keyEventLog?: KeyEvent[]
  /** The current version, if known. Supplying it upgrades `currency` from 'unknown'. */
  latestVersion?: { version: number; policyChainId: string }
  /** Revocation bit for this policy, if a status list was consulted. */
  revoked?: boolean
  /** Independent timestamp evidence, if a proof bundle supplied one. */
  timestamp?: { notLaterThan: string; source: 'rfc3161' | 'ots' | 'log-only' }
  /** Clock for expiry checks. Injectable so tests are not time-dependent. */
  now?: Date
}

/**
 * Verify a policy. PURE — no network, no filesystem, no PRM.
 *
 * Everything this function needs is passed in. That is what makes offline verification real rather
 * than aspirational: there is no code path here that could try to reach the internet.
 */
export function verifyPolicy (doc: unknown, opts: VerifyPolicyOptions = {}): VerificationResult {
  const r = emptyResult()
  const now = opts.now ?? new Date()

  const schema = validatePolicy(doc)
  if (!schema.valid) {
    r.errors.push(...schema.errors.map((e) => `schema: ${e}`))
    r.summary = 'failed'
    return r
  }
  const policy = schema.value as Policy

  // ---- Check 1: integrity -----------------------------------------------------
  const computed = digest(policy, 'policy')
  r.checked.digest = computed
  r.checked.version = policy.version
  r.checked.accountId = policy.issuer.id
  r.checked.effectiveDate = policy.effectiveDate
  if (policy.expirationDate) r.checked.expirationDate = policy.expirationDate

  if (policy.id !== undefined && policy.id !== policyId(policy)) {
    r.integrity = 'invalid'
    return grade(r)
  }
  r.integrity = 'valid'

  // ---- Check 2: signature -----------------------------------------------------
  if (verifyProofSelfContained(policy, 'policy', policy.proof)) {
    r.signature = 'valid'
    try {
      r.checked.signedBy = encodePublicKey(publicKeyFromVerificationMethod(policy.proof.verificationMethod))
    } catch { /* recorded as unknown-key below if unparseable */ }
  } else {
    try {
      publicKeyFromVerificationMethod(policy.proof.verificationMethod)
      r.signature = 'invalid'
    } catch {
      r.signature = 'unknown-key'
    }
    return grade(r)
  }

  // ---- Check 3: issuer authority at signing time ------------------------------
  if (!opts.keyEventLog || opts.keyEventLog.length === 0) {
    r.issuer = 'kel-unavailable'
  } else {
    const kel = verifyKeyEventLog(opts.keyEventLog)
    if (!kel.valid) {
      r.issuer = 'not-in-kel'
      r.errors.push(...kel.errors.map((e) => `key event log: ${e}`))
      return grade(r)
    }
    if (kel.accountId !== policy.issuer.id) {
      r.issuer = 'not-in-kel'
      r.errors.push(
        `issuer mismatch: the key event log self-certifies as ${kel.accountId}, ` +
        `but the policy claims ${policy.issuer.id}`)
      return grade(r)
    }

    const authorized = kel.authorizedAt.get(policy.issuer.keyEventHash)
    if (!authorized) {
      r.issuer = 'not-in-kel'
      r.errors.push(`policy names key event ${policy.issuer.keyEventHash}, which is not in the log`)
      return grade(r)
    }
    if (!r.checked.signedBy || !authorized.has(r.checked.signedBy)) {
      r.issuer = 'not-in-kel'
      r.errors.push('the signing key is not authorized by the key event this policy names')
      return grade(r)
    }

    // Time-scoped revocation, CRL semantics: a key revoked in June does not invalidate a policy
    // signed and logged in March. Anything else would destroy the archive, which IS the product.
    const revokedFrom = r.checked.signedBy ? kel.revoked.get(r.checked.signedBy) : undefined
    if (revokedFrom && policy.proof.created >= revokedFrom) {
      r.issuer = 'revoked-at-signing'
      return grade(r)
    }
    r.issuer = 'authorized'
  }

  // ---- Check 4: currency ------------------------------------------------------
  if (opts.latestVersion) {
    if (opts.latestVersion.policyChainId !== policy.policyChainId) {
      r.warnings.push('the supplied latest version belongs to a different policy chain')
      r.currency = 'unknown'
    } else {
      r.currency = opts.latestVersion.version > policy.version ? 'superseded' : 'current'
    }
  }

  // ---- Check 5: revocation ----------------------------------------------------
  if (opts.revoked !== undefined) r.revocation = opts.revoked ? 'revoked' : 'active'

  // ---- Check 6: timestamp -----------------------------------------------------
  if (opts.timestamp) {
    r.timestamp = { proven: true, notLaterThan: opts.timestamp.notLaterThan, source: opts.timestamp.source }
  }

  // ---- Non-fatal observations -------------------------------------------------
  for (const w of policyWarnings(policy)) r.warnings.push(w)

  const unknown = unknownCategories(policy)
  if (unknown.length > 0) {
    r.warnings.push(
      `${unknown.length} unrecognized ${unknown.length === 1 ? 'category' : 'categories'} ` +
      `(${unknown.join(', ')}) — treat as denied`)
  }
  if (policy.expirationDate && new Date(policy.expirationDate) < now) {
    r.warnings.push(`this policy expired on ${policy.expirationDate}`)
  }
  if (new Date(policy.effectiveDate) > now) {
    r.warnings.push(`this policy does not take effect until ${policy.effectiveDate}`)
  }
  if (policy.proof.created > new Date(now.getTime() + 24 * 3600_000).toISOString()) {
    r.warnings.push('the signature claims a creation time more than 24 hours in the future')
  }

  return grade(r)
}

/**
 * Verify a policy version chain, oldest first.
 *
 * Walking the chain is what defeats policy substitution: a swapped document cannot produce a valid
 * previousPolicyHash link back to a version the recipient already holds.
 */
export function verifyPolicyChain (chain: Policy[]): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (chain.length === 0) return { valid: false, errors: ['empty chain'] }

  const sorted = [...chain].sort((a, b) => a.version - b.version)
  const first = sorted[0] as Policy

  if (first.version === 1) {
    const derived = policyChainId(first)
    if (derived !== first.policyChainId) {
      errors.push(`v1 policyChainId is ${first.policyChainId} but derives to ${derived}`)
    }
    if (first.previousPolicyHash !== null) errors.push('v1 must not reference a predecessor')
  }

  for (let i = 0; i < sorted.length; i++) {
    const p = sorted[i] as Policy
    if (p.policyChainId !== first.policyChainId) {
      errors.push(`version ${p.version} belongs to a different chain`)
      continue
    }
    if (!verifyProofSelfContained(p, 'policy', p.proof)) {
      errors.push(`version ${p.version}: signature is not valid`)
    }
    if (i > 0) {
      const prev = sorted[i - 1] as Policy
      if (p.version !== prev.version + 1) {
        errors.push(`version gap: ${prev.version} -> ${p.version}`)
      }
      const expected = digest(prev, 'policy')
      if (p.previousPolicyHash !== expected) {
        errors.push(
          `version ${p.version}: previousPolicyHash does not match version ${prev.version} ` +
          `(substitution or a missing intermediate version)`)
      }
    }
  }
  return { valid: errors.length === 0, errors }
}
