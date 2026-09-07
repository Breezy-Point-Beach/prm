/**
 * Verification results are GRADED, never a bare boolean.
 *
 * docs/05 §3: a verifier that collapses six independent facts into one bit will make the wrong
 * decision when the network is down. "I could not check whether this is the current version" and
 * "this is not the current version" are different answers, and conflating them either blocks
 * legitimate offline use or silently accepts a superseded policy.
 */

export type IntegrityStatus = 'valid' | 'invalid'
export type SignatureStatus = 'valid' | 'invalid' | 'unknown-key'
export type IssuerStatus = 'authorized' | 'revoked-at-signing' | 'not-in-kel' | 'kel-unavailable'
export type CurrencyStatus = 'current' | 'superseded' | 'unknown'
export type RevocationStatus = 'active' | 'revoked' | 'unknown'
export type Summary = 'verified' | 'verified-with-warnings' | 'failed'

export interface TimestampEvidence {
  proven: boolean
  notLaterThan?: string
  source?: 'rfc3161' | 'ots' | 'log-only' | 'none'
  detail?: string
}

export interface VerificationResult {
  integrity: IntegrityStatus
  signature: SignatureStatus
  issuer: IssuerStatus
  currency: CurrencyStatus
  revocation: RevocationStatus
  timestamp: TimestampEvidence
  /** Non-fatal observations a human should see: unknown categories, expiry, clock skew. */
  warnings: string[]
  /** Reasons the document failed. Empty when summary !== 'failed'. */
  errors: string[]
  summary: Summary
  /** What was actually checked, for display and for audit. */
  checked: {
    digest?: string
    accountId?: string
    version?: number
    signedBy?: string
    effectiveDate?: string
    expirationDate?: string
  }
}

export function emptyResult (): VerificationResult {
  return {
    integrity: 'invalid',
    signature: 'invalid',
    issuer: 'not-in-kel',
    currency: 'unknown',
    revocation: 'unknown',
    timestamp: { proven: false, source: 'none' },
    warnings: [],
    errors: [],
    summary: 'failed',
    checked: {}
  }
}

/**
 * Grade a result.
 *
 * Checks 1-3 (integrity, signature, issuer authority) are REQUIRED — they are computable offline
 * from the document and its key event log alone. Checks 4-6 (currency, revocation, timestamp)
 * degrade to warnings when unknown, because an offline verifier is a supported and expected case:
 * a roadside stop, a records office, an archive review years later.
 */
export function grade (r: VerificationResult): VerificationResult {
  if (r.integrity !== 'valid') r.errors.push('document digest does not match its contents')
  if (r.signature === 'invalid') r.errors.push('signature is not valid')
  if (r.signature === 'unknown-key') r.errors.push('signing key could not be resolved')
  if (r.issuer === 'not-in-kel') r.errors.push('signing key is not authorized in the key event log')
  if (r.issuer === 'revoked-at-signing') r.errors.push('signing key was revoked before this document was logged')

  if (r.errors.length > 0) { r.summary = 'failed'; return r }

  if (r.currency === 'superseded') r.warnings.push('a newer version of this policy has been published')
  if (r.currency === 'unknown') r.warnings.push('could not confirm this is the current version (offline)')
  if (r.revocation === 'revoked') r.warnings.push('this document has been revoked by its issuer')
  if (r.revocation === 'unknown') r.warnings.push('could not check revocation status (offline)')
  if (!r.timestamp.proven) r.warnings.push('no independent timestamp evidence was supplied')
  if (r.issuer === 'kel-unavailable') r.warnings.push('key event log unavailable; issuer authority unconfirmed')

  r.summary = r.warnings.length > 0 ? 'verified-with-warnings' : 'verified'
  return r
}
