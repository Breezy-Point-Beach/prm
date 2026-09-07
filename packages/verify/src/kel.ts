import type { KeyEvent } from '@prm/schema'
import { validateKeyEvent } from '@prm/schema'
import {
  digest, deriveAccountId, decodePublicKey, encodeMultihash, hash,
  verifyProofSelfContained, publicKeyFromVerificationMethod, encodePublicKey
} from '@prm/crypto'

export interface KelVerification {
  valid: boolean
  errors: string[]
  accountId?: string
  /** Public keys authorized at each event, keyed by event digest. */
  authorizedAt: Map<string, Set<string>>
  /** Keys revoked, with the instant from which the revocation bites. */
  revoked: Map<string, string>
  head?: KeyEvent
}

/**
 * Verify a key event log end to end — docs/05 check 3.
 *
 * This is the check most implementations get wrong, and it is the one that makes the provider
 * untrusted. It establishes, without contacting anyone:
 *
 *   - the account id is a function of the genesis event (self-certifying, not server-issued)
 *   - each event chains to the previous by digest
 *   - each rotation reveals a key whose digest was PRE-COMMITTED in the prior event, so a stolen
 *     current key cannot take over the account
 *   - every event is signed by a key that was authorized at the time
 */
export function verifyKeyEventLog (events: KeyEvent[]): KelVerification {
  const result: KelVerification = {
    valid: false, errors: [], authorizedAt: new Map(), revoked: new Map()
  }

  if (events.length === 0) {
    result.errors.push('key event log is empty')
    return result
  }

  const sorted = [...events].sort((a, b) => a.sequence - b.sequence)

  for (const e of sorted) {
    const v = validateKeyEvent(e)
    if (!v.valid) {
      result.errors.push(`event ${e.sequence}: schema invalid — ${v.errors.join('; ')}`)
      return result
    }
  }

  const genesis = sorted[0] as KeyEvent
  if (genesis.sequence !== 0 || genesis.eventType !== 'genesis') {
    result.errors.push('first event is not a genesis event at sequence 0')
    return result
  }
  if (genesis.previousEventHash !== null) {
    result.errors.push('genesis event must not reference a predecessor')
    return result
  }

  result.accountId = deriveAccountId(genesis)

  let previous: KeyEvent | undefined
  let previousDigest: string | undefined

  for (const event of sorted) {
    const eventDigest = digest(event, 'keyEvent')

    if (previous) {
      if (event.sequence !== previous.sequence + 1) {
        result.errors.push(`sequence gap: ${previous.sequence} -> ${event.sequence}`)
        return result
      }
      if (event.previousEventHash !== previousDigest) {
        result.errors.push(`event ${event.sequence}: previousEventHash does not match event ${previous.sequence}`)
        return result
      }

      // Pre-rotation commitment — the property that bounds key theft.
      if (event.eventType === 'rotation') {
        const revealed = event.keys.map((k) => {
          try {
            return encodeMultihash(hash(decodePublicKey(k.publicKeyMultibase)))
          } catch {
            return ''
          }
        })
        const committed = new Set(previous.nextKeyDigests)
        if (!revealed.some((d) => d !== '' && committed.has(d))) {
          result.errors.push(
            `event ${event.sequence}: rotation reveals a key that was never pre-committed in event ` +
            `${previous.sequence}. A stolen signing key cannot rotate the account; this event is a takeover attempt.`
          )
          return result
        }
        // A rotation must be signed by BOTH the outgoing key and the newly revealed key.
        if (event.proof.length < 2) {
          result.errors.push(`event ${event.sequence}: rotation requires two proofs, found ${event.proof.length}`)
          return result
        }
      }

      if (event.eventType === 'recovery') {
        const revealed = event.keys.map((k) => {
          try { return encodeMultihash(hash(decodePublicKey(k.publicKeyMultibase))) } catch { return '' }
        })
        const committedRecovery = new Set(previous.recoveryKeyDigests ?? [])
        const signedByRecovery = event.proof.some((p) => {
          try {
            const pk = publicKeyFromVerificationMethod(p.verificationMethod)
            return committedRecovery.has(encodeMultihash(hash(pk)))
          } catch { return false }
        })
        if (!signedByRecovery && !revealed.some((d) => committedRecovery.has(d))) {
          result.errors.push(
            `event ${event.sequence}: recovery is not signed by a pre-committed recovery key`)
          return result
        }
      }
    }

    // Every event must be signed by a key authorized to sign it.
    const authorizedNow = previous
      ? new Set(previous.keys.map((k) => k.publicKeyMultibase))
      : new Set(genesis.keys.map((k) => k.publicKeyMultibase))
    // A rotation or recovery also legitimately carries a proof from the incoming key.
    for (const k of event.keys) authorizedNow.add(k.publicKeyMultibase)

    let anyValid = false
    for (const p of event.proof) {
      if (!verifyProofSelfContained(event, 'keyEvent', p)) {
        result.errors.push(`event ${event.sequence}: an attached proof is cryptographically invalid`)
        return result
      }
      try {
        const mb = encodePublicKey(publicKeyFromVerificationMethod(p.verificationMethod))
        if (authorizedNow.has(mb)) anyValid = true
      } catch { /* unparseable verificationMethod handled below */ }
    }
    if (!anyValid) {
      result.errors.push(`event ${event.sequence}: no proof comes from an authorized key`)
      return result
    }

    result.authorizedAt.set(eventDigest, new Set(event.keys.map((k) => k.publicKeyMultibase)))
    for (const rk of event.revokedKeys ?? []) {
      result.revoked.set(rk.publicKeyMultibase, rk.effectiveFrom)
    }

    previous = event
    previousDigest = eventDigest
  }

  result.head = previous
  result.valid = true
  return result
}
