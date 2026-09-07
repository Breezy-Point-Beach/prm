import type { Authorization, Policy } from '@prm/schema'
import { validateAuthorization } from '@prm/schema'
import {
  digest, computeCommitment, encodeMultihash, base64urlToBytes, verifyProofSelfContained
} from '@prm/crypto'
import { normalizeIdentifier } from '@prm/schema'

export interface AuthorizationVerification {
  valid: boolean
  errors: string[]
  warnings: string[]
  expired: boolean
  revoked: boolean | 'unknown'
  /** Identifier namespaces whose disclosed value opened a commitment in the bound policy. */
  provenIdentifiers: string[]
}

export interface VerifyAuthorizationOptions {
  /** The exact policy version the grant is bound to. Enables scope and commitment checks. */
  boundPolicy?: Policy
  /** Revocation bit from a status list, if consulted. */
  revoked?: boolean
  now?: Date
}

export function verifyAuthorization (
  doc: unknown,
  opts: VerifyAuthorizationOptions = {}
): AuthorizationVerification {
  const out: AuthorizationVerification = {
    valid: false, errors: [], warnings: [], expired: false,
    revoked: opts.revoked ?? 'unknown', provenIdentifiers: []
  }
  const now = opts.now ?? new Date()

  const schema = validateAuthorization(doc)
  if (!schema.valid) {
    out.errors.push(...schema.errors.map((e) => `schema: ${e}`))
    return out
  }
  const a = schema.value as Authorization

  if (!verifyProofSelfContained(a, 'authorization', a.proof)) {
    out.errors.push('signature is not valid')
    return out
  }

  // Expiry is mandatory by schema; enforce it here as a semantic result too.
  if (new Date(a.expires) <= now) {
    out.expired = true
    out.warnings.push(`this grant expired on ${a.expires}`)
  }
  if (a.notBefore && new Date(a.notBefore) > now) {
    out.warnings.push(`this grant is not effective until ${a.notBefore}`)
  }
  if (opts.revoked === true) out.warnings.push('this grant has been revoked by its issuer')
  if (opts.revoked === undefined && a.revocation) {
    out.warnings.push('revocation status was not checked; honour the expiry strictly')
  }

  if (opts.boundPolicy) {
    const bound = digest(opts.boundPolicy, 'policy')
    if (bound !== a.boundPolicyHash) {
      out.errors.push(
        `this grant is bound to policy ${a.boundPolicyHash} but was checked against ${bound} — ` +
        `a grant does not carry over to a different policy version`)
      return out
    }
    if (opts.boundPolicy.policyChainId !== a.policyChainId) {
      out.errors.push('policy chain mismatch between grant and policy')
      return out
    }

    // Selective disclosure: a disclosed identifier must open a commitment in the signed policy.
    // This is what lets a grantee confirm the grant actually covers the plate in their record,
    // without PRM ever holding the plate.
    for (const d of a.subjectRef?.disclosedIdentifiers ?? []) {
      let normalized: string
      try {
        normalized = normalizeIdentifier(d.namespace, d.value)
      } catch (e) {
        out.errors.push(`disclosed ${d.namespace} is not well-formed: ${(e as Error).message}`)
        continue
      }
      const computed = encodeMultihash(
        computeCommitment(d.namespace, normalized, base64urlToBytes(d.salt)))
      const present = (opts.boundPolicy.identifierCommitments ?? [])
        .some((c) => c.commitment === computed)
      if (present) out.provenIdentifiers.push(d.namespace)
      else out.errors.push(`disclosed ${d.namespace} does not open any commitment in the bound policy`)
    }
  }

  out.valid = out.errors.length === 0
  return out
}
