import type { SignedTreeHead } from '@prm/schema'
import {
  parseTimestampResponse, parseTimestampToken, timestampImprintForRoot, tokenFromBase64,
  timingSafeEqual, OID, type TimestampToken
} from '@prm/crypto'

/**
 * Bind an RFC 3161 token to a tree head — docs/08 §3, spec/NORMATIVE.md §9.
 *
 * WHAT THIS PROVES: the token is a token FOR this root. Its message imprint is SHA-256 over the
 * root's 32 bytes, and a TSA only signs the imprint it was sent — so a token that binds here cannot
 * have been issued for anything else. Combined with an inclusion proof, that carries the TSA's time
 * down to a single ledger entry, and through the entry's subjectHash to a policy.
 *
 * WHAT THIS DOES NOT PROVE: that the TSA's signature is valid, or that you trust the TSA. Checking
 * the CMS signature needs the TSA's certificate chain and a decision about which roots to accept —
 * a trust decision that belongs with the person verifying, not inside a library that would otherwise
 * be making it silently. The bundle carries the token, the chain when the operator archived it, and
 * the exact `openssl ts -verify` invocation. This function tells you WHICH token to run that on.
 */
export interface TimestampBinding {
  valid: boolean
  errors: string[]
  /** RFC 3339. The instant the TSA attests the root existed no later than. */
  genTime?: string
  tsaName?: string
  serialNumberHex?: string
  policyOid?: string
  /** Certificates embedded in the token; 0 means the verifier must supply the chain themselves. */
  certificateCount?: number
}

export function verifyTimestampBinding (
  tokenBase64: string,
  sth: Pick<SignedTreeHead, 'rootHash'>
): TimestampBinding {
  let token: TimestampToken
  try {
    const der = tokenFromBase64(tokenBase64)
    token = tokenOf(der)
  } catch (e) {
    return { valid: false, errors: [`not a readable RFC 3161 token: ${(e as Error).message}`] }
  }

  const errors: string[] = []
  if (token.hashAlgorithmOid !== OID.sha256) {
    errors.push(`token imprint uses hash algorithm ${token.hashAlgorithmOid}, not SHA-256`)
  } else {
    let expected: Uint8Array
    try {
      expected = timestampImprintForRoot(sth.rootHash)
    } catch (e) {
      return { valid: false, errors: [`tree head root is not usable: ${(e as Error).message}`] }
    }
    if (token.hashedMessage.length !== expected.length || !timingSafeEqual(token.hashedMessage, expected)) {
      errors.push(
        'token imprint does not match SHA-256 of this tree head\'s root — ' +
        'this token was issued for something else')
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    genTime: token.genTime,
    ...(token.tsaName ? { tsaName: token.tsaName } : {}),
    serialNumberHex: token.serialNumberHex,
    policyOid: token.policyOid,
    certificateCount: token.certificateCount
  }
}

/** A stored token may be the whole TimeStampResp (what a TSA returns) or the bare TimeStampToken. */
function tokenOf (der: Uint8Array): TimestampToken {
  try {
    const resp = parseTimestampResponse(der)
    if (resp.token) return resp.token
    throw new Error(`TSA reply status "${resp.statusText}" carries no token${resp.statusString ? `: ${resp.statusString}` : ''}`)
  } catch (responseError) {
    try {
      return parseTimestampToken(der)
    } catch {
      throw responseError
    }
  }
}
