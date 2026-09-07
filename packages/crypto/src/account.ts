import { sha256 } from '@noble/hashes/sha2'
import { hkdf } from '@noble/hashes/hkdf'
import { digestBytes } from './digest.js'
import { encodeBase32Lower, bytesToBase64url } from './encoding.js'
import { HKDF_SALT } from './keys.js'

/** Length of the base32 portion of an account id. spec/NORMATIVE.md §5: exactly 26 characters. */
export const ACCOUNT_ID_LENGTH = 26

/**
 * Derive the self-certifying account identifier from a genesis key event.
 *
 *   accountId = "prm:" + base32_nopad_lower(digest(genesisEvent)).slice(0, 26)
 *
 * This is what makes the account PRM-independent: it is a function of the genesis event alone, so
 * any third party can recompute it and no server can mint or reassign one.
 */
export function deriveAccountId (genesisEvent: object): string {
  return 'prm:' + encodeBase32Lower(digestBytes(genesisEvent, 'keyEvent')).slice(0, ACCOUNT_ID_LENGTH)
}

/** Recompute the account id and compare — the self-certification check a verifier must perform. */
export function accountIdMatches (accountId: string, genesisEvent: object): boolean {
  return deriveAccountId(genesisEvent) === accountId
}

/**
 * Per-identifier salt — docs/03 §5.
 *
 * Derived rather than random so that commitments survive vault loss: the salt is reproducible from
 * the master seed alone. The trade-off is that anyone holding the binding secret can open every
 * commitment, which is acceptable because that already implies full vault compromise.
 */
export function deriveIdentifierSalt (
  bindingSecret: Uint8Array,
  namespace: string,
  normalizedValue: string
): Uint8Array {
  return hkdf(
    sha256,
    bindingSecret,
    HKDF_SALT,
    new TextEncoder().encode(`prm/v1/salt/${namespace}/${normalizedValue}`),
    16
  )
}

/**
 * Identifier commitment — docs/03 §3.1.
 *
 *   commitment = SHA-256(namespace || 0x00 || normalized || 0x00 || salt)
 *
 * The 128-bit salt is what makes this safe. A bare SHA-256 of a license plate is enumerable in
 * minutes; the identifier spaces PRM cares about are tiny.
 */
export function computeCommitment (
  namespace: string,
  normalizedValue: string,
  salt: Uint8Array
): Uint8Array {
  const enc = new TextEncoder()
  const ns = enc.encode(namespace)
  const val = enc.encode(normalizedValue)
  const buf = new Uint8Array(ns.length + 1 + val.length + 1 + salt.length)
  let o = 0
  buf.set(ns, o); o += ns.length
  buf[o++] = 0x00
  buf.set(val, o); o += val.length
  buf[o++] = 0x00
  buf.set(salt, o)
  return sha256(buf)
}

/** The salt in the form carried by an authorization's `disclosedIdentifiers`. */
export function encodeSalt (salt: Uint8Array): string {
  return bytesToBase64url(salt)
}

/**
 * Pairwise identifier for one relationship — docs/03 §3.2.
 *
 * Two organizations comparing notes cannot tell that their pairwise ids refer to the same person.
 * The account id is public, so it must never be the value organizations key on.
 */
export function derivePairwiseId (bindingSecret: Uint8Array, granteeId: string): string {
  const bytes = hkdf(
    sha256,
    bindingSecret,
    new TextEncoder().encode(granteeId),
    new TextEncoder().encode('prm/v1/pairwise'),
    12
  )
  return encodeBase32Lower(bytes).slice(0, 16)
}
