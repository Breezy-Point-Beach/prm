import { sha256 } from '@noble/hashes/sha2'
import { NON_HASHED_MEMBERS } from '@prm/schema'
import { jcsBytes } from './jcs.js'
import { encodeMultihash } from './encoding.js'

export type DocumentKind = keyof typeof NON_HASHED_MEMBERS

/**
 * Strip the members that are excluded from the hashed bytes — spec/NORMATIVE.md §2.
 *
 * This exists as its own exported function because it is the rule most likely to be got wrong, and
 * the one whose failure mode is silent: you get a well-formed digest that nobody else computes.
 */
export function stripNonHashed<T extends object> (doc: T, kind: DocumentKind): Record<string, unknown> {
  const excluded = new Set<string>(NON_HASHED_MEMBERS[kind])
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(doc)) {
    if (!excluded.has(k) && v !== undefined) out[k] = v
  }
  return out
}

/** Raw 32-byte canonical digest of a PRM document. */
export function digestBytes (doc: object, kind: DocumentKind): Uint8Array {
  return sha256(jcsBytes(stripNonHashed(doc, kind)))
}

/** Canonical digest in multihash form — the value used as an id, a chain link, and a Merkle leaf. */
export function digest (doc: object, kind: DocumentKind): string {
  return encodeMultihash(digestBytes(doc, kind))
}

/** SHA-256 over arbitrary bytes. */
export function hash (data: Uint8Array): Uint8Array {
  return sha256(data)
}

/** SHA-256 over a UTF-8 string. */
export function hashString (s: string): Uint8Array {
  return sha256(new TextEncoder().encode(s))
}

/**
 * Policy chain identifier — spec/NORMATIVE.md §6.
 *
 * Excludes `policyChainId` in ADDITION to the usual `id` and `proof`, because version 1 carries the
 * very value being derived. A consequence worth stating: chainDigest !== digest(policyV1).
 */
export function policyChainId (policyV1: object): string {
  const stripped = stripNonHashed(policyV1, 'policy')
  delete stripped['policyChainId']
  return 'urn:prm:chain:' + encodeMultihash(sha256(jcsBytes(stripped)))
}

/** Self-referential policy id: "urn:prm:policy:" + its own digest. */
export function policyId (policy: object): string {
  return 'urn:prm:policy:' + digest(policy, 'policy')
}

/** Self-referential authorization id. */
export function authorizationId (authz: object): string {
  return 'urn:prm:authz:' + digest(authz, 'authorization')
}
