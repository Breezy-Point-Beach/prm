import { ed25519 } from '@noble/curves/ed25519'
import { SIGNING_DOMAINS } from '@prm/schema'
import type { DataIntegrityProof, UtcInstant } from '@prm/schema'
import { digestBytes, type DocumentKind } from './digest.js'
import { decodePublicKey, decodeSignature, encodePublicKey, encodeSignature } from './encoding.js'

export type SigningDomain = (typeof SIGNING_DOMAINS)[keyof typeof SIGNING_DOMAINS]

const DOMAIN_FOR: Record<DocumentKind, SigningDomain> = {
  policy: SIGNING_DOMAINS.policy,
  authorization: SIGNING_DOMAINS.authorization,
  keyEvent: SIGNING_DOMAINS.keyEvent,
  ledgerEntry: SIGNING_DOMAINS.ledgerEntry,
  signedTreeHead: SIGNING_DOMAINS.signedTreeHead
}

/**
 * Build the domain-separated message that actually gets signed — spec/NORMATIVE.md §4.
 *
 *     message = utf8(DOMAIN) || 0x00 || digest
 *
 * Signing the bare digest would let a policy signature be replayed as an authorization signature.
 * There is deliberately no "verify under any domain" mode anywhere in this codebase.
 */
export function signingMessage (domain: SigningDomain, digest32: Uint8Array): Uint8Array {
  if (digest32.length !== 32) throw new Error(`expected a 32-byte digest, got ${digest32.length}`)
  const prefix = new TextEncoder().encode(domain)
  const msg = new Uint8Array(prefix.length + 1 + 32)
  msg.set(prefix, 0)
  msg[prefix.length] = 0x00
  msg.set(digest32, prefix.length + 1)
  return msg
}

export function domainFor (kind: DocumentKind): SigningDomain {
  return DOMAIN_FOR[kind]
}

/** Sign raw bytes with an Ed25519 private key (32-byte seed). */
export function signBytes (privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey)
}

export function verifyBytes (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey)
  } catch {
    // A malformed signature or point is a verification failure, not an exception to propagate.
    return false
  }
}

/** Sign a PRM document, returning the multibase `proofValue`. */
export function signDocument (
  privateKey: Uint8Array,
  doc: object,
  kind: DocumentKind
): string {
  const msg = signingMessage(domainFor(kind), digestBytes(doc, kind))
  return encodeSignature(signBytes(privateKey, msg))
}

/** Verify a document against a raw public key and an explicit kind. */
export function verifyDocument (
  publicKey: Uint8Array,
  doc: object,
  kind: DocumentKind,
  proofValue: string
): boolean {
  let sig: Uint8Array
  try {
    sig = decodeSignature(proofValue)
  } catch {
    return false
  }
  return verifyBytes(publicKey, signingMessage(domainFor(kind), digestBytes(doc, kind)), sig)
}

export interface BuildProofOptions {
  privateKey: Uint8Array
  publicKey: Uint8Array
  kind: DocumentKind
  created: UtcInstant
}

/** Build a complete W3C Data Integrity proof for a document. */
export function buildProof (doc: object, opts: BuildProofOptions): DataIntegrityProof {
  const mb = encodePublicKey(opts.publicKey)
  return {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: opts.created,
    verificationMethod: `did:key:${mb}#${mb}`,
    proofPurpose: 'assertionMethod',
    proofValue: signDocument(opts.privateKey, doc, opts.kind)
  }
}

/** Extract the multibase public key from a `verificationMethod` such as "did:key:z6Mk…#z6Mk…". */
export function publicKeyFromVerificationMethod (vm: string): Uint8Array {
  const fragment = vm.includes('#') ? vm.slice(vm.lastIndexOf('#') + 1) : vm.slice(vm.lastIndexOf(':') + 1)
  return decodePublicKey(fragment)
}

/** Verify a document using the key named inside its own proof. */
export function verifyProofSelfContained (
  doc: object,
  kind: DocumentKind,
  proof: DataIntegrityProof
): boolean {
  try {
    return verifyDocument(publicKeyFromVerificationMethod(proof.verificationMethod), doc, kind, proof.proofValue)
  } catch {
    return false
  }
}
