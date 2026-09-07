import { ed25519 } from '@noble/curves/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { randomBytes } from '@noble/hashes/utils'
import { encodeMultihash, encodePublicKey } from './encoding.js'

/**
 * Key generation and derivation — docs/01 §3.
 *
 * Every key derives from one 32-byte master seed via HKDF-SHA256 with distinct info strings, so a
 * single mnemonic backs up everything and a rotation does not require a new backup. That is a
 * usability decision with a security purpose: backup fatigue causes far more account loss than key
 * theft does.
 */

export const HKDF_SALT = new Uint8Array(32) // 32 zero bytes — see spec/test-vectors/vectors.json

export interface KeyPair {
  /** 32-byte Ed25519 seed. SECRET — never transmit, log, or persist unencrypted. */
  privateKey: Uint8Array
  /** 32-byte raw Ed25519 public key. */
  publicKey: Uint8Array
  /** Multibase base58btc form, e.g. "z6Mk…". */
  publicKeyMultibase: string
  /** Multihash of SHA-256(publicKey) — the pre-rotation commitment value. */
  publicKeyDigest: string
  did: string
}

export function keyPairFromSeed (seed: Uint8Array): KeyPair {
  if (seed.length !== 32) throw new Error(`expected a 32-byte seed, got ${seed.length}`)
  const publicKey = ed25519.getPublicKey(seed)
  const publicKeyMultibase = encodePublicKey(publicKey)
  return {
    privateKey: seed,
    publicKey,
    publicKeyMultibase,
    publicKeyDigest: encodeMultihash(sha256(publicKey)),
    did: `did:key:${publicKeyMultibase}`
  }
}

/** Generate a fresh 32-byte master seed from the platform CSPRNG. */
export function generateMasterSeed (): Uint8Array {
  return randomBytes(32)
}

/** HKDF-SHA256 with the PRM salt and an explicit info string. */
export function deriveKeyMaterial (masterSeed: Uint8Array, info: string, length = 32): Uint8Array {
  return hkdf(sha256, masterSeed, HKDF_SALT, new TextEncoder().encode(info), length)
}

/** Signing key at rotation index n — info string "prm/v1/sign/{n}". */
export function deriveSigningKey (masterSeed: Uint8Array, index: number): KeyPair {
  if (!Number.isInteger(index) || index < 0) throw new Error(`invalid rotation index: ${index}`)
  return keyPairFromSeed(deriveKeyMaterial(masterSeed, `prm/v1/sign/${index}`))
}

/**
 * Recovery key — info string "prm/v1/recovery".
 *
 * Its digest is committed in the genesis event so a recovery event can later be proven legitimate.
 * It must be split or stored offline AT ONBOARDING: if the master seed is compromised, both the
 * current and pre-rotation keys are compromised with it, and this is the only remaining remedy.
 */
export function deriveRecoveryKey (masterSeed: Uint8Array): KeyPair {
  return keyPairFromSeed(deriveKeyMaterial(masterSeed, 'prm/v1/recovery'))
}

/** Binding secret — derives per-identifier salts and per-organization pairwise ids. */
export function deriveBindingSecret (masterSeed: Uint8Array): Uint8Array {
  return deriveKeyMaterial(masterSeed, 'prm/v1/binding')
}

/** The full set of keys an account uses at a given rotation index. */
export interface AccountKeys {
  masterSeed: Uint8Array
  /** Currently authorized signing key. */
  signing: KeyPair
  /** Pre-committed next key. NEVER used to sign until a rotation. */
  next: KeyPair
  recovery: KeyPair
  bindingSecret: Uint8Array
  rotationIndex: number
}

export function deriveAccountKeys (masterSeed: Uint8Array, rotationIndex = 0): AccountKeys {
  return {
    masterSeed,
    signing: deriveSigningKey(masterSeed, rotationIndex),
    next: deriveSigningKey(masterSeed, rotationIndex + 1),
    recovery: deriveRecoveryKey(masterSeed),
    bindingSecret: deriveBindingSecret(masterSeed),
    rotationIndex
  }
}

/**
 * Best-effort zeroing of secret material.
 *
 * JavaScript cannot guarantee this — the GC may have copied the buffer, and strings are immutable
 * and uncontrollable. It reduces the window in which a heap snapshot or a crash dump contains the
 * seed; it does not eliminate it. Never treat it as a security boundary.
 */
export function wipe (...secrets: Uint8Array[]): void {
  for (const s of secrets) s.fill(0)
}
