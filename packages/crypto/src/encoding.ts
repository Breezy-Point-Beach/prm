import { base58, base64urlnopad, base32nopad } from '@scure/base'

/**
 * Multibase / multihash encoding — spec/NORMATIVE.md §3.
 *
 * PRM uses exactly two encodings, and mixing them up produces values that look plausible and verify
 * against nothing:
 *   digests     multibase 'u' (base64url, no pad) over multihash(0x12, 0x20, sha256)
 *   public keys multibase 'z' (base58btc)        over multicodec(0xed, 0x01) || raw key
 */

const MULTIHASH_SHA256 = Uint8Array.from([0x12, 0x20])
const MULTICODEC_ED25519_PUB = Uint8Array.from([0xed, 0x01])

export class EncodingError extends Error {}

function concat (...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}

/** 32-byte SHA-256 digest -> "u" + base64url(multihash). */
export function encodeMultihash (digest: Uint8Array): string {
  if (digest.length !== 32) throw new EncodingError(`expected a 32-byte digest, got ${digest.length}`)
  return 'u' + base64urlnopad.encode(concat(MULTIHASH_SHA256, digest))
}

/** Inverse of encodeMultihash. Rejects anything that is not a sha2-256 multihash. */
export function decodeMultihash (mh: string): Uint8Array {
  if (!mh.startsWith('u')) throw new EncodingError(`expected multibase 'u' prefix: ${mh}`)
  let bytes: Uint8Array
  try {
    bytes = base64urlnopad.decode(mh.slice(1))
  } catch {
    throw new EncodingError(`not valid base64url: ${mh}`)
  }
  if (bytes.length !== 34 || bytes[0] !== 0x12 || bytes[1] !== 0x20) {
    throw new EncodingError(`not a sha2-256 multihash: ${mh}`)
  }
  return bytes.subarray(2)
}

/** Raw 32-byte Ed25519 public key -> "z" + base58btc(multicodec || key). */
export function encodePublicKey (raw: Uint8Array): string {
  if (raw.length !== 32) throw new EncodingError(`expected a 32-byte Ed25519 key, got ${raw.length}`)
  return 'z' + base58.encode(concat(MULTICODEC_ED25519_PUB, raw))
}

/** Inverse of encodePublicKey. Rejects keys that are not Ed25519. */
export function decodePublicKey (multibase: string): Uint8Array {
  if (!multibase.startsWith('z')) throw new EncodingError(`expected multibase 'z' prefix: ${multibase}`)
  let bytes: Uint8Array
  try {
    bytes = base58.decode(multibase.slice(1))
  } catch {
    throw new EncodingError(`not valid base58btc: ${multibase}`)
  }
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new EncodingError(`not an Ed25519 multicodec key: ${multibase}`)
  }
  return bytes.subarray(2)
}

/** Raw 64-byte signature -> multibase base58btc, the `proofValue` form. */
export function encodeSignature (sig: Uint8Array): string {
  if (sig.length !== 64) throw new EncodingError(`expected a 64-byte signature, got ${sig.length}`)
  return 'z' + base58.encode(sig)
}

export function decodeSignature (proofValue: string): Uint8Array {
  if (!proofValue.startsWith('z')) throw new EncodingError(`expected multibase 'z' prefix: ${proofValue}`)
  let sig: Uint8Array
  try {
    sig = base58.decode(proofValue.slice(1))
  } catch {
    throw new EncodingError(`not valid base58btc: ${proofValue}`)
  }
  if (sig.length !== 64) throw new EncodingError(`expected a 64-byte signature, got ${sig.length}`)
  return sig
}

/** Lower-case RFC 4648 base32, no padding. Used for account ids and pairwise ids. */
export function encodeBase32Lower (bytes: Uint8Array): string {
  return base32nopad.encode(bytes).toLowerCase()
}

export const bytesToBase64url = (b: Uint8Array): string => base64urlnopad.encode(b)
export const base64urlToBytes = (s: string): Uint8Array => base64urlnopad.decode(s)

export function bytesToHex (b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

export function hexToBytes (hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) throw new EncodingError('hex string has an odd length')
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new EncodingError('not a hex string')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

/** Constant-time comparison. Use for any secret or digest equality check. */
export function timingSafeEqual (a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}
