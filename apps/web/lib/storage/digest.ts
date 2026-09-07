import { hash, encodeMultihash, decodeMultihash, timingSafeEqual } from '@prm/crypto'

/**
 * Byte-level digests — the storage identity, distinct from the protocol policy digest.
 *
 * See types.ts for why the two must not be conflated.
 */

const encoder = new TextEncoder()

export function byteDigestOf (bytes: Uint8Array | string): string {
  return encodeMultihash(hash(typeof bytes === 'string' ? encoder.encode(bytes) : bytes))
}

export function byteDigestMatches (bytes: Uint8Array | string, expected: string): boolean {
  try {
    const actual = hash(typeof bytes === 'string' ? encoder.encode(bytes) : bytes)
    // Constant time, because this comparison gates whether corrupt content is served.
    return timingSafeEqual(actual, decodeMultihash(expected))
  } catch {
    return false
  }
}

/**
 * Storage key for an artifact.
 *
 * Digest-addressed, so the key IS an integrity claim: a reader who fetched
 * `artifacts/policy/uEiDy...` can hash what came back and know whether the backend lied.
 */
export function artifactKey (kind: string, byteDigest: string): string {
  if (!/^u[A-Za-z0-9_-]{40,}$/.test(byteDigest)) {
    throw new Error(`invalid byte digest for a storage key: ${byteDigest}`)
  }
  return `artifacts/${kind}/${byteDigest}`
}

export const utf8 = (s: string): Uint8Array => encoder.encode(s)
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b)
