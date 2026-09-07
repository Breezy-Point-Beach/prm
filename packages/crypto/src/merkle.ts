import { sha256 } from '@noble/hashes/sha2'

/**
 * RFC 6962 Merkle tree — spec/NORMATIVE.md §8.
 *
 * Used exactly as CT specifies so that existing verifier tooling and reasoning apply. The one thing
 * that is easy to get wrong, and that cost two real test failures while authoring the spec, is
 * PROOF ORDERING: the proof array is deepest-sibling-first, which is not self-describing.
 */

const LEAF_PREFIX = 0x00
const NODE_PREFIX = 0x01

export function leafHash (entryDigest: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + entryDigest.length)
  buf[0] = LEAF_PREFIX
  buf.set(entryDigest, 1)
  return sha256(buf)
}

export function nodeHash (left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length)
  buf[0] = NODE_PREFIX
  buf.set(left, 1)
  buf.set(right, 1 + left.length)
  return sha256(buf)
}

/** Largest power of two strictly less than n. */
function splitPoint (n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

export function merkleRoot (leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return sha256(new Uint8Array(0))
  if (leaves.length === 1) return leaves[0] as Uint8Array
  const k = splitPoint(leaves.length)
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)))
}

/** Inclusion proof for leaf `index`, ordered DEEPEST SIBLING FIRST. */
export function inclusionProof (leaves: Uint8Array[], index: number): Uint8Array[] {
  if (index < 0 || index >= leaves.length) throw new RangeError(`leaf index ${index} out of range`)
  if (leaves.length <= 1) return []
  const k = splitPoint(leaves.length)
  return index < k
    ? [...inclusionProof(leaves.slice(0, k), index), merkleRoot(leaves.slice(k))]
    : [...inclusionProof(leaves.slice(k), index - k), merkleRoot(leaves.slice(0, k))]
}

/**
 * Verify an inclusion proof.
 *
 * Derives the descent path top-down (recording which side was taken at each level), then consumes
 * the proof bottom-up, because proof[0] is the deepest sibling.
 */
export function verifyInclusion (
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  proof: Uint8Array[],
  expectedRoot: Uint8Array
): boolean {
  if (index < 0 || index >= treeSize || treeSize < 1) return false

  const path: Array<'L' | 'R'> = []
  let i = index
  let n = treeSize
  while (n > 1) {
    const k = splitPoint(n)
    if (i < k) { path.push('L'); n = k } else { path.push('R'); i -= k; n -= k }
  }
  if (proof.length !== path.length) return false

  let h = leaf
  for (let j = path.length - 1, p = 0; j >= 0; j--, p++) {
    const sibling = proof[p] as Uint8Array
    h = path[j] === 'L' ? nodeHash(h, sibling) : nodeHash(sibling, h)
  }
  return equal(h, expectedRoot)
}

/**
 * Consistency proof between tree sizes m and n (m <= n) — RFC 6962 §2.1.2.
 *
 * This is what detects a rewrite: if the operator ever removes or reorders a leaf, no valid
 * consistency proof exists between the old and new roots.
 */
export function consistencyProof (leaves: Uint8Array[], m: number, n: number): Uint8Array[] {
  if (m < 1 || m > n || n > leaves.length) throw new RangeError(`invalid consistency range ${m}..${n}`)
  return subproof(leaves.slice(0, n), m, true)
}

function subproof (leaves: Uint8Array[], m: number, isRoot: boolean): Uint8Array[] {
  const n = leaves.length
  // RFC 6962 SUBPROOF(m, D[n], b): empty when m == n and b is true, else {MTH(D[n])}.
  if (m === n) return isRoot ? [] : [merkleRoot(leaves)]
  const k = splitPoint(n)
  if (m <= k) {
    // `isRoot` PROPAGATES here. Passing false instead omits nothing and emits the old root
    // redundantly, which the verifier then rejects whenever m is a power of two.
    return [...subproof(leaves.slice(0, k), m, isRoot), merkleRoot(leaves.slice(k))]
  }
  return [...subproof(leaves.slice(k), m - k, false), merkleRoot(leaves.slice(0, k))]
}

/**
 * Verify a consistency proof — the RFC 6962 §2.1.2 algorithm, unmodified.
 *
 * Reconstructs BOTH roots from the same proof: the old root must come out of the left spine, and the
 * new root out of the full tree. If the operator removed or reordered any leaf, no proof can satisfy
 * both simultaneously.
 */
export function verifyConsistency (
  m: number, oldRoot: Uint8Array,
  n: number, newRoot: Uint8Array,
  proof: Uint8Array[]
): boolean {
  if (m < 1 || m > n) return false
  if (m === n) return proof.length === 0 && equal(oldRoot, newRoot)

  let fn = m - 1
  let sn = n - 1

  // Skip the complete subtrees that both trees share along the right edge of the old tree.
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1 }

  let idx = 0
  let fr: Uint8Array
  let sr: Uint8Array

  if (fn !== 0) {
    // The old tree's right edge is incomplete, so its root is not implicit: the proof supplies it.
    const seed = proof[idx++]
    if (seed === undefined) return false
    fr = seed
    sr = seed
  } else {
    // m is a power of two: the old root IS a node of the new tree and is not repeated in the proof.
    fr = oldRoot
    sr = oldRoot
  }

  while (sn !== 0) {
    const sib = proof[idx]
    if (sib === undefined) return false
    idx++
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(sib, fr)
      sr = nodeHash(sib, sr)
      while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1 }
    } else {
      sr = nodeHash(sr, sib)
    }
    fn >>= 1
    sn >>= 1
  }

  return idx === proof.length && equal(fr, oldRoot) && equal(sr, newRoot)
}

function equal (a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
