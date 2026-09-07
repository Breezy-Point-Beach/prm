import type { LedgerEntry, SignedTreeHead } from '@prm/schema'
import { validateLedgerEntry } from '@prm/schema'
import {
  digest, digestBytes, decodeMultihash, decodeSignature, decodePublicKey, jcsBytes,
  hash, leafHash, verifyInclusion, verifyBytes, signingMessage, verifyProofSelfContained
} from '@prm/crypto'

/** Verify a personal ledger hash chain: continuity plus a valid signature on every entry. */
export function verifyLedgerChain (entries: LedgerEntry[]): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  if (entries.length === 0) return { valid: false, errors: ['empty ledger'] }

  const sorted = [...entries].sort((a, b) => a.sequence - b.sequence)
  let previousDigest: string | null = null

  for (const e of sorted) {
    const v = validateLedgerEntry(e)
    if (!v.valid) { errors.push(`entry ${e.sequence}: ${v.errors.join('; ')}`); continue }

    if (e.previousEntryHash !== previousDigest) {
      errors.push(
        `entry ${e.sequence}: previousEntryHash does not match entry ${e.sequence - 1} — ` +
        `the chain has been broken, reordered, or had an entry removed`)
    }
    if (!verifyProofSelfContained(e, 'ledgerEntry', e.proof)) {
      errors.push(`entry ${e.sequence}: signature is not valid`)
    }
    previousDigest = digest(e, 'ledgerEntry')
  }
  return { valid: errors.length === 0, errors }
}

/** Verify a signed tree head against the log's published public key. */
export function verifySignedTreeHead (sth: SignedTreeHead, logPublicKeyMultibase: string): boolean {
  try {
    const { signature, ...body } = sth
    const msg = signingMessage('PRM-STH-v1', hash(jcsBytes(body)))
    return verifyBytes(decodePublicKey(logPublicKeyMultibase), msg, decodeSignature(signature))
  } catch {
    return false
  }
}

export interface InclusionCheck {
  valid: boolean
  errors: string[]
  rootHash?: string
  treeSize?: number
}

/**
 * Verify that a ledger entry is included in the transparency log.
 *
 * Note the digest is computed with `logInclusion` stripped (spec/NORMATIVE.md §2) — the entry was
 * signed before the log ever saw it, so hashing the log's own response would be circular.
 */
export function verifyLogInclusion (entry: LedgerEntry, sth?: SignedTreeHead): InclusionCheck {
  const errors: string[] = []
  const inc = entry.logInclusion
  if (!inc) return { valid: false, errors: ['entry carries no log inclusion proof'] }

  try {
    const leaf = leafHash(digestBytes(entry, 'ledgerEntry'))
    const proof = inc.inclusionProof.map((m) => decodeMultihash(m))
    const root = decodeMultihash(inc.rootHash)

    if (!verifyInclusion(leaf, inc.leafIndex, inc.treeSize, proof, root)) {
      errors.push(
        `entry ${entry.sequence}: inclusion proof does not reconstruct the claimed root — ` +
        `this entry was not in the tree the log says it was`)
    }
    if (sth) {
      if (sth.rootHash !== inc.rootHash) {
        errors.push('the entry\'s root hash does not match the supplied signed tree head')
      }
      if (sth.treeSize < inc.treeSize) {
        errors.push('the signed tree head is smaller than the tree the proof references')
      }
    }
    return { valid: errors.length === 0, errors, rootHash: inc.rootHash, treeSize: inc.treeSize }
  } catch (e) {
    return { valid: false, errors: [`malformed inclusion proof: ${(e as Error).message}`] }
  }
}
