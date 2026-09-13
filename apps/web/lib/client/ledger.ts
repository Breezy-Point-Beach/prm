'use client'

import type { LedgerEntry, LedgerEntryType } from '@prm/schema'
import { buildProof, digest, type KeyPair } from '@prm/crypto'
import { getLedger, upsertLoggedEntry, type LoggedEntry } from './session'

/**
 * The personal ledger, client side — docs/07 §2.
 *
 * Every entry is signed by the user and chained to the previous one. What reaches the server is the
 * DIGEST of an entry, never the entry, so the global log learns that something happened and nothing
 * about what. The entry document — which is what a .prmproof carries — stays here.
 */

const iso = (d: Date): string => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

export interface NewEntry {
  accountId: string
  entryType: LedgerEntryType
  subjectHash: string
  now?: Date
}

/** Sign the next entry in this device's ledger. Sequence and previous hash come from what is stored. */
export function buildNextEntry (spec: NewEntry, key: KeyPair): { entry: LedgerEntry; entryDigest: string } {
  const existing = getLedger()
  const last = existing[existing.length - 1]
  const recorded = iso(spec.now ?? new Date())
  const unsigned = {
    type: 'prm/LedgerEntry/v1' as const,
    accountId: spec.accountId,
    sequence: existing.length,
    previousEntryHash: last ? digest(last.entry, 'ledgerEntry') : null,
    recorded,
    entryType: spec.entryType,
    subjectHash: spec.subjectHash
  }
  const proof = buildProof(unsigned, {
    privateKey: key.privateKey, publicKey: key.publicKey, kind: 'ledgerEntry', created: recorded
  })
  const entry: LedgerEntry = { ...unsigned, proof }
  return { entry, entryDigest: digest(entry, 'ledgerEntry') }
}

export interface LogProofResponse {
  logId: string
  leafIndex: number
  treeSize: number
  rootHash: string
  inclusionProof: string[]
  signedTreeHead: string
  timestamps: Record<string, string>
  chains: Record<string, string>
  timestampedAt: string | null
  authorities: Array<{ tsa: string; genTime: string }>
}

/** Fetch the current proof for a leaf and attach it to the entry. */
export async function fetchInclusion (logged: LoggedEntry): Promise<LoggedEntry> {
  if (logged.leafIndex === undefined) return logged
  const response = await fetch(`/log/proof/${logged.leafIndex}.json`, { cache: 'no-store' })
  if (!response.ok) throw new Error(`could not fetch the inclusion proof (${response.status})`)
  const p = (await response.json()) as LogProofResponse
  const firstToken = Object.values(p.timestamps)[0]
  const updated: LoggedEntry = {
    ...logged,
    entry: {
      ...logged.entry,
      // Attached AFTER signing and excluded from the digest (spec/NORMATIVE.md §2).
      logInclusion: {
        logId: p.logId,
        leafIndex: p.leafIndex,
        treeSize: p.treeSize,
        rootHash: p.rootHash,
        inclusionProof: p.inclusionProof,
        ...(firstToken ? { timestampToken: firstToken } : {})
      }
    },
    proof: {
      signedTreeHead: p.signedTreeHead,
      timestamps: p.timestamps,
      chains: p.chains,
      timestampedAt: p.timestampedAt,
      authorities: p.authorities
    }
  }
  upsertLoggedEntry(updated)
  return updated
}

/**
 * Record a published policy: sign a `policy.published` entry, append its digest to the global log,
 * and attach the inclusion proof. The token arrives later (hourly); `fetchInclusion` picks it up.
 */
export async function logPublishedPolicy (opts: {
  accountId: string
  policyDigest: string
  handle: string
  key: KeyPair
}): Promise<LoggedEntry> {
  const { entry, entryDigest } = buildNextEntry(
    { accountId: opts.accountId, entryType: 'policy.published', subjectHash: opts.policyDigest }, opts.key)
  // Persist before appending, so a failed append leaves a signed entry that can be retried.
  upsertLoggedEntry({ entry })

  const response = await fetch('/api/v1/log/append', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // The digest and the handle. Not the entry, not the policy, nothing signed.
    body: JSON.stringify({ entryDigest, handle: opts.handle })
  })
  const result = (await response.json()) as { ok: boolean; leafIndex?: number; error?: string }
  if (!result.ok || result.leafIndex === undefined) throw new Error(result.error ?? 'the log refused the append')

  const logged: LoggedEntry = { entry, leafIndex: result.leafIndex }
  upsertLoggedEntry(logged)
  return fetchInclusion(logged)
}

/** The logged entry for a policy digest, if this device recorded one. */
export function loggedEntryFor (policyDigest: string): LoggedEntry | undefined {
  return getLedger().find((e) => e.entry.entryType === 'policy.published' && e.entry.subjectHash === policyDigest)
}
