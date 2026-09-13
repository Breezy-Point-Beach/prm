import type { SignedTreeHead } from '@prm/schema'
import {
  keyPairFromSeed, hash, hashString, jcsBytes, signBytes, signingMessage, encodeSignature,
  leafHash, merkleRoot, inclusionProof, encodeMultihash, decodeMultihash, timestampImprintForRoot,
  type KeyPair
} from '@prm/crypto'
import type { Storage, TimestampRecord } from './storage'
import { configuredAuthorities, requestTimestamp, type TimestampAuthority } from './tsa'

/**
 * The transparency log, server side — docs/07 §3, docs/08 §3.
 *
 * WHAT THE SERVER HOLDS: opaque leaf hashes, signed tree heads, and timestamp tokens. Never a ledger
 * entry. The client signs its entry, appends the DIGEST, and keeps the document (D23).
 *
 * WHEN A TREE HEAD IS EMITTED: on every append. The tree is small (docs/07 §6) and a head per append
 * means every leaf is covered by a head the moment it lands, so a client can attach an inclusion
 * proof immediately and only the TSA token is deferred.
 *
 * WHEN A TOKEN IS REQUESTED: at most once an hour, over the newest head — by the cron, and
 * opportunistically by whichever request finds the newest head unanchored after the hour is up.
 * Hourly batching is a privacy control, not an optimisation (docs/08 §4): the authority sees one
 * request per hour whose contents do not vary with who was active.
 */

export class LogNotConfiguredError extends Error {
  override name = 'LogNotConfiguredError'
}

export type LogEnvironment = 'development' | 'preview' | 'production'

export interface LogIdentity {
  logId: string
  keyPair: KeyPair
  publicKeyMultibase: string
  environment: LogEnvironment
}

let identity: LogIdentity | undefined

/**
 * The log's identity, from the environment. Refuses to run with a misconfiguration that could
 * corrupt evidence rather than guessing (docs/16 §4):
 *
 *   production  needs an explicit, production-looking NEXT_PUBLIC_LOG_ID and a signing key
 *   preview     needs a preview log id and its OWN signing key — never the production tree
 *   development derives a fixed, obviously-not-secret key so `pnpm dev` works with no setup
 */
export function logIdentity (env: Record<string, string | undefined> = process.env): LogIdentity {
  if (identity) return identity
  const environment = (env.VERCEL_ENV as LogEnvironment | undefined) ?? 'development'
  const configuredId = env.NEXT_PUBLIC_LOG_ID?.trim()
  const logId = configuredId || (environment === 'preview' ? 'prm-log-preview' : 'prm-log-dev')

  if (environment === 'production' && (!configuredId || /dev|preview|test/i.test(logId))) {
    throw new LogNotConfiguredError(
      `NEXT_PUBLIC_LOG_ID is "${logId}" in production. Set a production log id (e.g. prm-log-1).`)
  }
  if (environment === 'preview' && !/preview/i.test(logId)) {
    throw new LogNotConfiguredError(
      `NEXT_PUBLIC_LOG_ID is "${logId}" on a preview deployment. A preview must use its own log ` +
      '(e.g. prm-log-preview): appending to the production tree from a preview is unrecoverable.')
  }

  let seed: Uint8Array
  const b64 = env.LOG_SIGNING_KEY_B64?.trim()
  if (b64) {
    seed = new Uint8Array(Buffer.from(b64, 'base64'))
    if (seed.length !== 32) throw new LogNotConfiguredError('LOG_SIGNING_KEY_B64 must decode to 32 bytes')
  } else if (environment === 'development') {
    // Deterministic so tree heads stay verifiable across restarts of `pnpm dev`. Not a secret.
    seed = hashString('PRM development log key — not for production')
  } else {
    throw new LogNotConfiguredError(
      `LOG_SIGNING_KEY_B64 is not set for the ${environment} environment. ` +
      'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"')
  }

  const keyPair = keyPairFromSeed(seed)
  const published = env.NEXT_PUBLIC_LOG_PUBLIC_KEY?.trim()
  if (published && published !== keyPair.publicKeyMultibase) {
    throw new LogNotConfiguredError(
      'NEXT_PUBLIC_LOG_PUBLIC_KEY does not match the key derived from LOG_SIGNING_KEY_B64. ' +
      `Expected ${keyPair.publicKeyMultibase}.`)
  }

  identity = { logId, keyPair, publicKeyMultibase: keyPair.publicKeyMultibase, environment }
  return identity
}

/** Test hook. */
export function __resetLogIdentity (): void { identity = undefined }

const iso = (d: Date): string => d.toISOString().replace(/\.\d{3}Z$/, 'Z')
const MULTIHASH = /^u[A-Za-z0-9_-]{40,}$/

export function isMultihash (s: unknown): s is string {
  return typeof s === 'string' && MULTIHASH.test(s)
}

export interface TreeHead {
  treeSize: number
  sth: SignedTreeHead
  /** The exact JSON text that is stored and served. */
  sthJson: string
}

/** Sign a tree head over the current leaves, unless one for this size already exists. */
export async function emitTreeHead (storage: Storage, now: Date = new Date()): Promise<TreeHead> {
  const { logId, keyPair } = logIdentity()
  const leaves = await storage.log.leaves()
  if (leaves.length === 0) throw new Error('the log is empty; nothing to head')

  const latest = await storage.log.latestTreeHead()
  if (latest && latest.treeSize === leaves.length) {
    return { treeSize: latest.treeSize, sth: JSON.parse(latest.sthJson) as SignedTreeHead, sthJson: latest.sthJson }
  }

  const root = merkleRoot(leaves.map((l) => decodeMultihash(l.leafHash)))
  const body = {
    logId,
    treeSize: leaves.length,
    rootHash: encodeMultihash(root),
    timestamp: iso(now),
    ...(latest ? { previousRootHash: (JSON.parse(latest.sthJson) as SignedTreeHead).rootHash } : {})
  }
  const signature = encodeSignature(signBytes(keyPair.privateKey, signingMessage('PRM-STH-v1', hash(jcsBytes(body)))))
  const sth: SignedTreeHead = { ...body, signature }
  const sthJson = JSON.stringify(sth, null, 2)
  await storage.log.putTreeHead({ treeSize: leaves.length, sthJson, createdAt: iso(now) })
  // Another append may have won the write for this size; serve what is stored, never a competing head.
  const stored = await storage.log.treeHead(leaves.length)
  return stored
    ? { treeSize: stored.treeSize, sth: JSON.parse(stored.sthJson) as SignedTreeHead, sthJson: stored.sthJson }
    : { treeSize: leaves.length, sth, sthJson }
}

export interface AppendResult {
  logId: string
  leafIndex: number
  leafHash: string
  head: TreeHead
}

/** Append the digest of a user's signed ledger entry. Idempotent: the same digest is one leaf. */
export async function appendEntryDigest (storage: Storage, entryDigest: string, now: Date = new Date()): Promise<AppendResult> {
  if (!isMultihash(entryDigest)) throw new Error('entryDigest must be a multibase multihash')
  const { logId } = logIdentity()
  const leaf = encodeMultihash(leafHash(decodeMultihash(entryDigest)))
  const appended = await storage.log.append(leaf, iso(now))
  const head = await emitTreeHead(storage, now)
  return { logId, leafIndex: appended.leafIndex, leafHash: leaf, head }
}

export interface LogProof {
  logId: string
  leafIndex: number
  treeSize: number
  rootHash: string
  inclusionProof: string[]
  /** Exact JSON of the signed tree head the proof is against. */
  signedTreeHead: string
  /** `sth-<size>-<tsa>.tsr.b64` -> base64 TimeStampResp. Empty until anchored. */
  timestamps: Record<string, string>
  /** `<tsa>-chain.pem` -> PEM, for the authorities whose chain was archived. */
  chains: Record<string, string>
  /** Earliest attested time among the tokens, or null while a token is pending. */
  timestampedAt: string | null
  authorities: Array<{ tsa: string; genTime: string }>
}

/**
 * An inclusion proof for a leaf against the best available head: the newest ANCHORED head that
 * covers the leaf if there is one, else the newest head. A caller that wants a token can come back
 * after the next anchoring; the leaf index never changes.
 */
export async function proofForLeaf (storage: Storage, leafIndex: number): Promise<LogProof | null> {
  const leaves = await storage.log.leaves()
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= leaves.length) return null

  let head = await storage.log.latestTreeHead()
  const anchored = await storage.log.latestTimestamp()
  if (anchored && anchored.treeSize > leafIndex) {
    const h = await storage.log.treeHead(anchored.treeSize)
    if (h) head = h
  }
  if (!head || head.treeSize <= leafIndex) {
    await emitTreeHead(storage)
    head = await storage.log.latestTreeHead()
  }
  if (!head) return null

  const sth = JSON.parse(head.sthJson) as SignedTreeHead
  const subset = leaves.slice(0, head.treeSize).map((l) => decodeMultihash(l.leafHash))
  const tokens = await storage.log.timestamps(head.treeSize)
  return {
    logId: sth.logId,
    leafIndex,
    treeSize: head.treeSize,
    rootHash: sth.rootHash,
    inclusionProof: inclusionProof(subset, leafIndex).map(encodeMultihash),
    signedTreeHead: head.sthJson,
    ...timestampArtifacts(tokens)
  }
}

export function timestampArtifacts (tokens: TimestampRecord[]): Pick<LogProof, 'timestamps' | 'chains' | 'timestampedAt' | 'authorities'> {
  const timestamps: Record<string, string> = {}
  const chains: Record<string, string> = {}
  for (const t of tokens) {
    timestamps[`sth-${t.treeSize}-${t.tsa}.tsr.b64`] = t.tokenBase64
    if (t.chainPem) chains[`${t.tsa}-chain.pem`] = t.chainPem
  }
  const times = tokens.map((t) => t.genTime).sort()
  return {
    timestamps,
    chains,
    timestampedAt: times[0] ?? null,
    authorities: tokens.map((t) => ({ tsa: t.tsa, genTime: t.genTime }))
  }
}

export interface AnchorResult {
  treeSize: number | null
  skipped?: 'empty log' | 'already anchored' | 'rate limited' | 'no authorities configured'
  results: Array<{ tsa: string; ok: boolean; genTime?: string; error?: string }>
}

export const ANCHOR_INTERVAL_MS = 60 * 60 * 1000

/**
 * Get RFC 3161 tokens for the newest tree head from every configured authority that has not issued
 * one yet. Idempotent and safe to call from anywhere: the cron forces it; a request path calls it
 * without `force` and is turned away until an hour has passed since the last token.
 */
export async function anchorLatest (
  storage: Storage,
  opts: { force?: boolean; now?: Date; fetchImpl?: typeof fetch; authorities?: TimestampAuthority[] } = {}
): Promise<AnchorResult> {
  const now = opts.now ?? new Date()
  const head = await storage.log.latestTreeHead()
  if (!head) return { treeSize: null, skipped: 'empty log', results: [] }

  const authorities = opts.authorities ?? configuredAuthorities()
  if (authorities.length === 0) return { treeSize: head.treeSize, skipped: 'no authorities configured', results: [] }

  const existing = await storage.log.timestamps(head.treeSize)
  const missing = authorities.filter((a) => !existing.some((t) => t.tsa === a.tsa))
  if (missing.length === 0) return { treeSize: head.treeSize, skipped: 'already anchored', results: [] }

  if (!opts.force) {
    const last = await storage.log.latestTimestamp()
    if (last && now.getTime() - new Date(last.acquiredAt).getTime() < ANCHOR_INTERVAL_MS) {
      return { treeSize: head.treeSize, skipped: 'rate limited', results: [] }
    }
  }

  const sth = JSON.parse(head.sthJson) as SignedTreeHead
  const imprint = timestampImprintForRoot(sth.rootHash)
  const results: AnchorResult['results'] = []
  for (const authority of missing) {
    try {
      const acquired = await requestTimestamp(authority, imprint, opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {})
      await storage.log.putTimestamp({
        treeSize: head.treeSize,
        tsa: authority.tsa,
        tokenBase64: acquired.tokenBase64,
        genTime: acquired.genTime,
        acquiredAt: iso(now),
        ...(acquired.chainPem ? { chainPem: acquired.chainPem } : {})
      })
      results.push({ tsa: authority.tsa, ok: true, genTime: acquired.genTime })
    } catch (e) {
      // One authority failing must not stop the other: that independence is the reason there are two.
      results.push({ tsa: authority.tsa, ok: false, error: (e as Error).message })
    }
  }
  return { treeSize: head.treeSize, results }
}
