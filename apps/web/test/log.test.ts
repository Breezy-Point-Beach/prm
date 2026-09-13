import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { verifySignedTreeHead, verifyTimestampBinding } from '@prm/verify'
import { decodeMultihash, encodeMultihash, encodeOid, hash, leafHash, verifyInclusion, OID, tokenToBase64 } from '@prm/crypto'
import type { SignedTreeHead } from '@prm/schema'
import { createMemoryStorage } from '../lib/storage/memory'
import {
  __resetLogIdentity, anchorLatest, appendEntryDigest, emitTreeHead, logIdentity, proofForLeaf,
  LogNotConfiguredError, ANCHOR_INTERVAL_MS
} from '../lib/log'
import { configuredAuthorities, labelFor, requestTimestamp, TimestampAuthorityError } from '../lib/tsa'

/**
 * The server side of the evidentiary chain, with a fake time-stamp authority.
 *
 * The fake reads the imprint and nonce out of the real TimeStampReq the client built and answers
 * with a token-shaped reply for exactly that imprint — so what is tested is the plumbing (append,
 * head, proof, anchoring, rate limiting, independence of the two authorities), not ASN.1, which has
 * its own tests against a real freetsa.org exchange in @prm/crypto.
 */

// ---- DER for the fake reply (mirrors @prm/crypto's encoder) ----
const len = (n: number): number[] => n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]
const tlv = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = new Uint8Array(parts.reduce((s, p) => s + p.length, 0)); let o = 0
  for (const p of parts) { body.set(p, o); o += p.length }
  return Uint8Array.from([tag, ...len(body.length), ...body])
}
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p)
const asBody = (b: Uint8Array): ArrayBuffer => b.slice().buffer as ArrayBuffer

/** Reply to a TimeStampReq with a granted, token-shaped response echoing its imprint and nonce. */
function fakeReply (request: Uint8Array, genTime: string): Uint8Array {
  // TimeStampReq layout is fixed up to the imprint: 30 L 02 01 01 30 31 30 0d <algid 15> 04 20 <32>.
  const imprint = request.slice(24, 56)
  // The nonce INTEGER follows the imprint when present.
  let nonce: Uint8Array | undefined
  if (request[56] === 0x02) nonce = request.slice(56, 58 + (request[57] as number))
  const tst = seq(tlv(0x02, Uint8Array.of(1)), encodeOid('1.2.3.4.1'),
    seq(seq(encodeOid(OID.sha256), tlv(0x05)), tlv(0x04, imprint)),
    tlv(0x02, Uint8Array.of(0x42)), tlv(0x18, new TextEncoder().encode(genTime)),
    ...(nonce ? [nonce] : []))
  const sd = seq(tlv(0x02, Uint8Array.of(3)), tlv(0x31), seq(encodeOid(OID.tstInfo), tlv(0xa0, tlv(0x04, tst))), tlv(0x31))
  return seq(seq(tlv(0x02, Uint8Array.of(0))), seq(encodeOid(OID.signedData), tlv(0xa0, sd)))
}

function fakeTsa (opts: { genTime?: string; fail?: Set<string>; chainFor?: Set<string> } = {}) {
  const calls: string[] = []
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input)
    calls.push(url)
    if (url.endsWith('/chain.pem')) {
      return new Response('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', { status: 200 })
    }
    const host = new URL(url).hostname
    if (opts.fail?.has(host)) return new Response('nope', { status: 503 })
    const body = new Uint8Array(init?.body as ArrayBuffer)
    return new Response(asBody(fakeReply(body, opts.genTime ?? '20260915130000Z')), {
      status: 200, headers: { 'Content-Type': 'application/timestamp-reply' }
    })
  }) as typeof fetch
  return { fetchImpl, calls }
}

const AUTHORITIES = [
  { tsa: 'alpha', url: 'https://tsa.alpha.test/tsr', caUrl: 'https://tsa.alpha.test/chain.pem' },
  { tsa: 'beta', url: 'https://beta.test/tsr' }
]
const entryDigest = (s: string) => encodeMultihash(hash(new TextEncoder().encode(s)))

beforeEach(() => { __resetLogIdentity(); delete process.env.VERCEL_ENV; delete process.env.NEXT_PUBLIC_LOG_ID; delete process.env.LOG_SIGNING_KEY_B64; delete process.env.NEXT_PUBLIC_LOG_PUBLIC_KEY })
afterEach(() => { __resetLogIdentity() })

describe('log identity', () => {
  it('derives a fixed development key with no configuration', () => {
    const a = logIdentity()
    __resetLogIdentity()
    const b = logIdentity()
    expect(a.logId).toBe('prm-log-dev')
    expect(a.publicKeyMultibase).toBe(b.publicKeyMultibase)
  })

  it('REFUSES production without an explicit production log id and key', () => {
    expect(() => logIdentity({ VERCEL_ENV: 'production' })).toThrow(LogNotConfiguredError)
    __resetLogIdentity()
    expect(() => logIdentity({ VERCEL_ENV: 'production', NEXT_PUBLIC_LOG_ID: 'prm-log-dev', LOG_SIGNING_KEY_B64: Buffer.alloc(32, 1).toString('base64') })).toThrow(/production/)
    __resetLogIdentity()
    expect(() => logIdentity({ VERCEL_ENV: 'production', NEXT_PUBLIC_LOG_ID: 'prm-log-1' })).toThrow(/LOG_SIGNING_KEY_B64/)
    __resetLogIdentity()
    expect(logIdentity({ VERCEL_ENV: 'production', NEXT_PUBLIC_LOG_ID: 'prm-log-1', LOG_SIGNING_KEY_B64: Buffer.alloc(32, 1).toString('base64') }).logId).toBe('prm-log-1')
  })

  it('REFUSES a preview that would append to a non-preview log', () => {
    expect(() => logIdentity({ VERCEL_ENV: 'preview', NEXT_PUBLIC_LOG_ID: 'prm-log-1', LOG_SIGNING_KEY_B64: Buffer.alloc(32, 1).toString('base64') })).toThrow(/preview/)
  })

  it('REFUSES a published public key that does not match the signing key', () => {
    expect(() => logIdentity({ NEXT_PUBLIC_LOG_PUBLIC_KEY: 'z6MkNotTheKey' })).toThrow(/does not match/)
  })
})

describe('append, tree head, proof', () => {
  it('appends a leaf, signs a head for the new size, and the proof verifies end to end', async () => {
    const storage = createMemoryStorage()
    const r = await appendEntryDigest(storage, entryDigest('entry 0'))
    expect(r.leafIndex).toBe(0)
    expect(r.head.treeSize).toBe(1)
    expect(verifySignedTreeHead(r.head.sth, logIdentity().publicKeyMultibase)).toBe(true)

    await appendEntryDigest(storage, entryDigest('entry 1'))
    const r2 = await appendEntryDigest(storage, entryDigest('entry 2'))
    expect(r2.head.treeSize).toBe(3)
    expect(r2.head.sth.previousRootHash).toBeDefined()

    const proof = await proofForLeaf(storage, 1)
    expect(proof?.treeSize).toBe(3)
    const leaf = leafHash(decodeMultihash(entryDigest('entry 1')))
    expect(verifyInclusion(leaf, 1, 3, proof!.inclusionProof.map(decodeMultihash), decodeMultihash(proof!.rootHash))).toBe(true)
    expect(JSON.parse(proof!.signedTreeHead)).toMatchObject({ treeSize: 3, rootHash: proof!.rootHash })
    expect(proof!.timestampedAt).toBeNull()
  })

  it('the same digest appended twice is one leaf, and the head is not re-signed for the same size', async () => {
    const storage = createMemoryStorage()
    const a = await appendEntryDigest(storage, entryDigest('same'))
    const b = await appendEntryDigest(storage, entryDigest('same'))
    expect(b.leafIndex).toBe(a.leafIndex)
    expect(b.head.sthJson).toBe(a.head.sthJson)
    expect(await storage.log.size()).toBe(1)
  })

  it('refuses a digest that is not a multihash', async () => {
    await expect(appendEntryDigest(createMemoryStorage(), 'sha256:abcd')).rejects.toThrow(/multihash/)
  })

  it('proofForLeaf is null for an unknown leaf and emitTreeHead refuses an empty log', async () => {
    const storage = createMemoryStorage()
    expect(await proofForLeaf(storage, 0)).toBeNull()
    await expect(emitTreeHead(storage)).rejects.toThrow(/empty/)
  })
})

describe('anchoring', () => {
  it('gets a token from EVERY authority for the newest head, binds them, archives a chain, and the proof carries them', async () => {
    const storage = createMemoryStorage()
    await appendEntryDigest(storage, entryDigest('a'))
    const { fetchImpl, calls } = fakeTsa()
    const r = await anchorLatest(storage, { force: true, fetchImpl, authorities: AUTHORITIES })
    expect(r.results.map((x) => `${x.tsa}:${x.ok}`)).toEqual(['alpha:true', 'beta:true'])
    expect(calls.filter((c) => c.endsWith('/tsr'))).toHaveLength(2)

    const proof = await proofForLeaf(storage, 0)
    expect(Object.keys(proof!.timestamps).sort()).toEqual(['sth-1-alpha.tsr.b64', 'sth-1-beta.tsr.b64'])
    expect(Object.keys(proof!.chains)).toEqual(['alpha-chain.pem'])
    expect(proof!.timestampedAt).toBe('2026-09-15T13:00:00Z')
    const sth = JSON.parse(proof!.signedTreeHead) as SignedTreeHead
    for (const token of Object.values(proof!.timestamps)) {
      expect(verifyTimestampBinding(token, sth).valid).toBe(true)
    }
  })

  it('is idempotent, and one authority failing does not stop the other', async () => {
    const storage = createMemoryStorage()
    await appendEntryDigest(storage, entryDigest('a'))
    const failing = fakeTsa({ fail: new Set(['beta.test']) })
    const first = await anchorLatest(storage, { force: true, fetchImpl: failing.fetchImpl, authorities: AUTHORITIES })
    expect(first.results).toEqual([
      { tsa: 'alpha', ok: true, genTime: '2026-09-15T13:00:00Z' },
      { tsa: 'beta', ok: false, error: expect.stringMatching(/HTTP 503/) }
    ])
    // Next run asks only the one that is missing.
    const healthy = fakeTsa()
    const second = await anchorLatest(storage, { force: true, fetchImpl: healthy.fetchImpl, authorities: AUTHORITIES })
    expect(second.results.map((x) => x.tsa)).toEqual(['beta'])
    const third = await anchorLatest(storage, { force: true, fetchImpl: healthy.fetchImpl, authorities: AUTHORITIES })
    expect(third.skipped).toBe('already anchored')
  })

  it('without force, waits an hour between anchorings — the batching is a privacy control', async () => {
    const storage = createMemoryStorage()
    await appendEntryDigest(storage, entryDigest('a'))
    const { fetchImpl, calls } = fakeTsa()
    const t0 = new Date('2026-09-15T13:00:00Z')
    expect((await anchorLatest(storage, { now: t0, fetchImpl, authorities: AUTHORITIES })).results).toHaveLength(2)
    await appendEntryDigest(storage, entryDigest('b'))
    const soon = await anchorLatest(storage, { now: new Date(t0.getTime() + ANCHOR_INTERVAL_MS / 2), fetchImpl, authorities: AUTHORITIES })
    expect(soon.skipped).toBe('rate limited')
    const later = await anchorLatest(storage, { now: new Date(t0.getTime() + ANCHOR_INTERVAL_MS + 1), fetchImpl, authorities: AUTHORITIES })
    expect(later.results).toHaveLength(2)
    expect(calls.filter((c) => c.endsWith('/tsr'))).toHaveLength(4)
    // A leaf appended after the first anchoring gets a proof against the NEWER, anchored head.
    expect((await proofForLeaf(storage, 1))?.treeSize).toBe(2)
  })

  it('reports an empty log and no authorities honestly', async () => {
    const storage = createMemoryStorage()
    expect((await anchorLatest(storage, { force: true })).skipped).toBe('empty log')
    await appendEntryDigest(storage, entryDigest('a'))
    expect((await anchorLatest(storage, { force: true, authorities: [] })).skipped).toBe('no authorities configured')
  })
})

describe('the TSA client', () => {
  const imprint = hash(new TextEncoder().encode('imprint'))

  it('refuses a reply whose imprint is not the one requested', async () => {
    const fetchImpl = (async () => new Response(asBody(fakeReply(
      // A request for a DIFFERENT imprint, so the reply's imprint will not match ours.
      Uint8Array.from([...new Array(24).fill(0), ...hash(new TextEncoder().encode('other')), 0x02, 0x01, 0x01]), '20260915130000Z')), { status: 200 })) as unknown as typeof fetch
    await expect(requestTimestamp(AUTHORITIES[1]!, imprint, { fetchImpl })).rejects.toThrow(/does not match what was requested/)
  })

  it('refuses a rejection, and surfaces the authority in the error', async () => {
    const rejected = seq(seq(tlv(0x02, Uint8Array.of(2))))
    const fetchImpl = (async () => new Response(asBody(rejected), { status: 200 })) as unknown as typeof fetch
    await expect(requestTimestamp(AUTHORITIES[1]!, imprint, { fetchImpl })).rejects.toThrow(TimestampAuthorityError)
    await expect(requestTimestamp(AUTHORITIES[1]!, imprint, { fetchImpl })).rejects.toThrow(/beta: status rejection/)
  })

  it('labels authorities by operator and reads them from the environment', () => {
    expect(labelFor('freetsa.org')).toBe('freetsa')
    expect(labelFor('timestamp.digicert.com')).toBe('digicert')
    expect(labelFor('timestamp.sectigo.com')).toBe('sectigo')
    expect(labelFor('tsa.example.co.uk')).toBe('example')
    const auth = configuredAuthorities({ TSA_PRIMARY_URL: 'https://freetsa.org/tsr', TSA_PRIMARY_CA_URL: 'https://freetsa.org/files/cacert.pem', TSA_SECONDARY_URL: 'https://timestamp.digicert.com' })
    expect(auth).toEqual([
      { tsa: 'freetsa', url: 'https://freetsa.org/tsr', caUrl: 'https://freetsa.org/files/cacert.pem' },
      { tsa: 'digicert', url: 'https://timestamp.digicert.com' }
    ])
    expect(configuredAuthorities({})).toEqual([])
  })
})
