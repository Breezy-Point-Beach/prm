/**
 * The offline guarantee.
 *
 * These tests do not merely assume no network access — they SABOTAGE the network first. fetch,
 * XMLHttpRequest, WebSocket, http.request and https.request are all replaced with functions that
 * throw. If any code path in @prm/verify reaches for the network, these tests fail loudly.
 *
 * This is the executable form of the project's central claim.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import http from 'node:http'
import https from 'node:https'

const SPEC = resolve(import.meta.dirname, '../../../spec')
const load = (p: string) => JSON.parse(readFileSync(resolve(SPEC, p), 'utf8'))

const BOOM = () => { throw new Error('NETWORK ACCESS ATTEMPTED — @prm/verify must be fully offline') }

const saved: Record<string, unknown> = {}

beforeAll(() => {
  saved.fetch = globalThis.fetch
  saved.httpRequest = http.request
  saved.httpGet = http.get
  saved.httpsRequest = https.request
  saved.httpsGet = https.get
  // @ts-expect-error deliberately breaking the global
  globalThis.fetch = BOOM
  // @ts-expect-error deliberately breaking the global
  globalThis.XMLHttpRequest = BOOM
  // @ts-expect-error deliberately breaking the global
  globalThis.WebSocket = BOOM
  http.request = BOOM as never
  http.get = BOOM as never
  https.request = BOOM as never
  https.get = BOOM as never
})

afterAll(() => {
  globalThis.fetch = saved.fetch as typeof fetch
  http.request = saved.httpRequest as typeof http.request
  http.get = saved.httpGet as typeof http.get
  https.request = saved.httpsRequest as typeof https.request
  https.get = saved.httpsGet as typeof https.get
})

describe('verification works with the network sabotaged', () => {
  it('verifies a policy using only the document and its key event log', async () => {
    const { verifyPolicy } = await import('../src/index.js')
    const r = verifyPolicy(load('examples/policies/policy-v1.json'), {
      keyEventLog: [load('examples/key-events/genesis.json')],
      now: new Date('2026-10-01T00:00:00Z')
    })
    expect(r.summary).not.toBe('failed')
    expect(r.integrity).toBe('valid')
    expect(r.signature).toBe('valid')
    expect(r.issuer).toBe('authorized')
  })

  it('reports currency and revocation as UNKNOWN rather than guessing', async () => {
    // The distinction matters: "could not check" must never be reported as "current".
    const { verifyPolicy } = await import('../src/index.js')
    const r = verifyPolicy(load('examples/policies/policy-v1.json'), {
      keyEventLog: [load('examples/key-events/genesis.json')]
    })
    expect(r.currency).toBe('unknown')
    expect(r.revocation).toBe('unknown')
    expect(r.summary).toBe('verified-with-warnings')
    expect(r.warnings.join(' ')).toMatch(/offline/)
  })

  it('rejects a malformed proof bundle offline, without reaching for the network', async () => {
    // Full bundle round-trip coverage is in @prm/notice; what matters here is that the bundle path
    // never touches the network even on the failure branches.
    const { verifyProofBundle } = await import('../src/index.js')
    expect(verifyProofBundle({ prmproof: 2, manifest: null, artifacts: {} }).valid).toBe(false)
    expect(verifyProofBundle({ prmproof: 1 }).conclusion).toMatch(/version 1/)
  })

  it('verifies the key event log and inclusion proofs offline', async () => {
    const { verifyKeyEventLog, verifyLogInclusion, verifySignedTreeHead } = await import('../src/index.js')
    const kel = verifyKeyEventLog([
      load('examples/key-events/genesis.json'),
      load('examples/key-events/rotation-seq1.json')
    ])
    expect(kel.errors).toEqual([])
    expect(kel.valid).toBe(true)

    const entries = load('examples/ledger/entries.json')
    for (const e of entries.filter((x: { logInclusion?: unknown }) => x.logInclusion)) {
      expect(verifyLogInclusion(e, load('examples/ledger/signed-tree-head.json')).errors).toEqual([])
    }
    expect(verifySignedTreeHead(
      load('examples/ledger/signed-tree-head.json'),
      load('test-vectors/vectors.json').merkleLog.logPublicKeyMultibase
    )).toBe(true)
  })

  it('the sabotage is real (control test)', () => {
    expect(() => (globalThis.fetch as unknown as () => void)()).toThrow(/NETWORK ACCESS ATTEMPTED/)
    expect(() => https.get('https://example.com')).toThrow(/NETWORK ACCESS ATTEMPTED/)
  })
})
