import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { encodeMultihash, encodeOid, OID, tokenToBase64, hash } from '@prm/crypto'
import { verifyTimestampBinding } from '../src/index.js'

/**
 * Timestamp binding — the structural link between a token and a tree head.
 *
 * A real token cannot be minted offline, so the positive path uses a token-SHAPED structure: a CMS
 * ContentInfo whose TSTInfo carries the imprint under test and whose SignedData has no signers.
 * That is enough to exercise binding, which is deliberately independent of the signature. The real
 * exchange with freetsa.org lives in @prm/crypto's fixture and is used here for the negative path.
 */
const FX = JSON.parse(readFileSync(resolve(import.meta.dirname, '../../crypto/test/fixtures/rfc3161-freetsa.json'), 'utf8'))

// Minimal DER for the test double. Mirrors the encoder in @prm/crypto without depending on internals.
const len = (n: number): number[] => n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]
const tlv = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = new Uint8Array(parts.reduce((s, p) => s + p.length, 0))
  let o = 0; for (const p of parts) { body.set(p, o); o += p.length }
  return Uint8Array.from([tag, ...len(body.length), ...body])
}
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p)
const set = (...p: Uint8Array[]) => tlv(0x31, ...p)
const int = (n: number) => tlv(0x02, Uint8Array.of(n))
const oct = (b: Uint8Array) => tlv(0x04, b)
const nul = () => tlv(0x05)
const gt = (s: string) => tlv(0x18, new TextEncoder().encode(s))
const ctx0 = (...p: Uint8Array[]) => tlv(0xa0, ...p)

/** An unsigned TimeStampResp whose TSTInfo imprints `imprint` at `genTime`. */
export function fakeTimestampResponse (imprint: Uint8Array, genTime = '20260913053102Z'): Uint8Array {
  const tstInfo = seq(
    int(1), encodeOid('1.2.3.4.1'),
    seq(seq(encodeOid(OID.sha256), nul()), oct(imprint)),
    int(0x42), gt(genTime)
  )
  const signedData = seq(int(3), set(), seq(encodeOid(OID.tstInfo), ctx0(oct(tstInfo))), set())
  return seq(seq(int(0)), seq(encodeOid(OID.signedData), ctx0(signedData)))
}

const rootBytes = hash(new TextEncoder().encode('a tree head'))
const sth = { rootHash: encodeMultihash(rootBytes), treeSize: 7 }
const imprintFor = (root: Uint8Array) => hash(root)

describe('verifyTimestampBinding', () => {
  it('binds a token whose imprint is SHA-256 of the root bytes', () => {
    const b = verifyTimestampBinding(tokenToBase64(fakeTimestampResponse(imprintFor(rootBytes))), sth)
    expect(b.errors).toEqual([])
    expect(b.valid).toBe(true)
    expect(b.genTime).toBe('2026-09-13T05:31:02Z')
    expect(b.serialNumberHex).toBe('42')
    expect(b.policyOid).toBe('1.2.3.4.1')
  })

  it('REFUSES a token issued for a different root', () => {
    const other = hash(new TextEncoder().encode('another tree head'))
    const b = verifyTimestampBinding(tokenToBase64(fakeTimestampResponse(imprintFor(other))), sth)
    expect(b.valid).toBe(false)
    expect(b.errors[0]).toMatch(/issued for something else/)
    // The time is still reported, so a reader can see what the stray token claims.
    expect(b.genTime).toBe('2026-09-13T05:31:02Z')
  })

  it('REFUSES a token whose imprint is over the multihash STRING rather than the root bytes', () => {
    const wrong = hash(new TextEncoder().encode(sth.rootHash))
    expect(verifyTimestampBinding(tokenToBase64(fakeTimestampResponse(wrong)), sth).valid).toBe(false)
  })

  it('a REAL freetsa.org token does not bind to an unrelated tree head, and is still parsed', () => {
    const b = verifyTimestampBinding(FX.responseDerBase64, sth)
    expect(b.valid).toBe(false)
    expect(b.genTime).toBe(FX.expected.genTime)
    expect(b.tsaName).toBe('www.freetsa.org')
    expect(b.certificateCount).toBe(2)
  })

  it('reports unreadable input instead of throwing', () => {
    expect(verifyTimestampBinding('not base64!!', sth).errors[0]).toMatch(/not a readable/)
    expect(verifyTimestampBinding(tokenToBase64(new Uint8Array([0x30, 0x00])), sth).valid).toBe(false)
  })

  it('refuses a tree head whose root is not a digest', () => {
    const b = verifyTimestampBinding(tokenToBase64(fakeTimestampResponse(imprintFor(rootBytes))), { rootHash: 'uEiA' })
    expect(b.valid).toBe(false)
  })
})
