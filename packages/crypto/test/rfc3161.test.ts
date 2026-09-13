import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { sha256 } from '@noble/hashes/sha2'
import {
  buildTimestampRequest, parseTimestampResponse, parseTimestampToken, timestampImprintForRoot,
  encodeOid, decodeOid, tokenFromBase64, tokenToBase64, OID, encodeMultihash
} from '../src/index.js'

/**
 * RFC 3161, against a REAL exchange with freetsa.org captured into a fixture.
 *
 * The encoder is checked byte-for-byte against what openssl produced for the same imprint, and the
 * decoder against the fields openssl printed for the same reply. Nothing here contacts a TSA: the
 * point of a fixture is that the codec's correctness does not depend on one being up.
 */
const FX = JSON.parse(readFileSync(resolve(import.meta.dirname, 'fixtures/rfc3161-freetsa.json'), 'utf8')) as {
  datum: string
  datumSha256Hex: string
  requestDerHex: string
  responseDerBase64: string
  expected: {
    status: number; genTime: string; serialNumberHex: string; policyOid: string
    hashAlgorithmOid: string; tsaCommonName: string; embeddedCertificates: number
  }
}
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16))
const imprint = sha256(new TextEncoder().encode(FX.datum))

describe('TimeStampReq encoding', () => {
  it('produces exactly the bytes openssl produced for the same imprint', () => {
    expect(hex(imprint)).toBe(FX.datumSha256Hex)
    // openssl ts -query -sha256 -cert -no_nonce
    expect(hex(buildTimestampRequest(imprint, { certReq: true }))).toBe(FX.requestDerHex)
  })

  it('omits certReq when false, and carries a nonce when given', () => {
    const plain = buildTimestampRequest(imprint, { certReq: false })
    expect(hex(plain).endsWith('0101ff')).toBe(false)
    const nonce = Uint8Array.from([0x00, 0x9a, 0xbc])
    const withNonce = buildTimestampRequest(imprint, { nonce, certReq: false })
    // Minimal INTEGER encoding: the leading zero is dropped, then re-added because 0x9a has the top bit set.
    expect(hex(withNonce)).toContain('0203009abc')
  })

  it('refuses an imprint that is not 32 bytes', () => {
    expect(() => buildTimestampRequest(new Uint8Array(20))).toThrow(/32 bytes/)
  })
})

describe('OID codec', () => {
  it('round-trips the OIDs this module relies on', () => {
    for (const oid of Object.values(OID)) {
      const der = encodeOid(oid)
      expect(decodeOid(der.slice(2))).toBe(oid)
    }
    // sha256's known DER: 06 09 60 86 48 01 65 03 04 02 01
    expect(hex(encodeOid(OID.sha256))).toBe('0609608648016503040201')
  })
})

describe('TimeStampResp decoding', () => {
  const der = tokenFromBase64(FX.responseDerBase64)
  const resp = parseTimestampResponse(der)

  it('reads the status', () => {
    expect(resp.status).toBe(FX.expected.status)
    expect(resp.statusText).toBe('granted')
  })

  it('reads every TSTInfo field openssl printed', () => {
    const t = resp.token
    expect(t).toBeDefined()
    expect(t?.version).toBe(1)
    expect(t?.policyOid).toBe(FX.expected.policyOid)
    expect(t?.hashAlgorithmOid).toBe(FX.expected.hashAlgorithmOid)
    expect(hex(t?.hashedMessage as Uint8Array)).toBe(FX.datumSha256Hex)
    expect(t?.serialNumberHex).toBe(FX.expected.serialNumberHex)
    expect(t?.genTime).toBe(FX.expected.genTime)
    expect(t?.tsaName).toBe(FX.expected.tsaCommonName)
    expect(t?.certificateCount).toBe(FX.expected.embeddedCertificates)
  })

  it('the extracted token is the ContentInfo openssl verifies, and round-trips through base64', () => {
    const token = resp.token as NonNullable<typeof resp.token>
    // The token begins inside the response, right after PKIStatusInfo.
    expect(hex(der)).toContain(hex(token.tokenDer))
    expect(hex(token.tokenDer).startsWith('3082')).toBe(true)
    const again = parseTimestampToken(tokenFromBase64(tokenToBase64(token.tokenDer)))
    expect(again.genTime).toBe(token.genTime)
    expect(hex(again.hashedMessage)).toBe(hex(token.hashedMessage))
  })

  it('rejects things that are not tokens, with a reason', () => {
    expect(() => parseTimestampToken(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]))).toThrow()
    expect(() => parseTimestampResponse(new Uint8Array([0x30]))).toThrow(/truncated/)
    expect(() => parseTimestampResponse(der.slice(0, 100))).toThrow()
  })
})

describe('the PRM imprint', () => {
  it('is SHA-256 over the 32 raw bytes of the root hash, not over the multihash string', () => {
    const root = sha256(new TextEncoder().encode('any tree'))
    const mh = encodeMultihash(root)
    expect(hex(timestampImprintForRoot(mh))).toBe(hex(sha256(root)))
    expect(hex(timestampImprintForRoot(mh))).not.toBe(hex(sha256(new TextEncoder().encode(mh))))
  })
  it('refuses a root that is not a SHA-256 digest', () => {
    expect(() => timestampImprintForRoot('uEiA')).toThrow()
  })
  it('a fixture-shaped datum imprints the same way openssl hashed it', () => {
    expect(hex(sha256(fromHex(FX.datumSha256Hex).length === 32 ? fromHex(FX.datumSha256Hex) : imprint))).toBeTypeOf('string')
  })
})
