import { sha256 } from '@noble/hashes/sha2'
import { base64 } from '@scure/base'
import { decodeMultihash } from './encoding.js'

/**
 * RFC 3161 time-stamp requests and responses — docs/08, spec/NORMATIVE.md §9.
 *
 * A deliberately small DER codec: enough to BUILD a TimeStampReq and to READ the fields of a
 * TimeStampResp that a verifier needs to bind a token to a tree head — status, the message imprint,
 * the time, the serial, the policy, the TSA's name. It does not validate the CMS signature or the
 * certificate chain. That is a trust decision (which TSA roots do you accept?) and belongs with the
 * person doing the checking, using `openssl ts -verify` and the chain archived beside the token.
 *
 * What this DOES establish, offline and with no trust decision: that a given token is a token for a
 * given imprint. A bundle can then carry a token that provably refers to its own tree head, rather
 * than any token at all.
 *
 * Reference: RFC 3161 §2.4 (TimeStampReq, TimeStampResp), RFC 5652 (CMS SignedData).
 */

// ---- OIDs -------------------------------------------------------------------

export const OID = {
  sha256: '2.16.840.1.101.3.4.2.1',
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  commonName: '2.5.4.3'
} as const

export const PKI_STATUS = {
  0: 'granted',
  1: 'grantedWithMods',
  2: 'rejection',
  3: 'waiting',
  4: 'revocationWarning',
  5: 'revocationNotification'
} as const

// ---- DER encoding -----------------------------------------------------------

const TAG = {
  BOOLEAN: 0x01, INTEGER: 0x02, OCTET_STRING: 0x04, NULL: 0x05, OID: 0x06,
  UTF8: 0x0c, PRINTABLE: 0x13, IA5: 0x16, GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30, SET: 0x31
} as const

function encodeLength (n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.of(n)
  const bytes: number[] = []
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff)
  return Uint8Array.of(0x80 | bytes.length, ...bytes)
}

function tlv (tag: number, content: Uint8Array): Uint8Array {
  const len = encodeLength(content.length)
  const out = new Uint8Array(1 + len.length + content.length)
  out[0] = tag
  out.set(len, 1)
  out.set(content, 1 + len.length)
  return out
}

function concat (...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

export function encodeOid (oid: string): Uint8Array {
  const parts = oid.split('.').map(Number)
  if (parts.length < 2 || parts.some((p) => !Number.isInteger(p) || p < 0)) {
    throw new Error(`invalid OID ${oid}`)
  }
  const body: number[] = [(parts[0] as number) * 40 + (parts[1] as number)]
  for (const p of parts.slice(2)) {
    const stack: number[] = []
    let v = p
    do { stack.unshift(v & 0x7f); v = Math.floor(v / 128) } while (v > 0)
    for (let i = 0; i < stack.length - 1; i++) stack[i] = (stack[i] as number) | 0x80
    body.push(...stack)
  }
  return tlv(TAG.OID, Uint8Array.from(body))
}

/** Unsigned big-endian integer, minimal two's-complement encoding. */
function encodeUnsignedInteger (bytes: Uint8Array): Uint8Array {
  let i = 0
  while (i < bytes.length - 1 && bytes[i] === 0) i++
  let body: Uint8Array = bytes.slice(i)
  if ((body[0] as number) & 0x80) body = concat(Uint8Array.of(0), body)
  return tlv(TAG.INTEGER, body)
}

const derSequence = (...items: Uint8Array[]): Uint8Array => tlv(TAG.SEQUENCE, concat(...items))
const derNull = (): Uint8Array => tlv(TAG.NULL, new Uint8Array(0))
const derOctetString = (b: Uint8Array): Uint8Array => tlv(TAG.OCTET_STRING, b)
const derBoolean = (v: boolean): Uint8Array => tlv(TAG.BOOLEAN, Uint8Array.of(v ? 0xff : 0x00))
const derSmallInteger = (n: number): Uint8Array => encodeUnsignedInteger(Uint8Array.of(n))

export interface TimestampRequestOptions {
  /** Random bytes echoed back by the TSA; lets a caller match responses to requests. */
  nonce?: Uint8Array
  /** Ask the TSA to include its signing certificate. Default true: the token must be self-contained. */
  certReq?: boolean
}

/**
 * Build a TimeStampReq for a SHA-256 imprint.
 *
 *   TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,      -- SEQUENCE { AlgorithmIdentifier, OCTET STRING }
 *     reqPolicy      TSAPolicyId OPTIONAL, -- omitted; the TSA chooses
 *     nonce          INTEGER OPTIONAL,
 *     certReq        BOOLEAN DEFAULT FALSE }
 *
 * Byte-for-byte what `openssl ts -query -sha256 -cert -no_nonce` produces for the same imprint,
 * which is how the encoder is tested.
 */
export function buildTimestampRequest (imprint: Uint8Array, opts: TimestampRequestOptions = {}): Uint8Array {
  if (imprint.length !== 32) throw new Error(`a SHA-256 imprint is 32 bytes, got ${imprint.length}`)
  const certReq = opts.certReq ?? true
  const messageImprint = derSequence(derSequence(encodeOid(OID.sha256), derNull()), derOctetString(imprint))
  return derSequence(
    derSmallInteger(1),
    messageImprint,
    ...(opts.nonce ? [encodeUnsignedInteger(opts.nonce)] : []),
    ...(certReq ? [derBoolean(true)] : [])
  )
}

/**
 * The imprint PRM timestamps: SHA-256 over the 32 raw bytes of a tree head's root hash
 * (spec/NORMATIVE.md §9). The root already commits to every leaf, so one token covers the tree.
 */
export function timestampImprintForRoot (rootHashMultihash: string): Uint8Array {
  const root = decodeMultihash(rootHashMultihash)
  if (root.length !== 32) throw new Error('root hash is not a 32-byte digest')
  return sha256(root)
}

// ---- DER decoding -----------------------------------------------------------

interface Tlv {
  tag: number
  /** Offset of the tag byte — where the whole TLV begins. */
  offset: number
  /** Offset of the first content byte. */
  start: number
  /** Offset one past the last content byte. */
  end: number
  constructed: boolean
}

function readTlv (b: Uint8Array, offset: number): Tlv {
  if (offset + 2 > b.length) throw new Error('truncated DER')
  const tag = b[offset] as number
  let len = b[offset + 1] as number
  let p = offset + 2
  if (len & 0x80) {
    const n = len & 0x7f
    if (n === 0 || n > 4) throw new Error('unsupported DER length')
    len = 0
    for (let i = 0; i < n; i++) len = (len << 8) | (b[p++] as number)
  }
  if (p + len > b.length) throw new Error('truncated DER')
  return { tag, offset, start: p, end: p + len, constructed: (tag & 0x20) !== 0 }
}

/** The immediate children of a constructed value. */
function children (b: Uint8Array, node: Tlv): Tlv[] {
  const out: Tlv[] = []
  let p = node.start
  while (p < node.end) {
    const c = readTlv(b, p)
    out.push(c)
    p = c.end
  }
  return out
}

function slice (b: Uint8Array, t: Tlv): Uint8Array { return b.slice(t.start, t.end) }

export function decodeOid (content: Uint8Array): string {
  if (content.length === 0) throw new Error('empty OID')
  const first = content[0] as number
  const parts = [Math.floor(first / 40), first % 40]
  // 2.x arcs above 2.39 are encoded with first >= 80; the split above handles the common cases.
  if (first >= 80) { parts[0] = 2; parts[1] = first - 80 }
  let v = 0
  for (let i = 1; i < content.length; i++) {
    const c = content[i] as number
    v = v * 128 + (c & 0x7f)
    if ((c & 0x80) === 0) { parts.push(v); v = 0 }
  }
  return parts.join('.')
}

function bytesToHex (b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

/** GeneralizedTime "YYYYMMDDHHMMSS[.fff]Z" -> RFC 3339 second precision, the PRM instant form. */
function decodeGeneralizedTime (content: Uint8Array): string {
  const s = new TextDecoder().decode(content)
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s)
  if (!m) throw new Error(`unsupported GeneralizedTime ${s}`)
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`
}

function expectTag (t: Tlv, tag: number, what: string): Tlv {
  if (t.tag !== tag) throw new Error(`expected ${what} (tag 0x${tag.toString(16)}), got 0x${t.tag.toString(16)}`)
  return t
}

export interface TimestampToken {
  /** DER of the ContentInfo — the TimeStampToken itself, what `openssl ts -verify -in` reads. */
  tokenDer: Uint8Array
  version: number
  policyOid: string
  hashAlgorithmOid: string
  /** The imprint the TSA signed. */
  hashedMessage: Uint8Array
  serialNumberHex: string
  /** RFC 3339, second precision. */
  genTime: string
  nonceHex?: string
  /** The TSA's commonName, when it identified itself by directory name. */
  tsaName?: string
  /** Certificates embedded in the token. A self-contained token carries its signer. */
  certificateCount: number
}

export interface TimestampResponse {
  status: number
  statusText: string
  statusString?: string
  token?: TimestampToken
}

/** Parse a TimeStampResp (the bytes a TSA returns for `application/timestamp-query`). */
export function parseTimestampResponse (der: Uint8Array): TimestampResponse {
  const root = expectTag(readTlv(der, 0), TAG.SEQUENCE, 'TimeStampResp')
  const [statusInfo, contentInfo] = children(der, root)
  if (!statusInfo) throw new Error('TimeStampResp is empty')

  const statusFields = children(der, expectTag(statusInfo, TAG.SEQUENCE, 'PKIStatusInfo'))
  const statusTlv = expectTag(statusFields[0] as Tlv, TAG.INTEGER, 'PKIStatus')
  const status = Number(slice(der, statusTlv)[0] ?? 255)
  const out: TimestampResponse = {
    status,
    statusText: PKI_STATUS[status as keyof typeof PKI_STATUS] ?? `unknown(${status})`
  }
  // PKIFreeText, if present, is a SEQUENCE OF UTF8String — the TSA's human-readable reason.
  const freeText = statusFields[1]
  if (freeText && freeText.tag === TAG.SEQUENCE) {
    const strings = children(der, freeText).filter((c) => c.tag === TAG.UTF8)
    if (strings.length) out.statusString = strings.map((c) => new TextDecoder().decode(slice(der, c))).join(' ')
  }

  if (contentInfo) out.token = parseTimestampToken(der.slice(contentInfo.offset, contentInfo.end))
  return out
}

/**
 * Parse a TimeStampToken — a CMS ContentInfo wrapping SignedData whose encapsulated content is a
 * TSTInfo. Accepts either the token on its own or (via parseTimestampResponse) as part of a reply.
 */
export function parseTimestampToken (der: Uint8Array): TimestampToken {
  const ci = expectTag(readTlv(der, 0), TAG.SEQUENCE, 'ContentInfo')
  const [contentType, explicit] = children(der, ci)
  if (!contentType || decodeOid(slice(der, expectTag(contentType, TAG.OID, 'contentType'))) !== OID.signedData) {
    throw new Error('token is not CMS SignedData')
  }
  if (!explicit || explicit.tag !== 0xa0) throw new Error('SignedData is missing')
  const signedData = expectTag(readTlv(der, explicit.start), TAG.SEQUENCE, 'SignedData')
  const sd = children(der, signedData)
  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo SEQUENCE,
  //                           certificates [0] IMPLICIT OPTIONAL, crls [1] OPTIONAL, signerInfos SET }
  const encap = sd[2]
  if (!encap) throw new Error('SignedData is missing encapContentInfo')
  const [eType, eContentExplicit] = children(der, expectTag(encap, TAG.SEQUENCE, 'EncapsulatedContentInfo'))
  if (!eType || decodeOid(slice(der, eType)) !== OID.tstInfo) throw new Error('encapsulated content is not TSTInfo')
  if (!eContentExplicit || eContentExplicit.tag !== 0xa0) throw new Error('TSTInfo content is missing')
  const eContent = expectTag(readTlv(der, eContentExplicit.start), TAG.OCTET_STRING, 'eContent')
  const tstInfoDer = slice(der, eContent)

  let certificateCount = 0
  for (const t of sd.slice(3)) {
    if (t.tag === 0xa0) certificateCount = children(der, t).filter((c) => c.tag === TAG.SEQUENCE).length
  }

  return { tokenDer: der, ...parseTstInfo(tstInfoDer), certificateCount }
}

function parseTstInfo (b: Uint8Array): Omit<TimestampToken, 'tokenDer' | 'certificateCount'> {
  // TSTInfo ::= SEQUENCE { version INTEGER, policy OID, messageImprint, serialNumber INTEGER,
  //   genTime GeneralizedTime, accuracy OPTIONAL, ordering BOOLEAN DEFAULT FALSE, nonce INTEGER
  //   OPTIONAL, tsa [0] GeneralName OPTIONAL, extensions [1] OPTIONAL }
  const root = expectTag(readTlv(b, 0), TAG.SEQUENCE, 'TSTInfo')
  const f = children(b, root)
  const version = Number(slice(b, expectTag(f[0] as Tlv, TAG.INTEGER, 'version'))[0])
  const policyOid = decodeOid(slice(b, expectTag(f[1] as Tlv, TAG.OID, 'policy')))
  const [algId, hashed] = children(b, expectTag(f[2] as Tlv, TAG.SEQUENCE, 'MessageImprint'))
  const hashAlgorithmOid = decodeOid(slice(b, expectTag(children(b, algId as Tlv)[0] as Tlv, TAG.OID, 'hashAlgorithm')))
  const hashedMessage = slice(b, expectTag(hashed as Tlv, TAG.OCTET_STRING, 'hashedMessage'))
  const serialNumberHex = bytesToHex(slice(b, expectTag(f[3] as Tlv, TAG.INTEGER, 'serialNumber'))).replace(/^00(?=..)/, '')
  const genTime = decodeGeneralizedTime(slice(b, expectTag(f[4] as Tlv, TAG.GENERALIZED_TIME, 'genTime')))

  let nonceHex: string | undefined
  let tsaName: string | undefined
  for (const t of f.slice(5)) {
    if (t.tag === TAG.INTEGER) nonceHex = bytesToHex(slice(b, t))
    if (t.tag === 0xa0) tsaName = commonNameIn(b, t)
  }
  return {
    version, policyOid, hashAlgorithmOid, hashedMessage, serialNumberHex, genTime,
    ...(nonceHex ? { nonceHex } : {}),
    ...(tsaName ? { tsaName } : {})
  }
}

/** Best-effort commonName from a GeneralName that is a directoryName ([4] Name). */
function commonNameIn (b: Uint8Array, generalName: Tlv): string | undefined {
  try {
    const inner = readTlv(b, generalName.start)
    if (inner.tag !== 0xa4) return undefined
    const name = expectTag(readTlv(b, inner.start), TAG.SEQUENCE, 'Name')
    for (const rdn of children(b, name)) {
      for (const atv of children(b, rdn)) {
        const [type, value] = children(b, atv)
        if (type && value && decodeOid(slice(b, type)) === OID.commonName) {
          return new TextDecoder().decode(slice(b, value))
        }
      }
    }
  } catch { /* a token without a readable TSA name is still a token */ }
  return undefined
}

// ---- convenience ------------------------------------------------------------

export const tokenToBase64 = (der: Uint8Array): string => base64.encode(der)
export const tokenFromBase64 = (b64: string): Uint8Array => base64.decode(b64.replace(/\s+/g, ''))
