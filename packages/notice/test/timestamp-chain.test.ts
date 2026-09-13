import { describe, expect, it } from 'vitest'
import { alprRules, alprHumanReadable, composeHumanReadable, PRM_CONTEXT } from '@prm/schema'
import type { LedgerEntry, Policy, SignedTreeHead } from '@prm/schema'
import {
  deriveAccountKeys, buildProof, digest, digestBytes, hash, leafHash, merkleRoot, inclusionProof,
  encodeMultihash, keyPairFromSeed, signBytes, signingMessage, jcsBytes, encodeSignature,
  policyChainId, policyId, encodeOid, OID, tokenToBase64, deriveAccountId
} from '@prm/crypto'
import { verifyProofBundle } from '@prm/verify'
import { buildProofBundle } from '../src/index.js'

/**
 * The evidentiary chain end to end: token -> root -> leaf -> ledger entry -> policy.
 *
 * Built here because this package can BOTH assemble a bundle and verify it. The token is a
 * token-shaped structure with the right imprint and no signature (a real one cannot be minted
 * offline); binding does not depend on the signature, and the instructions tell the reader how to
 * check that part with openssl.
 */
const NOW = '2026-09-15T12:00:00Z'
const seed = hash(new TextEncoder().encode('timestamp chain test seed'))
const keys = deriveAccountKeys(seed)
const logKey = keyPairFromSeed(hash(new TextEncoder().encode('test log key')))
const enc = new TextEncoder()

// ---- DER for the test double (mirrors @prm/crypto's encoder) ----
const len = (n: number): number[] => n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]
const tlv = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = new Uint8Array(parts.reduce((s, p) => s + p.length, 0)); let o = 0
  for (const p of parts) { body.set(p, o); o += p.length }
  return Uint8Array.from([tag, ...len(body.length), ...body])
}
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p)
const fakeToken = (imprint: Uint8Array, genTime: string) => {
  const tst = seq(tlv(0x02, Uint8Array.of(1)), encodeOid('1.2.3.4.1'),
    seq(seq(encodeOid(OID.sha256), tlv(0x05)), tlv(0x04, imprint)), tlv(0x02, Uint8Array.of(7)), tlv(0x18, enc.encode(genTime)))
  const sd = seq(tlv(0x02, Uint8Array.of(3)), tlv(0x31), seq(encodeOid(OID.tstInfo), tlv(0xa0, tlv(0x04, tst))), tlv(0x31))
  return tokenToBase64(seq(seq(tlv(0x02, Uint8Array.of(0))), seq(encodeOid(OID.signedData), tlv(0xa0, sd))))
}

function fixture () {
  const genesis = {
    type: 'prm/KeyEvent/v1', eventType: 'genesis', sequence: 0, previousEventHash: null, created: NOW,
    keys: [{ id: '#k0', alg: 'Ed25519', publicKeyMultibase: keys.signing.publicKeyMultibase, use: ['assertion', 'authentication'] }],
    nextKeyDigests: [keys.next.publicKeyDigest], recoveryKeyDigests: [keys.recovery.publicKeyDigest], threshold: 1, proof: [] as unknown[]
  }
  genesis.proof = [buildProof(genesis, { privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey, kind: 'keyEvent', created: NOW })]
  const accountId = deriveAccountId(genesis)

  const rules = alprRules({ state: 'CA' })
  const base = {
    '@context': [...PRM_CONTEXT], type: ['VerifiableCredential', 'PersonalDataPolicy'],
    policyChainId: 'urn:prm:chain:PLACEHOLDER', version: 1, previousPolicyHash: null,
    issuer: { id: accountId, did: keys.signing.did, keyEventHash: digest(genesis, 'keyEvent') },
    effectiveDate: NOW, jurisdictions: ['US-CA'], rules,
    requests: { deletionOnPurposeCompletion: true, doNotSellOrShare: true, globalPrivacyControl: true },
    humanReadable: { mediaType: 'text/markdown', language: 'en', text: composeHumanReadable(alprHumanReadable({ agency: 'Test PD', state: 'CA' }), rules) }
  }
  const unsigned = { ...base, policyChainId: policyChainId(base) }
  const proof = buildProof(unsigned, { privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey, kind: 'policy', created: NOW })
  const policy = { ...unsigned, id: policyId(unsigned), proof } as unknown as Policy
  const policyJson = JSON.stringify(policy, null, 2)
  const policyDigest = digest(policy, 'policy')

  // The user's ledger: a key.event then the policy.published entry, chained and signed.
  const entries: LedgerEntry[] = []
  let prev: string | null = null
  for (const [i, spec] of [
    { entryType: 'key.event', subjectHash: digest(genesis, 'keyEvent') },
    { entryType: 'policy.published', subjectHash: policyDigest }
  ].entries()) {
    const e = { type: 'prm/LedgerEntry/v1', accountId, sequence: i, previousEntryHash: prev, recorded: NOW, ...spec } as unknown as LedgerEntry
    e.proof = buildProof(e, { privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey, kind: 'ledgerEntry', created: NOW })
    prev = digest(e, 'ledgerEntry')
    entries.push(e)
  }
  // The log: opaque leaves, a signed head, inclusion proofs attached AFTER signing.
  const leaves = entries.map((e) => leafHash(digestBytes(e, 'ledgerEntry')))
  const root = merkleRoot(leaves)
  const body = { logId: 'prm-log-test', treeSize: leaves.length, rootHash: encodeMultihash(root), timestamp: NOW }
  const sth: SignedTreeHead = { ...body, signature: encodeSignature(signBytes(logKey.privateKey, signingMessage('PRM-STH-v1', hash(jcsBytes(body))))) }
  for (const [i, e] of entries.entries()) {
    e.logInclusion = { logId: sth.logId, leafIndex: i, treeSize: leaves.length, rootHash: sth.rootHash, inclusionProof: inclusionProof(leaves, i).map(encodeMultihash) }
  }
  const token = fakeToken(hash(root), '20260915130000Z')
  return { genesis, policy, policyJson, policyDigest, entries, sth, root, token }
}

function bundleWith (f: ReturnType<typeof fixture>, extra: Partial<Parameters<typeof buildProofBundle>[0]> = {}) {
  return buildProofBundle({
    policy: f.policy, policyJson: f.policyJson,
    keyEventLogJson: JSON.stringify([f.genesis], null, 2),
    ledgerJson: JSON.stringify(f.entries, null, 2),
    signedTreeHeadJson: JSON.stringify(f.sth, null, 2),
    timestamps: { 'sth-2-testtsa.tsr.b64': f.token },
    generatedAt: new Date(NOW),
    ...extra
  })
}
const verify = (b: unknown) => verifyProofBundle(b, { logPublicKeyMultibase: logKey.publicKeyMultibase, now: new Date('2026-10-01T00:00:00Z') })

describe('a bundle carrying the whole evidentiary chain', () => {
  it('reports the timestamp as PROVEN for the policy, with the TSA time', () => {
    const r = verify(bundleWith(fixture()))
    expect(r.errors).toEqual([])
    expect(r.checks.map((c) => `${c.ok ? 'ok' : 'XX'} ${c.name}`)).toEqual(expect.arrayContaining([
      'ok transparency log', 'ok log inclusion', 'ok timestamp'
    ]))
    expect(r.policy?.timestamp).toMatchObject({ proven: true, source: 'rfc3161', notLaterThan: '2026-09-15T13:00:00Z' })
    expect(r.warnings).not.toContain('no independent timestamp evidence was supplied')
    expect(r.warnings).not.toContain('no independent timestamp evidence is included in this bundle')
  })

  it('a token for a DIFFERENT tree head FAILS the bundle', () => {
    const f = fixture()
    const other = hash(new TextEncoder().encode('some other root'))
    const r = verify(bundleWith(f, { timestamps: { 'sth-2-testtsa.tsr.b64': fakeToken(hash(other), '20260915130000Z') } }))
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/issued for something else/)
    expect(r.policy?.timestamp.proven).toBe(false)
  })

  it('a token with no ledger entry tying the policy to the tree is NOT proof for the policy', () => {
    const f = fixture()
    const r = verify(bundleWith(f, { ledgerJson: undefined }))
    expect(r.valid).toBe(true)
    expect(r.policy?.timestamp.proven).toBe(false)
    expect(r.warnings.join(' ')).toMatch(/nothing ties this policy to that tree/)
  })

  it('a ledger whose policy.published entry names ANOTHER policy does not prove this one', () => {
    const f = fixture()
    const swapped = f.entries.map((e) => e.entryType === 'policy.published'
      ? { ...e, subjectHash: encodeMultihash(hash(new TextEncoder().encode('another policy'))) }
      : e)
    // Re-sign so the chain itself is valid and only the subject differs.
    let prev: string | null = null
    const resigned = swapped.map((e) => {
      const { proof: _p, logInclusion: _l, ...bare } = e as LedgerEntry & { proof?: unknown }
      const fresh = { ...bare, previousEntryHash: prev } as unknown as LedgerEntry
      fresh.proof = buildProof(fresh, { privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey, kind: 'ledgerEntry', created: NOW })
      prev = digest(fresh, 'ledgerEntry')
      return fresh
    })
    const r = verify(bundleWith(f, { ledgerJson: JSON.stringify(resigned) }))
    expect(r.policy?.timestamp.proven).toBe(false)
    expect(r.warnings.join(' ')).toMatch(/no policy.published entry for this policy/)
  })

  it('a chain PEM beside the token is carried as a certificate chain, not mistaken for a token', () => {
    const f = fixture()
    const b = bundleWith(f, { timestamps: { 'sth-2-testtsa.tsr.b64': f.token, 'testtsa-chain.pem': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n' } })
    const entry = b.manifest.entries.find((e) => e.path === 'timestamps/testtsa-chain.pem')
    expect(entry?.contentType).toBe('application/x-pem-file')
    const r = verify(b)
    expect(r.errors).toEqual([])
    expect(r.checks.filter((c) => c.name === 'timestamp')).toHaveLength(1)
    expect(b.artifacts['verification/instructions.txt']).toMatch(/SHA-256\( the 32 raw bytes of rootHash \)/)
  })
})
