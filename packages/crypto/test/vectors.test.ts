/**
 * Conformance against the NORMATIVE test vectors.
 *
 * These tests are the point of the package. They do not check that @prm/crypto agrees with itself;
 * they check that it reproduces bytes committed to spec/ before this implementation existed. If any
 * of them fail, the implementation is wrong — not the vectors.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  jcs, digest, digestBytes, policyChainId, policyId, deriveAccountId, accountIdMatches,
  keyPairFromSeed, deriveSigningKey, deriveRecoveryKey, deriveBindingSecret, deriveAccountKeys,
  computeCommitment, deriveIdentifierSalt, encodeSalt, derivePairwiseId,
  signDocument, verifyDocument, verifyProofSelfContained, signingMessage, domainFor,
  encodeMultihash, decodeMultihash, encodePublicKey, decodePublicKey, hexToBytes, base64urlToBytes,
  leafHash, merkleRoot, inclusionProof, verifyInclusion, consistencyProof, verifyConsistency,
  hash, hashString
} from '../src/index.js'

const SPEC = resolve(import.meta.dirname, '../../../spec')
const load = (p: string) => JSON.parse(readFileSync(resolve(SPEC, p), 'utf8'))

const V = load('test-vectors/vectors.json')
const genesis = load('examples/key-events/genesis.json')
const rotation = load('examples/key-events/rotation-seq1.json')
const v1 = load('examples/policies/alpr-policy-v1.json')
const v2 = load('examples/policies/alpr-policy-v2.json')
const authz = load('examples/authorizations/alpr-investigation-grant.json')
const entries = load('examples/ledger/entries.json')
const sth = load('examples/ledger/signed-tree-head.json')

describe('PRM-JCS matches the normative vectors', () => {
  for (const c of V.jcs) {
    it(`${c.inputJson}`, () => {
      expect(jcs(JSON.parse(c.inputJson))).toBe(c.output)
    })
  }

  it('sorts by UTF-16 code unit, not by collation', () => {
    // NFD "e"+U+0301 (starts 0x65) must sort BEFORE NFC U+00E9 (0xE9).
    expect(jcs(JSON.parse('{"\\u00e9":1,"e\\u0301":2}'))).toBe('{"é":2,"é":1}')
  })

  it('does not Unicode-normalize keys', () => {
    const out = jcs(JSON.parse('{"\\u00e9":1,"e\\u0301":2}'))
    expect(out).toContain('é')
    expect(out).toContain('é')
  })

  it('rejects non-integer numbers (PRM profile)', () => {
    expect(() => jcs({ a: 1.5 })).toThrow(/integers-only/)
    expect(() => jcs({ a: NaN })).toThrow(/not representable/)
    expect(() => jcs({ a: Infinity })).toThrow(/not representable/)
  })

  it('rejects lone surrogates', () => {
    expect(() => jcs({ a: '\ud800' })).toThrow(/surrogate/)
    expect(() => jcs({ a: '\udc00x' })).toThrow(/surrogate/)
    expect(jcs({ a: '😀' })).toBe('{"a":"😀"}')
  })

  it('rejects Date, undefined, and bigint rather than guessing', () => {
    expect(() => jcs({ a: new Date() })).toThrow(/Date is not a JSON value/)
    expect(() => jcs({ a: 1n })).toThrow(/bigint/)
  })

  it('omits undefined members but preserves null', () => {
    expect(jcs({ a: undefined, b: null })).toBe('{"b":null}')
  })

  it('is stable regardless of key insertion order', () => {
    expect(jcs({ z: 1, a: 2, m: 3 })).toBe(jcs({ m: 3, a: 2, z: 1 }))
  })
})

describe('key derivation reproduces the vectors', () => {
  const masterSeed = hexToBytes(V.masterSeedHex)

  it('master seed derives sign/0 exactly', () => {
    const k = deriveSigningKey(masterSeed, 0)
    expect(k.publicKeyMultibase).toBe(V.keys['sign/0'].publicKeyMultibase)
    expect(k.publicKeyDigest).toBe(V.keys['sign/0'].publicKeyDigest)
    expect(k.did).toBe(V.keys['sign/0'].did)
  })

  it('derives sign/1 and sign/2 exactly', () => {
    expect(deriveSigningKey(masterSeed, 1).publicKeyMultibase).toBe(V.keys['sign/1'].publicKeyMultibase)
    expect(deriveSigningKey(masterSeed, 2).publicKeyMultibase).toBe(V.keys['sign/2'].publicKeyMultibase)
  })

  it('derives the recovery key and binding secret exactly', () => {
    expect(deriveRecoveryKey(masterSeed).publicKeyMultibase).toBe(V.keys.recovery.publicKeyMultibase)
    expect(Buffer.from(deriveBindingSecret(masterSeed)).toString('hex')).toBe(V.keys.binding.S_bindHex)
  })

  it('keyPairFromSeed round-trips the raw seed for sign/0', () => {
    expect(keyPairFromSeed(hexToBytes(V.keys['sign/0'].seedHex)).publicKeyMultibase)
      .toBe(V.keys['sign/0'].publicKeyMultibase)
  })

  it('deriveAccountKeys wires signing/next/recovery consistently', () => {
    const a = deriveAccountKeys(masterSeed, 0)
    expect(a.signing.publicKeyMultibase).toBe(V.keys['sign/0'].publicKeyMultibase)
    expect(a.next.publicKeyMultibase).toBe(V.keys['sign/1'].publicKeyMultibase)
    expect(a.recovery.publicKeyMultibase).toBe(V.keys.recovery.publicKeyMultibase)
  })
})

describe('document digests reproduce the vectors', () => {
  it.each([
    ['policies/alpr-policy-v1.json', v1, 'policy'],
    ['policies/alpr-policy-v2.json', v2, 'policy'],
    ['key-events/genesis.json', genesis, 'keyEvent'],
    ['key-events/rotation-seq1.json', rotation, 'keyEvent'],
    ['authorizations/alpr-investigation-grant.json', authz, 'authorization']
  ] as const)('%s', (name, doc, kind) => {
    expect(digest(doc, kind)).toBe(V.documents[name].digest)
  })

  it('the self-referential policy id equals the document digest', () => {
    expect(policyId(v1)).toBe(v1.id)
    expect(policyId(v2)).toBe(v2.id)
  })

  it('derives policyChainId, which is NOT digest(v1)', () => {
    expect(policyChainId(v1)).toBe(V.policyChain.chainId)
    expect(policyChainId(v1)).not.toBe(`urn:prm:chain:${digest(v1, 'policy')}`)
  })

  it('v2 chains to v1', () => {
    expect(v2.previousPolicyHash).toBe(digest(v1, 'policy'))
    expect(v2.policyChainId).toBe(v1.policyChainId)
  })

  it('EXCLUDES logInclusion from a ledger entry digest', () => {
    // spec/NORMATIVE.md §2. Including it would be circular and would break every inclusion proof.
    const withProof = entries[1]
    const bare = { ...withProof }
    delete bare.logInclusion
    expect(digest(withProof, 'ledgerEntry')).toBe(digest(bare, 'ledgerEntry'))
  })
})

describe('account identity self-certifies', () => {
  it('derives the account id from the genesis event', () => {
    expect(deriveAccountId(genesis)).toBe(V.accountId.accountId)
    expect(digest(genesis, 'keyEvent')).toBe(V.accountId.genesisDigest)
  })

  it('the account id is exactly 26 base32 characters', () => {
    expect(deriveAccountId(genesis)).toMatch(/^prm:[a-z2-7]{26}$/)
  })

  it('the policy issuer matches the derived account id', () => {
    expect(v1.issuer.id).toBe(deriveAccountId(genesis))
    expect(accountIdMatches(v1.issuer.id, genesis)).toBe(true)
  })

  it('a tampered genesis event yields a different account id', () => {
    const g = structuredClone(genesis)
    g.keys[0].publicKeyMultibase = V.keys['sign/1'].publicKeyMultibase
    expect(accountIdMatches(v1.issuer.id, g)).toBe(false)
  })
})

describe('identifier commitments and pairwise ids', () => {
  for (const c of V.identifierCommitments) {
    it(`opens the ${c.namespace} commitment with its salt`, () => {
      const computed = encodeMultihash(computeCommitment(c.namespace, c.value, base64urlToBytes(c.salt)))
      expect(computed).toBe(c.commitment)
    })
  }

  it('derives the salt from the binding secret (survives vault loss)', () => {
    const S = hexToBytes(V.keys.binding.S_bindHex)
    const target = V.identifierCommitments.find((c: { namespace: string }) => c.namespace === 'us-license-plate')
    const salt = deriveIdentifierSalt(S, target.namespace, target.value)
    expect(encodeSalt(salt)).toBe(target.salt)
    expect(encodeMultihash(computeCommitment(target.namespace, target.value, salt))).toBe(target.commitment)
  })

  it('a wrong salt does not open the commitment', () => {
    const c = V.identifierCommitments[0]
    const wrong = new Uint8Array(16).fill(7)
    expect(encodeMultihash(computeCommitment(c.namespace, c.value, wrong))).not.toBe(c.commitment)
  })

  it('an unsalted hash of the identifier is NOT what is published', () => {
    // A bare SHA-256 of a plate is enumerable in minutes; the salt is the whole defence.
    const bare = encodeMultihash(hashString('US-MN-ABC123'))
    expect(v1.identifierCommitments.map((x: { commitment: string }) => x.commitment)).not.toContain(bare)
  })

  it('derives the pairwise id for the grantee', () => {
    const S = hexToBytes(V.keys.binding.S_bindHex)
    expect(derivePairwiseId(S, V.pairwiseId.granteeId)).toBe(V.pairwiseId.pairwiseId)
  })

  it('different grantees get unlinkable pairwise ids', () => {
    const S = hexToBytes(V.keys.binding.S_bindHex)
    const a = derivePairwiseId(S, 'did:web:agency-a.gov')
    const b = derivePairwiseId(S, 'did:web:agency-b.gov')
    expect(a).not.toBe(b)
    expect(a).not.toContain(V.accountId.accountId.slice(4))
  })
})

describe('signatures verify and forgeries fail', () => {
  it.each([
    [v1, 'policy'], [v2, 'policy'], [authz, 'authorization']
  ] as const)('verifies the committed signature', (doc, kind) => {
    expect(verifyProofSelfContained(doc, kind, doc.proof)).toBe(true)
  })

  it('verifies both proofs on a rotation event', () => {
    expect(rotation.proof).toHaveLength(2)
    for (const p of rotation.proof) {
      expect(verifyProofSelfContained(rotation, 'keyEvent', p)).toBe(true)
    }
  })

  it('verifies every ledger entry signature', () => {
    for (const e of entries) {
      expect(verifyProofSelfContained(e, 'ledgerEntry', e.proof), `entry ${e.sequence}`).toBe(true)
    }
  })

  it('DETECTS tampering with a single rule', () => {
    const t = structuredClone(v1)
    t.rules.find((r: { category: string }) => r.category === 'prm:sale').decision = 'allow'
    expect(verifyProofSelfContained(t, 'policy', t.proof)).toBe(false)
  })

  it('DETECTS a changed previousPolicyHash (chain substitution)', () => {
    const t = structuredClone(v2)
    t.previousPolicyHash = digest(genesis, 'keyEvent')
    expect(verifyProofSelfContained(t, 'policy', t.proof)).toBe(false)
  })

  it('DETECTS a swapped issuer', () => {
    const t = structuredClone(v1)
    t.issuer.id = 'prm:aaaaaaaaaaaaaaaaaaaaaaaaaa'
    expect(verifyProofSelfContained(t, 'policy', t.proof)).toBe(false)
  })

  it('DETECTS an added identifier commitment', () => {
    const t = structuredClone(v1)
    t.identifierCommitments.push({ namespace: 'email', commitment: V.identifierCommitments[1].commitment })
    expect(verifyProofSelfContained(t, 'policy', t.proof)).toBe(false)
  })

  it('REJECTS domain confusion: a policy proof is not valid as an authorization', () => {
    expect(verifyProofSelfContained(v1, 'authorization', v1.proof)).toBe(false)
  })

  it('REJECTS domain confusion in every direction', () => {
    const kinds = ['policy', 'authorization', 'keyEvent', 'ledgerEntry'] as const
    for (const k of kinds) {
      if (k === 'policy') continue
      expect(verifyProofSelfContained(v1, k, v1.proof), `policy proof accepted as ${k}`).toBe(false)
    }
  })

  it('produces distinct signing messages per domain', () => {
    const d = digestBytes(v1, 'policy')
    const seen = new Set(
      (['policy', 'authorization', 'keyEvent', 'ledgerEntry', 'signedTreeHead'] as const)
        .map((k) => Buffer.from(signingMessage(domainFor(k), d)).toString('hex'))
    )
    expect(seen.size).toBe(5)
  })

  it('round-trips sign then verify with a derived key', () => {
    const k = deriveSigningKey(hexToBytes(V.masterSeedHex), 0)
    const doc = { type: ['PersonalDataPolicy'], version: 1, note: 'round trip' }
    const sig = signDocument(k.privateKey, doc, 'policy')
    expect(verifyDocument(k.publicKey, doc, 'policy', sig)).toBe(true)
    expect(verifyDocument(k.publicKey, { ...doc, version: 2 }, 'policy', sig)).toBe(false)
  })

  it('signing is deterministic (Ed25519 is not randomized)', () => {
    const k = deriveSigningKey(hexToBytes(V.masterSeedHex), 0)
    const doc = { a: 1, b: 'two' }
    expect(signDocument(k.privateKey, doc, 'policy')).toBe(signDocument(k.privateKey, doc, 'policy'))
  })

  it('a malformed proofValue fails closed rather than throwing', () => {
    expect(verifyProofSelfContained(v1, 'policy', { ...v1.proof, proofValue: 'znotbase58!!' })).toBe(false)
    expect(verifyProofSelfContained(v1, 'policy', { ...v1.proof, verificationMethod: 'garbage' })).toBe(false)
  })
})

describe('pre-rotation commitment', () => {
  it('the rotation reveals a key committed in genesis', () => {
    const revealed = decodePublicKey(rotation.keys[0].publicKeyMultibase)
    expect(genesis.nextKeyDigests).toContain(encodeMultihash(hash(revealed)))
  })

  it('a key that was never pre-committed CANNOT rotate', () => {
    const attacker = deriveSigningKey(hashString('attacker seed for this test'), 0)
    expect(genesis.nextKeyDigests).not.toContain(attacker.publicKeyDigest)
  })

  it('the committed next key is exactly sign/1', () => {
    expect(genesis.nextKeyDigests).toContain(V.keys['sign/1'].publicKeyDigest)
  })
})

describe('Merkle log reproduces the vectors', () => {
  const leaves = entries.map((e: object) => leafHash(digestBytes(e, 'ledgerEntry')))

  it('leaf hashes match', () => {
    expect(leaves.map((l: Uint8Array) => encodeMultihash(l))).toEqual(V.merkleLog.leaves)
  })

  it('root matches the signed tree head', () => {
    expect(encodeMultihash(merkleRoot(leaves))).toBe(V.merkleLog.rootHash)
    expect(encodeMultihash(merkleRoot(leaves))).toBe(sth.rootHash)
  })

  it.each([1, 4])('inclusion proof for leaf %i matches and verifies', (i) => {
    const proof = inclusionProof(leaves, i)
    expect(proof.map((p) => encodeMultihash(p))).toEqual(V.merkleLog.inclusionProofs[String(i)])
    expect(verifyInclusion(leaves[i], i, leaves.length, proof, merkleRoot(leaves))).toBe(true)
  })

  it('verifies the committed proof bytes from the entry itself', () => {
    const e = entries[1]
    const proof = e.logInclusion.inclusionProof.map((m: string) => decodeMultihash(m))
    expect(verifyInclusion(leaves[1], 1, leaves.length, proof, decodeMultihash(sth.rootHash))).toBe(true)
  })

  it('a forged leaf FAILS its inclusion proof', () => {
    const forged = leafHash(hashString('a policy the user never signed'))
    expect(verifyInclusion(forged, 1, leaves.length, inclusionProof(leaves, 1), merkleRoot(leaves)))
      .toBe(false)
  })

  it('a proof presented at the wrong index fails', () => {
    expect(verifyInclusion(leaves[1], 2, leaves.length, inclusionProof(leaves, 1), merkleRoot(leaves)))
      .toBe(false)
  })

  it('every leaf in every tree size 1..64 proves inclusion', () => {
    const all = Array.from({ length: 64 }, (_, i) => leafHash(hashString(`leaf-${i}`)))
    for (let n = 1; n <= 64; n++) {
      const sub = all.slice(0, n)
      const root = merkleRoot(sub)
      for (let i = 0; i < n; i++) {
        expect(verifyInclusion(sub[i]!, i, n, inclusionProof(sub, i), root), `n=${n} i=${i}`).toBe(true)
      }
    }
  })

  it('consistency proofs hold for every m <= n up to 40', () => {
    const all = Array.from({ length: 40 }, (_, i) => leafHash(hashString(`leaf-${i}`)))
    for (let n = 1; n <= 40; n++) {
      const newRoot = merkleRoot(all.slice(0, n))
      for (let m = 1; m <= n; m++) {
        const oldRoot = merkleRoot(all.slice(0, m))
        const proof = consistencyProof(all, m, n)
        expect(verifyConsistency(m, oldRoot, n, newRoot, proof), `m=${m} n=${n}`).toBe(true)
      }
    }
  })

  it('DETECTS a rewritten history via consistency failure', () => {
    const all = Array.from({ length: 16 }, (_, i) => leafHash(hashString(`leaf-${i}`)))
    const oldRoot = merkleRoot(all.slice(0, 7))
    // The operator swaps a leaf that was already committed, then presents a bigger tree.
    const rewritten = [...all]
    rewritten[3] = leafHash(hashString('substituted'))
    const newRoot = merkleRoot(rewritten.slice(0, 16))
    const proof = consistencyProof(rewritten, 7, 16)
    expect(verifyConsistency(7, oldRoot, 16, newRoot, proof)).toBe(false)
  })
})

describe('encoding round-trips', () => {
  it('multihash', () => {
    const d = hashString('x')
    expect(decodeMultihash(encodeMultihash(d))).toEqual(d)
  })
  it('public key', () => {
    const k = deriveSigningKey(hexToBytes(V.masterSeedHex), 0)
    expect(decodePublicKey(encodePublicKey(k.publicKey))).toEqual(k.publicKey)
  })
  it('rejects a non-sha256 multihash', () => {
    expect(() => decodeMultihash('uEiAA')).toThrow()
    expect(() => decodeMultihash('notmultibase')).toThrow()
  })
})
