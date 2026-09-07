import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  verifyPolicy, verifyPolicyChain, verifyKeyEventLog, verifyLedgerChain,
  verifyLogInclusion, verifySignedTreeHead, verifyAuthorization, verifyProofBundle
} from '../src/index.js'
import {
  deriveAccountKeys, buildProof, digest, hashString, encodeMultihash, hash, decodePublicKey
} from '@prm/crypto'

const SPEC = resolve(import.meta.dirname, '../../../spec')
const load = (p: string) => JSON.parse(readFileSync(resolve(SPEC, p), 'utf8'))
const V = load('test-vectors/vectors.json')

const genesis = () => load('examples/key-events/genesis.json')
const rotation = () => load('examples/key-events/rotation-seq1.json')
const v1 = () => load('examples/policies/policy-v1.json')
const v2 = () => load('examples/policies/policy-v2.json')
const authz = () => load('examples/authorizations/example-grant.json')
const entries = () => load('examples/ledger/entries.json')
const sth = () => load('examples/ledger/signed-tree-head.json')
const NOW = new Date('2026-12-01T00:00:00Z')
const KEYS = deriveAccountKeys(Buffer.from(V.masterSeedHex, 'hex'))

/**
 * Re-sign a mutated document.
 *
 * Needed because the verifier checks the signature BEFORE the semantic rule under test. Mutating a
 * signed document and asserting on a downstream error would only ever prove that tampering breaks
 * signatures — which is already covered. To isolate a rule, the forged document must be otherwise
 * perfectly valid, which is also the realistic adversary: someone who holds a key.
 */
function resign<T extends Record<string, unknown>> (doc: T, kind: 'policy' | 'authorization' | 'keyEvent', created: string): T {
  const bare = { ...doc }
  delete bare.id
  delete bare.proof
  const proof = buildProof(bare, {
    privateKey: KEYS.signing.privateKey, publicKey: KEYS.signing.publicKey, kind, created
  })
  return { ...bare, proof: kind === 'keyEvent' ? [proof] : proof } as unknown as T
}

describe('policy verification — the happy path', () => {
  it('verifies the normative policy against its key event log', () => {
    const r = verifyPolicy(v1(), { keyEventLog: [genesis()], now: NOW })
    expect(r.errors).toEqual([])
    expect(r.integrity).toBe('valid')
    expect(r.signature).toBe('valid')
    expect(r.issuer).toBe('authorized')
    expect(r.checked.accountId).toBe(V.accountId.accountId)
    expect(r.checked.digest).toBe(V.documents['policies/policy-v1.json'].digest)
  })

  it('reports currency when the latest version is supplied', () => {
    const p = v1()
    expect(verifyPolicy(p, {
      keyEventLog: [genesis()], latestVersion: { version: 1, policyChainId: p.policyChainId }, now: NOW
    }).currency).toBe('current')
    expect(verifyPolicy(p, {
      keyEventLog: [genesis()], latestVersion: { version: 2, policyChainId: p.policyChainId }, now: NOW
    }).currency).toBe('superseded')
  })

  it('reaches "verified" with no warnings when everything is supplied', () => {
    const p = v1()
    const r = verifyPolicy(p, {
      keyEventLog: [genesis()],
      latestVersion: { version: 1, policyChainId: p.policyChainId },
      revoked: false,
      timestamp: { notLaterThan: '2026-11-20T01:00:00Z', source: 'rfc3161' },
      now: NOW
    })
    expect(r.warnings).toEqual([])
    expect(r.summary).toBe('verified')
  })
})

describe('policy verification — adversarial', () => {
  it('REJECTS a tampered rule', () => {
    const p = v1()
    p.rules.find((r: { category: string }) => r.category === 'prm:sale').decision = 'allow'
    const r = verifyPolicy(p, { keyEventLog: [genesis()], now: NOW })
    expect(r.summary).toBe('failed')
    expect(r.signature).toBe('invalid')
  })

  it('REJECTS a mismatched self-referential id', () => {
    const p = v1()
    p.id = 'urn:prm:policy:' + V.documents['policies/policy-v2.json'].digest
    const r = verifyPolicy(p, { keyEventLog: [genesis()], now: NOW })
    expect(r.integrity).toBe('invalid')
    expect(r.summary).toBe('failed')
  })

  it('REJECTS a policy whose issuer does not match its key event log', () => {
    // Malicious PRM operator swapping in a different account's key history.
    const p = v1()
    p.issuer.id = 'prm:aaaaaaaaaaaaaaaaaaaaaaaaaa'
    const r = verifyPolicy(p, { keyEventLog: [genesis()], now: NOW })
    expect(r.summary).toBe('failed')
  })

  it('REJECTS a policy naming a key event that is not in the log', () => {
    const p = v1()
    p.issuer.keyEventHash = encodeMultihash(hashString('an event that never happened'))
    const r = verifyPolicy(p, { keyEventLog: [genesis()], now: NOW })
    expect(r.issuer).toBe('not-in-kel')
    expect(r.summary).toBe('failed')
  })

  it('REJECTS a policy signed by a key not authorized in the named event', () => {
    // Re-sign a policy with the pre-rotation key, which is NOT yet authorized at genesis.
    const keys = deriveAccountKeys(Buffer.from(V.masterSeedHex, 'hex'))
    const p = v1()
    delete p.id
    delete p.proof
    p.proof = buildProof(p, {
      privateKey: keys.next.privateKey, publicKey: keys.next.publicKey,
      kind: 'policy', created: '2026-09-06T14:07:33Z'
    })
    const r = verifyPolicy(p, { keyEventLog: [genesis()], now: NOW })
    expect(r.signature).toBe('valid')     // the signature itself is fine...
    expect(r.issuer).toBe('not-in-kel')   // ...but the key was never authorized
    expect(r.summary).toBe('failed')
  })

  it('degrades to kel-unavailable rather than failing when no log is supplied', () => {
    const r = verifyPolicy(v1(), { now: NOW })
    expect(r.issuer).toBe('kel-unavailable')
    expect(r.summary).toBe('verified-with-warnings')
  })

  it('warns, not fails, on an expired policy', () => {
    const r = verifyPolicy(v2(), { keyEventLog: [genesis()], now: new Date('2029-01-01T00:00:00Z') })
    expect(r.summary).toBe('verified-with-warnings')
    expect(r.warnings.join(' ')).toMatch(/expired/)
  })

  it('warns about unrecognized categories and says to treat them as denied', () => {
    const keys = deriveAccountKeys(Buffer.from(V.masterSeedHex, 'hex'))
    const p = v1()
    delete p.id; delete p.proof
    p.rules.push({ category: 'xyz:drone-imagery', decision: 'deny' })
    p.proof = buildProof(p, {
      privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey,
      kind: 'policy', created: '2026-09-06T14:07:33Z'
    })
    const r = verifyPolicy(p, { keyEventLog: [genesis()], now: NOW })
    expect(r.summary).toBe('verified-with-warnings')
    expect(r.warnings.join(' ')).toMatch(/xyz:drone-imagery.*treat as denied/)
  })
})

describe('policy chain', () => {
  it('verifies v1 -> v2', () => {
    expect(verifyPolicyChain([v1(), v2()])).toEqual({ valid: true, errors: [] })
  })

  it('DETECTS policy substitution in the chain', () => {
    const bad = v2()
    bad.previousPolicyHash = encodeMultihash(hashString('a different v1'))
    const r = verifyPolicyChain([v1(), bad])
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/substitution|does not match/)
  })

  it('DETECTS a missing intermediate version', () => {
    const v3 = v2(); v3.version = 3
    const r = verifyPolicyChain([v1(), v3])
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/version gap/)
  })

  it('DETECTS a foreign chain id', () => {
    const foreign = v2()
    foreign.policyChainId = 'urn:prm:chain:' + encodeMultihash(hashString('other'))
    expect(verifyPolicyChain([v1(), foreign]).valid).toBe(false)
  })

  it('derives and checks the v1 chain id', () => {
    const p = v1()
    p.policyChainId = 'urn:prm:chain:' + encodeMultihash(hashString('wrong'))
    expect(verifyPolicyChain([p]).valid).toBe(false)
  })
})

describe('key event log', () => {
  it('verifies genesis alone and genesis + rotation', () => {
    expect(verifyKeyEventLog([genesis()]).valid).toBe(true)
    const r = verifyKeyEventLog([genesis(), rotation()])
    expect(r.errors).toEqual([])
    expect(r.accountId).toBe(V.accountId.accountId)
  })

  it('REJECTS a rotation to a key that was never pre-committed (account takeover)', () => {
    // The real attack, modelled faithfully: a thief has stolen the CURRENT signing key. They forge a
    // rotation to a key they control, chained and signed perfectly — outgoing signature from the
    // stolen key, incoming signature from their own. Every other check passes. Only the pre-rotation
    // commitment stops them, because they cannot produce a key whose digest genesis already named.
    const g = genesis()
    const attacker = deriveAccountKeys(hashString('attacker: stolen sign/0, wants the account'))

    const forged: Record<string, unknown> = {
      type: 'prm/KeyEvent/v1',
      eventType: 'rotation',
      sequence: 1,
      previousEventHash: digest(g, 'keyEvent'),
      created: '2027-01-01T00:00:00Z',
      keys: [{
        id: '#k1', alg: 'Ed25519',
        publicKeyMultibase: attacker.signing.publicKeyMultibase,
        use: ['assertion', 'authentication']
      }],
      nextKeyDigests: [attacker.next.publicKeyDigest],
      recoveryKeyDigests: g.recoveryKeyDigests,
      threshold: 1
    }
    forged.proof = [
      buildProof(forged, { privateKey: KEYS.signing.privateKey, publicKey: KEYS.signing.publicKey,
        kind: 'keyEvent', created: '2027-01-01T00:00:00Z' }),
      buildProof(forged, { privateKey: attacker.signing.privateKey, publicKey: attacker.signing.publicKey,
        kind: 'keyEvent', created: '2027-01-01T00:00:00Z' })
    ]

    const r = verifyKeyEventLog([g, forged as never])
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/never pre-committed/)
    expect(r.errors.join(' ')).toMatch(/takeover attempt/)
  })

  it('ACCEPTS the legitimate rotation, proving the previous test is not a false positive', () => {
    expect(verifyKeyEventLog([genesis(), rotation()]).valid).toBe(true)
  })

  it('REJECTS a broken chain link', () => {
    const rot = rotation()
    rot.previousEventHash = encodeMultihash(hashString('not the genesis'))
    const r = verifyKeyEventLog([genesis(), rot])
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/previousEventHash/)
  })

  it('REJECTS a sequence gap', () => {
    const rot = rotation(); rot.sequence = 5
    expect(verifyKeyEventLog([genesis(), rot]).valid).toBe(false)
  })

  it('REJECTS a rotation carrying only one proof', () => {
    const rot = rotation(); rot.proof = [rot.proof[0]]
    const r = verifyKeyEventLog([genesis(), rot])
    expect(r.valid).toBe(false)
  })

  it('REJECTS a tampered genesis (account id no longer self-certifies)', () => {
    const g = genesis()
    g.created = '2020-01-01T00:00:00Z'
    const r = verifyKeyEventLog([g])
    // The event's own signature no longer matches its contents.
    expect(r.valid).toBe(false)
  })

  it('the rotation reveals exactly the pre-committed key', () => {
    const revealed = decodePublicKey(rotation().keys[0].publicKeyMultibase)
    expect(genesis().nextKeyDigests).toContain(encodeMultihash(hash(revealed)))
  })
})

describe('ledger and transparency log', () => {
  it('verifies the personal hash chain', () => {
    expect(verifyLedgerChain(entries())).toEqual({ valid: true, errors: [] })
  })

  it('DETECTS a removed entry (history rewriting)', () => {
    const e = entries()
    e.splice(2, 1)
    const r = verifyLedgerChain(e)
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/broken, reordered, or had an entry removed/)
  })

  it('DETECTS a reordered ledger', () => {
    const e = entries()
    const tmp = e[2].recorded; e[2].recorded = e[3].recorded; e[3].recorded = tmp
    expect(verifyLedgerChain(e).valid).toBe(false)
  })

  it('verifies inclusion proofs against the signed tree head', () => {
    for (const e of entries().filter((x: { logInclusion?: unknown }) => x.logInclusion)) {
      expect(verifyLogInclusion(e, sth()).errors).toEqual([])
    }
  })

  it('REJECTS an inclusion proof for a leaf that was never logged', () => {
    const e = entries()[1]
    e.subjectHash = encodeMultihash(hashString('a policy never published'))
    const r = verifyLogInclusion(e, sth())
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/does not reconstruct the claimed root/)
  })

  it('verifies the signed tree head against the published log key', () => {
    expect(verifySignedTreeHead(sth(), V.merkleLog.logPublicKeyMultibase)).toBe(true)
  })

  it('REJECTS a forged tree head', () => {
    const s = sth()
    s.rootHash = encodeMultihash(hashString('a root the log never published'))
    expect(verifySignedTreeHead(s, V.merkleLog.logPublicKeyMultibase)).toBe(false)
  })

  it('REJECTS a tree head signed by the wrong key', () => {
    expect(verifySignedTreeHead(sth(), V.keys['sign/0'].publicKeyMultibase)).toBe(false)
  })
})

describe('authorizations', () => {
  it('verifies the grant against the exact policy version it binds', () => {
    const r = verifyAuthorization(authz(), { boundPolicy: v2(), now: new Date('2026-12-01T00:00:00Z') })
    expect(r.errors).toEqual([])
    expect(r.valid).toBe(true)
    expect(r.provenIdentifiers).toContain('vin')
  })

  it('REJECTS the grant against a DIFFERENT policy version', () => {
    // A new policy version must not silently re-scope an existing grant.
    const r = verifyAuthorization(authz(), { boundPolicy: v1(), now: NOW })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/does not carry over to a different policy version/)
  })

  it('flags an expired grant', () => {
    const r = verifyAuthorization(authz(), { boundPolicy: v2(), now: new Date('2028-01-01T00:00:00Z') })
    expect(r.expired).toBe(true)
    expect(r.warnings.join(' ')).toMatch(/expired/)
  })

  it('flags a revoked grant', () => {
    const r = verifyAuthorization(authz(), { boundPolicy: v2(), revoked: true, now: NOW })
    expect(r.warnings.join(' ')).toMatch(/revoked/)
  })

  it('REJECTS a disclosed identifier that opens no commitment', () => {
    // A validly signed grant that discloses an identifier the policy never committed to. This is
    // the realistic attack: the issuer's own key, used to overclaim coverage.
    const base = authz()
    // A well-formed VIN the policy never committed to — so it fails on the commitment check, not on
    // normalization. Testing with a malformed value would prove something else entirely.
    base.subjectRef.disclosedIdentifiers[0].value = '1HGBH41JXMN109187'
    const a = resign(base, 'authorization', '2026-11-20T00:00:00Z')
    const r = verifyAuthorization(a, { boundPolicy: v2(), now: NOW })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/does not open any commitment/)
  })

  it('REJECTS a tampered grant', () => {
    const a = authz()
    a.categories.push('prm:sale')
    expect(verifyAuthorization(a, { boundPolicy: v2(), now: NOW }).valid).toBe(false)
  })
})

describe('proof bundles — structural cases', () => {
  // Full round-trip coverage lives in @prm/notice, which can both build and verify a bundle.
  // These are the cases that must fail before a bundle is ever parsed.
  it('rejects a non-bundle', () => {
    expect(verifyProofBundle(null).valid).toBe(false)
    expect(verifyProofBundle('nope').conclusion).toMatch(/not a PRM proof bundle/)
  })

  it('rejects the removed v1 format, and explains why', () => {
    const r = verifyProofBundle({ prmproof: 1, policy: {}, keyEventLog: [] })
    expect(r.valid).toBe(false)
    expect(r.conclusion).toMatch(/did not preserve exact artifact bytes/)
  })

  it('rejects an unknown future version', () => {
    expect(verifyProofBundle({ prmproof: 99 }).conclusion).toMatch(/incompatible version/)
  })

  it('rejects a bundle with no manifest', () => {
    const r = verifyProofBundle({ prmproof: 2, artifacts: {} })
    expect(r.valid).toBe(false)
    expect(r.conclusion).toMatch(/malformed/)
  })
})
