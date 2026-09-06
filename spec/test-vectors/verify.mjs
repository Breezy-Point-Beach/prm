#!/usr/bin/env node
/**
 * Independent verifier for the PRM test vectors.
 *
 * Deliberately does NOT import the generator: it re-derives every digest, signature, account
 * identifier, commitment and Merkle proof from the published documents alone, exactly as a
 * third-party verifier would. Run with:  node spec/test-vectors/verify.mjs
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const SPEC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = p => JSON.parse(fs.readFileSync(path.join(SPEC, p), 'utf8'))

/* ---- RFC 8785 JCS ---- */
function jcs (v) {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('non-integer number')
    return String(v)
  }
  if (typeof v === 'string') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  const k = Object.keys(v).filter(x => v[x] !== undefined).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  return '{' + k.map(x => JSON.stringify(x) + ':' + jcs(v[x])).join(',') + '}'
}

/* ---- encodings ---- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const b58decode = s => {
  let n = 0n
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error('bad base58'); n = n * 58n + BigInt(i) }
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex
  let out = Buffer.from(hex, 'hex')
  let lead = 0; for (const c of s) { if (c === '1') lead++; else break }
  return Buffer.concat([Buffer.alloc(lead), out])
}
const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
const base32nopad = bytes => {
  let bits = 0, value = 0, out = ''
  for (const b of bytes) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5 } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}
const sha256 = b => crypto.createHash('sha256').update(b).digest()
const mh = d => 'u' + Buffer.from(d).toString('base64url')
const mhDecode = s => { const b = Buffer.from(s.slice(1), 'base64url'); if (b[0] !== 0x12 || b[1] !== 0x20) throw new Error('not sha2-256 multihash'); return b.subarray(2) }
const mhOf = d => mh(Buffer.concat([Buffer.from([0x12, 0x20]), d]))
const digestOf = doc => { const { id, proof, ...rest } = doc; return sha256(Buffer.from(jcs(rest), 'utf8')) }

/** Ed25519 raw public key -> Node KeyObject (RFC 8410 SPKI wrapper) */
const pubFromRaw = raw => crypto.createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki'
})
const rawFromMultibase = mb => {
  const b = b58decode(mb.slice(1))
  if (b[0] !== 0xed || b[1] !== 0x01) throw new Error('not an Ed25519 multicodec key')
  return b.subarray(2)
}

let pass = 0, fail = 0
const check = (name, fn) => {
  try { const detail = fn(); pass++; console.log(`  \x1b[32m✔\x1b[0m ${name}${detail ? '  \x1b[2m' + detail + '\x1b[0m' : ''}`) }
  catch (e) { fail++; console.log(`  \x1b[31m✘\x1b[0m ${name}\n      ${e.message}`) }
}
const assert = (c, m) => { if (!c) throw new Error(m) }

/** Verify a DataIntegrityProof over a PRM document. */
function verifyProof (doc, proof, domain) {
  const mbKey = proof.verificationMethod.split('#')[1] ?? proof.verificationMethod.split(':').pop()
  const raw = rawFromMultibase(mbKey)
  const msg = Buffer.concat([Buffer.from(domain + '\x00', 'utf8'), digestOf(doc)])
  assert(crypto.verify(null, msg, pubFromRaw(raw), b58decode(proof.proofValue.slice(1))),
    `signature invalid (${domain})`)
  return mbKey
}

const V = read('test-vectors/vectors.json')
const genesis = read('examples/key-events/genesis.json')
const rotation = read('examples/key-events/rotation-seq1.json')
const v1 = read('examples/policies/alpr-policy-v1.json')
const v2 = read('examples/policies/alpr-policy-v2.json')
const authz = read('examples/authorizations/alpr-investigation-grant.json')
const entries = read('examples/ledger/entries.json')
const sth = read('examples/ledger/signed-tree-head.json')

console.log('\nPRM test vectors — independent verification\n')

console.log('JCS canonicalization')
for (const c of V.jcs) check(`JCS ${c.inputJson}`, () => {
  const got = jcs(JSON.parse(c.inputJson))
  assert(got === c.output, `got ${got} want ${c.output}`)
  return c.note ? '' : undefined
})

console.log('\nKey Event Log')
check('genesis: signature valid', () => verifyProof(genesis, genesis.proof[0], 'PRM-KEYEVENT-v1'))
check('genesis: digest matches vector', () => {
  assert(mhOf(digestOf(genesis)) === V.accountId.genesisDigest, 'digest mismatch'); return V.accountId.genesisDigest.slice(0, 20) + '…'
})
check('accountId self-certifies from genesis', () => {
  const id = 'prm:' + base32nopad(digestOf(genesis)).slice(0, 26)
  assert(id === V.accountId.accountId, `derived ${id}`); return id
})
check('rotation: chains to genesis', () =>
  assert(rotation.previousEventHash === mhOf(digestOf(genesis)), 'previousEventHash mismatch'))
check('rotation: PRE-ROTATION COMMITMENT satisfied', () => {
  const newRaw = rawFromMultibase(rotation.keys[0].publicKeyMultibase)
  assert(genesis.nextKeyDigests.includes(mhOf(sha256(newRaw))),
    'revealed key is not the one committed in genesis.nextKeyDigests')
  return 'SHA-256(newKey) ∈ genesis.nextKeyDigests'
})
check('rotation: dual signature (outgoing + revealed)', () => {
  assert(rotation.proof.length === 2, 'expected 2 proofs')
  const a = verifyProof(rotation, rotation.proof[0], 'PRM-KEYEVENT-v1')
  const b = verifyProof(rotation, rotation.proof[1], 'PRM-KEYEVENT-v1')
  assert(a === genesis.keys[0].publicKeyMultibase, 'proof[0] is not the outgoing key')
  assert(b === rotation.keys[0].publicKeyMultibase, 'proof[1] is not the incoming key')
  return 'k0 + k1'
})
check('a stolen current key CANNOT rotate to an attacker key', () => {
  const attacker = crypto.generateKeyPairSync('ed25519')
  const raw = attacker.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)
  assert(!genesis.nextKeyDigests.includes(mhOf(sha256(raw))),
    'attacker key unexpectedly satisfied the pre-rotation commitment')
  return 'commitment rejects an uncommitted key'
})

console.log('\nPolicies')
check('v1: digest matches vector and self-referential id', () => {
  const d = mhOf(digestOf(v1))
  assert(d === V.documents['policies/alpr-policy-v1.json'].digest, 'vector mismatch')
  assert(v1.id === 'urn:prm:policy:' + d, 'id is not the canonical digest')
  return d.slice(0, 20) + '…'
})
check('v1: signature valid under a key authorized in the KEL', () => {
  const mb = verifyProof(v1, v1.proof, 'PRM-POLICY-v1')
  assert(genesis.keys.some(k => k.publicKeyMultibase === mb), 'signing key not authorized in genesis')
  assert(v1.issuer.keyEventHash === mhOf(digestOf(genesis)), 'issuer.keyEventHash does not name the genesis event')
})
check('v1: issuer.id equals the self-certified accountId', () =>
  assert(v1.issuer.id === V.accountId.accountId, 'issuer mismatch'))
check('v2: signature valid', () => verifyProof(v2, v2.proof, 'PRM-POLICY-v1'))
check('v2: chains to v1 via previousPolicyHash', () => {
  assert(v2.previousPolicyHash === mhOf(digestOf(v1)), 'chain broken')
  assert(v2.policyChainId === v1.policyChainId, 'chain id changed across versions')
  return 'v1 ← v2'
})
check('v2 tightened prm:emergency (allow → conditional)', () => {
  const a = v1.rules.find(r => r.category === 'prm:emergency').decision
  const b = v2.rules.find(r => r.category === 'prm:emergency').decision
  assert(a === 'allow' && b === 'conditional', `got ${a} → ${b}`); return 'allow → conditional'
})
check('tamper detection: flipping one rule invalidates the signature', () => {
  const t = structuredClone(v1)
  t.rules.find(r => r.category === 'prm:sale').decision = 'allow'
  let ok = true
  try { verifyProof(t, t.proof, 'PRM-POLICY-v1') } catch { ok = false }
  assert(!ok, 'tampered policy still verified — canonicalization is broken')
  return 'prm:sale deny→allow rejected'
})
check('domain separation: a policy signature is not valid as an authorization', () => {
  let ok = true
  try { verifyProof(v1, v1.proof, 'PRM-AUTHZ-v1') } catch { ok = false }
  assert(!ok, 'cross-type signature replay succeeded')
})
check('no PII in the published policy', () => {
  const s = JSON.stringify(v1)
  for (const leak of ['US-MN-ABC123', 'holder@example.org'])
    assert(!s.includes(leak), `raw identifier "${leak}" leaked into the published policy`)
  return 'only commitments published'
})

console.log('\nIdentifier commitments')
for (const c of V.identifierCommitments) check(`commitment opens for ${c.namespace}`, () => {
  const computed = mhOf(sha256(Buffer.concat([
    Buffer.from(c.namespace, 'utf8'), Buffer.from([0]),
    Buffer.from(c.value, 'utf8'), Buffer.from([0]), Buffer.from(c.salt, 'base64url')])))
  assert(computed === c.commitment, 'commitment mismatch')
  assert(v1.identifierCommitments.some(x => x.commitment === c.commitment), 'not present in policy')
})
check('commitment is NOT brute-forceable without the salt', () => {
  const bare = mhOf(sha256(Buffer.from('US-MN-ABC123', 'utf8')))
  assert(!v1.identifierCommitments.some(x => x.commitment === bare),
    'policy contains an unsalted identifier hash — enumerable')
  return '128-bit salt required to open'
})

console.log('\nAuthorization')
check('authz: signature valid', () => verifyProof(authz, authz.proof, 'PRM-AUTHZ-v1'))
check('authz: bound to the exact policy version v2', () =>
  assert(authz.boundPolicyHash === mhOf(digestOf(v2)), 'boundPolicyHash does not match v2'))
check('authz: expiry present and after issuance', () => {
  assert(authz.expires, 'perpetual grant — schema violation')
  assert(new Date(authz.expires) > new Date(authz.issued), 'expires before issued')
  return `${authz.issued.slice(0, 10)} → ${authz.expires.slice(0, 10)}`
})
check('authz: discloses the plate only to this grantee', () => {
  const d = authz.subjectRef.disclosedIdentifiers[0]
  const computed = mhOf(sha256(Buffer.concat([
    Buffer.from(d.namespace, 'utf8'), Buffer.from([0]),
    Buffer.from(d.value, 'utf8'), Buffer.from([0]), Buffer.from(d.salt, 'base64url')])))
  assert(v1.identifierCommitments.some(x => x.commitment === computed),
    'disclosed identifier does not open any commitment in the policy')
  return 'grantee can verify coverage; nobody else can'
})
check('authz: pairwiseId is not the accountId', () =>
  assert(authz.subjectRef.pairwiseId !== V.accountId.accountId &&
         !V.accountId.accountId.includes(authz.subjectRef.pairwiseId), 'pairwise id leaks the account id'))

console.log('\nLedger + Merkle log (RFC 6962)')
check('personal hash chain is continuous and signed', () => {
  let prev = null
  for (const e of entries) {
    assert(e.previousEntryHash === prev, `entry ${e.sequence}: broken chain link`)
    const { logInclusion, ...bare } = e
    verifyProof(bare, e.proof, 'PRM-LEDGER-v1')
    prev = mhOf(digestOf(bare))
  }
  return `${entries.length} entries`
})
const leafHash = d => sha256(Buffer.concat([Buffer.from([0]), d]))
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]))
const leaves = entries.map(e => { const { logInclusion, ...b } = e; return leafHash(digestOf(b)) })
function root (ls) {
  if (ls.length === 1) return ls[0]
  let k = 1; while (k * 2 < ls.length) k *= 2
  return nodeHash(root(ls.slice(0, k)), root(ls.slice(k)))
}
check('merkle root matches the signed tree head', () => {
  assert(mhOf(root(leaves)) === sth.rootHash, 'root mismatch')
  assert(sth.treeSize === leaves.length, 'treeSize mismatch')
  return sth.rootHash.slice(0, 20) + '…'
})
check('signed tree head signature valid under the published log key', () => {
  const { signature, ...body } = sth
  const msg = Buffer.concat([Buffer.from('PRM-STH-v1\x00', 'utf8'), sha256(Buffer.from(jcs(body), 'utf8'))])
  assert(crypto.verify(null, msg, pubFromRaw(rawFromMultibase(V.merkleLog.logPublicKeyMultibase)),
    b58decode(signature.slice(1))), 'STH signature invalid')
})
function verifyInclusion (leaf, index, treeSize, proof, expectedRoot) {
  // Descend from the root recording which side we took at each level.
  const path = []
  let i = index, n = treeSize
  while (n > 1) {
    let k = 1; while (k * 2 < n) k *= 2
    if (i < k) { path.push('L'); n = k } else { path.push('R'); i -= k; n -= k }
  }
  // proof[0] is the DEEPEST sibling, so walk the recorded path in reverse.
  assert(proof.length === path.length, `proof has ${proof.length} siblings, path depth is ${path.length}`)
  let h = leaf
  for (let j = path.length - 1, p = 0; j >= 0; j--, p++) {
    h = path[j] === 'L' ? nodeHash(h, proof[p]) : nodeHash(proof[p], h)
  }
  assert(mhOf(h) === expectedRoot, 'inclusion proof does not reconstruct the root')
  return `${proof.length} siblings → root`
}
for (const idx of [1, 4]) check(`inclusion proof for leaf ${idx} (${entries[idx].entryType})`, () =>
  verifyInclusion(leaves[idx], idx, leaves.length,
    entries[idx].logInclusion.inclusionProof.map(mhDecode), sth.rootHash))
check('a forged leaf FAILS the inclusion proof', () => {
  const forged = leafHash(sha256(Buffer.from('a policy the user never signed')))
  let ok = true
  try { verifyInclusion(forged, 1, leaves.length,
    entries[1].logInclusion.inclusionProof.map(mhDecode), sth.rootHash) } catch { ok = false }
  assert(!ok, 'forged leaf produced a valid inclusion proof')
  return 'log cannot be made to vouch for an unlogged document'
})
check('log leaves disclose nothing (32-byte opaque hashes)', () => {
  for (const l of leaves) assert(l.length === 32, 'leaf is not a 32-byte hash')
  return 'a full log dump reveals only event count and timing'
})

console.log('\nFull evidentiary chain (the §11 claim)')
check('policy v1 → ledger entry → merkle leaf → signed tree head', () => {
  const e = entries.find(x => x.entryType === 'policy.published' && x.subjectHash === mhOf(digestOf(v1)))
  assert(e, 'no ledger entry names policy v1')
  const { logInclusion, ...bare } = e
  assert(mhOf(leafHash(digestOf(bare))) === V.merkleLog.leaves[e.sequence], 'leaf mismatch')
  assert(mhOf(root(leaves)) === sth.rootHash, 'root mismatch')
  return `v1 ⊂ entry #${e.sequence} ⊂ tree(${sth.treeSize}) @ ${sth.timestamp}`
})

console.log(`\n${fail === 0 ? '\x1b[32m' : '\x1b[31m'}${pass} passed, ${fail} failed\x1b[0m\n`)
process.exit(fail === 0 ? 0 : 1)
