#!/usr/bin/env node
/**
 * Generates spec/examples/** and spec/test-vectors/vectors.json.
 *
 * Deterministic: same seed in, same bytes out. Regenerate with
 *   node spec/test-vectors/generate.mjs
 * then confirm with
 *   node spec/test-vectors/verify.mjs
 *
 * The keys here derive from a PUBLISHED test seed and MUST NOT be used in production.
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

/* ---------- RFC 8785 JCS (sufficient subset: no floats, no lone surrogates) ---------- */
function jcs (v) {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('PRM documents MUST NOT contain non-integer numbers')
    return String(v)
  }
  if (typeof v === 'string') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  if (typeof v === 'object') {
    const keys = Object.keys(v).filter(k => v[k] !== undefined)
    // RFC 8785: sort by UTF-16 code units
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    return '{' + keys.map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}'
  }
  throw new Error('unsupported type ' + typeof v)
}

/* ---------- encodings ---------- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58btc (bytes) {
  let n = 0n
  for (const b of bytes) n = n * 256n + BigInt(b)
  let out = ''
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n }
  for (const b of bytes) { if (b === 0) out = '1' + out; else break }
  return out
}
const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
function base32nopad (bytes) {
  let bits = 0, value = 0, out = ''
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5 }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}
const b64u = b => Buffer.from(b).toString('base64url')

const sha256 = b => crypto.createHash('sha256').update(b).digest()
/** multibase 'u' + multihash(0x12,0x20,digest) */
const mh = digest => 'u' + b64u(Buffer.concat([Buffer.from([0x12, 0x20]), digest]))
/** canonical digest of a PRM document: SHA-256(JCS(doc minus id, proof)) */
function digestOf (doc) {
  const { id, proof, ...rest } = doc
  return sha256(Buffer.from(jcs(rest), 'utf8'))
}

/* ---------- keys ---------- */
const MASTER_SEED = sha256(Buffer.from('PRM TEST VECTOR SEED v1 — DO NOT USE IN PRODUCTION', 'utf8'))
function derive (info) {
  return Buffer.from(crypto.hkdfSync('sha256', MASTER_SEED, Buffer.alloc(32), Buffer.from(info, 'utf8'), 32))
}
function keypair (seed) {
  // RFC 8410 PKCS#8 prefix for Ed25519 private keys
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
  const privateKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  const publicKey = crypto.createPublicKey(privateKey)
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)
  return {
    seed, privateKey, publicKey, raw,
    multibase: 'z' + base58btc(Buffer.concat([Buffer.from([0xed, 0x01]), raw])),
    digest: mh(sha256(raw))
  }
}
const k0   = keypair(derive('prm/v1/sign/0'))
const k1   = keypair(derive('prm/v1/sign/1'))
const k2   = keypair(derive('prm/v1/sign/2'))
const krec = keypair(derive('prm/v1/recovery'))
const S_BIND = derive('prm/v1/binding')

function sign (key, domain, digest) {
  const msg = Buffer.concat([Buffer.from(domain + '\x00', 'utf8'), digest])
  return 'z' + base58btc(crypto.sign(null, msg, key.privateKey))
}
function proofFor (doc, key, domain, created) {
  const did = 'did:key:' + key.multibase
  return {
    type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created,
    verificationMethod: `${did}#${key.multibase}`, proofPurpose: 'assertionMethod',
    proofValue: sign(key, domain, digestOf(doc))
  }
}

/* ---------- 1. genesis key event ---------- */
let genesis = {
  type: 'prm/KeyEvent/v1', eventType: 'genesis', sequence: 0, previousEventHash: null,
  created: '2026-09-06T14:02:11Z',
  keys: [{ id: '#k0', alg: 'Ed25519', publicKeyMultibase: k0.multibase, use: ['assertion', 'authentication'], device: 'laptop' }],
  nextKeyDigests: [k1.digest],
  recoveryKeyDigests: [krec.digest],
  threshold: 1,
  services: [{ type: 'PRMPublisher', endpoint: 'https://prm.app/u/ab12cd' }]
}
genesis.proof = [proofFor(genesis, k0, 'PRM-KEYEVENT-v1', '2026-09-06T14:02:11Z')]
const GENESIS_DIGEST = digestOf(genesis)
const ACCOUNT_ID = 'prm:' + base32nopad(GENESIS_DIGEST).slice(0, 26)

/* ---------- 2. rotation key event (seq 1) ---------- */
let rotation = {
  type: 'prm/KeyEvent/v1', eventType: 'rotation', sequence: 1,
  previousEventHash: mh(GENESIS_DIGEST), created: '2027-09-06T09:00:00Z',
  keys: [{ id: '#k1', alg: 'Ed25519', publicKeyMultibase: k1.multibase, use: ['assertion', 'authentication'], device: 'laptop' }],
  nextKeyDigests: [k2.digest], recoveryKeyDigests: [krec.digest], threshold: 1,
  services: [{ type: 'PRMPublisher', endpoint: 'https://prm.app/u/ab12cd' }]
}
// Two proofs: outgoing key AND the newly revealed pre-committed key.
rotation.proof = [
  proofFor(rotation, k0, 'PRM-KEYEVENT-v1', '2027-09-06T09:00:00Z'),
  proofFor(rotation, k1, 'PRM-KEYEVENT-v1', '2027-09-06T09:00:00Z')
]

/* ---------- 3. identifier commitment ---------- */
function commitmentFor (namespace, value) {
  const salt = Buffer.from(crypto.hkdfSync('sha256', S_BIND, Buffer.alloc(32),
    Buffer.from(`prm/v1/salt/${namespace}/${value}`, 'utf8'), 16))
  const c = sha256(Buffer.concat([
    Buffer.from(namespace, 'utf8'), Buffer.from([0]),
    Buffer.from(value, 'utf8'), Buffer.from([0]), salt
  ]))
  return { salt: b64u(salt), commitment: mh(c) }
}
// Deliberately jurisdiction-neutral fixtures. A VIN (ISO 3779) identifies a vehicle without naming
// any state; example.org is reserved by RFC 2606. Plate normalization — the only namespace with
// jurisdiction-specific parsing — is covered by @prm/schema unit tests, which do not participate in
// normative digests, so nothing is lost by keeping a real state code out of the vectors.
const VIN = commitmentFor('vin', '1HGBH41JXMN109186')
const EMAIL = commitmentFor('email', 'holder@example.org')
const DEVICE = commitmentFor('device-id', 'device-0001-synthetic')

/* ---------- 4. ALPR policy v1 ---------- */
const HUMAN = `# Personal Data Policy

This document states the terms on which information about me may be retained and reused after it has
been collected. It is a synthetic example used to pin the PRM canonicalization and signature format;
it is not anyone's real policy and it describes no real organization.

I permit observation and the use strictly necessary to complete an interaction I have initiated.

I object to retention beyond that purpose, to combining these records with other databases, to
building a behavioral profile, to inferring facts about me that were never observed, to disclosure to
other organizations, to sale or other commercial exploitation, to advertising use, and to inclusion in
the training or evaluation of any machine learning model.

I acknowledge that a court order or a specific statutory mandate may lawfully override these
objections, and I do not assert otherwise.

Please confirm receipt and state which of these restrictions your systems can and cannot honour.`

function buildPolicy ({ version, previousPolicyHash, chainId, key, created, effectiveDate, rules, extra = {} }) {
  const doc = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://prm.dev/ns/policy/v1'],
    type: ['VerifiableCredential', 'PersonalDataPolicy'],
    policyChainId: chainId, version, previousPolicyHash,
    issuer: {
      id: ACCOUNT_ID, did: 'did:key:' + key.multibase,
      keyEventLog: 'https://prm.app/u/ab12cd/kel.json',
      keyEventHash: mh(GENESIS_DIGEST)
    },
    effectiveDate,
    jurisdictions: ['US'],
    rules,
    identifierCommitments: [
      { namespace: 'vin', commitment: VIN.commitment },
      { namespace: 'email', commitment: EMAIL.commitment },
      { namespace: 'device-id', commitment: DEVICE.commitment }
    ],
    requests: { deletionOnPurposeCompletion: true, doNotSellOrShare: true, globalPrivacyControl: true },
    humanReadable: { mediaType: 'text/markdown', language: 'en', text: HUMAN },
    distribution: {
      canonicalUrl: 'https://prm.app/u/ab12cd',
      machineUrl: 'https://prm.app/u/ab12cd/policy.json',
      shortUrl: 'https://prm.li/9fK2xQ',
      statusList: 'https://prm.app/status/1'
    },
    ...extra
  }
  const d = digestOf(doc)
  doc.id = 'urn:prm:policy:' + mh(d)
  doc.proof = proofFor(doc, key, 'PRM-POLICY-v1', created)
  return { doc, digest: d }
}

// Exercises every shape the schema allows: allow / deny / conditional, conditions with each
// supported field, and basisAcknowledged. Coverage of the format, not of any jurisdiction's law.
const GENERIC_RULES = [
  { category: 'prm:observation', decision: 'allow', note: 'Observation itself is not contested.' },
  { category: 'prm:transactional', decision: 'conditional',
    conditions: { maxRetention: 'PT0S', purposes: ['dpv:ServiceProvision'], requiresLegalProcess: false,
      note: 'Use strictly necessary to complete an interaction I initiated.' } },
  { category: 'prm:retention', decision: 'conditional',
    conditions: { maxRetention: 'PT0S', recipients: ['prm:none'],
      note: 'Delete once the initiating purpose is complete.' } },
  { category: 'prm:location-history', decision: 'deny' },
  { category: 'prm:correlation', decision: 'deny', note: 'No joining to other databases.' },
  { category: 'prm:profiling', decision: 'deny' },
  { category: 'prm:inference', decision: 'deny' },
  { category: 'prm:third-party-sharing', decision: 'deny' },
  { category: 'prm:sale', decision: 'deny' },
  { category: 'prm:commercialization', decision: 'deny' },
  { category: 'prm:advertising', decision: 'deny' },
  { category: 'prm:ai-training', decision: 'deny' },
  { category: 'prm:biometric', decision: 'deny' },
  { category: 'prm:law-enforcement', decision: 'conditional',
    conditions: { requiresLegalProcess: true, requiresNotice: true, jurisdictions: ['US'] },
    basisAcknowledged: ['court-order', 'statutory-override'] },
  { category: 'prm:emergency', decision: 'allow',
    basisAcknowledged: ['vital-interest'], note: 'Imminent threat to life, for its duration.' },
  { category: 'prm:deletion', decision: 'conditional',
    conditions: { maxRetention: 'PT0S', note: 'Delete once the purpose is complete.' } }
]

// v1: chainId is self-referential, so compute the digest with a placeholder then rebind.
const probe = buildPolicy({ version: 1, previousPolicyHash: null, chainId: 'urn:prm:chain:PLACEHOLDER',
  key: k0, created: '2026-09-06T14:07:33Z', effectiveDate: '2026-09-06T00:00:00Z', rules: GENERIC_RULES })
// Chain id is defined as the digest of v1 computed with chainId omitted entirely.
const { policyChainId: _drop, ...v1NoChain } = (() => { const { id, proof, ...r } = probe.doc; return r })()
const CHAIN_DIGEST = sha256(Buffer.from(jcs(v1NoChain), 'utf8'))
const CHAIN_ID = 'urn:prm:chain:' + mh(CHAIN_DIGEST)

const v1 = buildPolicy({ version: 1, previousPolicyHash: null, chainId: CHAIN_ID,
  key: k0, created: '2026-09-06T14:07:33Z', effectiveDate: '2026-09-06T00:00:00Z', rules: GENERIC_RULES })

// v2: tightens emergency use to require after-the-fact notice.
const V2_RULES = GENERIC_RULES.map(r => r.category === 'prm:emergency'
  ? { category: 'prm:emergency', decision: 'conditional',
      conditions: { maxRetention: 'P30D', requiresNotice: true, note: 'Written notice within 30 days of use.' },
      basisAcknowledged: ['vital-interest'] }
  : r)
const v2 = buildPolicy({ version: 2, previousPolicyHash: mh(v1.digest), chainId: CHAIN_ID,
  key: k0, created: '2026-11-02T10:15:00Z', effectiveDate: '2026-11-09T00:00:00Z', rules: V2_RULES,
  extra: { supersedes: mh(v1.digest), expirationDate: '2028-11-09T00:00:00Z' } })

/* ---------- 5. authorization ---------- */
const GRANTEE_ID = 'did:web:example.org'
const pairwiseId = base32nopad(Buffer.from(crypto.hkdfSync('sha256', S_BIND,
  Buffer.from(GRANTEE_ID, 'utf8'), Buffer.from('prm/v1/pairwise', 'utf8'), 12))).slice(0, 16)

let authz = {
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://prm.dev/ns/policy/v1'],
  type: ['VerifiableCredential', 'PRMAuthorization'],
  policyChainId: CHAIN_ID, boundPolicyHash: mh(v2.digest),
  grantee: { name: 'Example Data Controller', id: GRANTEE_ID,
    did: GRANTEE_ID, domain: 'example.org', contact: 'privacy@example.org' },
  subjectRef: {
    pairwiseId,
    disclosedIdentifiers: [{ namespace: 'vin', value: '1HGBH41JXMN109186', salt: VIN.salt }]
  },
  purposes: ['dpv:FraudPreventionAndDetection'],
  categories: ['prm:retention', 'prm:correlation'],
  dataCategories: ['transaction-record'],
  issued: '2026-11-20T00:00:00Z', expires: '2027-02-18T00:00:00Z',
  maxRetention: 'P90D', onwardSharing: 'prohibited',
  revocation: { statusListCredential: 'https://prm.app/status/1', statusListIndex: 4211, statusPurpose: 'revocation' },
  receiptRequested: true,
  note: 'Synthetic fixture. Scoped to a single stated purpose; no onward sharing.'
}
const AUTHZ_DIGEST = digestOf(authz)
authz.id = 'urn:prm:authz:' + mh(AUTHZ_DIGEST)
authz.proof = proofFor(authz, k0, 'PRM-AUTHZ-v1', '2026-11-20T00:00:00Z')

/* ---------- 6. ledger entries + Merkle log (RFC 6962) ---------- */
const leafHash = d => sha256(Buffer.concat([Buffer.from([0x00]), d]))
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([0x01]), l, r]))
function merkleRoot (leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0))
  if (leaves.length === 1) return leaves[0]
  let k = 1; while (k * 2 < leaves.length) k *= 2
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)))
}
function inclusionProof (leaves, i) {
  if (leaves.length <= 1) return []
  let k = 1; while (k * 2 < leaves.length) k *= 2
  return i < k
    ? [...inclusionProof(leaves.slice(0, k), i), merkleRoot(leaves.slice(k))]
    : [...inclusionProof(leaves.slice(k), i - k), merkleRoot(leaves.slice(0, k))]
}

const entrySpecs = [
  { seq: 0, recorded: '2026-09-06T14:02:12Z', entryType: 'key.event', subject: GENESIS_DIGEST },
  { seq: 1, recorded: '2026-09-06T14:07:35Z', entryType: 'policy.published', subject: v1.digest },
  { seq: 2, recorded: '2026-09-12T09:30:00Z', entryType: 'notice.sent', subject: sha256(Buffer.from('notice-packet-synthetic-2026-09-12')),
    counterparty: { name: 'Example Data Controller', id: GRANTEE_ID, channel: 'postal' },
    evidence: [{ kind: 'certified-mail-receipt', digest: mh(sha256(Buffer.from('usps-9407-1118-9876-5432-1098-76'))), note: 'Synthetic delivery receipt reference' }] },
  { seq: 3, recorded: '2026-09-16T00:00:00Z', entryType: 'notice.delivered', subject: sha256(Buffer.from('notice-packet-synthetic-2026-09-12')),
    counterparty: { name: 'Example Data Controller', id: GRANTEE_ID, channel: 'postal' },
    evidence: [{ kind: 'usps-tracking', digest: mh(sha256(Buffer.from('delivered-2026-09-16-signed-by-recipient'))) }] },
  { seq: 4, recorded: '2026-11-02T10:15:02Z', entryType: 'policy.published', subject: v2.digest },
  { seq: 5, recorded: '2026-11-20T00:00:03Z', entryType: 'authorization.granted', subject: AUTHZ_DIGEST,
    counterparty: { name: 'Example Data Controller', id: GRANTEE_ID, channel: 'email' } }
]

let prev = null
const entries = []
for (const s of entrySpecs) {
  const e = {
    type: 'prm/LedgerEntry/v1', accountId: ACCOUNT_ID, sequence: s.seq,
    previousEntryHash: prev, recorded: s.recorded, entryType: s.entryType,
    subjectHash: mh(s.subject),
    ...(s.counterparty ? { counterparty: s.counterparty } : {}),
    ...(s.evidence ? { evidence: s.evidence } : {})
  }
  const d = digestOf(e)
  e.proof = proofFor(e, k0, 'PRM-LEDGER-v1', s.recorded)
  prev = mh(d)
  entries.push({ entry: e, digest: d })
}

const leaves = entries.map(e => leafHash(e.digest))
const ROOT = merkleRoot(leaves)
const sth = {
  logId: 'prm-log-1', treeSize: leaves.length, rootHash: mh(ROOT),
  timestamp: '2026-11-20T01:00:00Z', previousRootHash: mh(merkleRoot(leaves.slice(0, 5)))
}
// Log key is the ONLY server-held signing key.
const kLog = keypair(sha256(Buffer.from('PRM TEST LOG KEY v1 — DO NOT USE IN PRODUCTION')))
sth.signature = sign(kLog, 'PRM-STH-v1', sha256(Buffer.from(jcs(sth), 'utf8')))

// Attach inclusion proofs to the two policy entries.
for (const idx of [1, 4]) {
  entries[idx].entry.logInclusion = {
    logId: 'prm-log-1', leafIndex: idx, treeSize: leaves.length, rootHash: mh(ROOT),
    inclusionProof: inclusionProof(leaves, idx).map(mh),
    signedTreeHead: '<detached JWS — see spec/examples/ledger/signed-tree-head.json>'
  }
}

/* ---------- write ---------- */
const w = (p, o) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, JSON.stringify(o, null, 2) + '\n') }
w(`${OUT}/examples/policies/policy-v1.json`, v1.doc)
w(`${OUT}/examples/policies/policy-v2.json`, v2.doc)
w(`${OUT}/examples/key-events/genesis.json`, genesis)
w(`${OUT}/examples/key-events/rotation-seq1.json`, rotation)
w(`${OUT}/examples/authorizations/example-grant.json`, authz)
w(`${OUT}/examples/ledger/entries.json`, entries.map(e => e.entry))
w(`${OUT}/examples/ledger/signed-tree-head.json`, sth)

/* ---------- test vectors ---------- */
w(`${OUT}/test-vectors/vectors.json`, {
  note: 'Generated by spec/test-vectors/generate.mjs. Every PRM implementation MUST reproduce these byte-for-byte. Keys derive from a published test seed and MUST NOT be used in production. These fixtures are deliberately synthetic and jurisdiction-neutral: they pin the wire format, not any jurisdiction\'s law. The California ALPR material lives in examples/whittier/ and is NOT part of the normative digest set.',
  masterSeedHex: MASTER_SEED.toString('hex'),
  hkdf: { hash: 'SHA-256', salt: '32 zero bytes', infoPrefix: 'prm/v1/' },
  keys: {
    'sign/0': { seedHex: k0.seed.toString('hex'), publicKeyMultibase: k0.multibase, publicKeyDigest: k0.digest, did: 'did:key:' + k0.multibase },
    'sign/1': { seedHex: k1.seed.toString('hex'), publicKeyMultibase: k1.multibase, publicKeyDigest: k1.digest },
    'sign/2': { publicKeyMultibase: k2.multibase, publicKeyDigest: k2.digest },
    recovery: { publicKeyMultibase: krec.multibase, publicKeyDigest: krec.digest },
    binding: { S_bindHex: S_BIND.toString('hex') }
  },
  jcs: [
    { inputJson: '{"b":1,"a":2}', output: '{"a":2,"b":1}' },
    { inputJson: '{"a":1,"A":2,"\\u00e1":3}', output: '{"A":2,"a":1,"\u00e1":3}' },
    { inputJson: '{"z":[3,1,2],"n":null,"t":true}', output: '{"n":null,"t":true,"z":[3,1,2]}' },
    { inputJson: '{"\\u00e9":1,"e\\u0301":2}', output: '{"e\u0301":2,"\u00e9":1}',
      note: 'Sorting is by UTF-16 code unit, NOT by collation. NFC U+00E9 (0xE9) sorts AFTER NFD "e"+U+0301 (0x65). PRM never Unicode-normalizes keys.' },
    { inputJson: '{"k":"tab\\tquote\\"backslash\\\\"}', output: '{"k":"tab\\tquote\\"backslash\\\\"}',
      note: 'Only the RFC 8785 minimal escape set: \\b \\t \\n \\f \\r \\" \\\\ and control chars as \\u00XX.' }
  ],
  accountId: { genesisDigest: mh(GENESIS_DIGEST), accountId: ACCOUNT_ID,
    derivation: "'prm:' + base32-nopad-lower(SHA-256(JCS(genesis minus id, proof))).slice(0,26)" },
  identifierCommitments: [
    { namespace: 'vin', value: '1HGBH41JXMN109186', salt: VIN.salt, commitment: VIN.commitment },
    { namespace: 'email', value: 'holder@example.org', salt: EMAIL.salt, commitment: EMAIL.commitment },
    { namespace: 'device-id', value: 'device-0001-synthetic', salt: DEVICE.salt, commitment: DEVICE.commitment }
  ],
  pairwiseId: { granteeId: GRANTEE_ID, pairwiseId },
  documents: {
    'policies/policy-v1.json': { digest: mh(v1.digest), signedBy: 'sign/0', domain: 'PRM-POLICY-v1' },
    'policies/policy-v2.json': { digest: mh(v2.digest), signedBy: 'sign/0', domain: 'PRM-POLICY-v1' },
    'key-events/genesis.json': { digest: mh(GENESIS_DIGEST), signedBy: 'sign/0', domain: 'PRM-KEYEVENT-v1' },
    'key-events/rotation-seq1.json': { digest: mh(digestOf(rotation)), signedBy: ['sign/0', 'sign/1'], domain: 'PRM-KEYEVENT-v1' },
    'authorizations/example-grant.json': { digest: mh(AUTHZ_DIGEST), signedBy: 'sign/0', domain: 'PRM-AUTHZ-v1' }
  },
  policyChain: { chainId: CHAIN_ID, v1: mh(v1.digest), v2: mh(v2.digest), v2PreviousPolicyHash: v2.doc.previousPolicyHash },
  merkleLog: {
    hashing: 'RFC 6962: leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right)',
    treeSize: leaves.length, leaves: leaves.map(mh), rootHash: mh(ROOT),
    inclusionProofs: { 1: inclusionProof(leaves, 1).map(mh), 4: inclusionProof(leaves, 4).map(mh) },
    logPublicKeyMultibase: kLog.multibase
  }
})

console.log('accountId        :', ACCOUNT_ID)
console.log('chainId          :', CHAIN_ID)
console.log('policy v1 digest :', mh(v1.digest))
console.log('policy v2 digest :', mh(v2.digest))
console.log('merkle root      :', mh(ROOT))
console.log('pairwiseId       :', pairwiseId)
