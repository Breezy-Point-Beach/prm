#!/usr/bin/env node
/**
 * Checks the committed Whittier artifacts, and proves the offline acceptance criterion.
 *
 * Three jobs:
 *   1. the notice chain verifies end to end — an example that does not verify is worse than none
 *   2. NO private identifier reached any published artifact
 *   3. verification works with the network SABOTAGED, using only the portable files
 *
 * Job 3 is the acceptance test from the PR brief: with PRM unavailable, no database, no blob store,
 * no deployment and no networking, a third party can still establish everything that matters.
 */
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import http from 'node:http'
import https from 'node:https'

const DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'generated')
const load = (f) => JSON.parse(readFileSync(resolve(DIR, f), 'utf8'))
const text = (f) => readFileSync(resolve(DIR, f), 'utf8')
const NOW = new Date('2026-10-01T00:00:00Z')

// ---------------------------------------------------------------------------
// Sabotage the network BEFORE importing anything. If any verification path
// reaches for it, these tests fail loudly rather than silently passing online.
// ---------------------------------------------------------------------------
const BOOM = () => { throw new Error('NETWORK ACCESS ATTEMPTED — verification must be fully offline') }
globalThis.fetch = BOOM
globalThis.XMLHttpRequest = BOOM
globalThis.WebSocket = BOOM
http.request = BOOM; http.get = BOOM
https.request = BOOM; https.get = BOOM

const { verifyProofBundle, verifyPolicy, verifyKeyEventLog, verifyAuthorization } = await import('@prm/verify')
const { validatePolicy, validateNotice, validateDelivery, validateResponse, validateKeyEvent,
  validateLedgerEntry, findForbiddenAssertions, findOutOfScopeTopics } = await import('@prm/schema')
const { digest, hash, encodeMultihash } = await import('@prm/crypto')

const byteDigest = (s) => encodeMultihash(hash(new TextEncoder().encode(s)))

let pass = 0
let fail = 0
const check = (name, fn) => {
  try {
    const detail = fn()
    pass++
    console.log(`  ok   ${name}${detail ? '  ' + detail : ''}`)
  } catch (e) {
    fail++
    console.log(`  XX   ${name}\n         ${e.message}`)
  }
}
const assert = (c, m) => { if (!c) throw new Error(m) }

const policy = load('policy.json')
const policyText = text('policy.json')
const kel = load('kel.json')
const notice = load('notice.json')
const delivery = load('delivery.json')
const response = load('response.json')
const bundle = load('notice.prmproof')
const cover = text('cover-letter.md')

console.log('\nWhittier example — verification with the network sabotaged\n')

check('the sabotage is real (control)', () => {
  let threw = false
  try { globalThis.fetch('https://example.com') } catch { threw = true }
  assert(threw, 'fetch did not throw — the sabotage is not in effect')
  return 'fetch, XHR, WebSocket, http and https all throw'
})

// ---------------------------------------------------------------------------
console.log('\nSchemas and signatures')
check('every artifact conforms to its schema', () => {
  assert(validatePolicy(policy).valid, 'policy invalid')
  for (const e of kel) assert(validateKeyEvent(e).valid, 'key event invalid')
  for (const e of load('ledger.json')) assert(validateLedgerEntry(e).valid, `ledger ${e.sequence}`)
  assert(validateNotice(notice).valid, `notice: ${validateNotice(notice).errors.join('; ')}`)
  assert(validateDelivery(delivery).valid, `delivery: ${validateDelivery(delivery).errors.join('; ')}`)
  assert(validateResponse(response).valid, `response: ${validateResponse(response).errors.join('; ')}`)
  return '9 documents'
})

check('the key chain self-certifies', () => {
  const r = verifyKeyEventLog(kel)
  assert(r.valid, r.errors.join('; '))
  assert(r.accountId === policy.issuer.id, 'account id does not match the policy issuer')
  return r.accountId
})

check('the policy signature is valid and the issuer authorized', () => {
  const r = verifyPolicy(policy, { keyEventLog: kel, now: NOW })
  assert(r.summary !== 'failed', r.errors.join('; '))
  assert(r.issuer === 'authorized', `issuer status: ${r.issuer}`)
  return `v${r.checked.version}`
})

check('the notice references the correct policy, by BOTH digests', () => {
  assert(notice.policyDigest === digest(policy, 'policy'), 'policy digest mismatch')
  assert(notice.policyByteDigest === byteDigest(policyText), 'policy BYTE digest mismatch')
  assert(notice.policyDigest !== notice.policyByteDigest, 'the two digests must differ')
  return 'document identity and exact bytes both pinned'
})

check('delivery and response reference the notice', () => {
  const noticeDigest = digest(notice, 'notice')
  assert(delivery.noticeDigest === noticeDigest, 'delivery points elsewhere')
  assert(response.noticeDigest === noticeDigest, 'response points elsewhere')
  assert(response.deliveryDigest === digest(delivery, 'delivery'), 'response/delivery mismatch')
  return `${delivery.method} -> ${response.status}`
})

// ---------------------------------------------------------------------------
console.log('\nProof bundle (the acceptance criterion)')
check('the bundle verifies with nothing but the file itself', () => {
  const r = verifyProofBundle(bundle, { now: NOW })
  assert(r.valid, r.errors.join('; '))
  return `${r.checks.length} checks, ${bundle.manifest.entries.length} artifacts`
})

check('every manifest entry matches its artifact', () => {
  for (const entry of bundle.manifest.entries) {
    const content = bundle.artifacts[entry.path]
    assert(content !== undefined, `missing artifact ${entry.path}`)
    assert(byteDigest(content) === entry.byteDigest, `digest mismatch for ${entry.path}`)
  }
  return `${bundle.manifest.entries.length} artifacts pinned`
})

check('the bundle carries the policy bytes exactly', () => {
  assert(bundle.artifacts['policy.json'] === policyText, 'policy bytes differ from the published file')
  return `${policyText.length} bytes`
})

check('the bundle includes verification instructions and a README', () => {
  const i = bundle.artifacts['verification/instructions.txt']
  assert(i.includes('openssl ts -verify'), 'no RFC 3161 instructions')
  assert(bundle.artifacts['README.txt'].includes('does not'), 'README missing the disclaimer')
  return 'openssl and CLI instructions present'
})

// ---------------------------------------------------------------------------
console.log('\nLanguage discipline')
check('the notice makes no unsupported legal assertion', () => {
  const all = [notice.requestedTreatment, notice.legalEffect, notice.purpose ?? '', cover].join('\n')
  const found = findForbiddenAssertions(all)
  assert(found.length === 0, `contains: ${found.join(', ')}`)
  return 'no obligation is asserted'
})

check('the notice does NOT repeat a records request', () => {
  // Those questions were asked in earlier correspondence and are handled separately. Repeating them
  // here would turn a focused notice into a second information request.
  const all = [notice.requestedTreatment, notice.legalEffect, notice.purpose ?? '',
    notice.note ?? '', cover].join('\n')
  const found = findOutOfScopeTopics(all)
  assert(found.length === 0, `asks about: ${found.join(', ')}`)
  return 'notice only, no questions'
})

check('the disclaimer is present and explicit', () => {
  assert(/does not independently create legal rights/.test(notice.legalEffect), 'missing')
  assert(/record of my express position and non-consent/.test(notice.legalEffect), 'missing fallback')
  return 'legal effect stated carefully'
})

// ---------------------------------------------------------------------------
console.log('\nPrivacy')
check('NO private identifier appears in any PUBLISHED artifact', () => {
  const plate = notice.matchingIdentifiers.find((d) => d.namespace === 'us-license-plate').value
  const published = ['policy.json', 'kel.json', 'ledger.json', 'signed-tree-head.json']
  for (const f of published) {
    assert(!text(f).includes(plate), `${f} contains the raw plate`)
  }
  assert(policy.identifierCommitments.some((c) => c.namespace === 'us-license-plate'),
    'policy is missing the plate commitment')
  return `plate is in notice.json only, never in ${published.length} published files`
})

check('the plate appears in the bundle ONLY inside the notice', () => {
  const plate = notice.matchingIdentifiers[0].value
  for (const [path, content] of Object.entries(bundle.artifacts)) {
    if (path === 'notice.json') continue
    assert(!content.includes(plate), `${path} leaked the plate`)
  }
  return 'recipient-specific, as designed'
})

check('the committed example uses PLACEHOLDER identifiers', () => {
  const plate = notice.matchingIdentifiers[0].value
  assert(plate === 'US-CA-0EXAMPLE',
    `committed artifacts contain a non-placeholder plate (${plate}) — regenerate without --local`)
  return plate
})

check('no local/ directory was committed', () => {
  assert(!readdirSync(resolve(DIR, '..')).includes('local'),
    'examples/whittier/local/ exists and must never be committed')
  return 'clean'
})

// ---------------------------------------------------------------------------
console.log('\nTampering')
const tamper = (mutate) => {
  const copy = JSON.parse(JSON.stringify(bundle))
  mutate(copy)
  return verifyProofBundle(copy, { now: NOW })
}
const detects = (name, mutate) => check(`DETECTS ${name}`, () => {
  assert(!tamper(mutate).valid, 'tampering was NOT detected')
})

detects('a modified policy', (b) => {
  const p = JSON.parse(b.artifacts['policy.json'])
  p.rules.find((r) => r.category === 'prm:sale').decision = 'allow'
  b.artifacts['policy.json'] = JSON.stringify(p, null, 2)
})
detects('reserialized policy bytes', (b) => {
  b.artifacts['policy.json'] = JSON.stringify(JSON.parse(b.artifacts['policy.json']))
})
detects('a modified manifest', (b) => { b.manifest.subject.policyVersion = 99 })
detects('a missing artifact', (b) => { delete b.artifacts['notice.json'] })
detects('an artifact with no manifest entry', (b) => { b.artifacts['x/injected.json'] = '{}' })
detects('a modified delivery timestamp', (b) => {
  const d = JSON.parse(b.artifacts['delivery/delivery-1.json'])
  d.deliveredAt = '2020-01-01T00:00:00Z'
  const s = JSON.stringify(d, null, 2)
  b.artifacts['delivery/delivery-1.json'] = s
  const e = b.manifest.entries.find((x) => x.path === 'delivery/delivery-1.json')
  e.byteDigest = byteDigest(s)
  e.byteLength = new TextEncoder().encode(s).length
  b.manifestDigest = manifestDigestOfLocal(b.manifest)
})

check('CONTROL: the untouched bundle still verifies', () => {
  assert(tamper(() => {}).valid, 'the control case failed — the suite is broken')
  return 'valid artifacts succeed'
})

/** Local manifest digest, so this file does not import the producer package. */
function manifestDigestOfLocal (manifest) {
  const jcs = (v) => {
    if (v === null) return 'null'
    if (typeof v === 'boolean') return v ? 'true' : 'false'
    if (typeof v === 'number') return String(v)
    if (typeof v === 'string') return JSON.stringify(v)
    if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
    const k = Object.keys(v).filter((x) => v[x] !== undefined).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    return '{' + k.map((x) => JSON.stringify(x) + ':' + jcs(v[x])).join(',') + '}'
  }
  return byteDigest(jcs(manifest))
}

console.log(`\n  ${pass} passed, ${fail} failed\n`)
process.exit(fail === 0 ? 0 : 1)
