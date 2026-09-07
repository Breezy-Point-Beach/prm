#!/usr/bin/env node
/**
 * Checks the committed Whittier artifacts.
 *
 * Two jobs. First, prove the example actually verifies end to end — an example that does not verify
 * is worse than no example. Second, and more importantly, assert that NO private identifier reached
 * any published artifact. That second check is the one that matters when a real user runs this with
 * their own plate.
 */
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyBundle, verifyPolicy, verifyKeyEventLog, verifyAuthorization } from '@prm/verify'
import { validatePolicy, validateAuthorization, validateKeyEvent, validateLedgerEntry } from '@prm/schema'

const DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'generated')
const load = (f) => JSON.parse(readFileSync(resolve(DIR, f), 'utf8'))
const NOW = new Date('2026-10-01T00:00:00Z')

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
const kel = load('kel.json')
const ledger = load('ledger.json')
const grant = load('authorization-whittier-pd.json')
const bundle = load('evidence.prmproof')

console.log('\nWhittier example — verification\n')

check('every artifact conforms to its schema', () => {
  assert(validatePolicy(policy).valid, 'policy invalid')
  for (const e of kel) assert(validateKeyEvent(e).valid, 'key event invalid')
  for (const e of ledger) assert(validateLedgerEntry(e).valid, `ledger entry ${e.sequence} invalid`)
  assert(validateAuthorization(grant).valid, 'authorization invalid')
  return `${1 + kel.length + ledger.length + 1} documents`
})

check('key event log self-certifies', () => {
  const r = verifyKeyEventLog(kel)
  assert(r.valid, r.errors.join('; '))
  assert(r.accountId === policy.issuer.id, 'account id does not match the policy issuer')
  return r.accountId
})

check('policy verifies against the key event log', () => {
  const r = verifyPolicy(policy, { keyEventLog: kel, now: NOW })
  assert(r.summary !== 'failed', r.errors.join('; '))
  assert(r.issuer === 'authorized', `issuer status: ${r.issuer}`)
  return `v${r.checked.version}`
})

check('policy uses the California ALPR template', () => {
  assert(policy.jurisdictions.includes('US-CA'), 'jurisdiction is not US-CA')
  const d = (c) => policy.rules.find((r) => r.category === c)
  assert(d('prm:observation').decision === 'allow', 'observation should be authorized')
  assert(d('prm:transactional').conditions.maxRetention === 'PT0S', 'hotlist check should not retain')
  assert(d('prm:retention').conditions.maxRetention === 'PT0S', 'non-hit reads should not be retained')
  for (const c of ['prm:location-history', 'prm:correlation', 'prm:profiling', 'prm:inference',
    'prm:third-party-sharing', 'prm:sale', 'prm:ai-training', 'prm:biometric']) {
    assert(d(c).decision === 'deny', `${c} should be objected to`)
  }
  return 'observation authorized, downstream objected to'
})

check('policy does not overstate legal effect', () => {
  const text = policy.humanReadable.text
  assert(/does not purport to create rights/.test(text), 'missing the disclaimer')
  for (const forbidden of ['you must comply', 'is unlawful', 'legally binding', 'you are required by law']) {
    assert(!text.toLowerCase().includes(forbidden), `prose asserts: ${forbidden}`)
  }
  return 'states instructions, not obligations'
})

check('authorization discloses the plate to Whittier PD only', () => {
  const r = verifyAuthorization(grant, { boundPolicy: policy, now: NOW })
  assert(r.valid, r.errors.join('; '))
  assert(r.provenIdentifiers.includes('us-license-plate'), 'plate does not open a policy commitment')
  assert(grant.grantee.domain === 'whittierpd.org', 'unexpected grantee')
  return 'commitment opens for the named grantee'
})

check('evidence bundle verifies end to end', () => {
  const r = verifyBundle(bundle, { now: NOW })
  assert(r.valid, r.errors.join('; '))
  return r.conclusion.slice(0, 68) + '...'
})

// ---------------------------------------------------------------------------
// The check that actually protects a real user.
// ---------------------------------------------------------------------------
check('NO private identifier appears in any PUBLISHED artifact', () => {
  const plate = grant.subjectRef.disclosedIdentifiers.find((d) => d.namespace === 'us-license-plate').value
  const published = ['policy.json', 'kel.json', 'ledger.json', 'signed-tree-head.json']
  for (const f of published) {
    const raw = readFileSync(resolve(DIR, f), 'utf8')
    assert(!raw.includes(plate), `${f} contains the raw plate ${plate}`)
    assert(!raw.includes('@example.org'), `${f} contains a raw email address`)
  }
  // The policy must carry the commitment, so coverage is still provable.
  assert(policy.identifierCommitments.some((c) => c.namespace === 'us-license-plate'),
    'policy is missing the plate commitment')
  return `plate appears only in the authorization, never in ${published.length} published files`
})

check('the committed example uses PLACEHOLDER identifiers, not real ones', () => {
  const plate = grant.subjectRef.disclosedIdentifiers[0].value
  assert(plate === 'US-CA-0EXAMPLE',
    `committed artifacts contain a non-placeholder plate (${plate}) — regenerate without --local`)
  return plate
})

check('no local/ directory was committed', () => {
  const entries = readdirSync(resolve(DIR, '..'))
  assert(!entries.includes('local'), 'examples/whittier/local/ exists and must never be committed')
  return 'clean'
})

console.log(`\n  ${pass} passed, ${fail} failed\n`)
process.exit(fail === 0 ? 0 : 1)
