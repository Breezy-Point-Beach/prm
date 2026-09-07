import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  validatePolicy, validateAuthorization, validateKeyEvent, validateLedgerEntry,
  policyWarnings, assertPolicy
} from '../src/validate.js'
import type { LedgerEntry, Policy } from '../src/types.js'

const SPEC = resolve(import.meta.dirname, '../../../spec')
const load = (p: string) => JSON.parse(readFileSync(resolve(SPEC, p), 'utf8'))

describe('normative examples validate', () => {
  it.each([
    'examples/policies/policy-v1.json',
    'examples/policies/policy-v2.json'
  ])('%s', (f) => {
    const r = validatePolicy(load(f))
    expect(r.errors).toEqual([])
    expect(r.valid).toBe(true)
  })

  it.each([
    'examples/key-events/genesis.json',
    'examples/key-events/rotation-seq1.json'
  ])('%s', (f) => {
    const r = validateKeyEvent(load(f))
    expect(r.errors).toEqual([])
  })

  it('authorization', () => {
    expect(validateAuthorization(load('examples/authorizations/example-grant.json')).errors)
      .toEqual([])
  })

  it('every ledger entry', () => {
    for (const e of load('examples/ledger/entries.json') as LedgerEntry[]) {
      expect(validateLedgerEntry(e).errors, `entry ${e.sequence}`).toEqual([])
    }
  })

  it('the normative examples produce no semantic warnings', () => {
    expect(policyWarnings(load('examples/policies/policy-v1.json'))).toEqual([])
    expect(policyWarnings(load('examples/policies/policy-v2.json'))).toEqual([])
  })
})

describe('invalid documents are rejected', () => {
  const base = (): Policy => load('examples/policies/policy-v1.json')

  it('rejects a v1 policy that claims a previous version', () => {
    const p = base(); p.previousPolicyHash = 'uEiBE9fuWQIzOQe08QcgbkYJdl54EKVdIlWi6GC2xmIZmqA'
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects a v2 policy with no previous version', () => {
    const p = base(); p.version = 2; p.previousPolicyHash = null
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects an unknown decision value', () => {
    const p = base(); p.rules[0]!.decision = 'maybe' as never
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects a conditional rule with no conditions', () => {
    const p = base()
    p.rules = [{ category: 'prm:sale', decision: 'conditional' }]
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects fractional-second timestamps (canonicalization hazard)', () => {
    const p = base(); p.effectiveDate = '2026-09-06T00:00:00.500Z'
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects a non-UTC timestamp', () => {
    const p = base(); p.effectiveDate = '2026-09-06T00:00:00-07:00'
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects a policy with no rules', () => {
    const p = base(); p.rules = []
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects a malformed account id', () => {
    const p = base(); p.issuer.id = 'prm:NOT-BASE32!'
    expect(validatePolicy(p).valid).toBe(false)
  })

  it('rejects an authorization with no expiry (perpetual grants are inexpressible)', () => {
    const a = load('examples/authorizations/example-grant.json')
    delete a.expires
    expect(validateAuthorization(a).valid).toBe(false)
  })

  it('assertPolicy throws with a readable message', () => {
    const p = base(); p.rules = []
    expect(() => assertPolicy(p)).toThrow(/failed schema validation/)
  })
})

describe('extensibility is preserved', () => {
  it('accepts an unknown top-level member (it is inside the signed bytes)', () => {
    const p = base2(); (p as Record<string, unknown>)['xyz:future'] = { some: 'value' }
    expect(validatePolicy(p).valid).toBe(true)
  })

  it('accepts an extension category URI', () => {
    const p = base2()
    p.rules.push({ category: 'xyz:drone-imagery', decision: 'deny' })
    expect(validatePolicy(p).errors).toEqual([])
  })

  function base2 (): Policy { return load('examples/policies/policy-v1.json') }
})
