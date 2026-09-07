import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { CORE_CATEGORIES, resolveDecision, unknownCategories, isCoreCategory } from '../src/categories.js'
import { alprRules, alprHumanReadable, TEMPLATES } from '../src/templates/alpr.js'
import type { Policy } from '../src/types.js'

const policy = (): Policy => JSON.parse(
  readFileSync(resolve(import.meta.dirname, '../../../spec/examples/policies/policy-v1.json'), 'utf8')
)

describe('category resolution fails closed', () => {
  it('returns the explicit decision when one exists', () => {
    expect(resolveDecision(policy(), 'prm:sale')).toMatchObject({ decision: 'deny', reason: 'explicit' })
    expect(resolveDecision(policy(), 'prm:observation')).toMatchObject({ decision: 'allow' })
  })

  it('DENIES an unknown category rather than permitting it', () => {
    expect(resolveDecision(policy(), 'xyz:drone-imagery'))
      .toMatchObject({ decision: 'deny', reason: 'unknown-category-denied' })
  })

  it('DENIES a known category the policy is silent about', () => {
    const p = policy()
    p.rules = p.rules.filter((r) => r.category !== 'prm:sale')
    expect(resolveDecision(p, 'prm:sale')).toMatchObject({ decision: 'deny', reason: 'absent-denied' })
  })

  it('surfaces unknown categories for human review', () => {
    const p = policy()
    p.rules.push({ category: 'xyz:drone-imagery', decision: 'deny' })
    expect(unknownCategories(p)).toEqual(['xyz:drone-imagery'])
  })

  it('the v1 vocabulary has 16 categories and all are recognized', () => {
    expect(CORE_CATEGORIES).toHaveLength(16)
    expect(CORE_CATEGORIES.every((c) => isCoreCategory(c.id))).toBe(true)
  })
})

describe('ALPR template (California)', () => {
  const rules = alprRules()

  it('covers every core category the demonstration case requires', () => {
    const covered = new Set(rules.map((r) => r.category))
    for (const c of ['prm:observation', 'prm:transactional', 'prm:retention', 'prm:location-history',
      'prm:correlation', 'prm:profiling', 'prm:inference', 'prm:third-party-sharing', 'prm:sale',
      'prm:commercialization', 'prm:advertising', 'prm:ai-training', 'prm:biometric',
      'prm:law-enforcement', 'prm:emergency', 'prm:deletion']) {
      expect(covered, `missing ${c}`).toContain(c)
    }
  })

  it('separates the moment of observation from everything downstream', () => {
    // The whole argument in one assertion: the scan is authorized, the database built from scans is not.
    expect(rules.find((r) => r.category === 'prm:observation')?.decision).toBe('allow')
    const t = rules.find((r) => r.category === 'prm:transactional')
    expect(t?.decision).toBe('conditional')
    expect(t?.conditions?.maxRetention).toBe('PT0S')
    expect(t?.conditions?.purposes).toContain('prm:hotlist-comparison')
    expect(rules.find((r) => r.category === 'prm:retention')?.conditions?.maxRetention).toBe('PT0S')
  })

  it('permits use tied to a valid individualized investigation, with limits', () => {
    const r = rules.find((x) => x.category === 'prm:law-enforcement')
    expect(r?.decision).toBe('conditional')
    expect(r?.conditions?.requiresLegalProcess).toBe(true)
    expect(r?.conditions?.purposes).toContain('prm:active-investigation')
    expect(r?.conditions?.maxRetention).toBe('P60D')
  })

  it('permits emergency use where legally authorized', () => {
    const r = rules.find((x) => x.category === 'prm:emergency')
    expect(r?.decision).toBe('conditional')
    expect(r?.basisAcknowledged).toContain('vital-interest')
  })

  it.each(['prm:location-history', 'prm:correlation', 'prm:profiling', 'prm:inference',
    'prm:third-party-sharing', 'prm:sale', 'prm:commercialization', 'prm:advertising',
    'prm:ai-training', 'prm:biometric'])('objects to %s', (c) => {
    expect(rules.find((r) => r.category === c)?.decision).toBe('deny')
  })

  it('concedes lawful override rather than claiming rights it cannot assert', () => {
    const r = rules.find((x) => x.category === 'prm:law-enforcement')
    expect(r?.basisAcknowledged).toContain('court-order')
    expect(r?.basisAcknowledged).toContain('statutory-override')
  })

  it('defaults to California and accepts another state', () => {
    expect(TEMPLATES.alpr.defaultJurisdictions()).toEqual(['US-CA', 'US'])
    expect(TEMPLATES.alpr.defaultJurisdictions('TX')).toEqual(['US-TX', 'US'])
    expect(alprRules({ state: 'TX' }).find((r) => r.category === 'prm:transactional')
      ?.conditions?.jurisdictions).toEqual(['US-TX'])
  })

  it('has no duplicate categories', () => {
    const ids = rules.map((r) => r.category)
    expect(new Set(ids).size).toBe(ids.length)
  })
})

describe('ALPR prose does not overstate legal effect', () => {
  const text = alprHumanReadable({ agency: 'the City of Whittier Police Department', state: 'CA' })

  it('states what it authorizes before what it objects to', () => {
    expect(text.indexOf('What I authorize')).toBeLessThan(text.indexOf('What I object to'))
  })

  it('explicitly disclaims creating rights', () => {
    expect(text).toMatch(/does not purport to create rights that do not already exist/)
    expect(text).toMatch(/I make no claim here about which/)
  })

  it('concedes that a court order or statutory mandate governs', () => {
    expect(text).toMatch(/I acknowledge that it governs/)
  })

  it('makes no unqualified legal assertion', () => {
    // Phrases that would turn a records request into a dismissible demand.
    for (const forbidden of [
      'you are required by law', 'you must comply', 'is unlawful', 'violates the law',
      'legally binding', 'you are prohibited'
    ]) {
      expect(text.toLowerCase(), `prose must not assert: ${forbidden}`).not.toContain(forbidden)
    }
  })

  it('asks a question the recipient can actually answer', () => {
    expect(text).toMatch(/which of these restrictions your systems can and cannot honour/)
    expect(text).toMatch(/A partial answer with a citation is more useful/)
  })

  it('names the agency it is addressed to', () => {
    expect(text).toContain('the City of Whittier Police Department')
  })
})
