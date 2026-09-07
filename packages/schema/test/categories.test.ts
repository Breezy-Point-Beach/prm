import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { CORE_CATEGORIES, resolveDecision, unknownCategories, isCoreCategory } from '../src/categories.js'
import { alprRules } from '../src/templates/alpr.js'
import type { Policy } from '../src/types.js'

const policy = (): Policy => JSON.parse(
  readFileSync(resolve(import.meta.dirname, '../../../spec/examples/policies/alpr-policy-v1.json'), 'utf8')
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

describe('ALPR template', () => {
  const rules = alprRules()

  it('covers every core category the brief requires', () => {
    const covered = new Set(rules.map((r) => r.category))
    for (const c of ['prm:observation', 'prm:transactional', 'prm:retention', 'prm:location-history',
      'prm:correlation', 'prm:profiling', 'prm:inference', 'prm:third-party-sharing', 'prm:sale',
      'prm:commercialization', 'prm:advertising', 'prm:ai-training', 'prm:biometric',
      'prm:law-enforcement', 'prm:emergency', 'prm:deletion']) {
      expect(covered, `missing ${c}`).toContain(c)
    }
  })

  it('permits observation and the immediate hotlist check', () => {
    expect(rules.find((r) => r.category === 'prm:observation')?.decision).toBe('allow')
    const t = rules.find((r) => r.category === 'prm:transactional')
    expect(t?.decision).toBe('conditional')
    expect(t?.conditions?.maxRetention).toBe('PT0S')
  })

  it('denies retention of a non-hit read', () => {
    expect(rules.find((r) => r.category === 'prm:retention')?.conditions?.maxRetention).toBe('PT0S')
  })

  it.each(['prm:location-history', 'prm:correlation', 'prm:profiling', 'prm:inference',
    'prm:third-party-sharing', 'prm:sale', 'prm:commercialization', 'prm:advertising',
    'prm:ai-training', 'prm:biometric'])('denies %s', (c) => {
    expect(rules.find((r) => r.category === c)?.decision).toBe('deny')
  })

  it('concedes lawful override on law-enforcement use', () => {
    const r = rules.find((x) => x.category === 'prm:law-enforcement')
    expect(r?.basisAcknowledged).toContain('court-order')
    expect(r?.basisAcknowledged).toContain('statutory-override')
    expect(r?.conditions?.requiresLegalProcess).toBe(true)
  })

  it('has no duplicate categories', () => {
    const ids = rules.map((r) => r.category)
    expect(new Set(ids).size).toBe(ids.length)
  })
})
