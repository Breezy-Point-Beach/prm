import { describe, expect, it } from 'vitest'
import {
  presentCategory, presentRule, presentIdentifierNamespace, presentIdentifierValue,
  humanDuration, ALPR_PRESENTATION, GENERIC_PRESENTATION
} from '../src/presentation.js'
import { alprRules } from '../src/templates/alpr.js'
import { categoryLabel } from '../src/categories.js'
import type { Rule } from '../src/types.js'

describe('a presentation profile changes WORDS ONLY', () => {
  it('never alters a decision', () => {
    for (const rule of alprRules({ state: 'CA' })) {
      expect(presentRule(rule, ALPR_PRESENTATION).decision).toBe(rule.decision)
      expect(presentRule(rule, GENERIC_PRESENTATION).decision).toBe(rule.decision)
    }
  })

  it('never mutates the rule it is given', () => {
    // The signed document must be untouched by anything in this layer.
    const rules = alprRules({ state: 'CA' })
    const before = JSON.stringify(rules)
    for (const r of rules) { presentRule(r, ALPR_PRESENTATION); presentRule(r, GENERIC_PRESENTATION) }
    expect(JSON.stringify(rules)).toBe(before)
  })

  it('only overrides categories that actually exist', () => {
    for (const category of Object.keys(ALPR_PRESENTATION.labels ?? {})) {
      expect(categoryLabel(category), `${category} is not a real category`).not.toBe(category)
    }
  })

  it('falls back to the core vocabulary for anything it does not override', () => {
    expect(presentCategory('prm:sale', ALPR_PRESENTATION)).toBe(categoryLabel('prm:sale'))
    expect(presentCategory('prm:biometric', ALPR_PRESENTATION)).toBe(categoryLabel('prm:biometric'))
  })
})

describe('ALPR wording', () => {
  it('renders the hotlist check in words a records officer uses', () => {
    // "Necessary transactional use" is precise in the ontology and meaningless in a letter about
    // plate readers: nobody thinks of a hotlist check as a transaction.
    expect(presentCategory('prm:transactional', ALPR_PRESENTATION)).toBe('Immediate automated comparison')
    expect(presentCategory('prm:transactional', GENERIC_PRESENTATION)).toBe('Necessary transactional use')
  })

  it('spells out what the comparison condition means', () => {
    const rule = alprRules().find((r) => r.category === 'prm:transactional') as Rule
    expect(presentRule(rule, ALPR_PRESENTATION).detail)
      .toBe('Hotlist comparison only; no retention beyond the moment of comparison.')
  })

  it('renders durations as English, not ISO 8601', () => {
    expect(humanDuration('P60D')).toBe('60 days')
    expect(humanDuration('P1D')).toBe('1 day')
    expect(humanDuration('P90D')).toBe('90 days')
    expect(humanDuration('PT0S')).toBe('no time at all')
    expect(humanDuration('P1Y6M')).toBe('1 year, 6 months')
    expect(humanDuration('not-a-duration')).toBe('not-a-duration')
  })

  it('shows a retention ceiling in days inside a rule detail', () => {
    const rule = alprRules().find((r) => r.category === 'prm:law-enforcement') as Rule
    const detail = presentRule(rule, ALPR_PRESENTATION).detail
    expect(detail).toContain('60 days')
    expect(detail).not.toContain('P60D')
  })
})

describe('identifier labels read as English, not schema keys', () => {
  it('names the issuing state when the value carries it', () => {
    expect(presentIdentifierNamespace('us-license-plate', 'US-CA-7ABC123')).toBe('California license plate')
    expect(presentIdentifierNamespace('us-license-plate', 'US-TX-ABC123')).toBe('Texas license plate')
  })

  it('degrades gracefully without a value', () => {
    expect(presentIdentifierNamespace('us-license-plate')).toBe('License plate')
  })

  it('never renders a raw schema key', () => {
    for (const ns of ['us-license-plate', 'vin', 'email', 'phone', 'device-id', 'account-id']) {
      const label = presentIdentifierNamespace(ns, ns === 'us-license-plate' ? 'US-CA-X' : undefined)
      expect(label, `${ns} rendered as a schema key`).not.toBe(ns.replace(/-/g, ' '))
      expect(label[0]).toBe(label[0]?.toUpperCase())
    }
  })

  it('drops the canonical prefix once the label already states the state', () => {
    // "California license plate: US-CA-7ABC123" says California twice.
    expect(presentIdentifierValue('us-license-plate', 'US-CA-7ABC123')).toBe('7ABC123')
    expect(presentIdentifierValue('email', 'a@example.org')).toBe('a@example.org')
  })
})
