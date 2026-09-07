import { describe, expect, it } from 'vitest'
import {
  renderRulesSummary, composeHumanReadable, stripRulesSummary, checkProseAlignment,
  RULES_SUMMARY_HEADING, machineSummary
} from '../src/prose.js'
import { alprRules, alprHumanReadable } from '../src/templates/alpr.js'
import type { Policy, Rule } from '../src/types.js'

const rules = alprRules()

describe('generated rules summary prevents drift structurally', () => {
  it('is deterministic — same rules in, same bytes out', () => {
    expect(renderRulesSummary(rules)).toBe(renderRulesSummary(alprRules()))
  })

  it('groups by what is authorized, conditional, and objected to', () => {
    const s = renderRulesSummary(rules)
    expect(s).toContain('I authorize')
    expect(s).toContain('I authorize only under these conditions')
    expect(s).toContain('I object to and do not consent to')
    expect(s.indexOf('I authorize')).toBeLessThan(s.indexOf('I object to'))
  })

  it('spells out conditions in plain language', () => {
    const s = renderRulesSummary(rules)
    expect(s).toContain('no retention beyond the moment of use')
    expect(s).toContain('requires legal process')
  })

  it('names categories the policy is silent about, as not authorized', () => {
    const partial: Rule[] = [{ category: 'prm:sale', decision: 'deny' }]
    const s = renderRulesSummary(partial)
    expect(s).toContain('Not addressed here')
    expect(s).toContain('Initial observation')
  })

  it('states that the machine-readable terms govern', () => {
    expect(renderRulesSummary(rules)).toMatch(/machine-readable terms govern/)
  })

  it('changes when a rule changes', () => {
    const flipped = rules.map((r) => (r.category === 'prm:sale' ? { ...r, decision: 'allow' as const } : r))
    expect(renderRulesSummary(flipped)).not.toBe(renderRulesSummary(rules))
  })
})

describe('composing the signed prose', () => {
  const narrative = alprHumanReadable({ agency: 'the City of Whittier Police Department' })

  it('keeps the narrative and appends the generated summary', () => {
    const composed = composeHumanReadable(narrative, rules)
    expect(composed).toContain('What I authorize')
    expect(composed).toContain(RULES_SUMMARY_HEADING)
  })

  it('is idempotent — re-signing does not stack summaries', () => {
    const once = composeHumanReadable(narrative, rules)
    const twice = composeHumanReadable(once, rules)
    expect(twice).toBe(once)
    expect(twice.split(RULES_SUMMARY_HEADING)).toHaveLength(2)
  })

  it('REGENERATES a stale summary rather than preserving it', () => {
    // The failure this prevents: user edits rules, re-signs, and the document keeps a summary
    // describing the OLD rules — with the same signature authority as the new ones.
    const stale = composeHumanReadable(narrative, rules)
    const changed = rules.map((r) => (r.category === 'prm:sale' ? { ...r, decision: 'allow' as const } : r))
    const fresh = composeHumanReadable(stale, changed)
    expect(fresh).toBe(composeHumanReadable(narrative, changed))
    expect(fresh).not.toBe(stale)
  })

  it('strips a summary back out, leaving the user words untouched', () => {
    expect(stripRulesSummary(composeHumanReadable(narrative, rules)).trimEnd()).toBe(narrative.trimEnd())
  })
})

describe('prose alignment is advisory and conservative', () => {
  it('finds nothing wrong with the default template', () => {
    expect(checkProseAlignment(alprHumanReadable(), rules)).toEqual([])
  })

  it('flags a narrative that authorizes something the rules object to', () => {
    const d = checkProseAlignment('I permit the sale of these records to anyone.', rules)
    expect(d).toHaveLength(1)
    expect(d[0]?.category).toBe('prm:sale')
    expect(d[0]?.proseSuggests).toBe('authorizes')
    expect(d[0]?.message).toMatch(/opposite meanings/)
  })

  it('flags a narrative that objects to something the rules authorize', () => {
    const d = checkProseAlignment('I object to any observation of my vehicle whatsoever.', rules)
    expect(d.some((x) => x.category === 'prm:observation' && x.proseSuggests === 'objects')).toBe(true)
  })

  it('stays quiet on neutral or descriptive sentences', () => {
    expect(checkProseAlignment(
      'This policy concerns retention, sharing, and profiling of plate reads.', rules)).toEqual([])
    expect(checkProseAlignment('Retention periods vary between agencies.', rules)).toEqual([])
  })

  it('reports each category at most once', () => {
    const d = checkProseAlignment(
      'I permit the sale of my data. I allow selling it. I consent to the sale.', rules)
    expect(d.filter((x) => x.category === 'prm:sale')).toHaveLength(1)
  })

  it('ignores the generated summary when scanning', () => {
    // The summary legitimately contains both authorizing and objecting language.
    expect(checkProseAlignment(composeHumanReadable(alprHumanReadable(), rules), rules)).toEqual([])
  })

  it('never modifies the text it is given', () => {
    const before = 'I permit the sale of these records.'
    checkProseAlignment(before, rules)
    expect(before).toBe('I permit the sale of these records.')
  })
})

describe('machine preview', () => {
  it('renders one row per rule with a readable condition', () => {
    const policy = { rules } as Policy
    const rows = machineSummary(policy)
    expect(rows).toHaveLength(rules.length)
    const retention = rows.find((r) => r.category === 'prm:retention')
    expect(retention?.decision).toBe('conditional')
    expect(retention?.conditions).toContain('no retention beyond the moment of use')
    expect(rows.find((r) => r.category === 'prm:sale')?.conditions).toBe('')
  })
})
