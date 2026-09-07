import type { Policy, Rule } from './types.js'
import { CORE_CATEGORIES, categoryLabel } from './categories.js'

/**
 * Keeping the prose and the machine rules from drifting apart.
 *
 * The policy carries human text INSIDE the signed bytes so the two cannot be separated. But that
 * alone does not stop them from disagreeing: a user can write "I allow anything" above a rules matrix
 * that denies everything, sign it, and now the document says two contradictory things with equal
 * authority.
 *
 * Two mechanisms, in order of strength:
 *
 *   1. STRUCTURAL (renderRulesSummary). Every signed policy carries a summary section generated
 *      deterministically from the rules at signing time. The user cannot edit it, and it is
 *      regenerated on every signature, so it is always an accurate rendering of the machine terms.
 *      Drift is prevented, not detected.
 *
 *   2. ADVISORY (checkProseAlignment). The user's own narrative is free text, and it is scanned for
 *      statements that appear to contradict the rules. This is a heuristic and is treated as one: it
 *      warns, it does not block, and it never edits the user's words. A false positive that silently
 *      rewrote someone's policy would be far worse than a missed contradiction.
 */

export const RULES_SUMMARY_HEADING = '## Summary of my machine-readable terms'

const DECISION_HEADING: Record<Rule['decision'], string> = {
  allow: 'I authorize',
  conditional: 'I authorize only under these conditions',
  deny: 'I object to and do not consent to'
}

/** Deterministic markdown for a rules matrix. Same rules in, same bytes out. */
export function renderRulesSummary (rules: Rule[]): string {
  const order: Array<Rule['decision']> = ['allow', 'conditional', 'deny']
  const lines: string[] = [RULES_SUMMARY_HEADING, '']

  for (const decision of order) {
    const group = rules.filter((r) => r.decision === decision)
    if (group.length === 0) continue
    lines.push(`**${DECISION_HEADING[decision]}:**`, '')
    for (const rule of group) {
      lines.push(`- ${categoryLabel(rule.category)}${conditionSuffix(rule)}`)
    }
    lines.push('')
  }

  const silent = CORE_CATEGORIES.filter((c) => !rules.some((r) => r.category === c.id))
  if (silent.length > 0) {
    lines.push('**Not addressed here** (treat as not authorized):', '')
    lines.push(`- ${silent.map((c) => c.label).join(', ')}`, '')
  }

  lines.push(
    '*This section is generated from the machine-readable terms in this document and cannot be',
    '*edited separately. If it disagrees with anything above, the machine-readable terms govern.*'
  )
  return lines.join('\n')
}

function conditionSuffix (rule: Rule): string {
  const c = rule.conditions
  if (!c) return ''
  const bits: string[] = []
  if (c.maxRetention === 'PT0S') bits.push('no retention beyond the moment of use')
  else if (c.maxRetention) bits.push(`retention limited to ${c.maxRetention}`)
  if (c.requiresLegalProcess) bits.push('requires legal process')
  if (c.requiresNotice) bits.push('requires written notice to me')
  if (c.recipients?.includes('prm:none')) bits.push('no recipients')
  if (c.purposes?.length) bits.push(`only for: ${c.purposes.join(', ')}`)
  return bits.length > 0 ? ` — ${bits.join('; ')}` : ''
}

/**
 * Compose the full signed prose: the user's narrative, then the generated summary.
 *
 * Called at signing time, always. An existing summary is stripped first so re-signing never stacks
 * duplicates and never preserves a stale one.
 */
export function composeHumanReadable (narrative: string, rules: Rule[]): string {
  return `${stripRulesSummary(narrative).trimEnd()}\n\n---\n\n${renderRulesSummary(rules)}\n`
}

/** Remove a previously generated summary, so the user only ever edits their own words. */
export function stripRulesSummary (text: string): string {
  const at = text.indexOf(RULES_SUMMARY_HEADING)
  if (at === -1) return text
  const separator = text.lastIndexOf('\n---', at)
  return text.slice(0, separator === -1 ? at : separator)
}

export interface ProseDivergence {
  category: string
  /** What the machine-readable rule says. */
  ruleDecision: Rule['decision']
  /** What the narrative appears to say. */
  proseSuggests: 'authorizes' | 'objects'
  quote: string
  message: string
}

// Phrases that indicate the writer is authorizing, versus objecting. Matched per sentence.
const AUTHORIZES = /\b(?:i (?:permit|allow|authorize|consent to|agree to|am happy for|do not object to)|is (?:permitted|allowed|authorized))\b/i
const OBJECTS = /\b(?:i (?:object|do not (?:consent|permit|allow|authorize|agree)|refuse|withhold consent|prohibit))\b/i

// Words that identify a category inside a sentence. Deliberately conservative: a missed
// contradiction is a warning nobody sees, while a false positive nags at every signature.
const CATEGORY_WORDS: Record<string, RegExp> = {
  'prm:retention': /\bretain(?:ing|ed)?\b|\bretention\b|\bkeep(?:ing)? (?:the |these )?(?:record|read|data)/i,
  'prm:location-history': /\bmovement (?:history|record)\b|\blocation history\b|\bhistorical (?:location|movement)\b/i,
  'prm:correlation': /\bcorrelat(?:e|ing|ion)\b|\bcombin(?:e|ing) (?:it |them |these )?with\b/i,
  'prm:profiling': /\bprofil(?:e|ing)\b/i,
  'prm:inference': /\binfer(?:ence|ring)?\b|\bpattern[- ]of[- ]life\b/i,
  'prm:third-party-sharing': /\bshar(?:e|ing)\b|\bdisclos(?:e|ure|ing)\b/i,
  'prm:sale': /\bsell(?:ing)?\b|\bsale\b/i,
  'prm:commercialization': /\bcommercial(?:ise|ize|isation|ization|ly)?\b/i,
  'prm:advertising': /\badvertis(?:e|ing|ement)\b|\bmarketing\b/i,
  'prm:ai-training': /\b(?:ai|machine learning|model) train(?:ing)?\b|\btrain(?:ing)? (?:an? )?model\b/i,
  'prm:biometric': /\bbiometric\b|\bfacial recognition\b/i,
  'prm:observation': /\bobserv(?:e|ation|ing)\b|\bscan(?:ning|ned)?\b|\bphotograph(?:ing|ed)?\b/i,
  'prm:sale-or-share': /\bsell or share\b/i
}

/**
 * Look for narrative statements that contradict the rules.
 *
 * Advisory only. Sentence-level matching on explicit first-person phrasing, which misses plenty —
 * that is the intended trade. It exists to catch the case where someone edits the prose to say the
 * opposite of what they set in the matrix and does not notice before signing.
 */
export function checkProseAlignment (narrative: string, rules: Rule[]): ProseDivergence[] {
  const out: ProseDivergence[] = []
  const sentences = stripRulesSummary(narrative)
    .replace(/\n+/g, ' ')
    .split(/(?<=[.;:!?])\s+/)
    .map((s) => s.trim())
    .filter(Boolean)

  for (const sentence of sentences) {
    const authorizes = AUTHORIZES.test(sentence)
    const objects = OBJECTS.test(sentence)
    // Ambiguous or neutral sentences are left alone.
    if (authorizes === objects) continue

    for (const rule of rules) {
      const pattern = CATEGORY_WORDS[rule.category]
      if (!pattern?.test(sentence)) continue

      const label = categoryLabel(rule.category)
      if (authorizes && rule.decision === 'deny') {
        out.push({
          category: rule.category,
          ruleDecision: rule.decision,
          proseSuggests: 'authorizes',
          quote: sentence,
          message:
            `Your text appears to authorize ${label}, but the machine-readable terms object to it. ` +
            'A reader and a machine would take away opposite meanings.'
        })
      } else if (objects && rule.decision === 'allow') {
        out.push({
          category: rule.category,
          ruleDecision: rule.decision,
          proseSuggests: 'objects',
          quote: sentence,
          message:
            `Your text appears to object to ${label}, but the machine-readable terms authorize it. ` +
            'A reader and a machine would take away opposite meanings.'
        })
      }
    }
  }
  // One warning per category is enough; repeating it per sentence is noise.
  const seen = new Set<string>()
  return out.filter((d) => (seen.has(d.category) ? false : (seen.add(d.category), true)))
}

/** Everything the "what a machine will verify" preview needs, without re-deriving it in the UI. */
export function machineSummary (policy: Policy): Array<{
  category: string
  label: string
  decision: Rule['decision']
  conditions: string
}> {
  return policy.rules.map((r) => ({
    category: r.category,
    label: categoryLabel(r.category),
    decision: r.decision,
    conditions: conditionSuffix(r).replace(/^ — /, '')
  }))
}
