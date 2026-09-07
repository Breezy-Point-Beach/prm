import type { Category, Rule } from './types.js'
import { categoryLabel } from './categories.js'

/**
 * Presentation profiles — how a category is WORDED for a human reader.
 *
 * This layer exists because the vocabulary that is right for a machine is often wrong for a records
 * officer. "Necessary transactional use" is precise inside the PRM ontology and meaningless to
 * someone reading a notice about plate readers, who does not think of a hotlist check as a
 * transaction.
 *
 * THE HARD RULE: a profile may only change WORDS. It cannot change a decision, a condition, a
 * category, or anything else that a verifier reads. The signed document is untouched; only the
 * rendering differs. A test asserts that applying any profile leaves the rules byte-identical.
 *
 * This is deliberately NOT used by renderRulesSummary(), which goes inside the signed bytes. That
 * summary must stay a faithful rendering of the machine vocabulary, because it travels with the
 * signature. Profiles apply to presentation surfaces only — the PDF, and the web UI.
 */

export interface PresentationProfile {
  id: string
  description: string
  /** Category -> human label for this context. */
  labels?: Partial<Record<Category, string>>
  /** Category -> replacement for the auto-generated condition line. */
  conditions?: Partial<Record<Category, string>>
}

/**
 * ALPR profile.
 *
 * Only categories where the generic wording actively misleads a non-technical reader are overridden.
 * Everything else falls through to the core vocabulary, because a profile that renames everything is
 * a second vocabulary, and a second vocabulary drifts.
 */
export const ALPR_PRESENTATION: PresentationProfile = {
  id: 'prm:presentation:alpr:v1',
  description: 'Wording for notices about automated license plate readers.',
  labels: {
    'prm:transactional': 'Immediate automated comparison',
    'prm:retention': 'Retention of a read after comparison',
    'prm:location-history': 'Historical location storage and search',
    'prm:correlation': 'Aggregation and cross-database correlation',
    'prm:inference': 'Derived movement inference',
    'prm:observation': 'Initial observation'
  },
  conditions: {
    'prm:transactional': 'Hotlist comparison only; no retention beyond the moment of comparison.'
  }
}

export const GENERIC_PRESENTATION: PresentationProfile = {
  id: 'prm:presentation:generic:v1',
  description: 'The core PRM vocabulary, unmodified.'
}

/** Human label for a category under a profile. Falls back to the core vocabulary. */
export function presentCategory (category: Category, profile: PresentationProfile = GENERIC_PRESENTATION): string {
  return profile.labels?.[category] ?? categoryLabel(category)
}

/**
 * Render one rule for display.
 *
 * Returns words only. The caller must not derive any decision from this — `rule.decision` is the
 * authoritative value, and it is passed straight through untouched.
 */
export function presentRule (
  rule: Rule,
  profile: PresentationProfile = GENERIC_PRESENTATION
): { label: string; detail: string; decision: Rule['decision'] } {
  return {
    label: presentCategory(rule.category, profile),
    detail: profile.conditions?.[rule.category] ?? describeConditions(rule),
    decision: rule.decision
  }
}

function describeConditions (rule: Rule): string {
  const c = rule.conditions
  if (!c) return ''
  const parts: string[] = []
  if (c.maxRetention === 'PT0S') parts.push('no retention beyond the moment of use')
  else if (c.maxRetention) parts.push(`retention limited to ${humanDuration(c.maxRetention)}`)
  if (c.requiresLegalProcess) parts.push('requires legal process')
  if (c.requiresNotice) parts.push('requires written notice to me')
  if (c.recipients?.includes('prm:none')) parts.push('no recipients')
  if (c.purposes?.length) parts.push(`only for: ${c.purposes.map(shortPurpose).join(', ')}`)
  return parts.length > 0 ? `${parts.join('; ')}.` : ''
}

/** "P60D" reads as machine output in a letter; "60 days" does not. */
export function humanDuration (iso: string): string {
  const m = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(iso)
  if (!m) return iso
  const [, y, mo, w, d, h, mi, s] = m
  const bits: string[] = []
  const plural = (n: string, unit: string) => `${n} ${unit}${n === '1' ? '' : 's'}`
  if (y) bits.push(plural(y, 'year'))
  if (mo) bits.push(plural(mo, 'month'))
  if (w) bits.push(plural(w, 'week'))
  if (d) bits.push(plural(d, 'day'))
  if (h) bits.push(plural(h, 'hour'))
  if (mi) bits.push(plural(mi, 'minute'))
  if (s && s !== '0') bits.push(plural(s, 'second'))
  if (bits.length === 0) return 'no time at all'
  return bits.join(', ')
}

/** Strip the namespace prefix from a purpose URI for display. */
function shortPurpose (purpose: string): string {
  return purpose.replace(/^prm:/, '').replace(/^dpv:/, '').replace(/-/g, ' ')
}

const US_STATES: Record<string, string> = {
  AL: 'Alabama', AK: 'Alaska', AZ: 'Arizona', AR: 'Arkansas', CA: 'California', CO: 'Colorado',
  CT: 'Connecticut', DE: 'Delaware', FL: 'Florida', GA: 'Georgia', HI: 'Hawaii', ID: 'Idaho',
  IL: 'Illinois', IN: 'Indiana', IA: 'Iowa', KS: 'Kansas', KY: 'Kentucky', LA: 'Louisiana',
  ME: 'Maine', MD: 'Maryland', MA: 'Massachusetts', MI: 'Michigan', MN: 'Minnesota',
  MS: 'Mississippi', MO: 'Missouri', MT: 'Montana', NE: 'Nebraska', NV: 'Nevada',
  NH: 'New Hampshire', NJ: 'New Jersey', NM: 'New Mexico', NY: 'New York', NC: 'North Carolina',
  ND: 'North Dakota', OH: 'Ohio', OK: 'Oklahoma', OR: 'Oregon', PA: 'Pennsylvania',
  RI: 'Rhode Island', SC: 'South Carolina', SD: 'South Dakota', TN: 'Tennessee', TX: 'Texas',
  UT: 'Utah', VT: 'Vermont', VA: 'Virginia', WA: 'Washington', WV: 'West Virginia',
  WI: 'Wisconsin', WY: 'Wyoming', DC: 'District of Columbia', PR: 'Puerto Rico'
}

/**
 * Human label for an identifier namespace.
 *
 * "us license plate" is a schema key with the hyphens taken out, and it reads like one. A person
 * receiving a letter should see "California license plate".
 */
export function presentIdentifierNamespace (namespace: string, value?: string): string {
  switch (namespace) {
    case 'us-license-plate': {
      const state = value ? /^US-([A-Z]{2})-/.exec(value)?.[1] : undefined
      const name = state ? US_STATES[state] : undefined
      return name ? `${name} license plate` : 'License plate'
    }
    case 'vin': return 'Vehicle identification number (VIN)'
    case 'email': return 'Email address'
    case 'phone': return 'Phone number'
    case 'device-id': return 'Device identifier'
    case 'account-id': return 'Account identifier'
    default: return namespace.replace(/-/g, ' ').replace(/^./, (c) => c.toUpperCase())
  }
}

/** Show a plate as "7ABC123" rather than the canonical "US-CA-7ABC123" once it is already labelled. */
export function presentIdentifierValue (namespace: string, value: string): string {
  if (namespace === 'us-license-plate') {
    return value.replace(/^US-[A-Z]{2}-/, '')
  }
  return value
}
