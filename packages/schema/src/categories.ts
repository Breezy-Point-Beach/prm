import type { Category, CoreCategory, Decision, Policy, Rule } from './types.js'

/**
 * The v1 core rights vocabulary, with the human labels used in the UI and the PDF, and the DPV
 * term each aligns to so enterprise privacy tooling can ingest a PRM policy.
 */
export const CORE_CATEGORIES: ReadonlyArray<{
  id: CoreCategory
  label: string
  description: string
  dpv: string
}> = [
  { id: 'prm:observation', label: 'Initial observation',
    description: 'The act of sensing or recording me in the first place.', dpv: 'dpv:Collect' },
  { id: 'prm:transactional', label: 'Necessary transactional use',
    description: 'Use strictly needed to complete the interaction I started.', dpv: 'dpv:ServiceProvision' },
  { id: 'prm:retention', label: 'Retention',
    description: 'Keeping the record after the interaction is over.', dpv: 'dpv:Store' },
  { id: 'prm:location-history', label: 'Historical location storage',
    description: 'Keeping a time-stamped series of where I have been.', dpv: 'dpv:Store' },
  { id: 'prm:correlation', label: 'Cross-database correlation',
    description: 'Joining this record to records from other systems or sources.', dpv: 'dpv:Combine' },
  { id: 'prm:profiling', label: 'Behavioral profiling',
    description: 'Building a profile of my behavior or habits.', dpv: 'dpv:Profiling' },
  { id: 'prm:inference', label: 'Derived inference',
    description: 'Deriving new facts about me that were never observed.', dpv: 'dpv:Infer' },
  { id: 'prm:third-party-sharing', label: 'Third-party sharing',
    description: 'Disclosing the record to another organization.', dpv: 'dpv:Share' },
  { id: 'prm:sale', label: 'Sale',
    description: 'Disclosing the record for money.', dpv: 'dpv:Sell' },
  { id: 'prm:commercialization', label: 'Commercialization',
    description: 'Any commercial exploitation short of an outright sale.', dpv: 'dpv:CommercialInterest' },
  { id: 'prm:advertising', label: 'Advertising',
    description: 'Targeting, measurement, or audience building.', dpv: 'dpv:Advertising' },
  { id: 'prm:ai-training', label: 'AI / model training',
    description: 'Including the record in training, fine-tuning, or evaluation data.', dpv: 'dpv:AlgorithmicLogic' },
  { id: 'prm:biometric', label: 'Biometric processing',
    description: 'Face, gait, voice, iris, or other biometric analysis.', dpv: 'dpv:Biometric' },
  { id: 'prm:law-enforcement', label: 'Law-enforcement use',
    description: 'Disclosure to, or querying by, law enforcement.', dpv: 'dpv:LegalCompliance' },
  { id: 'prm:emergency', label: 'Emergency use',
    description: 'Use during an imminent threat to life.', dpv: 'dpv:ProtectionOfNaturalPerson' },
  { id: 'prm:deletion', label: 'Deletion after purpose completion',
    description: 'Affirmatively deleting the record once its purpose is done.', dpv: 'dpv:Erase' }
]

const CORE_IDS = new Set<string>(CORE_CATEGORIES.map((c) => c.id))

export function isCoreCategory (c: string): c is CoreCategory {
  return CORE_IDS.has(c)
}

export function categoryLabel (c: Category): string {
  return CORE_CATEGORIES.find((x) => x.id === c)?.label ?? c
}

/**
 * Resolve the effective decision for a category, FAIL-CLOSED.
 *
 * spec/schemas §category: "Unknown categories MUST be treated as 'deny' by conservative processors."
 * A category absent from the policy is also 'deny': a policy that does not grant something has not
 * granted it. Both defaults exist so that a processor which does not understand a newer vocabulary
 * cannot accidentally read silence as permission.
 */
export function resolveDecision (policy: Policy, category: Category): {
  decision: Decision
  rule?: Rule
  reason: 'explicit' | 'unknown-category-denied' | 'absent-denied'
} {
  const rule = policy.rules.find((r) => r.category === category)
  if (rule) return { decision: rule.decision, rule, reason: 'explicit' }
  if (!isCoreCategory(category)) return { decision: 'deny', reason: 'unknown-category-denied' }
  return { decision: 'deny', reason: 'absent-denied' }
}

/** Categories present in a policy that this build does not recognize. Surface these to a human. */
export function unknownCategories (policy: Policy): string[] {
  return policy.rules.map((r) => r.category).filter((c) => !isCoreCategory(c))
}
