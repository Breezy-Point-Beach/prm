/**
 * The legally careful language a notice must carry.
 *
 * These strings are constants, not template literals assembled in a UI, because they are the part of
 * the product most likely to drift toward overstatement. Every one of them is asserted in tests, and
 * the forbidden-phrase list below is checked against generated notices.
 *
 * The governing principle: PRM records a person's instructions and objections. It does not create
 * legal rights or obligations, and it does not override controlling legal authority. A notice that
 * implies otherwise is easy for a records officer to dismiss wholesale, which costs far more than
 * the careful wording does.
 */

export const PRM_EXPLANATION =
  'Personal Rights Management records my standing instructions, authorizations, and objections ' +
  'concerning downstream processing of personal information associated with me. This notice does ' +
  'not independently create legal rights or obligations where none otherwise exist, and nothing in ' +
  'it overrides a valid court order, statutory mandate, or other controlling legal authority.'

export const OBSERVATION_DISTINCTION =
  'I recognize that lawful initial observation may occur. My policy distinguishes that initial ' +
  'observation from subsequent retention, historical search, aggregation, correlation, sharing, ' +
  'profiling, inference, commercialization, and other secondary processing.'

export const REQUESTED_TREATMENT =
  'Please associate this Personal Rights Management policy with records reasonably identifiable as ' +
  'relating to me and honor the stated instructions and objections to the extent permitted by ' +
  'applicable law, policy, contract, and technical capability.'

export const NON_CONSENT_FALLBACK =
  'If any portion of this policy cannot or will not be honored, this notice should still be treated ' +
  'as a record of my express position and non-consent regarding those downstream uses.'

export const LEGAL_EFFECT_DISCLAIMER = `${PRM_EXPLANATION}\n\n${NON_CONSENT_FALLBACK}`

export const VERIFICATION_NOTE =
  'Verification displayed by PRM is provided for convenience. The underlying artifacts are ' +
  'independently verifiable without PRM.'

/**
 * Phrases a notice must never contain.
 *
 * Each of these implies PRM supplies legal authority that has not been established. Asserting an
 * obligation the issuer cannot support is the fastest way to make the entire notice dismissible.
 */
export const FORBIDDEN_ASSERTIONS: readonly string[] = [
  'you must comply',
  'this is legally binding',
  'legally binding',
  'your continued processing is unlawful',
  'is unlawful',
  'you are required by law',
  'required by law',
  'you are prohibited',
  'failure to comply',
  'we will pursue',
  'under penalty of'
]

/** Returns any forbidden assertion found in the text. Empty means the wording is safe. */
export function findForbiddenAssertions (text: string): string[] {
  const haystack = text.toLowerCase()
  return FORBIDDEN_ASSERTIONS.filter((phrase) => haystack.includes(phrase))
}

/**
 * Topics this notice deliberately does NOT raise.
 *
 * The PRM packet is a notice and an evidentiary artifact, not another information request. Those
 * questions are handled through separate correspondence, and repeating them here would turn a
 * focused notice into a second records request — diluting it and inviting it to be routed and
 * answered as one.
 *
 * Checked by tests against generated notice text.
 */
export const OUT_OF_SCOPE_TOPICS: readonly string[] = [
  'retention schedule',
  'retention period',
  'please provide a list',
  'public records request',
  'california public records act',
  'records request',
  'please disclose',
  'i request a copy',
  'please identify all',
  'what is your legal authority',
  'sharing list',
  'access logs',
  'please explain your',
  'copy of your contract'
]

export function findOutOfScopeTopics (text: string): string[] {
  const haystack = text.toLowerCase()
  return OUT_OF_SCOPE_TOPICS.filter((phrase) => haystack.includes(phrase))
}

/** Human labels for recipient types. Descriptive only; asserts nothing about obligations. */
export const RECIPIENT_TYPE_LABELS: Record<string, string> = {
  'government-agency': 'Government agency',
  'law-enforcement': 'Law enforcement agency',
  company: 'Company',
  'data-processor': 'Data processor',
  vendor: 'Vendor',
  attorney: 'Attorney',
  other: 'Other'
}

export const DELIVERY_METHOD_LABELS: Record<string, string> = {
  email: 'Email',
  'certified-mail': 'Certified mail',
  'postal-mail': 'Postal mail',
  'hand-delivery': 'Hand delivery',
  'web-form': 'Web form',
  other: 'Other'
}

export const RESPONSE_STATUS_LABELS: Record<string, string> = {
  acknowledged: 'Acknowledged',
  accepted: 'Accepted',
  'partially-accepted': 'Partially accepted',
  declined: 'Declined',
  'no-response': 'No response received',
  superseded: 'Superseded'
}
