/**
 * @prm/schema — document types, normative JSON Schemas, validation, normalization, templates.
 *
 * This package deliberately contains no cryptography and makes no network calls.
 */
export * from './types.js'
export * from './categories.js'
export * from './normalize.js'
export * from './validate.js'
export * from './prose.js'
export * from './templates/alpr.js'
export {
  policySchema,
  authorizationSchema,
  keyEventSchema,
  ledgerEntrySchema,
  allSchemas
} from './generated/schemas.js'

/** Signature domain separation strings — spec/NORMATIVE.md §4. */
export const SIGNING_DOMAINS = {
  policy: 'PRM-POLICY-v1',
  authorization: 'PRM-AUTHZ-v1',
  keyEvent: 'PRM-KEYEVENT-v1',
  ledgerEntry: 'PRM-LEDGER-v1',
  signedTreeHead: 'PRM-STH-v1'
} as const

/**
 * Members excluded from the hashed bytes, per document type — spec/NORMATIVE.md §2.
 * Getting this wrong is the single most likely cause of a cross-implementation signature failure.
 */
export const NON_HASHED_MEMBERS = {
  policy: ['id', 'proof'],
  authorization: ['id', 'proof'],
  keyEvent: ['proof'],
  ledgerEntry: ['proof', 'logInclusion'],
  signedTreeHead: ['signature']
} as const

export const PRM_CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://prm.dev/ns/policy/v1'
] as const
