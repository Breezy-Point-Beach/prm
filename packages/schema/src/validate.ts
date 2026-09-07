// ajv and ajv-formats ship CommonJS, so a default import resolves to the module namespace under
// NodeNext rather than to the callable. ajv exposes the class as a named export; ajv-formats only
// has a default, which is reachable at `.default`. Both forms are correct at runtime in Node ESM,
// Vitest, and a browser bundle, and both typecheck without an `any`.
import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js'
import addFormatsModule from 'ajv-formats'

const addFormats = addFormatsModule.default
import { policySchema, authorizationSchema, keyEventSchema, ledgerEntrySchema } from './generated/schemas.js'
import type { Authorization, KeyEvent, LedgerEntry, Policy } from './types.js'

export interface ValidationResult<T> {
  valid: boolean
  errors: string[]
  /** Present only when valid. */
  value?: T
}

// `strict: false` because the schemas use $comment and annotation keywords intentionally.
const ajv = new Ajv2020({ strict: false, allErrors: true, allowUnionTypes: true })
addFormats(ajv)
for (const s of [policySchema, authorizationSchema, keyEventSchema, ledgerEntrySchema]) {
  ajv.addSchema(s as object)
}

const compiled = new Map<string, ValidateFunction>()
function validator (id: string): ValidateFunction {
  const cached = compiled.get(id)
  if (cached) return cached
  const found = ajv.getSchema(id)
  if (!found) throw new Error(`schema not registered: ${id}`)
  compiled.set(id, found)
  return found
}

function format (errors: ErrorObject[] | null | undefined): string[] {
  if (!errors) return []
  return errors.map((e) => {
    const at = e.instancePath === '' ? '(root)' : e.instancePath
    const params = Object.entries(e.params ?? {})
      .map(([k, val]) => `${k}=${JSON.stringify(val)}`)
      .join(' ')
    return `${at} ${e.message}${params ? ` [${params}]` : ''}`.trim()
  })
}

function run<T> (id: string, doc: unknown): ValidationResult<T> {
  const v = validator(id)
  const valid = v(doc) as boolean
  return valid
    ? { valid: true, errors: [], value: doc as T }
    : { valid: false, errors: format(v.errors) }
}

const BASE = 'https://prm.dev/schemas'

export const validatePolicy = (d: unknown) => run<Policy>(`${BASE}/prm-policy-v1.schema.json`, d)
export const validateAuthorization = (d: unknown) => run<Authorization>(`${BASE}/prm-authorization-v1.schema.json`, d)
export const validateKeyEvent = (d: unknown) => run<KeyEvent>(`${BASE}/prm-key-event-v1.schema.json`, d)
export const validateLedgerEntry = (d: unknown) => run<LedgerEntry>(`${BASE}/prm-ledger-entry-v1.schema.json`, d)

/** Throwing variants, for call sites where an invalid document is a programmer error. */
function assertValid<T> (r: ValidationResult<T>, kind: string): T {
  if (!r.valid) throw new SchemaValidationError(kind, r.errors)
  return r.value as T
}

export class SchemaValidationError extends Error {
  constructor (public readonly kind: string, public readonly errors: string[]) {
    super(`${kind} failed schema validation:\n  ${errors.join('\n  ')}`)
    this.name = 'SchemaValidationError'
  }
}

export const assertPolicy = (d: unknown) => assertValid(validatePolicy(d), 'policy')
export const assertAuthorization = (d: unknown) => assertValid(validateAuthorization(d), 'authorization')
export const assertKeyEvent = (d: unknown) => assertValid(validateKeyEvent(d), 'key event')
export const assertLedgerEntry = (d: unknown) => assertValid(validateLedgerEntry(d), 'ledger entry')

/**
 * Structural checks the JSON Schema cannot express.
 *
 * JSON Schema can require that previousPolicyHash is null when version is 1, but it cannot check
 * cross-document invariants or semantic contradictions. These are warnings, not validation failures:
 * a policy that trips one is still a valid signed document, and refusing to render it would be worse
 * than telling the reader what is odd about it.
 */
export function policyWarnings (p: Policy): string[] {
  const w: string[] = []

  if (p.version === 1 && p.previousPolicyHash !== null) {
    w.push('version 1 must have previousPolicyHash === null')
  }
  if (p.version > 1 && p.previousPolicyHash === null) {
    w.push(`version ${p.version} must chain to a previous policy`)
  }
  if (p.expirationDate && p.expirationDate <= p.effectiveDate) {
    w.push('expirationDate is not after effectiveDate')
  }

  const seen = new Set<string>()
  for (const r of p.rules) {
    if (seen.has(r.category)) w.push(`duplicate rule for category ${r.category}`)
    seen.add(r.category)
    if (r.decision === 'conditional' && !r.conditions) {
      w.push(`${r.category}: conditional decision without conditions`)
    }
  }

  // A denial the issuer simultaneously concedes can be overridden is not a contradiction, but a
  // denial with retention conditions attached usually means the author meant 'conditional'.
  for (const r of p.rules) {
    if (r.decision === 'deny' && r.conditions?.maxRetention) {
      w.push(`${r.category}: decision is 'deny' but a retention period is set — did you mean 'conditional'?`)
    }
  }
  return w
}
