// Validation runs against AHEAD-OF-TIME compiled validators (src/generated/validators.ts), not against
// an Ajv instance built here at run time.
//
// Ajv's normal mode compiles a schema by handing a generated source string to `new Function`, which a
// browser treats as eval. Signing happens in this browser, so a Content-Security-Policy that allowed
// 'unsafe-eval' would hand any XSS the ability to run code beside an unlocked key. Precompiling keeps
// the identical validation logic and removes the run-time eval, so the policy can forbid it outright.
//
// `ErrorObject` is a type-only import: it is erased at build time and pulls no Ajv code into the bundle.
import type { ErrorObject } from 'ajv'
import * as compiled from './generated/validators.js'
import type {
  Authorization, KeyEvent, LedgerEntry, Policy, Notice, DeliveryRecord, ResponseRecord
} from './types.js'

export interface ValidationResult<T> {
  valid: boolean
  errors: string[]
  /** Present only when valid. */
  value?: T
}

/** Shape of a precompiled Ajv validator: a predicate that parks its errors on itself. */
type CompiledValidator = ((doc: unknown) => boolean) & { errors?: ErrorObject[] | null }

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

function run<T> (validate: CompiledValidator, doc: unknown): ValidationResult<T> {
  const valid = validate(doc)
  return valid
    ? { valid: true, errors: [], value: doc as T }
    : { valid: false, errors: format(validate.errors) }
}

export const validatePolicy = (d: unknown) => run<Policy>(compiled.policy, d)
export const validateAuthorization = (d: unknown) => run<Authorization>(compiled.authorization, d)
export const validateKeyEvent = (d: unknown) => run<KeyEvent>(compiled.keyEvent, d)
export const validateLedgerEntry = (d: unknown) => run<LedgerEntry>(compiled.ledgerEntry, d)
export const validateNotice = (d: unknown) => run<Notice>(compiled.notice, d)
export const validateDelivery = (d: unknown) => run<DeliveryRecord>(compiled.delivery, d)
export const validateResponse = (d: unknown) => run<ResponseRecord>(compiled.response, d)

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
export const assertNotice = (d: unknown) => assertValid(validateNotice(d), 'notice')
export const assertDelivery = (d: unknown) => assertValid(validateDelivery(d), 'delivery record')
export const assertResponse = (d: unknown) => assertValid(validateResponse(d), 'response record')

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
