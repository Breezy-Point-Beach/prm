/**
 * Identifier normalization — NORMATIVE.
 *
 * A commitment that depends on whitespace or letter case is useless: the person and the organization
 * would compute different values for the same identifier. These rules are part of the protocol, not
 * a convenience, and they are covered by test vectors.
 *
 * Deliberate non-rule: no provider-specific email canonicalization (Gmail dot/plus stripping). That
 * is a policy judgement about identity, not a normalization, and applying it would silently merge
 * addresses the user considers distinct.
 */

export type Namespace =
  | 'email' | 'phone' | 'us-license-plate' | 'vin' | 'device-id' | 'account-id'

export class NormalizationError extends Error {}

const US_STATES = new Set([
  'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA','ME','MD',
  'MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK','OR','PA','RI','SC',
  'SD','TN','TX','UT','VT','VA','WA','WV','WI','WY','DC','PR','VI','GU','AS','MP'
])

export function normalizeIdentifier (namespace: string, raw: string): string {
  const v = raw.trim()
  if (v.length === 0) throw new NormalizationError('identifier is empty')

  switch (namespace) {
    case 'email': {
      const at = v.lastIndexOf('@')
      if (at <= 0 || at === v.length - 1) throw new NormalizationError(`not an email address: ${v}`)
      // Lower-case the whole address. The local part is technically case-sensitive per RFC 5321,
      // but no real provider treats it that way, and matching must be predictable.
      return v.toLowerCase()
    }
    case 'phone': {
      const digits = v.replace(/[^\d+]/g, '')
      const e164 = digits.startsWith('+') ? digits : `+${digits}`
      if (!/^\+\d{7,15}$/.test(e164)) {
        throw new NormalizationError(`not an E.164 phone number: ${v} (include the country code)`)
      }
      return e164
    }
    case 'us-license-plate': {
      // Canonical form: US-{STATE}-{ALNUM}. Accepts "ca 7abc123", "CA-7ABC-123", "US-CA-7ABC123".
      const cleaned = v.toUpperCase().replace(/^US[-\s]+/, '')
      const m = cleaned.match(/^([A-Z]{2})[-\s]*(.+)$/)
      if (!m) throw new NormalizationError(`expected a two-letter state then the plate, got: ${v}`)
      const state = m[1]!
      const plate = m[2]!.replace(/[^A-Z0-9]/g, '')
      if (!US_STATES.has(state)) throw new NormalizationError(`unknown US state or territory: ${state}`)
      if (plate.length < 2 || plate.length > 8) {
        throw new NormalizationError(`implausible plate: "${plate}" (expected 2-8 alphanumerics)`)
      }
      return `US-${state}-${plate}`
    }
    case 'vin': {
      const vin = v.toUpperCase().replace(/[^A-Z0-9]/g, '')
      // ISO 3779: 17 characters, and I/O/Q are excluded to avoid confusion with 1/0.
      if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(vin)) {
        throw new NormalizationError(`not a valid 17-character VIN: ${v}`)
      }
      return vin
    }
    case 'device-id':
      // Opaque and case-sensitive as issued. Any transformation could collide two distinct devices.
      return v
    case 'account-id': {
      const i = v.indexOf(':')
      if (i <= 0) throw new NormalizationError('expected "{issuer-domain}:{id}"')
      return `${v.slice(0, i).toLowerCase()}:${v.slice(i + 1)}`
    }
    default:
      // Unknown namespaces are trimmed only. Inventing a rule would be worse than doing nothing.
      return v
  }
}

export const NAMESPACES: ReadonlyArray<{ id: Namespace; label: string; placeholder: string; help: string }> = [
  { id: 'us-license-plate', label: 'License plate', placeholder: 'CA 7ABC123',
    help: 'Two-letter state, then the plate. Stored only as a salted commitment.' },
  { id: 'email', label: 'Email address', placeholder: 'you@example.com', help: 'Lower-cased.' },
  { id: 'phone', label: 'Phone number', placeholder: '+1 555 123 4567', help: 'E.164 with country code.' },
  { id: 'vin', label: 'Vehicle VIN', placeholder: '1HGBH41JXMN109186', help: '17 characters.' },
  { id: 'device-id', label: 'Device identifier', placeholder: 'device-abc123', help: 'Used exactly as entered.' },
  { id: 'account-id', label: 'Account at an organization', placeholder: 'example.com:12345',
    help: 'Domain, colon, then your account id.' }
]
