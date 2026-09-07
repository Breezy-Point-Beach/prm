/**
 * PRM-JCS — RFC 8785 JSON Canonicalization Scheme, PRM profile.
 *
 * This is the most load-bearing function in the system. Every digest, and therefore every signature,
 * depends on it producing identical bytes in every implementation, forever. A change here
 * retroactively invalidates every signature ever produced.
 *
 * See spec/NORMATIVE.md §1. The PRM profile adds two restrictions to RFC 8785:
 *
 *   1. Integers only. Non-integer numbers throw rather than serialize. This removes the ES6
 *      float-serialization algorithm (the hardest part of RFC 8785 to reimplement correctly) and an
 *      entire class of cross-implementation disagreement. No PRM document has a use for a float.
 *   2. No lone surrogates. An unpaired UTF-16 surrogate throws rather than being escaped.
 */

export class CanonicalizationError extends Error {
  constructor (message: string, public readonly path: string) {
    super(`${message} (at ${path || '(root)'})`)
    this.name = 'CanonicalizationError'
  }
}

/**
 * RFC 8785 string serialization: escape only what must be escaped.
 *
 * JSON.stringify already implements exactly this escape set — \b \t \n \f \r \" \\ and \u00XX for
 * remaining control characters, with non-ASCII emitted literally. We reuse it rather than
 * hand-rolling, but scan first for lone surrogates, which JSON.stringify would silently escape into
 * well-formed-but-different output.
 */
function serializeString (s: string, path: string): string {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0
      if (next < 0xdc00 || next > 0xdfff) {
        throw new CanonicalizationError(`unpaired high surrogate at index ${i}`, path)
      }
      i++
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonicalizationError(`unpaired low surrogate at index ${i}`, path)
    }
  }
  return JSON.stringify(s)
}

function canon (value: unknown, path: string): string {
  if (value === null) return 'null'

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'

    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`${value} is not representable in JSON`, path)
      }
      if (!Number.isInteger(value)) {
        throw new CanonicalizationError(
          `non-integer number ${value}: PRM documents are integers-only (spec/NORMATIVE.md §1)`, path)
      }
      if (!Number.isSafeInteger(value)) {
        throw new CanonicalizationError(`integer ${value} exceeds the safe range`, path)
      }
      // Number.isInteger already excludes -0 reaching here as a distinct value: String(-0) is "0".
      return String(value)

    case 'string':
      return serializeString(value, path)

    case 'bigint':
      throw new CanonicalizationError('bigint is not a JSON type', path)

    case 'undefined':
      throw new CanonicalizationError('undefined is not a JSON value', path)

    case 'function':
    case 'symbol':
      throw new CanonicalizationError(`${typeof value} is not a JSON value`, path)

    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map((v, i) => canon(v, `${path}[${i}]`)).join(',') + ']'
      }
      if (value instanceof Date) {
        throw new CanonicalizationError(
          'Date is not a JSON value — format it as an RFC 3339 UTC string first', path)
      }
      const obj = value as Record<string, unknown>
      // RFC 8785: sort by UTF-16 code unit. JavaScript's default string comparison IS code-unit
      // order, so an explicit comparator is used only to make that intent unmistakable.
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
      const parts: string[] = []
      for (const k of keys) {
        parts.push(serializeString(k, path) + ':' + canon(obj[k], path ? `${path}.${k}` : k))
      }
      return '{' + parts.join(',') + '}'
    }

    default:
      throw new CanonicalizationError(`unsupported type ${typeof value}`, path)
  }
}

/** Canonicalize a JSON value to its RFC 8785 / PRM-profile string form. */
export function jcs (value: unknown): string {
  return canon(value, '')
}

/** Canonicalize to UTF-8 bytes — the form that actually gets hashed. */
export function jcsBytes (value: unknown): Uint8Array {
  return new TextEncoder().encode(jcs(value))
}
