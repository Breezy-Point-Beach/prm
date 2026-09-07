import type { VerificationResult } from '@prm/verify'

// Built via fromCharCode so no literal control byte ever appears in this source file.
const ESC = String.fromCharCode(27)
const useColor = process.env.NO_COLOR === undefined && process.stdout.isTTY === true
const c = (code: string, s: string) => (useColor ? `${ESC}[${code}m${s}${ESC}[0m` : s)

export const green = (s: string) => c('32', s)
export const red = (s: string) => c('31', s)
export const yellow = (s: string) => c('33', s)
export const dim = (s: string) => c('2', s)
export const bold = (s: string) => c('1', s)

export const TICK = green('ok')
export const CROSS = red('XX')
export const WARN = yellow('!!')

export function line (mark: string, label: string, detail = ''): string {
  return `${mark} ${label.padEnd(12)}${detail ? ' ' + dim(detail) : ''}`
}

export function short (s: string | undefined, n = 22): string {
  if (!s) return '(none)'
  return s.length > n ? s.slice(0, n) + '...' : s
}

/**
 * Render a graded result.
 *
 * Shows all six checks every time, including the ones that could not be performed. A reader who only
 * sees "verified" cannot tell whether currency was confirmed or merely unchecked, and that
 * distinction is the difference between a current policy and a superseded one.
 */
export function renderResult (r: VerificationResult): string {
  const out: string[] = []
  const mark = (ok: boolean, unknown = false) => (ok ? TICK : unknown ? WARN : CROSS)

  out.push(line(mark(r.integrity === 'valid'), 'integrity',
    r.integrity === 'valid'
      ? `digest ${short(r.checked.digest)} matches contents`
      : 'digest does not match contents'))

  out.push(line(mark(r.signature === 'valid'), 'signature',
    r.signature === 'valid' ? `Ed25519 by ${short(r.checked.signedBy)}` : r.signature))

  out.push(line(mark(r.issuer === 'authorized', r.issuer === 'kel-unavailable'), 'issuer',
    r.issuer === 'authorized'
      ? `${r.checked.accountId} self-certifies from genesis`
      : r.issuer === 'kel-unavailable' ? 'no key event log supplied' : r.issuer))

  out.push(line(mark(r.currency === 'current', r.currency === 'unknown'), 'currency',
    r.currency === 'current' ? `version ${r.checked.version} is current`
      : r.currency === 'superseded' ? `version ${r.checked.version} has been superseded`
      : 'unknown (offline)'))

  out.push(line(mark(r.revocation === 'active', r.revocation === 'unknown'), 'revocation',
    r.revocation === 'unknown' ? 'unknown (offline)' : r.revocation))

  out.push(line(mark(r.timestamp.proven, !r.timestamp.proven), 'timestamp',
    r.timestamp.proven
      ? `not later than ${r.timestamp.notLaterThan} (${r.timestamp.source})`
      : 'no independent timestamp supplied'))

  if (r.warnings.length > 0) {
    out.push('')
    for (const w of r.warnings) out.push(`  ${WARN} ${w}`)
  }
  if (r.errors.length > 0) {
    out.push('')
    for (const e of r.errors) out.push(`  ${CROSS} ${e}`)
  }

  out.push('')
  out.push(
    r.summary === 'verified' ? bold(green('VERIFIED'))
      : r.summary === 'verified-with-warnings' ? bold(yellow('VERIFIED WITH WARNINGS'))
      : bold(red('FAILED')))
  return out.join('\n')
}

/** Exit codes: 0 verified, 1 verified-with-warnings, 2 failed, 3 malformed input. */
export function exitCodeFor (summary: VerificationResult['summary']): number {
  return summary === 'verified' ? 0 : summary === 'verified-with-warnings' ? 1 : 2
}
