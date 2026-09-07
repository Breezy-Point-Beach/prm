import { readFileSync } from 'node:fs'
import { basename } from 'node:path'
import type { KeyEvent, Policy } from '@prm/schema'
import { validatePolicy, CORE_CATEGORIES, categoryLabel, resolveDecision, unknownCategories } from '@prm/schema'
import { digest, digestBytes, jcs, policyChainId, stripNonHashed, bytesToHex } from '@prm/crypto'
import {
  verifyPolicy, verifyPolicyChain, verifyKeyEventLog, verifyProofBundle,
  type ProofBundle, type VerificationResult
} from '@prm/verify'
import { renderResult, exitCodeFor, bold, dim, green, red, yellow, TICK, CROSS, WARN, short } from './render.js'

export class UsageError extends Error {}

export interface CommandResult {
  output: string
  exitCode: number
}

function readJson (path: string): unknown {
  let raw: string
  try {
    raw = readFileSync(path, 'utf8')
  } catch (e) {
    throw new UsageError(`cannot read ${path}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`)
  }
  try {
    return JSON.parse(raw)
  } catch (e) {
    throw new UsageError(`${path} is not valid JSON: ${(e as Error).message}`)
  }
}

/** Load a key event log from a file that holds either one event or an array of them. */
function readKel (path: string): KeyEvent[] {
  const parsed = readJson(path)
  return (Array.isArray(parsed) ? parsed : [parsed]) as KeyEvent[]
}

export interface VerifyOptions {
  kel?: string
  chain?: string
  /** Transparency log public key, so a signed tree head inside a bundle can be checked. */
  logKey?: string
  /** Accepted and documented, but a no-op: this CLI never contacts the network in any mode. */
  offline?: boolean
  json?: boolean
  now?: Date
}

/**
 * `prm verify <file>` — dispatches on content, so users do not have to know the artifact type.
 */
export function cmdVerify (path: string, opts: VerifyOptions = {}): CommandResult {
  const doc = readJson(path)

  if (isBundle(doc)) return renderBundleResult(doc as ProofBundle, path, opts)

  if (isKeyEvent(doc)) {
    const kel = Array.isArray(doc) ? (doc as KeyEvent[]) : [doc as KeyEvent]
    const r = verifyKeyEventLog(kel)
    if (opts.json) return { output: JSON.stringify(r, replacer, 2), exitCode: r.valid ? 0 : 2 }
    const out = [bold(`Key event log: ${basename(path)}`), '']
    if (r.valid) {
      out.push(`${TICK} chain of ${kel.length} event(s) is continuous and correctly signed`)
      out.push(`${TICK} account ${r.accountId} self-certifies from its genesis event`)
      if (kel.some((e) => e.eventType === 'rotation')) {
        out.push(`${TICK} every rotation revealed a pre-committed key`)
      }
      out.push('', bold(green('VERIFIED')))
    } else {
      for (const e of r.errors) out.push(`${CROSS} ${e}`)
      out.push('', bold(red('FAILED')))
    }
    return { output: out.join('\n'), exitCode: r.valid ? 0 : 2 }
  }

  // Default: a policy document.
  const keyEventLog = opts.kel ? readKel(opts.kel) : undefined
  const chain = opts.chain ? (readJson(opts.chain) as Policy[]) : undefined

  const r = verifyPolicy(doc, {
    ...(keyEventLog ? { keyEventLog } : {}),
    ...(opts.now ? { now: opts.now } : {})
  })

  if (opts.json) return { output: JSON.stringify(r, replacer, 2), exitCode: exitCodeFor(r.summary) }

  const out = [bold(`Policy: ${basename(path)}`), '', renderResult(r)]

  if (chain) {
    const cr = verifyPolicyChain(chain)
    out.splice(2, 0, cr.valid
      ? `${TICK} chain        ${dim(`${chain.length} version(s) link correctly`)}`
      : `${CROSS} chain        ${dim(cr.errors[0] ?? 'invalid')}`, '')
    if (!cr.valid) return { output: out.join('\n'), exitCode: 2 }
  }
  return { output: out.join('\n'), exitCode: exitCodeFor(r.summary) }
}

/**
 * Renders a proof bundle verification. Does NOT verify anything itself — verifyProofBundle() from
 * @prm/verify does all of it. A `verify*` function living in the CLI is exactly the drift this
 * package must not have, and a test asserts none exists.
 */
function renderBundleResult (bundle: ProofBundle, path: string, opts: VerifyOptions): CommandResult {
  const r = verifyProofBundle(bundle, {
    ...(opts.now ? { now: opts.now } : {}),
    ...(opts.logKey ? { logPublicKeyMultibase: opts.logKey } : {})
  })
  if (opts.json) return { output: JSON.stringify(r, replacer, 2), exitCode: r.valid ? 0 : 2 }

  const out = [bold(`Proof bundle: ${basename(path)}`), '']
  for (const check of r.checks) {
    out.push(`${check.ok ? TICK : CROSS} ${check.name.padEnd(18)}${dim(check.detail)}`)
  }
  for (const w of r.warnings) out.push(`  ${WARN} ${w}`)

  out.push('')
  out.push(r.valid ? bold(green('VERIFIED')) : bold(red('FAILED')))
  out.push('')
  out.push(r.conclusion)

  if (r.policyDigest) {
    out.push('')
    out.push(dim(`policy digest  ${r.policyDigest}`))
    out.push(dim(`byte digest    ${r.policyByteDigest ?? '(none)'}`))
    if (r.noticeDigest) out.push(dim(`notice digest  ${r.noticeDigest}`))
  }
  return { output: out.join('\n'), exitCode: r.valid ? 0 : 2 }
}

/** `prm digest <file>` — print the canonical digest and the exact bytes it was computed over. */
export function cmdDigest (path: string, opts: { kind?: string; bytes?: boolean } = {}): CommandResult {
  const doc = readJson(path) as object
  const kind = (opts.kind ?? detectKind(doc)) as Parameters<typeof digest>[1]
  const stripped = stripNonHashed(doc, kind)
  const canonical = jcs(stripped)

  const out = [
    `${bold('kind')}      ${kind}`,
    `${bold('digest')}    ${digest(doc, kind)}`,
    `${bold('sha256')}    ${bytesToHex(digestBytes(doc, kind))}`,
    `${bold('excluded')}  ${dim(excludedFor(kind).join(', ') || '(none)')}`,
    `${bold('bytes')}     ${canonical.length} bytes of canonical JSON`
  ]
  if ((doc as Policy).version === 1 && kind === 'policy') {
    out.push(`${bold('chainId')}   ${policyChainId(doc)}`)
  }
  if (opts.bytes) out.push('', dim('--- canonical bytes ---'), canonical)
  return { output: out.join('\n'), exitCode: 0 }
}

/** `prm inspect <file>` — human-readable summary of what a policy actually says. */
export function cmdInspect (path: string): CommandResult {
  const doc = readJson(path)
  const v = validatePolicy(doc)
  if (!v.valid) {
    return {
      output: [bold(red('Not a valid PRM policy:')), ...v.errors.map((e) => `  ${CROSS} ${e}`)].join('\n'),
      exitCode: 3
    }
  }
  const p = v.value as Policy

  const out: string[] = []
  out.push(bold('PRM Personal Data Policy'))
  out.push('')
  out.push(`  account      ${p.issuer.id}`)
  if (p.issuer.displayName) out.push(`  name         ${p.issuer.displayName}`)
  out.push(`  version      ${p.version}${p.previousPolicyHash ? dim(`  (supersedes ${short(p.previousPolicyHash, 16)})`) : ''}`)
  out.push(`  effective    ${p.effectiveDate}`)
  if (p.expirationDate) out.push(`  expires      ${p.expirationDate}`)
  out.push(`  jurisdiction ${p.jurisdictions.join(', ')}`)
  out.push(`  digest       ${digest(p, 'policy')}`)
  if (p.identifierCommitments?.length) {
    out.push(`  identifiers  ${dim(`${p.identifierCommitments.length} committed (${p.identifierCommitments.map((c) => c.namespace).join(', ')}) — values not disclosed`)}`)
  }

  out.push('', bold('Permitted'))
  const permitted = p.rules.filter((r) => r.decision === 'allow')
  if (permitted.length === 0) out.push(dim('  (nothing is permitted unconditionally)'))
  for (const r of permitted) out.push(`  ${green('+')} ${categoryLabel(r.category)}`)

  const conditional = p.rules.filter((r) => r.decision === 'conditional')
  if (conditional.length > 0) {
    out.push('', bold('Permitted only under conditions'))
    for (const r of conditional) {
      const bits: string[] = []
      if (r.conditions?.maxRetention) bits.push(`retention ${r.conditions.maxRetention}`)
      if (r.conditions?.requiresLegalProcess) bits.push('requires legal process')
      if (r.conditions?.requiresNotice) bits.push('requires notice')
      if (r.conditions?.purposes?.length) bits.push(`purpose: ${r.conditions.purposes.join(', ')}`)
      out.push(`  ${yellow('~')} ${categoryLabel(r.category)}${bits.length ? dim(`  [${bits.join('; ')}]`) : ''}`)
    }
  }

  out.push('', bold('Objected to'))
  for (const r of p.rules.filter((x) => x.decision === 'deny')) {
    out.push(`  ${red('-')} ${categoryLabel(r.category)}`)
  }

  const silent = CORE_CATEGORIES.filter((c) => !p.rules.some((r) => r.category === c.id))
  if (silent.length > 0) {
    out.push('', bold('Not addressed') + dim(' (treat as denied)'))
    for (const c of silent) out.push(`  ${dim('?')} ${dim(c.label)}`)
  }

  const unknown = unknownCategories(p)
  if (unknown.length > 0) {
    out.push('', bold(yellow('Unrecognized categories')) + dim(' (treat as denied)'))
    for (const u of unknown) out.push(`  ${WARN} ${u}`)
  }

  if (p.humanReadable?.text) {
    out.push('', bold('In the issuer\'s own words'), '')
    for (const l of p.humanReadable.text.split('\n')) out.push(`  ${dim(l)}`)
  }

  out.push('', dim('This document records the issuer\'s stated instructions. It does not by itself'))
  out.push(dim('establish that every restriction is enforceable under the law of any jurisdiction.'))
  return { output: out.join('\n'), exitCode: 0 }
}

/** `prm verify-chain <file>` — file holds an array of policy versions. */
export function cmdVerifyChain (path: string): CommandResult {
  const chain = readJson(path)
  if (!Array.isArray(chain)) throw new UsageError(`${path} must contain an array of policy versions`)
  const r = verifyPolicyChain(chain as Policy[])
  const out = [bold(`Policy chain: ${basename(path)} (${chain.length} version(s))`), '']
  if (r.valid) {
    const sorted = [...(chain as Policy[])].sort((a, b) => a.version - b.version)
    for (const p of sorted) {
      out.push(`${TICK} v${p.version}  ${dim(`${p.effectiveDate}  ${short(digest(p, 'policy'), 24)}`)}`)
    }
    out.push('', bold(green('CHAIN VERIFIED')))
  } else {
    for (const e of r.errors) out.push(`${CROSS} ${e}`)
    out.push('', bold(red('CHAIN FAILED')))
  }
  return { output: out.join('\n'), exitCode: r.valid ? 0 : 2 }
}

// ---- helpers ----------------------------------------------------------------

function isBundle (d: unknown): boolean {
  return typeof d === 'object' && d !== null && 'prmproof' in (d as object)
}

function isKeyEvent (d: unknown): boolean {
  const one = Array.isArray(d) ? d[0] : d
  return typeof one === 'object' && one !== null && (one as { type?: string }).type === 'prm/KeyEvent/v1'
}

function detectKind (d: object): string {
  const t = (d as { type?: unknown }).type
  if (t === 'prm/KeyEvent/v1') return 'keyEvent'
  if (t === 'prm/LedgerEntry/v1') return 'ledgerEntry'
  if (Array.isArray(t) && t.includes('PRMAuthorization')) return 'authorization'
  if (Array.isArray(t) && t.includes('PersonalDataPolicy')) return 'policy'
  if ('rootHash' in d && 'treeSize' in d) return 'signedTreeHead'
  throw new UsageError('cannot determine the document type; pass --kind')
}

function excludedFor (kind: string): string[] {
  const map: Record<string, string[]> = {
    policy: ['id', 'proof'],
    authorization: ['id', 'proof'],
    keyEvent: ['proof'],
    ledgerEntry: ['proof', 'logInclusion'],
    signedTreeHead: ['signature']
  }
  return map[kind] ?? []
}

/** Maps and Sets do not survive JSON.stringify; render them as arrays for --json output. */
function replacer (_k: string, v: unknown): unknown {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, val]) => [k, val instanceof Set ? [...val] : val]))
  if (v instanceof Set) return [...v]
  return v
}

export type { VerificationResult }
