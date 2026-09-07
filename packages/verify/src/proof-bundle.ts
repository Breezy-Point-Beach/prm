import type {
  DeliveryRecord, KeyEvent, Notice, Policy, ResponseRecord, SignedTreeHead
} from '@prm/schema'
import { validateNotice, validateDelivery, validateResponse } from '@prm/schema'
import { digest, hash, encodeMultihash, jcs, verifyProofSelfContained } from '@prm/crypto'
import { verifyPolicy, verifyPolicyChain } from './policy.js'
import { verifyKeyEventLog } from './kel.js'
import { verifySignedTreeHead } from './ledger.js'
import type { VerificationResult } from './types.js'

/**
 * Verification of the portable .prmproof bundle (version 2).
 *
 * PURE. No network, no filesystem, no PRM. Everything needed is inside the bundle, which is the
 * whole point: a recipient can check this with the PRM deployment deleted and its operator hostile.
 *
 * THE MANIFEST IS THE INTEGRITY MAP. Verification recomputes the digest of every artifact and
 * compares it to the manifest, then recomputes the manifest digest itself. That ordering matters:
 * checking artifacts against a manifest nobody verified would let an attacker rewrite both.
 */

export const SUPPORTED_PRMPROOF_VERSION = 2

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s)
const byteDigestOf = (s: string): string => encodeMultihash(hash(utf8(s)))

export interface ManifestEntry {
  path: string
  byteDigest: string
  byteLength: number
  contentType: string
  description?: string
}

export interface ProofManifest {
  prmproof: number
  generatedAt: string
  subject: {
    accountId: string
    policyChainId: string
    policyDigest: string
    policyByteDigest: string
    policyVersion: number
    noticeDigest?: string
  }
  entries: ManifestEntry[]
}

export interface ProofBundle {
  prmproof: number
  mediaType: string
  manifestDigest: string
  manifest: ProofManifest
  artifacts: Record<string, string>
}

export interface BundleCheck {
  name: string
  ok: boolean
  detail: string
}

export interface BundleVerification {
  valid: boolean
  checks: BundleCheck[]
  errors: string[]
  warnings: string[]
  policy?: VerificationResult
  accountId?: string
  policyDigest?: string
  policyByteDigest?: string
  noticeDigest?: string
  /** One-line plain-language conclusion, for a reader who will not read the checks. */
  conclusion: string
}

export interface VerifyBundleOptions {
  now?: Date
  /** Public key of the transparency log, if the caller has one to check the tree head against. */
  logPublicKeyMultibase?: string
}

export function verifyProofBundle (
  input: unknown,
  opts: VerifyBundleOptions = {}
): BundleVerification {
  const out: BundleVerification = { valid: false, checks: [], errors: [], warnings: [], conclusion: '' }
  const pass = (name: string, detail: string): void => { out.checks.push({ name, ok: true, detail }) }
  const fail = (name: string, detail: string): void => {
    out.checks.push({ name, ok: false, detail })
    out.errors.push(`${name}: ${detail}`)
  }

  if (typeof input !== 'object' || input === null) {
    out.errors.push('not a PRM proof bundle')
    out.conclusion = 'This file is not a PRM proof bundle.'
    return out
  }
  const bundle = input as ProofBundle

  if (bundle.prmproof !== SUPPORTED_PRMPROOF_VERSION) {
    out.errors.push(`unsupported bundle version ${String(bundle.prmproof)}`)
    out.conclusion = bundle.prmproof === 1
      ? 'This bundle uses the older version 1 format, which did not preserve exact artifact bytes.'
      : 'This bundle was produced by an incompatible version of PRM.'
    return out
  }
  if (!bundle.manifest || !Array.isArray(bundle.manifest.entries) || !bundle.artifacts) {
    out.errors.push('bundle is missing its manifest or artifacts')
    out.conclusion = 'This bundle is malformed.'
    return out
  }

  // ---- 1. The manifest itself, before anything is checked against it -------
  const recomputed = encodeMultihash(hash(utf8(jcs(bundle.manifest))))
  if (recomputed !== bundle.manifestDigest) {
    fail('manifest', `manifest digest mismatch: declared ${bundle.manifestDigest}, computed ${recomputed}`)
    out.conclusion = 'This bundle did NOT verify: its manifest has been altered.'
    return out
  }
  pass('manifest', `integrity map verified (${bundle.manifest.entries.length} artifacts)`)

  // ---- 2. Every artifact against the manifest ------------------------------
  let artifactFailures = 0
  for (const entry of bundle.manifest.entries) {
    const content = bundle.artifacts[entry.path]
    if (content === undefined) {
      fail('artifacts', `missing artifact: ${entry.path}`)
      artifactFailures++
      continue
    }
    const actual = byteDigestOf(content)
    if (actual !== entry.byteDigest) {
      fail('artifacts', `${entry.path}: expected ${entry.byteDigest}, computed ${actual}`)
      artifactFailures++
    }
  }
  // An artifact present but unlisted is as much a problem as one listed but absent: it means the
  // manifest is not a complete description of what the bundle carries.
  for (const path of Object.keys(bundle.artifacts)) {
    if (path === 'manifest.json') continue
    if (!bundle.manifest.entries.some((e) => e.path === path)) {
      fail('artifacts', `artifact present but absent from the manifest: ${path}`)
      artifactFailures++
    }
  }
  if (artifactFailures === 0) {
    pass('artifacts', `${bundle.manifest.entries.length} artifacts match their recorded digests`)
  }

  // ---- 3. The policy -------------------------------------------------------
  const policyJson = bundle.artifacts['policy.json']
  const kelJson = bundle.artifacts['key-events/kel.json']
  if (!policyJson || !kelJson) {
    fail('policy', 'the bundle does not contain both a policy and a key event log')
    out.conclusion = 'This bundle did NOT verify: it is incomplete.'
    return out
  }

  let policy: Policy
  let keyEventLog: KeyEvent[]
  try {
    policy = JSON.parse(policyJson) as Policy
    const parsed = JSON.parse(kelJson)
    keyEventLog = Array.isArray(parsed) ? parsed : [parsed]
  } catch (e) {
    fail('policy', `could not parse the policy or key event log: ${(e as Error).message}`)
    out.conclusion = 'This bundle did NOT verify.'
    return out
  }

  const kel = verifyKeyEventLog(keyEventLog)
  if (!kel.valid) fail('key history', kel.errors.join('; '))
  else pass('key history', `${kel.accountId} self-certifies from its genesis event`)
  out.accountId = kel.accountId

  const policyResult = verifyPolicy(policy, {
    keyEventLog,
    ...(opts.now ? { now: opts.now } : {})
  })
  out.policy = policyResult
  out.policyDigest = policyResult.checked.digest
  out.policyByteDigest = byteDigestOf(policyJson)

  if (policyResult.summary === 'failed') fail('policy', policyResult.errors.join('; '))
  else pass('policy', `v${policy.version}, signed and issuer authorized`)
  out.warnings.push(...policyResult.warnings)

  // The manifest's own claims about the policy must agree with the policy itself.
  if (bundle.manifest.subject.policyDigest !== out.policyDigest) {
    fail('manifest subject', 'the manifest names a different policy digest than the policy it carries')
  }
  if (bundle.manifest.subject.policyByteDigest !== out.policyByteDigest) {
    fail('manifest subject', 'the manifest names a different policy byte digest than the bytes it carries')
  }

  // ---- 4. Version chain ----------------------------------------------------
  const chainEntries = bundle.manifest.entries.filter((e) => e.path.startsWith('policy-chain/'))
  if (chainEntries.length > 0) {
    try {
      const chain = chainEntries
        .map((e) => JSON.parse(bundle.artifacts[e.path] as string) as Policy)
        .sort((a, b) => a.version - b.version)
      const result = verifyPolicyChain(chain)
      if (!result.valid) fail('version chain', result.errors.join('; '))
      else pass('version chain', `${chain.length} version(s) link correctly`)
    } catch (e) {
      fail('version chain', (e as Error).message)
    }
  }

  // ---- 5. The notice -------------------------------------------------------
  const noticeJson = bundle.artifacts['notice.json']
  let notice: Notice | undefined
  if (noticeJson) {
    try {
      notice = JSON.parse(noticeJson) as Notice
    } catch (e) {
      fail('notice', `could not parse: ${(e as Error).message}`)
    }
    if (notice) {
      const schema = validateNotice(notice)
      if (!schema.valid) fail('notice', schema.errors.join('; '))
      else if (!verifyProofSelfContained(notice, 'notice', notice.proof)) {
        fail('notice', 'signature is not valid')
      } else if (notice.policyDigest !== out.policyDigest) {
        // The failure this catches: a notice lifted from one policy and attached to another.
        fail('notice', `references policy ${notice.policyDigest} but this bundle carries ${out.policyDigest}`)
      } else if (notice.policyByteDigest !== out.policyByteDigest) {
        fail('notice', 'references a different serialization of the policy than the bytes in this bundle')
      } else if (kel.accountId && notice.issuer.id !== kel.accountId) {
        fail('notice', 'was issued by a different account than the policy')
      } else {
        out.noticeDigest = digest(notice, 'notice')
        pass('notice', `addressed to ${notice.recipient.name}, references this exact policy`)
      }
    }
  }

  // ---- 6. Delivery ---------------------------------------------------------
  const deliveries = bundle.manifest.entries.filter((e) => e.path.startsWith('delivery/'))
  for (const entry of deliveries) {
    try {
      const record = JSON.parse(bundle.artifacts[entry.path] as string) as DeliveryRecord
      const schema = validateDelivery(record)
      if (!schema.valid) { fail('delivery', `${entry.path}: ${schema.errors.join('; ')}`); continue }
      if (!verifyProofSelfContained(record, 'delivery', record.proof)) {
        fail('delivery', `${entry.path}: signature is not valid`); continue
      }
      if (out.noticeDigest && record.noticeDigest !== out.noticeDigest) {
        fail('delivery', `${entry.path}: references a different notice`); continue
      }
      if (record.policyDigest !== out.policyDigest) {
        fail('delivery', `${entry.path}: references a different policy`); continue
      }
      if (record.manifestDigest && record.manifestDigest !== bundle.manifestDigest) {
        // Not fatal: a delivery may legitimately reference an earlier bundle that has since had a
        // response added. Worth surfacing, because it also fits a swapped-packet story.
        out.warnings.push(
          `${entry.path} references a different proof bundle than this one — it may have been ` +
          'delivered with an earlier packet')
      }
      pass('delivery', `${record.method} to ${record.recipient.name}, asserted ${record.deliveredAt}`)
    } catch (e) {
      fail('delivery', `${entry.path}: ${(e as Error).message}`)
    }
  }

  // ---- 7. Response ---------------------------------------------------------
  const responses = bundle.manifest.entries.filter((e) => e.path.startsWith('response/'))
  for (const entry of responses) {
    try {
      const record = JSON.parse(bundle.artifacts[entry.path] as string) as ResponseRecord
      const schema = validateResponse(record)
      if (!schema.valid) { fail('response', `${entry.path}: ${schema.errors.join('; ')}`); continue }
      if (!verifyProofSelfContained(record, 'response', record.proof)) {
        fail('response', `${entry.path}: signature is not valid`); continue
      }
      if (out.noticeDigest && record.noticeDigest !== out.noticeDigest) {
        fail('response', `${entry.path}: references a different notice`); continue
      }
      pass('response', `recorded as "${record.status}"${record.receivedAt ? ` on ${record.receivedAt}` : ''}`)
    } catch (e) {
      fail('response', `${entry.path}: ${(e as Error).message}`)
    }
  }

  // ---- 8. Transparency log head -------------------------------------------
  const sthJson = bundle.artifacts['log/signed-tree-head.json']
  if (sthJson) {
    if (!opts.logPublicKeyMultibase) {
      out.warnings.push('a signed tree head is included but no log public key was supplied to check it')
    } else {
      try {
        const sth = JSON.parse(sthJson) as SignedTreeHead
        if (verifySignedTreeHead(sth, opts.logPublicKeyMultibase)) {
          pass('transparency log', `tree head at size ${sth.treeSize}, signed by the published log key`)
        } else {
          fail('transparency log', 'the signed tree head signature is not valid')
        }
      } catch (e) {
        fail('transparency log', (e as Error).message)
      }
    }
  }

  // ---- 9. Timestamp evidence ----------------------------------------------
  const tokens = bundle.manifest.entries.filter((e) => e.path.startsWith('timestamps/'))
  if (tokens.length === 0) {
    out.warnings.push('no independent timestamp evidence is included in this bundle')
  } else {
    // Deliberately not parsed here. Verifying an RFC 3161 token requires the TSA certificate chain,
    // which is exactly the kind of trust decision that belongs with the person doing the checking.
    // The bundle carries the tokens and instructions/openssl commands rather than a verdict.
    pass('timestamps', `${tokens.length} RFC 3161 token(s) included — verify with openssl, see verification/instructions.txt`)
  }

  out.valid = out.errors.length === 0
  out.conclusion = describe(out, notice)
  return out
}

function describe (r: BundleVerification, notice?: Notice): string {
  if (!r.valid) return 'This bundle did NOT verify. See the failed checks below.'

  const who = r.accountId ?? 'an unidentified account'
  const version = r.policy?.checked.version
  let s = `Verified: PRM account ${who} signed version ${version} of this policy`
  if (notice) s += `, and issued a notice about it to ${notice.recipient.name} on ${notice.issued.slice(0, 10)}`
  s += '. Nothing in this check required contacting PRM.'
  if (r.warnings.length > 0) s += ` ${r.warnings.length} note(s) below.`
  return s
}
