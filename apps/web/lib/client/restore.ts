'use client'

import type { KeyEvent, Policy } from '@prm/schema'
import { validateKeyEvent, validatePolicy, stripRulesSummary } from '@prm/schema'
import { adoptAccount, type AdoptedAccount } from '@prm/vault'
import { verifyKeyEventLog, verifyPolicy } from '@prm/verify'
import { digest } from '@prm/crypto'
import type { PolicyDraftState, PublishedState } from './session'

/**
 * Restore — rejoin an account from its backup phrase and its PUBLISHED documents.
 *
 * Nothing here is trusted because it came from the server. The key event log is checked as a chain,
 * the phrase is checked against the log head, the policy is verified against the log, and the
 * policy's issuer is checked against the account id the log certifies. Only then does the caller get
 * something worth sealing into a vault. A restore that silently produced a vault for the wrong
 * account — or a vault that cannot sign for the account it names — would be worse than no restore.
 *
 * Pure: no storage, no DOM. The page decides what to persist.
 */
export interface RestoreInput {
  phrase: string
  /** Exact text of kel.json — from /u/{handle}/kel.json or a .prmproof bundle. */
  keyEventLogJson: string
  /** Exact text of the current policy.json, if there is one. Optional: a key can exist unpublished. */
  policyJson?: string
  handle?: string
  /** The origin the policy was fetched from, used only to reconstruct the published URLs. */
  origin?: string
}

export interface RestoreResult {
  account: AdoptedAccount
  /** Present when a published policy was supplied and verified. */
  published?: PublishedState
  /** A draft seeded from the published policy, so the next version can be authored immediately. */
  draft?: PolicyDraftState
  /** What was checked, in order, for the page to show. */
  checks: string[]
}

export class RestoreError extends Error {
  override name = 'RestoreError'
}

export function restoreFromPublished (input: RestoreInput): RestoreResult {
  const checks: string[] = []

  let events: KeyEvent[]
  try {
    const parsed = JSON.parse(input.keyEventLogJson)
    events = Array.isArray(parsed) ? parsed : [parsed]
  } catch {
    throw new RestoreError('The key event log is not valid JSON.')
  }
  for (const e of events) {
    const r = validateKeyEvent(e)
    if (!r.valid) throw new RestoreError(`A key event failed schema validation: ${r.errors.join('; ')}`)
  }
  const kel = verifyKeyEventLog(events)
  if (!kel.valid) throw new RestoreError(`The key event log did not verify: ${kel.errors.join('; ')}`)
  checks.push(`Key history verified — ${events.length} event${events.length === 1 ? '' : 's'}, self-certifying from genesis`)

  // Throws AccountControlError with a specific message when the phrase is for another account.
  const account = adoptAccount({ phrase: input.phrase, events })
  checks.push(`Your phrase controls ${account.accountId} (signing key #${account.keyIndex})`)

  if (input.policyJson === undefined) return { account, checks }

  let policy: Policy
  try {
    policy = JSON.parse(input.policyJson) as Policy
  } catch {
    throw new RestoreError('The published policy is not valid JSON.')
  }
  const schema = validatePolicy(policy)
  if (!schema.valid) throw new RestoreError(`The published policy failed schema validation: ${schema.errors.join('; ')}`)

  if (policy.issuer.id !== account.accountId) {
    throw new RestoreError(
      `The policy at that address was issued by ${policy.issuer.id}, not by the account your phrase ` +
      'controls. Check the handle.')
  }
  const verification = verifyPolicy(policy, { keyEventLog: events })
  if (verification.summary === 'failed') {
    throw new RestoreError(`The published policy did not verify: ${verification.errors.join('; ')}`)
  }
  const policyDigest = digest(policy, 'policy')
  checks.push(`Published policy v${policy.version} verified and issued by this account`)

  const handle = input.handle ?? ''
  const origin = input.origin ?? ''
  const published: PublishedState = {
    handle,
    digest: policyDigest,
    version: policy.version,
    policyChainId: policy.policyChainId,
    policyUrl: `${origin}/u/${handle}/policy.json`,
    canonicalUrl: `${origin}/u/${handle}#sha256=${policyDigest}`,
    publishedAt: policy.proof?.created ?? policy.effectiveDate
  }

  // The plate cannot be recovered from the policy — only its commitment was published. The user
  // re-enters it; the salt is derived from the seed, so the commitment will come out identical.
  const draft: PolicyDraftState = {
    rules: policy.rules,
    narrative: stripRulesSummary(policy.humanReadable?.text ?? ''),
    jurisdictions: policy.jurisdictions,
    effectiveDate: new Date().toISOString().slice(0, 10),
    ...(policy.issuer.displayName ? { displayName: policy.issuer.displayName } : {})
  }

  return { account, published, draft, checks }
}
