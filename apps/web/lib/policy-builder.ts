import type { Policy, Rule, IdentifierCommitment } from '@prm/schema'
import { PRM_CONTEXT } from '@prm/schema'
import { buildProof, digest, policyChainId, policyId, type KeyPair } from '@prm/crypto'

/**
 * Client-side policy construction and signing.
 *
 * Runs in the browser. Nothing here touches the network, and the signing key is passed in from the
 * unlocked vault rather than being loaded here — this module builds and signs a document, and knows
 * nothing about how keys are stored.
 *
 * The one subtlety worth understanding is SERIALIZATION. signPolicyDocument returns both the signed
 * object and the exact JSON string, and the caller must publish THAT STRING. Re-serializing the
 * object later would produce different bytes for the same document; the signature would still
 * verify, but the published artifact would no longer be the artifact the user signed, and the
 * round-trip check would fail. Returning the string makes the correct thing the easy thing.
 */

export interface PolicyDraft {
  accountId: string
  did: string
  keyEventHash: string
  rules: Rule[]
  jurisdictions: string[]
  humanReadable: string
  effectiveDate: string
  expirationDate?: string
  identifierCommitments?: IdentifierCommitment[]
  displayName?: string
  distribution?: Policy['distribution']
  /** Set for versions after the first. */
  previous?: { policyChainId: string; digest: string; version: number }
  now?: Date
}

const iso = (d: Date): string => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

/**
 * Assemble an unsigned policy.
 *
 * policyChainId is self-referential for version 1 — the chain id is derived from the v1 document,
 * which itself carries the chain id. Resolved by building a draft with a placeholder, deriving the
 * real value from it (the derivation excludes the field), then rebuilding. See
 * spec/NORMATIVE.md §6.
 */
export function buildPolicyDocument (draft: PolicyDraft): Policy {
  const assemble = (chainId: string, version: number, previousPolicyHash: string | null): Policy => ({
    '@context': [...PRM_CONTEXT],
    type: ['VerifiableCredential', 'PersonalDataPolicy'],
    policyChainId: chainId,
    version,
    previousPolicyHash,
    issuer: {
      id: draft.accountId,
      did: draft.did,
      keyEventHash: draft.keyEventHash,
      ...(draft.displayName ? { displayName: draft.displayName } : {})
    },
    effectiveDate: draft.effectiveDate,
    ...(draft.expirationDate ? { expirationDate: draft.expirationDate } : {}),
    jurisdictions: draft.jurisdictions,
    rules: draft.rules,
    ...(draft.identifierCommitments?.length
      ? { identifierCommitments: draft.identifierCommitments }
      : {}),
    requests: {
      deletionOnPurposeCompletion: true,
      doNotSellOrShare: true,
      globalPrivacyControl: true
    },
    humanReadable: { mediaType: 'text/markdown', language: 'en', text: draft.humanReadable },
    ...(draft.distribution ? { distribution: draft.distribution } : {}),
    proof: undefined as unknown as Policy['proof']
  })

  if (draft.previous) {
    return assemble(draft.previous.policyChainId, draft.previous.version + 1, draft.previous.digest)
  }
  const probe = assemble('urn:prm:chain:PLACEHOLDER', 1, null)
  return assemble(policyChainId(stripProof(probe)), 1, null)
}

function stripProof (policy: Policy): Policy {
  const { proof, ...rest } = policy
  return rest as Policy
}

export interface SignedPolicy {
  policy: Policy
  /**
   * THE bytes. Publish exactly this string; do not re-serialize `policy`.
   */
  policyJson: string
  digest: string
}

/**
 * Sign a policy and freeze its serialization.
 *
 * Serialized once, with 2-space indentation, because the published artifact should be readable by a
 * records officer who opens it in a text editor. The indentation is not part of the signature —
 * canonicalization strips it — but it IS part of the bytes that get compared on the round trip, so
 * it must be decided here and never again.
 */
export function signPolicyDocument (unsigned: Policy, key: KeyPair, now: Date = new Date()): SignedPolicy {
  const withoutProof = stripProof(unsigned)
  const proof = buildProof(withoutProof, {
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    kind: 'policy',
    created: iso(now)
  })
  const policy: Policy = { ...withoutProof, id: policyId(withoutProof), proof }
  return {
    policy,
    policyJson: JSON.stringify(policy, null, 2),
    digest: digest(policy, 'policy')
  }
}

/** Human-facing description of what changed between two rule sets, for the review step. */
export function diffRules (before: Rule[], after: Rule[]): string[] {
  const changes: string[] = []
  const byCategory = (rules: Rule[]) => new Map(rules.map((r) => [r.category, r]))
  const a = byCategory(before)
  const b = byCategory(after)

  for (const [category, rule] of b) {
    const previous = a.get(category)
    if (!previous) changes.push(`added ${category} (${rule.decision})`)
    else if (previous.decision !== rule.decision) {
      changes.push(`${category}: ${previous.decision} to ${rule.decision}`)
    }
  }
  for (const category of a.keys()) {
    if (!b.has(category)) changes.push(`removed ${category}`)
  }
  return changes
}
