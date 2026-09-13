import { describe, expect, it } from 'vitest'
import { createAccount } from '@prm/vault'
import { alprRules, alprHumanReadable, composeHumanReadable } from '@prm/schema'
import { digest } from '@prm/crypto'
import { buildPolicyDocument, signPolicyDocument } from '../lib/policy-builder'
import { restoreFromPublished, RestoreError } from '../lib/client/restore'

/**
 * Restore, enforced — docs/13-mvp.md §5 criterion 7:
 *
 *   "Restoring from mnemonic on a second browser reproduces the same accountId and can sign a v2
 *    that chains to v1."
 *
 * The first half is what these tests pin. The second is exercised by the publish page, whose
 * `previous` comes from the `published` state this module returns.
 */
const NOW = new Date('2026-09-15T12:00:00Z')

function publishedAccount () {
  const acct = createAccount({ now: NOW, deviceLabel: 'laptop' })
  const rules = alprRules({ state: 'CA' })
  const unsigned = buildPolicyDocument({
    accountId: acct.accountId,
    did: acct.keys.signing.did,
    keyEventHash: digest(acct.genesis, 'keyEvent'),
    rules,
    jurisdictions: ['US-CA', 'US'],
    humanReadable: composeHumanReadable(alprHumanReadable({ agency: 'Test PD', state: 'CA' }), rules),
    effectiveDate: '2026-09-15T00:00:00Z'
  })
  const signed = signPolicyDocument(unsigned, acct.keys.signing, NOW)
  return { acct, signed, keyEventLogJson: JSON.stringify([acct.genesis]) }
}

describe('restoring from the phrase and the published documents', () => {
  it('reproduces the same account id on a different device, weeks later', () => {
    const { acct, signed, keyEventLogJson } = publishedAccount()
    const result = restoreFromPublished({
      phrase: acct.backupPhrase,
      keyEventLogJson,
      policyJson: signed.policyJson,
      handle: 'someone',
      origin: 'https://rightsroot.com'
    })
    expect(result.account.accountId).toBe(acct.accountId)
    expect(result.account.genesis).toEqual(acct.genesis)
    expect(result.account.keyIndex).toBe(0)
    expect(result.checks).toHaveLength(3)
  })

  it('returns everything needed to publish the NEXT version, chained to this one', () => {
    const { acct, signed, keyEventLogJson } = publishedAccount()
    const result = restoreFromPublished({
      phrase: acct.backupPhrase, keyEventLogJson, policyJson: signed.policyJson, handle: 'someone'
    })
    expect(result.published).toMatchObject({
      handle: 'someone',
      version: 1,
      digest: signed.digest,
      policyChainId: signed.policy.policyChainId
    })
    // A v2 built from this state chains correctly.
    const v2 = buildPolicyDocument({
      accountId: acct.accountId,
      did: acct.keys.signing.did,
      keyEventHash: digest(acct.genesis, 'keyEvent'),
      rules: result.draft!.rules,
      jurisdictions: result.draft!.jurisdictions,
      humanReadable: 'updated',
      effectiveDate: '2026-11-01T00:00:00Z',
      previous: {
        policyChainId: result.published!.policyChainId!,
        digest: result.published!.digest,
        version: result.published!.version
      }
    })
    expect(v2.version).toBe(2)
    expect(v2.previousPolicyHash).toBe(signed.digest)
    expect(v2.policyChainId).toBe(signed.policy.policyChainId)
  })

  it('seeds a draft from the published policy, with the generated summary stripped', () => {
    const { acct, signed, keyEventLogJson } = publishedAccount()
    const { draft } = restoreFromPublished({ phrase: acct.backupPhrase, keyEventLogJson, policyJson: signed.policyJson })
    expect(draft?.rules).toEqual(signed.policy.rules)
    expect(draft?.narrative).not.toContain('Summary of my machine-readable terms')
    expect(draft?.plate).toBeUndefined()
  })

  it('works with no published policy — a key that never published is still restorable', () => {
    const { acct, keyEventLogJson } = publishedAccount()
    const result = restoreFromPublished({ phrase: acct.backupPhrase, keyEventLogJson })
    expect(result.account.accountId).toBe(acct.accountId)
    expect(result.published).toBeUndefined()
  })

  it('REFUSES a phrase that controls a different account', () => {
    const { signed, keyEventLogJson } = publishedAccount()
    const other = createAccount({ now: NOW })
    expect(() => restoreFromPublished({ phrase: other.backupPhrase, keyEventLogJson, policyJson: signed.policyJson }))
      .toThrow(/does not control the account/)
  })

  it("REFUSES a policy issued by someone else, even when the phrase and log are the user's own", () => {
    const mine = publishedAccount()
    const theirs = publishedAccount()
    expect(() => restoreFromPublished({
      phrase: mine.acct.backupPhrase,
      keyEventLogJson: mine.keyEventLogJson,
      policyJson: theirs.signed.policyJson
    })).toThrow(RestoreError)
  })

  it('REFUSES a tampered key event log', () => {
    const { acct, keyEventLogJson } = publishedAccount()
    const tampered = keyEventLogJson.replace('"threshold": 1', '"threshold": 2').replace('"threshold":1', '"threshold":2')
    expect(tampered).not.toBe(keyEventLogJson)
    expect(() => restoreFromPublished({ phrase: acct.backupPhrase, keyEventLogJson: tampered })).toThrow(RestoreError)
  })

  it('REFUSES a policy whose bytes were altered after signing', () => {
    const { acct, signed, keyEventLogJson } = publishedAccount()
    const altered = signed.policyJson.replace('"decision": "deny"', '"decision": "allow"')
    expect(altered).not.toBe(signed.policyJson)
    expect(() => restoreFromPublished({ phrase: acct.backupPhrase, keyEventLogJson, policyJson: altered }))
      .toThrow(/did not verify/)
  })
})
