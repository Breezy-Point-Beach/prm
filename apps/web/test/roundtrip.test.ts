import { describe, expect, it, beforeEach } from 'vitest'
import { handlePublish, artifactResponse, readPolicyBytes, type PublishRequest } from '../lib/publish'
import { createMemoryStorage } from '../lib/storage/memory'
import { byteDigestOf, utf8 } from '../lib/storage/digest'
import type { PolicyRecord, Storage } from '../lib/storage/types'
import { createAccount } from '@prm/vault'
import { buildPolicyDocument, signPolicyDocument } from '../lib/policy-builder'
import { alprRules, alprHumanReadable, composeHumanReadable } from '@prm/schema'
import {
  digest, jcs, deriveIdentifierSalt, computeCommitment, encodeMultihash
} from '@prm/crypto'
import { normalizeIdentifier } from '@prm/schema'
import { verifyPolicy } from '@prm/verify'

/**
 * THE ACCEPTANCE PROPERTY
 *
 *   The browser signs bytes A. The server stores bytes A. The browser retrieves bytes A.
 *   Any server-side mutation, reserialization, field reordering that affects canonicalized
 *   content, or substitution causes the publish flow to fail visibly.
 *
 * This is what makes the claim "PRM publishes what Bryan signed; PRM does not reinterpret what
 * Bryan meant" a testable property rather than an intention. Every mutation below is applied by a
 * simulated hostile or careless server, and every one must be caught by the client's check.
 */

const ORIGIN = 'https://prm.test'
const NOW = new Date('2026-09-20T12:00:00Z')

interface Signed {
  policyJson: string
  digest: string
  request: PublishRequest
}

/** Exactly what the browser does: build, sign, serialize once, keep those bytes. */
function signInBrowser (handle = 'user0001'): Signed {
  const account = createAccount({ now: NOW, deviceLabel: 'test' })
  const rules = alprRules({ state: 'CA' })
  // A realistic policy carries identifier commitments — salted, never the raw values.
  const plate = normalizeIdentifier('us-license-plate', 'US-CA-0EXAMPLE')
  const salt = deriveIdentifierSalt(account.keys.bindingSecret, 'us-license-plate', plate)
  const draft = buildPolicyDocument({
    identifierCommitments: [{
      namespace: 'us-license-plate',
      commitment: encodeMultihash(computeCommitment('us-license-plate', plate, salt))
    }],
    accountId: account.accountId,
    did: account.keys.signing.did,
    keyEventHash: digest(account.genesis, 'keyEvent'),
    rules,
    jurisdictions: ['US-CA', 'US'],
    humanReadable: composeHumanReadable(alprHumanReadable({ agency: 'City of Whittier Police Department' }), rules),
    effectiveDate: '2026-09-20T00:00:00Z',
    now: NOW
  })
  const { policy, policyJson, digest: d } = signPolicyDocument(draft, account.keys.signing, NOW)
  return {
    policyJson,
    digest: d,
    request: {
      handle,
      policyJson,
      keyEventLogJson: JSON.stringify([account.genesis])
    }
  }
}

/** The client-side check that runs after publish. Returns true only on an exact byte match. */
function clientAcceptsFetchedBytes (signedJson: string, fetchedJson: string): boolean {
  return signedJson === fetchedJson
}

let store: Storage
beforeEach(() => { store = createMemoryStorage() })

describe('the happy path', () => {
  it('signs, publishes, and retrieves byte-identical content', async () => {
    const signed = signInBrowser()
    const result = await handlePublish(signed.request, store, ORIGIN)
    expect(result.ok, JSON.stringify(result)).toBe(true)
    if (!result.ok) return

    expect(result.digest).toBe(signed.digest)

    const record = await store.metadata.currentVersion('user0001')
    expect(record).not.toBeNull()
    const response = artifactResponse(
      await readPolicyBytes(store, record as PolicyRecord), record as PolicyRecord)
    const fetched = await response.text()

    expect(fetched).toBe(signed.policyJson)
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(true)
    expect(response.headers.get('ETag')).toBe(`"${signed.digest}"`)
  })

  it('the retrieved bytes verify independently', async () => {
    const account = createAccount({ now: NOW })
    const rules = alprRules()
    const draft = buildPolicyDocument({
      accountId: account.accountId,
      did: account.keys.signing.did,
      keyEventHash: digest(account.genesis, 'keyEvent'),
      rules,
      jurisdictions: ['US-CA', 'US'],
      humanReadable: composeHumanReadable(alprHumanReadable(), rules),
      effectiveDate: '2026-09-20T00:00:00Z',
      now: NOW
    })
    const { policyJson } = signPolicyDocument(draft, account.keys.signing, NOW)
    await handlePublish(
      { handle: 'user0001', policyJson, keyEventLogJson: JSON.stringify([account.genesis]) },
      store, ORIGIN)

    const record = await store.metadata.currentVersion('user0001') as PolicyRecord
    const fetched = JSON.parse(await readPolicyBytes(store, record))
    const r = verifyPolicy(fetched, { keyEventLog: [account.genesis], now: new Date('2026-10-01T00:00:00Z') })
    expect(r.errors).toEqual([])
    expect(r.issuer).toBe('authorized')
  })
})

describe('a mutating server is caught', () => {
  /**
   * Publish honestly, then have a HOSTILE STORAGE BACKEND return something else.
   *
   * The tampering happens below the adapter — which is the realistic threat, since the object store
   * is the part most likely to be operated by someone else. The adapter's read verification catches
   * it, so this helper asks for the raw stored bytes directly to model a server that ignored the
   * error and served them anyway.
   */
  async function publishThenMutate (
    mutate: (bytes: string) => string
  ): Promise<{ signed: Signed; fetched: string }> {
    const signed = signInBrowser()
    const result = await handlePublish(signed.request, store, ORIGIN)
    expect(result.ok).toBe(true)
    const record = await store.metadata.currentVersion('user0001') as PolicyRecord
    const stored = await readPolicyBytes(store, record)
    return { signed, fetched: mutate(stored) }
  }

  it('DETECTS reserialization, even though the signature still verifies', async () => {
    // The subtle one. JSON.parse + JSON.stringify changes the bytes but not the JCS
    // canonicalization, so the SIGNATURE still checks out. Only a byte comparison catches it, which
    // is exactly why the client compares bytes rather than trusting a signature check.
    const { signed, fetched } = await publishThenMutate((b) => JSON.stringify(JSON.parse(b)))
    expect(fetched).not.toBe(signed.policyJson)
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)

    const stillVerifies = verifyPolicy(JSON.parse(fetched), { now: NOW })
    expect(stillVerifies.signature).toBe('valid')   // signature survives...
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false) // ...the check does not
  })

  it('DETECTS key reordering', async () => {
    const { signed, fetched } = await publishThenMutate((b) => {
      const parsed = JSON.parse(b) as Record<string, unknown>
      return JSON.stringify(Object.fromEntries(Object.entries(parsed).reverse()), null, 2)
    })
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)
  })

  it('DETECTS whitespace-only reformatting', async () => {
    const { signed, fetched } = await publishThenMutate((b) => JSON.stringify(JSON.parse(b), null, 4))
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)
  })

  it('DETECTS a substituted rule, and the signature also fails', async () => {
    const { signed, fetched } = await publishThenMutate((b) => {
      const p = JSON.parse(b)
      p.rules.find((x: { category: string }) => x.category === 'prm:sale').decision = 'allow'
      return JSON.stringify(p, null, 2)
    })
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)
    expect(verifyPolicy(JSON.parse(fetched), { now: NOW }).summary).toBe('failed')
  })

  it('DETECTS a wholly substituted policy from another account', async () => {
    const other = signInBrowser('someone-else')
    const { signed, fetched } = await publishThenMutate(() => other.policyJson)
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)
    expect(digest(JSON.parse(fetched), 'policy')).not.toBe(signed.digest)
  })

  it('DETECTS an added field, even a harmless-looking one', async () => {
    const { signed, fetched } = await publishThenMutate((b) => {
      const p = JSON.parse(b)
      p.publishedBy = 'rightsroot.com'
      return JSON.stringify(p, null, 2)
    })
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)
    expect(verifyPolicy(JSON.parse(fetched), { now: NOW }).summary).toBe('failed')
  })

  it('DETECTS a stripped field', async () => {
    const { signed, fetched } = await publishThenMutate((b) => {
      const p = JSON.parse(b)
      delete p.identifierCommitments
      return JSON.stringify(p, null, 2)
    })
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)
  })

  it('DETECTS truncation', async () => {
    const { signed, fetched } = await publishThenMutate((b) => b.slice(0, -20))
    expect(clientAcceptsFetchedBytes(signed.policyJson, fetched)).toBe(false)
  })

  it('the STORAGE LAYER itself refuses corrupted bytes before the client ever sees them', async () => {
    // Belt and braces: even if the client skipped its byte check, a content-addressed store cannot
    // serve altered content, because the read is verified against the address it came from.
    const corrupting = createMemoryStorage((b) => utf8(JSON.stringify(JSON.parse(new TextDecoder().decode(b)))))
    const signed = signInBrowser()
    expect((await handlePublish(signed.request, corrupting, ORIGIN)).ok).toBe(true)
    const record = await corrupting.metadata.currentVersion('user0001') as PolicyRecord
    await expect(readPolicyBytes(corrupting, record)).rejects.toThrow(/does not match its digest/)
  })

  it('stores the policy at an address derived from its BYTES, not its protocol digest', async () => {
    const signed = signInBrowser()
    await handlePublish(signed.request, store, ORIGIN)
    const record = await store.metadata.currentVersion('user0001') as PolicyRecord
    expect(record.policyByteDigest).toBe(byteDigestOf(signed.policyJson))
    // The two digests are different values; conflating them would give a reserialized document the
    // same storage address as the original.
    expect(record.policyByteDigest).not.toBe(record.policyDigest)
    expect(record.policyLocation).toBe(`artifacts/policy/${record.policyByteDigest}`)
  })
})

describe('the server refuses what it should not publish', () => {
  it('rejects a tampered policy at publish time', async () => {
    const signed = signInBrowser()
    const p = JSON.parse(signed.policyJson)
    p.rules.find((x: { category: string }) => x.category === 'prm:sale').decision = 'allow'
    const r = await handlePublish(
      { ...signed.request, policyJson: JSON.stringify(p) }, store, ORIGIN)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/did not verify/)
  })

  it('rejects a policy whose issuer does not match its key event log', async () => {
    const a = signInBrowser()
    const b = createAccount({ now: NOW })
    const r = await handlePublish(
      { ...a.request, keyEventLogJson: JSON.stringify([b.genesis]) }, store, ORIGIN)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/does not match the account/)
  })

  it('rejects a handle already owned by another account', async () => {
    const first = signInBrowser('taken')
    expect((await handlePublish(first.request, store, ORIGIN)).ok).toBe(true)
    const second = signInBrowser('taken')
    const r = await handlePublish(second.request, store, ORIGIN)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/belongs to another account/)
  })

  it('rejects a first publish that is not version 1', async () => {
    const signed = signInBrowser()
    const p = JSON.parse(signed.policyJson)
    p.version = 2
    p.previousPolicyHash = 'uEiBE9fuWQIzOQe08QcgbkYJdl54EKVdIlWi6GC2xmIZmqA'
    const r = await handlePublish({ ...signed.request, policyJson: JSON.stringify(p) }, store, ORIGIN)
    expect(r.ok).toBe(false)
  })

  it('rejects invalid and reserved handles', async () => {
    const signed = signInBrowser()
    for (const handle of ['api', 'ab', 'Has-Caps', 'has_underscore', '-leading', 'a'.repeat(40)]) {
      const r = await handlePublish({ ...signed.request, handle }, store, ORIGIN)
      expect(r.ok, `handle ${handle} should be rejected`).toBe(false)
    }
  })

  it('rejects non-string document fields', async () => {
    const signed = signInBrowser()
    const r = await handlePublish(
      { ...signed.request, policyJson: JSON.parse(signed.policyJson) as unknown as string },
      store, ORIGIN)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/exact signed bytes/)
  })
})

describe('the server never re-serializes on the way in', () => {
  it('stores bytes that differ from a re-serialization of the same document', async () => {
    const signed = signInBrowser()
    await handlePublish(signed.request, store, ORIGIN)
    const record = await store.metadata.currentVersion('user0001') as PolicyRecord
    const stored = await readPolicyBytes(store, record)

    expect(stored).toBe(signed.policyJson)
    // Proof the stored form is the client's, not the server's idea of the same object.
    expect(stored).not.toBe(JSON.stringify(JSON.parse(signed.policyJson)))
    // And the canonicalization is identical either way, which is why bytes had to be compared.
    expect(jcs(JSON.parse(stored))).toBe(jcs(JSON.parse(signed.policyJson)))
  })
})
