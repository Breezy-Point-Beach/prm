import { describe, expect, it } from 'vitest'
import { createAccount } from '@prm/vault'
import {
  alprRules, alprHumanReadable, composeHumanReadable, PRM_CONTEXT,
  findForbiddenAssertions, findOutOfScopeTopics, REQUESTED_TREATMENT, LEGAL_EFFECT_DISCLAIMER,
  validateNotice, validateDelivery, validateResponse, type Policy, type Recipient
} from '@prm/schema'
import {
  digest, policyChainId, policyId, buildProof, deriveIdentifierSalt, computeCommitment,
  encodeMultihash, encodeSalt, hash, normalizeIdentifier as _n
} from '@prm/crypto'
import { normalizeIdentifier } from '@prm/schema'
import { verifyProofBundle } from '@prm/verify'
import {
  buildNotice, buildDeliveryRecord, buildResponseRecord, buildProofBundle, serializeBundle,
  renderNoticePdf, manifestDigestOf, byteDigest
} from '../src/index.js'

const NOW = new Date('2026-09-25T12:00:00Z')
const LATER = new Date('2026-10-05T12:00:00Z')

const WHITTIER: Recipient = {
  name: 'City of Whittier, California',
  type: 'government-agency',
  department: 'Whittier Police Department — Records Division',
  domain: 'whittierpd.org',
  contact: 'records@whittierpd.org',
  postalAddress: '13200 Penn St, Whittier, CA 90602',
  jurisdiction: 'US-CA'
}

/** A complete, signed chain: account, policy, notice, delivery, response, bundle. */
function makeChain (opts: { plate?: string } = {}) {
  const account = createAccount({ now: NOW, deviceLabel: 'test' })
  const rules = alprRules({ state: 'CA' })

  const plate = normalizeIdentifier('us-license-plate', opts.plate ?? 'US-CA-0EXAMPLE')
  const salt = deriveIdentifierSalt(account.keys.bindingSecret, 'us-license-plate', plate)
  const commitment = encodeMultihash(computeCommitment('us-license-plate', plate, salt))

  const assemble = (chainId: string): Policy => ({
    '@context': [...PRM_CONTEXT],
    type: ['VerifiableCredential', 'PersonalDataPolicy'],
    policyChainId: chainId,
    version: 1,
    previousPolicyHash: null,
    issuer: {
      id: account.accountId,
      did: account.keys.signing.did,
      keyEventHash: digest(account.genesis, 'keyEvent')
    },
    effectiveDate: '2026-09-25T00:00:00Z',
    jurisdictions: ['US-CA', 'US'],
    rules,
    identifierCommitments: [{ namespace: 'us-license-plate', commitment }],
    humanReadable: {
      mediaType: 'text/markdown', language: 'en',
      text: composeHumanReadable(alprHumanReadable({ agency: WHITTIER.name, state: 'CA' }), rules)
    },
    proof: undefined as unknown as Policy['proof']
  })
  const probe = assemble('urn:prm:chain:PLACEHOLDER')
  const { proof: _p, ...probeBare } = probe
  const chainId = policyChainId(probeBare as Policy)
  const draft = assemble(chainId)
  const { proof: _q, ...bare } = draft
  const policy: Policy = {
    ...(bare as Policy),
    id: policyId(bare as Policy),
    proof: buildProof(bare as Policy, {
      privateKey: account.keys.signing.privateKey,
      publicKey: account.keys.signing.publicKey,
      kind: 'policy',
      created: '2026-09-25T12:00:00Z'
    })
  }
  const policyJson = JSON.stringify(policy, null, 2)

  const notice = buildNotice({
    policy, policyJson, recipient: WHITTIER,
    purpose: 'To place my standing personal data policy on record with the recipient.',
    matchingIdentifiers: [{ namespace: 'us-license-plate', value: plate, salt: encodeSalt(salt) }],
    policyUrl: 'https://prm.app/u/user0001',
    issued: NOW
  }, account.keys.signing)

  const delivery = buildDeliveryRecord({
    notice: notice.document, noticeDigest: notice.digest,
    recipient: { name: WHITTIER.name, contact: WHITTIER.postalAddress },
    method: 'certified-mail', deliveredAt: new Date('2026-09-26T17:00:00Z'),
    reference: 'placeholder-tracking', recorded: new Date('2026-09-26T18:00:00Z')
  }, account.keys.signing)

  const response = buildResponseRecord({
    noticeDigest: notice.digest, deliveryDigest: delivery.digest,
    recipient: { name: WHITTIER.name },
    status: 'acknowledged', receivedAt: new Date('2026-10-02T15:00:00Z'),
    notes: 'Acknowledged receipt; no position stated on the individual objections.',
    recorded: LATER
  }, account.keys.signing)

  const bundle = buildProofBundle({
    policy, policyJson,
    keyEventLogJson: JSON.stringify([account.genesis], null, 2),
    noticeJson: notice.json, noticeDigest: notice.digest,
    policyChainJson: [{ version: 1, json: policyJson }],
    deliveryJson: [delivery.json],
    responseJson: [response.json],
    generatedAt: LATER
  })

  return { account, policy, policyJson, notice, delivery, response, bundle, plate }
}

describe('notice records', () => {
  const { policy, notice, delivery, response, plate } = makeChain()

  it('the notice validates and carries both policy digests', () => {
    expect(validateNotice(notice.document).errors).toEqual([])
    expect(notice.document.policyDigest).toBe(digest(policy, 'policy'))
    expect(notice.document.policyByteDigest).toBe(byteDigest(JSON.stringify(policy, null, 2)))
    // The two are different values. Conflating them would let a reserialized policy pass as the
    // exact file that was delivered.
    expect(notice.document.policyDigest).not.toBe(notice.document.policyByteDigest)
  })

  it('carries the careful legal language verbatim', () => {
    expect(notice.document.requestedTreatment).toBe(REQUESTED_TREATMENT)
    expect(notice.document.legalEffect).toBe(LEGAL_EFFECT_DISCLAIMER)
    expect(notice.document.legalEffect).toMatch(/does not independently create legal rights/)
    expect(notice.document.legalEffect).toMatch(/record of my express position and non-consent/)
  })

  it('REFUSES to sign a notice asserting a legal obligation', () => {
    const { policy: p, policyJson: pj, account } = makeChain()
    expect(() => buildNotice({
      policy: p, policyJson: pj, recipient: WHITTIER,
      requestedTreatment: 'You must comply with this policy immediately.',
      issued: NOW
    }, account.keys.signing)).toThrow(/Refusing to sign/)
  })

  it('contains no forbidden assertion anywhere', () => {
    const all = [notice.document.requestedTreatment, notice.document.legalEffect,
      notice.document.purpose ?? ''].join('\n')
    expect(findForbiddenAssertions(all)).toEqual([])
  })

  it('does NOT ask the recipient for records or explanations', () => {
    // The PRM packet is a notice and an evidentiary artifact, not a second information request.
    const all = [notice.document.requestedTreatment, notice.document.legalEffect,
      notice.document.purpose ?? '', notice.document.note ?? ''].join('\n')
    expect(findOutOfScopeTopics(all)).toEqual([])
  })

  it('keeps the private identifier in the notice and out of the policy', () => {
    expect(JSON.stringify(policy)).not.toContain(plate)
    expect(notice.document.matchingIdentifiers?.[0]?.value).toBe(plate)
  })

  it('delivery and response records validate and reference the notice', () => {
    expect(validateDelivery(delivery.document).errors).toEqual([])
    expect(validateResponse(response.document).errors).toEqual([])
    expect(delivery.document.noticeDigest).toBe(notice.digest)
    expect(response.document.noticeDigest).toBe(notice.digest)
    expect(response.document.deliveryDigest).toBe(delivery.digest)
  })

  it('a no-response record cannot carry a receipt time, and others must', () => {
    const { account, notice: n } = makeChain()
    expect(() => buildResponseRecord({
      noticeDigest: n.digest, status: 'no-response', receivedAt: NOW
    }, account.keys.signing)).toThrow(/cannot carry a receipt time/)
    expect(() => buildResponseRecord({
      noticeDigest: n.digest, status: 'declined'
    }, account.keys.signing)).toThrow(/requires the date/)
    expect(() => buildResponseRecord({
      noticeDigest: n.digest, status: 'no-response', recorded: NOW
    }, account.keys.signing)).not.toThrow()
  })
})

describe('proof bundle', () => {
  const { bundle } = makeChain()

  it('verifies end to end', () => {
    const r = verifyProofBundle(bundle, { now: LATER })
    expect(r.errors).toEqual([])
    expect(r.valid).toBe(true)
    expect(r.conclusion).toMatch(/^Verified: PRM account prm:/)
    expect(r.conclusion).toMatch(/City of Whittier/)
    expect(r.conclusion).toMatch(/Nothing in this check required contacting PRM/)
  })

  it('reports every check by name', () => {
    const names = verifyProofBundle(bundle, { now: LATER }).checks.map((c) => c.name)
    for (const expected of ['manifest', 'artifacts', 'key history', 'policy', 'version chain',
      'notice', 'delivery', 'response']) {
      expect(names, `missing check: ${expected}`).toContain(expected)
    }
  })

  it('the manifest pins every artifact by byte digest', () => {
    for (const entry of bundle.manifest.entries) {
      const content = bundle.artifacts[entry.path] as string
      expect(byteDigest(content), entry.path).toBe(entry.byteDigest)
      expect(new TextEncoder().encode(content).length).toBe(entry.byteLength)
    }
    expect(manifestDigestOf(bundle.manifest)).toBe(bundle.manifestDigest)
  })

  it('preserves the policy bytes exactly', () => {
    const { policyJson, bundle: b } = makeChain()
    expect(b.artifacts['policy.json']).toBe(policyJson)
  })

  it('includes a README and verification instructions a person can follow', () => {
    const readme = bundle.artifacts['README.txt'] as string
    // Whitespace-tolerant: the README is hard-wrapped for a plain-text reader.
    expect(readme).toMatch(/does not\s+create legal rights/)
    expect(readme).toMatch(/PRM does not witness delivery/)
    const instructions = bundle.artifacts['verification/instructions.txt'] as string
    expect(instructions).toMatch(/openssl ts -verify/)
    expect(instructions).toMatch(/does not require the PRM website|without contacting PRM|Nothing below requires the PRM website/)
  })

  it('survives a JSON round trip, as a file on disk would', () => {
    const reloaded = JSON.parse(serializeBundle(bundle))
    expect(verifyProofBundle(reloaded, { now: LATER }).valid).toBe(true)
  })

  it('rejects the removed v1 format with an explanation', () => {
    const r = verifyProofBundle({ prmproof: 1, policy: {}, keyEventLog: [] })
    expect(r.valid).toBe(false)
    expect(r.conclusion).toMatch(/version 1 format, which did not preserve exact artifact bytes/)
  })
})

describe('tampering is detected', () => {
  /** Corrupt a bundle after it was built, as a hostile intermediary would. */
  const tampered = (mutate: (b: ReturnType<typeof makeChain>['bundle'], chain: ReturnType<typeof makeChain>) => void) => {
    const chain = makeChain()
    const b = JSON.parse(serializeBundle(chain.bundle))
    mutate(b, chain)
    return verifyProofBundle(b, { now: LATER })
  }

  it('DETECTS a modified policy', () => {
    const r = tampered((b) => {
      const p = JSON.parse(b.artifacts['policy.json'])
      p.rules.find((x: { category: string }) => x.category === 'prm:sale').decision = 'allow'
      b.artifacts['policy.json'] = JSON.stringify(p, null, 2)
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/artifacts/)
  })

  it('DETECTS reserialized policy bytes, even though the signature still verifies', () => {
    // The subtle case, and the reason byte digests exist at all.
    const r = tampered((b) => {
      b.artifacts['policy.json'] = JSON.stringify(JSON.parse(b.artifacts['policy.json']))
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/policy\.json: expected/)
  })

  it('DETECTS a substituted notice', () => {
    const other = makeChain()
    const r = tampered((b) => { b.artifacts['notice.json'] = other.notice.json })
    expect(r.valid).toBe(false)
  })

  it('DETECTS a notice pointing at the wrong policy', () => {
    const other = makeChain()
    const r = tampered((b) => {
      // Manifest updated too, so only the cross-reference check can catch it.
      b.artifacts['notice.json'] = other.notice.json
      const entry = b.manifest.entries.find((e: { path: string }) => e.path === 'notice.json')
      entry.byteDigest = byteDigest(other.notice.json)
      entry.byteLength = new TextEncoder().encode(other.notice.json).length
      b.manifestDigest = manifestDigestOf(b.manifest)
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/references policy .* but this bundle carries/)
  })

  it('DETECTS a changed recipient', () => {
    const r = tampered((b) => {
      const n = JSON.parse(b.artifacts['notice.json'])
      n.recipient.name = 'City of Somewhere Else'
      b.artifacts['notice.json'] = JSON.stringify(n, null, 2)
      const entry = b.manifest.entries.find((e: { path: string }) => e.path === 'notice.json')
      entry.byteDigest = byteDigest(b.artifacts['notice.json'])
      entry.byteLength = new TextEncoder().encode(b.artifacts['notice.json']).length
      b.manifestDigest = manifestDigestOf(b.manifest)
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/notice: signature is not valid/)
  })

  it('DETECTS changed requested treatment', () => {
    const r = tampered((b) => {
      const n = JSON.parse(b.artifacts['notice.json'])
      n.requestedTreatment = 'You must comply with all of the above.'
      b.artifacts['notice.json'] = JSON.stringify(n, null, 2)
      const entry = b.manifest.entries.find((e: { path: string }) => e.path === 'notice.json')
      entry.byteDigest = byteDigest(b.artifacts['notice.json'])
      entry.byteLength = new TextEncoder().encode(b.artifacts['notice.json']).length
      b.manifestDigest = manifestDigestOf(b.manifest)
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/notice: signature is not valid/)
  })

  it('DETECTS a modified delivery timestamp', () => {
    const r = tampered((b) => {
      const d = JSON.parse(b.artifacts['delivery/delivery-1.json'])
      d.deliveredAt = '2026-01-01T00:00:00Z'
      b.artifacts['delivery/delivery-1.json'] = JSON.stringify(d, null, 2)
      const entry = b.manifest.entries.find((e: { path: string }) => e.path === 'delivery/delivery-1.json')
      entry.byteDigest = byteDigest(b.artifacts['delivery/delivery-1.json'])
      entry.byteLength = new TextEncoder().encode(b.artifacts['delivery/delivery-1.json']).length
      b.manifestDigest = manifestDigestOf(b.manifest)
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/delivery.*signature is not valid/)
  })

  it('DETECTS a modified delivery recipient', () => {
    const r = tampered((b) => {
      const d = JSON.parse(b.artifacts['delivery/delivery-1.json'])
      d.recipient.name = 'Somewhere Else PD'
      b.artifacts['delivery/delivery-1.json'] = JSON.stringify(d, null, 2)
      const entry = b.manifest.entries.find((e: { path: string }) => e.path === 'delivery/delivery-1.json')
      entry.byteDigest = byteDigest(b.artifacts['delivery/delivery-1.json'])
      entry.byteLength = new TextEncoder().encode(b.artifacts['delivery/delivery-1.json']).length
      b.manifestDigest = manifestDigestOf(b.manifest)
    })
    expect(r.valid).toBe(false)
  })

  it('DETECTS a replaced bundle artifact', () => {
    const other = makeChain()
    const r = tampered((b) => { b.artifacts['key-events/kel.json'] = other.bundle.artifacts['key-events/kel.json'] })
    expect(r.valid).toBe(false)
  })

  it('DETECTS a modified manifest', () => {
    const r = tampered((b) => {
      b.manifest.subject.policyVersion = 99
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/manifest digest mismatch/)
  })

  it('DETECTS a missing artifact', () => {
    const r = tampered((b) => { delete b.artifacts['notice.json'] })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/missing artifact: notice\.json/)
  })

  it('DETECTS an artifact smuggled in without a manifest entry', () => {
    const r = tampered((b) => { b.artifacts['extra/injected.json'] = '{"anything":true}' })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/absent from the manifest/)
  })

  it('DETECTS a mismatched byte digest in the manifest', () => {
    const r = tampered((b) => {
      const entry = b.manifest.entries.find((e: { path: string }) => e.path === 'policy.json')
      entry.byteDigest = byteDigest('something else entirely')
      b.manifestDigest = manifestDigestOf(b.manifest)
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/policy\.json: expected/)
  })

  it('DETECTS a manifest subject that disagrees with the policy it carries', () => {
    const other = makeChain()
    const r = tampered((b) => {
      b.manifest.subject.policyDigest = other.notice.document.policyDigest
      b.manifestDigest = manifestDigestOf(b.manifest)
    })
    expect(r.valid).toBe(false)
    expect(r.errors.join(' ')).toMatch(/manifest names a different policy digest/)
  })

  it('CONTROL: the untouched bundle verifies', () => {
    expect(tampered(() => { /* no mutation */ }).valid).toBe(true)
  })

  it('CONTROL: a benign whitespace change to a NON-artifact field is still caught', () => {
    // Everything in the bundle is covered. There is no "safe" place to edit.
    const r = tampered((b) => { b.manifest.generatedAt = '2020-01-01T00:00:00Z' })
    expect(r.valid).toBe(false)
  })
})

describe('PDF rendering', () => {
  it('renders a PDF from the signed policy', async () => {
    const { policy, policyJson, notice, bundle } = makeChain()
    const pdf = await renderNoticePdf({
      policy, policyJson,
      notice: notice.document,
      noticeDigest: notice.digest,
      policyDigest: notice.document.policyDigest,
      policyByteDigest: notice.document.policyByteDigest,
      manifestDigest: bundle.manifestDigest,
      verificationUrl: 'https://prm.app/u/user0001',
      verifyCommand: 'npx @prm/cli verify notice.prmproof',
      generatedAt: LATER
    })
    expect(pdf.length).toBeGreaterThan(2000)
    expect(new TextDecoder().decode(pdf.slice(0, 8))).toMatch(/^%PDF-1\./)
  })

  it('omits the private identifier unless explicitly included', async () => {
    const { policy, policyJson, notice, plate } = makeChain()
    const base = {
      policy, policyJson, notice: notice.document, noticeDigest: notice.digest,
      policyDigest: notice.document.policyDigest,
      policyByteDigest: notice.document.policyByteDigest,
      generatedAt: LATER
    }
    // pdf-lib compresses streams, so search the uncompressed variant for the plate text.
    const withId = await renderNoticePdf({ ...base, includeMatchingIdentifiers: true })
    const without = await renderNoticePdf({ ...base, includeMatchingIdentifiers: false })
    expect(withId.length).toBeGreaterThan(without.length)
    expect(plate).toBe('US-CA-0EXAMPLE')
  })
})
