#!/usr/bin/env node
/**
 * Whittier, California — worked example.
 *
 * Generates a complete, cryptographically valid PRM notice package addressed to the City of Whittier
 * and its ALPR provider, using the production California ALPR template.
 *
 * THIS SCRIPT CONTAINS NO REAL PERSONAL DATA, AND MUST NOT.
 *
 * The identifiers below are placeholders. User 0001's actual plate, address, phone and email are
 * entered locally at generation time and never enter this repository. Run with --local to supply real
 * values; the output of a --local run is gitignored.
 *
 *   node examples/whittier/generate.mjs              # placeholders, committed artifacts
 *   node examples/whittier/generate.mjs --local      # prompts for real values, writes ./local/
 *
 * The committed artifacts under examples/whittier/generated/ are NOT normative test vectors. They
 * illustrate the flow and are validated by CI, but they do not participate in the digest guard, so
 * they can be regenerated freely as the template evolves.
 */
import { createInterface } from 'node:readline/promises'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  alprRules, alprHumanReadable, TEMPLATES, normalizeIdentifier, PRM_CONTEXT
} from '@prm/schema'
import {
  generateMasterSeed, deriveAccountKeys, deriveAccountId, deriveIdentifierSalt, computeCommitment,
  derivePairwiseId, encodeMultihash, encodeSalt, buildProof, digest, policyChainId, policyId,
  hashString, leafHash, merkleRoot, inclusionProof, keyPairFromSeed, jcsBytes, hash, signBytes,
  signingMessage, encodeSignature
} from '@prm/crypto'
import { verifyProofBundle } from '@prm/verify'
import {
  buildNotice, buildDeliveryRecord, buildResponseRecord, buildProofBundle, serializeBundle,
  renderNoticePdf
} from '@prm/notice'

const HERE = dirname(fileURLToPath(import.meta.url))
const local = process.argv.includes('--local')
const OUT = resolve(HERE, local ? 'local' : 'generated')

// ---------------------------------------------------------------------------
// Recipients. Public bodies and a public vendor — organizations, not people.
// ---------------------------------------------------------------------------
const AGENCY = {
  name: 'City of Whittier Police Department',
  domain: 'whittierpd.org',
  id: 'did:web:whittierpd.org',
  contact: 'records@whittierpd.org',
  postal: '13200 Penn St\nWhittier, CA 90602'
}
const VENDOR = {
  name: 'ALPR system vendor (as identified in the agency contract)',
  domain: 'example-alpr-vendor.com',
  id: 'did:web:example-alpr-vendor.com',
  contact: 'privacy@example-alpr-vendor.com'
}

// ---------------------------------------------------------------------------
// Subject identifiers. PLACEHOLDERS unless --local.
// ---------------------------------------------------------------------------
const PLACEHOLDERS = {
  plate: 'US-CA-0EXAMPLE',
  email: 'user0001@example.org'
}

async function collectLocalIdentifiers () {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  console.log('\nLocal run: values stay on this machine and are written only to examples/whittier/local/,')
  console.log('which is gitignored. Press enter to accept a placeholder.\n')
  const plate = (await rl.question(`  License plate [${PLACEHOLDERS.plate}]: `)).trim() || PLACEHOLDERS.plate
  const email = (await rl.question(`  Contact email [${PLACEHOLDERS.email}]: `)).trim() || PLACEHOLDERS.email
  await rl.close()
  return { plate, email }
}

// A fixed seed for the committed example so its output is stable across runs and reviewable in a
// diff. A --local run generates a real random seed instead.
const EXAMPLE_SEED = hash(new TextEncoder().encode(
  'PRM WHITTIER EXAMPLE SEED — PLACEHOLDER, NOT A REAL ACCOUNT'))

const ISO = (d) => new Date(d).toISOString().replace(/\.\d{3}Z$/, 'Z')

async function main () {
  const ids = local ? await collectLocalIdentifiers() : PLACEHOLDERS
  const seed = local ? generateMasterSeed() : EXAMPLE_SEED
  const keys = deriveAccountKeys(seed)

  const now = local ? ISO(Date.now()) : '2026-09-15T17:00:00Z'
  const effective = local ? ISO(Date.now()) : '2026-09-15T00:00:00Z'

  // ---- 1. Genesis key event: the account certifies itself ------------------
  const genesis = {
    type: 'prm/KeyEvent/v1',
    eventType: 'genesis',
    sequence: 0,
    previousEventHash: null,
    created: now,
    keys: [{
      id: '#k0', alg: 'Ed25519',
      publicKeyMultibase: keys.signing.publicKeyMultibase,
      use: ['assertion', 'authentication'],
      device: 'user-device'
    }],
    nextKeyDigests: [keys.next.publicKeyDigest],
    recoveryKeyDigests: [keys.recovery.publicKeyDigest],
    threshold: 1,
    services: [{ type: 'PRMPublisher', endpoint: 'https://prm.app/u/user0001' }]
  }
  genesis.proof = [buildProof(genesis, {
    privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey,
    kind: 'keyEvent', created: now
  })]
  const accountId = deriveAccountId(genesis)

  // ---- 2. Identifier commitments: values never leave this machine ----------
  const commit = (namespace, raw) => {
    const value = normalizeIdentifier(namespace, raw)
    const salt = deriveIdentifierSalt(keys.bindingSecret, namespace, value)
    return {
      namespace,
      value,
      salt: encodeSalt(salt),
      commitment: encodeMultihash(computeCommitment(namespace, value, salt))
    }
  }
  const plate = commit('us-license-plate', ids.plate)
  const email = commit('email', ids.email)

  // ---- 3. The policy, from the production California template ---------------
  const buildPolicy = (chainId) => {
    const doc = {
      '@context': [...PRM_CONTEXT],
      type: ['VerifiableCredential', 'PersonalDataPolicy'],
      policyChainId: chainId,
      version: 1,
      previousPolicyHash: null,
      issuer: {
        id: accountId,
        did: keys.signing.did,
        keyEventLog: 'https://prm.app/u/user0001/kel.json',
        keyEventHash: digest(genesis, 'keyEvent')
      },
      effectiveDate: effective,
      jurisdictions: TEMPLATES.alpr.defaultJurisdictions('CA'),
      rules: alprRules({ state: 'CA' }),
      // Only commitments are published. The plate itself is disclosed to a named recipient in an
      // authorization, never in the public document.
      identifierCommitments: [
        { namespace: plate.namespace, commitment: plate.commitment },
        { namespace: email.namespace, commitment: email.commitment }
      ],
      requests: {
        deletionOnPurposeCompletion: true,
        doNotSellOrShare: true,
        globalPrivacyControl: true
      },
      humanReadable: {
        mediaType: 'text/markdown',
        language: 'en',
        text: alprHumanReadable({ agency: AGENCY.name, state: 'CA' })
      },
      distribution: {
        canonicalUrl: 'https://prm.app/u/user0001',
        machineUrl: 'https://prm.app/u/user0001/policy.json',
        shortUrl: 'https://prm.li/user0001',
        statusList: 'https://prm.app/status/1'
      }
    }
    return doc
  }

  // policyChainId is self-referential, so derive it from a chain-id-free draft first.
  const draft = buildPolicy('urn:prm:chain:PLACEHOLDER')
  const chainId = policyChainId(draft)
  const policy = buildPolicy(chainId)
  policy.id = policyId(policy)
  policy.proof = buildProof(policy, {
    privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey,
    kind: 'policy', created: now
  })
  const policyDigest = digest(policy, 'policy')

  // ---- 4. Ledger: what was done, to whom, with what evidence ---------------
  const noticePacketDigest = encodeMultihash(hashString(
    `whittier-notice-packet-${policyDigest}`))

  const entrySpecs = [
    { entryType: 'key.event', subjectHash: digest(genesis, 'keyEvent'), recorded: now },
    { entryType: 'policy.published', subjectHash: policyDigest, recorded: now },
    {
      entryType: 'notice.sent',
      subjectHash: noticePacketDigest,
      recorded: local ? ISO(Date.now()) : '2026-09-16T16:00:00Z',
      counterparty: { name: AGENCY.name, id: AGENCY.id, channel: 'postal' },
      evidence: [{
        kind: 'certified-mail-receipt',
        digest: encodeMultihash(hashString('certified-mail-tracking-placeholder')),
        note: 'USPS Certified Mail, return receipt requested (tracking recorded locally)'
      }]
    },
    {
      entryType: 'notice.sent',
      subjectHash: noticePacketDigest,
      recorded: local ? ISO(Date.now()) : '2026-09-16T16:05:00Z',
      counterparty: { name: VENDOR.name, id: VENDOR.id, channel: 'email' },
      evidence: [{
        kind: 'smtp-receipt',
        digest: encodeMultihash(hashString('smtp-message-id-placeholder')),
        note: 'Raw .eml with DKIM headers preserved locally'
      }]
    },
    {
      entryType: 'request.access',
      subjectHash: encodeMultihash(hashString(`whittier-access-request-${policyDigest}`)),
      recorded: local ? ISO(Date.now()) : '2026-09-16T16:10:00Z',
      counterparty: { name: AGENCY.name, id: AGENCY.id, channel: 'postal' },
      evidence: []
    }
  ]

  let previousEntryHash = null
  const entries = []
  for (const [i, spec] of entrySpecs.entries()) {
    const entry = {
      type: 'prm/LedgerEntry/v1',
      accountId,
      sequence: i,
      previousEntryHash,
      recorded: spec.recorded,
      entryType: spec.entryType,
      subjectHash: spec.subjectHash,
      ...(spec.counterparty ? { counterparty: spec.counterparty } : {}),
      ...(spec.evidence?.length ? { evidence: spec.evidence } : {})
    }
    entry.proof = buildProof(entry, {
      privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey,
      kind: 'ledgerEntry', created: spec.recorded
    })
    previousEntryHash = digest(entry, 'ledgerEntry')
    entries.push(entry)
  }

  // ---- 5. Transparency log: opaque leaves, signed head ---------------------
  const leaves = entries.map((e) => leafHash(hash(jcsBytes(strip(e)))))
  const root = merkleRoot(leaves)
  const logKey = keyPairFromSeed(hash(new TextEncoder().encode('PRM WHITTIER EXAMPLE LOG KEY')))
  const sthBody = {
    logId: 'prm-log-example',
    treeSize: leaves.length,
    rootHash: encodeMultihash(root),
    timestamp: local ? ISO(Date.now()) : '2026-09-16T17:00:00Z'
  }
  const sth = {
    ...sthBody,
    signature: encodeSignature(signBytes(
      logKey.privateKey, signingMessage('PRM-STH-v1', hash(jcsBytes(sthBody)))))
  }
  for (const [i, entry] of entries.entries()) {
    entry.logInclusion = {
      logId: sth.logId,
      leafIndex: i,
      treeSize: leaves.length,
      rootHash: sth.rootHash,
      inclusionProof: inclusionProof(leaves, i).map(encodeMultihash)
    }
  }

  // ---- 6. Authorization: discloses the plate to ONE named recipient --------
  const grant = {
    '@context': [...PRM_CONTEXT],
    type: ['VerifiableCredential', 'PRMAuthorization'],
    policyChainId: chainId,
    boundPolicyHash: policyDigest,
    grantee: {
      name: AGENCY.name, id: AGENCY.id, did: AGENCY.id,
      domain: AGENCY.domain, contact: AGENCY.contact
    },
    subjectRef: {
      pairwiseId: derivePairwiseId(keys.bindingSecret, AGENCY.id),
      // Disclosed HERE and only here, so the agency can find the vehicle in its own records.
      // The published policy carries only the commitment.
      disclosedIdentifiers: [{ namespace: plate.namespace, value: plate.value, salt: plate.salt }]
    },
    purposes: ['prm:records-request-identification'],
    categories: ['prm:transactional'],
    dataCategories: ['plate-read'],
    issued: local ? ISO(Date.now()) : '2026-09-16T16:00:00Z',
    expires: local ? ISO(Date.now() + 180 * 86400_000) : '2027-03-15T00:00:00Z',
    maxRetention: 'P180D',
    onwardSharing: 'prohibited',
    revocation: {
      statusListCredential: 'https://prm.app/status/1',
      statusListIndex: 1,
      statusPurpose: 'revocation'
    },
    receiptRequested: true,
    note:
      'Issued solely so the recipient can identify which vehicle this notice concerns. It does not ' +
      'authorize retention, sharing, or any processing beyond that identification.'
  }
  grant.id = 'urn:prm:authz:' + digest(grant, 'authorization')
  grant.proof = buildProof(grant, {
    privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey,
    kind: 'authorization', created: grant.issued
  })

  // ---- 7. Recipient-specific notice ----------------------------------------
  // Distinct from the standing policy: the policy is public and general, this is targeted and
  // carries the plate so the agency can find the right records. The plate is HERE and nowhere public.
  const policyJson = JSON.stringify(policy, null, 2)
  const notice = buildNotice({
    policy,
    policyJson,
    recipient: {
      name: AGENCY.name,
      type: 'law-enforcement',
      department: 'Records Division',
      domain: AGENCY.domain,
      contact: AGENCY.contact,
      postalAddress: AGENCY.postal,
      jurisdiction: 'US-CA'
    },
    purpose: 'To place my standing personal data policy on record with the recipient.',
    matchingIdentifiers: [{ namespace: plate.namespace, value: plate.value, salt: plate.salt }],
    policyUrl: 'https://prm.app/u/user0001',
    issued: local ? new Date() : new Date('2026-09-16T16:00:00Z')
  }, keys.signing)

  // ---- 8. Delivery record ---------------------------------------------------
  const delivery = buildDeliveryRecord({
    notice: notice.document,
    noticeDigest: notice.digest,
    recipient: { name: AGENCY.name, domain: AGENCY.domain, contact: AGENCY.postal },
    method: 'certified-mail',
    deliveredAt: local ? new Date() : new Date('2026-09-17T16:00:00Z'),
    reference: local ? undefined : 'PLACEHOLDER-TRACKING-0000',
    notes: 'Certified mail, return receipt requested. Receipt retained privately.',
    recorded: local ? new Date() : new Date('2026-09-17T17:00:00Z')
  }, keys.signing)

  // ---- 9. Response record (optional) ---------------------------------------
  // PRM preserves what came back and how the issuer characterised it. It does not evaluate whether
  // the recipient's position is legally correct.
  const response = buildResponseRecord({
    noticeDigest: notice.digest,
    deliveryDigest: delivery.digest,
    recipient: { name: AGENCY.name },
    status: 'acknowledged',
    receivedAt: local ? new Date() : new Date('2026-09-24T15:00:00Z'),
    notes: 'Placeholder: receipt acknowledged, no position stated on the individual objections.',
    recorded: local ? new Date() : new Date('2026-09-24T16:00:00Z')
  }, keys.signing)

  // ---- 10. Portable evidence bundle ----------------------------------------
  const bundle = buildProofBundle({
    policy,
    policyJson,
    keyEventLogJson: JSON.stringify([genesis], null, 2),
    noticeJson: notice.json,
    noticeDigest: notice.digest,
    policyChainJson: [{ version: policy.version, json: policyJson }],
    ledgerJson: JSON.stringify(entries, null, 2),
    signedTreeHeadJson: JSON.stringify(sth, null, 2),
    deliveryJson: [delivery.json],
    responseJson: [response.json],
    generatedAt: local ? new Date() : new Date('2026-09-24T17:00:00Z'),
    verifyCommand: 'npx @prm/cli verify notice.prmproof'
  })

  // ---- 11. Write, then verify what we wrote --------------------------------
  mkdirSync(OUT, { recursive: true })
  const write = (name, data) =>
    writeFileSync(resolve(OUT, name), JSON.stringify(data, null, 2) + '\n')

  write('kel.json', [genesis])
  write('ledger.json', entries)
  write('signed-tree-head.json', sth)

  // NO trailing newline on any signed artifact. The byte digest recorded in the notice and the
  // bundle manifest describes these exact bytes, so a stray newline written here would make the
  // file on disk fail the very check the notice invites the recipient to run. The offline suite
  // caught precisely that.
  writeFileSync(resolve(OUT, 'policy.json'), policyJson)
  writeFileSync(resolve(OUT, 'notice.json'), notice.json)
  writeFileSync(resolve(OUT, 'delivery.json'), delivery.json)
  writeFileSync(resolve(OUT, 'response.json'), response.json)
  writeFileSync(resolve(OUT, 'notice.prmproof'), serializeBundle(bundle))
  writeFileSync(resolve(OUT, 'cover-letter.md'), coverLetter({ policy, policyDigest, accountId, notice: notice.document }))

  const pdf = await renderNoticePdf({
    policy,
    policyJson,
    notice: notice.document,
    noticeDigest: notice.digest,
    policyDigest: notice.document.policyDigest,
    policyByteDigest: notice.document.policyByteDigest,
    manifestDigest: bundle.manifestDigest,
    verificationUrl: 'https://prm.app/u/user0001',
    verifyCommand: 'npx @prm/cli verify notice.prmproof',
    includeMatchingIdentifiers: true,
    generatedAt: local ? new Date() : new Date('2026-09-16T16:00:00Z')
  })
  writeFileSync(resolve(OUT, 'notice.pdf'), pdf)

  const result = verifyProofBundle(bundle, {
    now: new Date(local ? Date.now() : '2026-10-01T00:00:00Z')
  })

  console.log(`\n  account       ${accountId}`)
  console.log(`  policy        v${policy.version}  ${policyDigest}`)
  console.log(`  policy bytes  ${notice.document.policyByteDigest}`)
  console.log(`  notice        ${notice.digest}`)
  console.log(`  delivery      ${delivery.digest}  (${delivery.document.method})`)
  console.log(`  response      ${response.digest}  (${response.document.status})`)
  console.log(`  bundle        ${bundle.manifestDigest}  ${bundle.manifest.entries.length} artifacts`)
  console.log(`  PDF           ${(pdf.length / 1024).toFixed(1)} KB`)
  console.log(`  written to    ${OUT}`)
  console.log(`\n  bundle verifies: ${result.valid ? 'YES' : 'NO'}`)
  if (!result.valid) {
    for (const e of result.errors) console.log(`    error: ${e}`)
    process.exitCode = 1
    return
  }
  console.log(`  ${result.conclusion}`)

  if (!local) {
    console.log('\n  These are PLACEHOLDER identifiers. Run with --local to generate a real notice;')
    console.log('  that output goes to examples/whittier/local/, which is gitignored.\n')
  }
}

/** Strip the members excluded from a ledger entry digest — spec/NORMATIVE.md section 2. */
function strip (entry) {
  const { proof, logInclusion, ...rest } = entry
  return rest
}

/**
 * The cover letter.
 *
 * DELIBERATELY NOT A RECORDS REQUEST. Earlier correspondence already asked about retention periods,
 * sharing lists, and technical capability; repeating those here would turn a focused notice into a
 * second information request, and invite it to be routed and answered as one. This packet is a
 * notice and an evidentiary artifact.
 */
function coverLetter ({ policy, policyDigest, accountId, notice }) {
  return `# Notice of Personal Data Policy

**To:** ${AGENCY.name}
**Attn:** Records Division
**Address:** ${AGENCY.postal}
**Copy to:** ${VENDOR.name} — ${VENDOR.contact}

**From:** PRM account \`${accountId}\`
**Date:** ${notice.issued.slice(0, 10)}
**Re:** Personal data policy concerning automated license plate reader records

---

${notice.legalEffect.split('\n\n')[0]}

I recognize that lawful initial observation may occur. My policy distinguishes that initial
observation from subsequent retention, historical search, aggregation, correlation, sharing,
profiling, inference, commercialization, and other secondary processing.

## What I am asking

${notice.requestedTreatment}

If any portion of this policy cannot or will not be honored, this notice should still be treated as a
record of my express position and non-consent regarding those downstream uses.

## Enclosures

| File | What it is |
|---|---|
| \`notice.pdf\` | This notice, in full |
| \`policy.json\` | The signed policy. Digest \`${policyDigest}\` |
| \`notice.json\` | The signed recipient-specific notice |
| \`kel.json\` | Key history proving the policy was signed by this account |
| \`notice.prmproof\` | A single-file evidence bundle covering all of the above |

## Verifying this independently

No PRM service is required, and none is trusted:

\`\`\`
npx @prm/cli verify notice.prmproof
\`\`\`

---

*This document records my instructions and the date I gave them. It does not create legal rights or
obligations that do not otherwise exist, and nothing in it overrides a valid court order, statutory
mandate, or other controlling legal authority.*
`
}

main().catch((e) => {
  console.error(e)
  process.exitCode = 1
})
