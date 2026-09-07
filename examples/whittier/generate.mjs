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
import { buildBundle, verifyBundle } from '@prm/verify'

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
  postal: 'Records Division, Whittier Police Department, 13200 Penn St, Whittier, CA 90602'
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

  // ---- 7. Portable evidence bundle -----------------------------------------
  const bundle = buildBundle({
    generatedAt: now,
    policy,
    policyChain: [policy],
    keyEventLog: [genesis],
    ledgerEntries: entries,
    signedTreeHead: sth,
    logPublicKeyMultibase: logKey.publicKeyMultibase,
    authorizations: [grant],
    note:
      `Notice delivered to ${AGENCY.name} by certified mail and to the ALPR vendor by email. ` +
      'Timestamp evidence is attached by the PRM service after the tree head is anchored; this ' +
      'example bundle carries none, so timestamp status reads as unproven.'
  })

  // ---- 8. Write, then verify what we wrote ---------------------------------
  mkdirSync(OUT, { recursive: true })
  const write = (name, data) =>
    writeFileSync(resolve(OUT, name), JSON.stringify(data, null, 2) + '\n')

  write('kel.json', [genesis])
  write('policy.json', policy)
  write('ledger.json', entries)
  write('signed-tree-head.json', sth)
  write('authorization-whittier-pd.json', grant)
  write('evidence.prmproof', bundle)
  writeFileSync(resolve(OUT, 'notice.md'), noticeLetter({ policy, policyDigest, accountId, plate }))

  const result = verifyBundle(bundle, { now: new Date(local ? Date.now() : '2026-10-01T00:00:00Z') })

  console.log(`\n  account      ${accountId}`)
  console.log(`  policy       v${policy.version}  ${policyDigest}`)
  console.log(`  chain        ${chainId}`)
  console.log(`  ledger       ${entries.length} entries, root ${sth.rootHash}`)
  console.log(`  pairwise id  ${grant.subjectRef.pairwiseId}  (for ${AGENCY.name})`)
  console.log(`  written to   ${OUT}`)
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

function noticeLetter ({ policy, policyDigest, accountId, plate }) {
  return `# Notice of Personal Data Policy

**To:** ${AGENCY.name}
**Attn:** Records Division / Custodian of Records
**Address:** ${AGENCY.postal}
**Copy to:** ${VENDOR.name} — ${VENDOR.contact}

**From:** PRM account \`${accountId}\`
**Date:** ${policy.effectiveDate.slice(0, 10)}
**Re:** Personal data policy and records request concerning automated license plate reader data

---

I am writing about automated license plate reader (ALPR) data your department collects, and about
records associated with one vehicle I operate.

Enclosed is my personal data policy. In short: **I do not object to the plate scan itself, or to the
immediate hotlist comparison at the moment of capture.** I do object to what happens afterwards — the
retention of reads that produced no match, the accumulation of those reads into a searchable history
of my movements, their correlation with other databases, their disclosure to other agencies or
sharing networks, their use in profiling or movement inference, and their use in training machine
learning models.

The enclosed document is signed and independently timestamped, so that you or any third party can
confirm precisely what it said and on what date, without relying on me or on any service.

**I would also like to request, as a separate matter:**

1. A copy of your ALPR usage and privacy policy.
2. The reads currently associated with the vehicle identified in the enclosed authorization.
3. Your retention period for reads that produce no hotlist match.
4. A list of the agencies, networks, or vendors with whom ALPR data has been shared.

I recognize that some of what I have asked for may be subject to statutory requirements that override
my preferences, and that some restrictions I have stated may not be ones you are obliged to honour. I
am not asserting otherwise. A partial response that tells me which restrictions your systems can and
cannot honour, and why, is more useful to me than no response.

## Enclosures

| File | What it is |
|---|---|
| \`policy.json\` | The signed policy. Digest \`${policyDigest}\` |
| \`kel.json\` | The key history proving the policy was signed by this account |
| \`authorization-whittier-pd.json\` | Identifies the vehicle to you, and to no one else |
| \`evidence.prmproof\` | A single-file evidence bundle covering all of the above |
| \`notice.md\` | This letter |

## Verifying this notice independently

No PRM service is required, and none is trusted:

\`\`\`
npx @prm/cli verify evidence.prmproof
\`\`\`

Vehicle identified to you: \`${plate.value}\`
(The published policy contains only a salted commitment to this value. Disclosing it to you does not
disclose it to anyone else, and no PRM server holds it.)

---

*This document records my instructions and the date I gave them. It does not purport to create legal
rights that do not already exist.*
`
}

main().catch((e) => {
  console.error(e)
  process.exitCode = 1
})
