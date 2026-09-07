import { digest, hash, encodeMultihash, jcs } from '@prm/crypto'
import { VERIFICATION_NOTE } from '@prm/schema'
import type { Policy } from '@prm/schema'

/**
 * The portable .prmproof bundle, version 2.
 *
 * WHY VERSION 2. Version 1 embedded artifacts as nested JSON objects. Every signature still verified,
 * because canonicalization erases formatting — but the exact bytes the user signed were lost the
 * moment the envelope was serialized, so a recipient could not check the byte digest that PR 6 made
 * load-bearing. Version 2 carries every artifact as an exact STRING and pins each one in a manifest.
 *
 * THE MANIFEST IS THE INTEGRITY MAP. Not the file format, not the envelope, not a ZIP. Whatever the
 * bundle is transported as, verification means: recompute the digest of every artifact, compare it
 * to the manifest, then recompute the manifest digest itself. A container that reorders or reformats
 * entries changes nothing, and a container that alters one is caught.
 *
 * Paths follow the logical layout in the PR brief, so a ZIP export is a direct mapping — write each
 * manifest entry to its path — rather than a second format to keep in step.
 */

export const PRMPROOF_VERSION = 2
export const PRMPROOF_MEDIA_TYPE = 'application/prm-proof+json'

export const PATHS = {
  manifest: 'manifest.json',
  policy: 'policy.json',
  notice: 'notice.json',
  keyEvents: 'key-events/kel.json',
  signedTreeHead: 'log/signed-tree-head.json',
  readme: 'README.txt',
  policyChain: (version: number) => `policy-chain/v${version}.json`,
  ledger: 'log/ledger.json',
  delivery: (n: number) => `delivery/delivery-${n}.json`,
  response: (n: number) => `response/response-${n}.json`,
  timestamp: (name: string) => `timestamps/${name}`,
  verification: 'verification/instructions.txt'
} as const

export interface ManifestEntry {
  path: string
  /** SHA-256 of the exact artifact bytes. */
  byteDigest: string
  byteLength: number
  contentType: string
  /** What this artifact is, in one line, for a reader opening the bundle by hand. */
  description: string
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

export interface PrmProofBundleV2 {
  prmproof: number
  mediaType: typeof PRMPROOF_MEDIA_TYPE
  /** Digest of JCS(manifest). Pinning this pins every artifact transitively. */
  manifestDigest: string
  manifest: ProofManifest
  /** path -> exact artifact bytes, as a string. */
  artifacts: Record<string, string>
}

export interface BundleInput {
  policyJson: string
  policy: Policy
  keyEventLogJson: string
  noticeJson?: string
  noticeDigest?: string
  policyChainJson?: Array<{ version: number; json: string }>
  ledgerJson?: string
  signedTreeHeadJson?: string
  deliveryJson?: string[]
  responseJson?: string[]
  /** RFC 3161 tokens, base64, keyed by a file name such as "sth-148223.tsr.b64". */
  timestamps?: Record<string, string>
  generatedAt?: Date
  verifyCommand?: string
}

const utf8Length = (s: string): number => new TextEncoder().encode(s).length
const byteDigestOf = (s: string): string => encodeMultihash(hash(new TextEncoder().encode(s)))

export function manifestDigestOf (manifest: ProofManifest): string {
  return encodeMultihash(hash(new TextEncoder().encode(jcs(manifest))))
}

export function buildProofBundle (input: BundleInput): PrmProofBundleV2 {
  const generatedAt = (input.generatedAt ?? new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z')
  const artifacts: Record<string, string> = {}
  const entries: ManifestEntry[] = []

  const add = (path: string, content: string, contentType: string, description: string): void => {
    artifacts[path] = content
    entries.push({
      path,
      byteDigest: byteDigestOf(content),
      byteLength: utf8Length(content),
      contentType,
      description
    })
  }

  add(PATHS.policy, input.policyJson, 'application/prm-policy+json',
    'The signed policy, exactly as published. This is the authoritative document.')
  add(PATHS.keyEvents, input.keyEventLogJson, 'application/json',
    'The issuer key history. Proves the signing key was authorized, and that the account identifier derives from its own genesis event.')

  if (input.noticeJson) {
    add(PATHS.notice, input.noticeJson, 'application/json',
      'The recipient-specific notice. References the policy by both digests.')
  }
  for (const v of input.policyChainJson ?? []) {
    add(PATHS.policyChain(v.version), v.json, 'application/prm-policy+json',
      `Policy version ${v.version}, retained so the version chain can be walked offline.`)
  }
  if (input.ledgerJson) {
    add(PATHS.ledger, input.ledgerJson, 'application/json',
      'Personal ledger entries relevant to this notice.')
  }
  if (input.signedTreeHeadJson) {
    add(PATHS.signedTreeHead, input.signedTreeHeadJson, 'application/json',
      'Transparency log head. With an inclusion proof, shows the entry was logged.')
  }
  for (const [i, json] of (input.deliveryJson ?? []).entries()) {
    add(PATHS.delivery(i + 1), json, 'application/json',
      'Signed delivery record. The delivery time is asserted by the issuer, not witnessed by PRM.')
  }
  for (const [i, json] of (input.responseJson ?? []).entries()) {
    add(PATHS.response(i + 1), json, 'application/json',
      'Signed response record. Preserves what came back; PRM does not evaluate it.')
  }
  for (const [name, token] of Object.entries(input.timestamps ?? {})) {
    add(PATHS.timestamp(name), token, 'application/timestamp-reply',
      'RFC 3161 timestamp token, base64. Verifiable with standard tooling; see verification/instructions.txt.')
  }

  const verifyCommand = input.verifyCommand ?? 'npx @prm/cli verify notice.prmproof'
  add(PATHS.verification, verificationInstructions(verifyCommand), 'text/plain',
    'How to verify everything in this bundle without contacting PRM.')
  add(PATHS.readme, readme(input, verifyCommand), 'text/plain',
    'Plain-language description of this bundle.')

  // Sorted so the manifest is deterministic regardless of construction order.
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))

  const manifest: ProofManifest = {
    prmproof: PRMPROOF_VERSION,
    generatedAt,
    subject: {
      accountId: input.policy.issuer.id,
      policyChainId: input.policy.policyChainId,
      policyDigest: digest(input.policy, 'policy'),
      policyByteDigest: byteDigestOf(input.policyJson),
      policyVersion: input.policy.version,
      ...(input.noticeDigest ? { noticeDigest: input.noticeDigest } : {})
    },
    entries
  }

  const manifestJson = JSON.stringify(manifest, null, 2)
  artifacts[PATHS.manifest] = manifestJson

  return {
    prmproof: PRMPROOF_VERSION,
    mediaType: PRMPROOF_MEDIA_TYPE,
    manifestDigest: manifestDigestOf(manifest),
    manifest,
    artifacts
  }
}

/** Serialize a bundle to the bytes written to a .prmproof file. */
export function serializeBundle (bundle: PrmProofBundleV2): string {
  return JSON.stringify(bundle, null, 2)
}

function verificationInstructions (verifyCommand: string): string {
  return `HOW TO VERIFY THIS BUNDLE
=========================

${VERIFICATION_NOTE}

Nothing below requires the PRM website, an account, or a network connection.


1. EVERYTHING AT ONCE

   ${verifyCommand}

   Exit code 0 means verified, 1 means verified with warnings (for example, no
   timestamp evidence was included), 2 means it failed.


2. WHAT THAT CHECKS

   - manifest.json lists every artifact with the SHA-256 of its exact bytes.
     Each one is recomputed and compared.
   - The manifest itself is hashed and compared against the bundle's
     manifestDigest, so a single altered entry is detected.
   - policy.json is checked against its own signature.
   - key-events/kel.json is walked from its genesis event. The account
     identifier is recomputed from that event, so identity is not taken on
     trust from anyone, including PRM.
   - notice.json, if present, is checked against its signature and confirmed to
     reference the policy in this bundle by BOTH digests.
   - Delivery and response records, if present, are checked against their
     signatures and their references.


3. TWO DIGESTS, AND WHY BOTH ARE RECORDED

   Policy digest  Identifies the DOCUMENT. It is computed over a canonical form,
                  so reformatting the JSON does not change it.
   Byte digest    Identifies the exact BYTES. Reformatting does change it.

   A reserialized policy keeps its policy digest but gets a different byte
   digest. Recording both lets you show not only which policy was issued, but
   which exact file was delivered.


4. TIMESTAMP EVIDENCE, IF PRESENT

   Tokens under timestamps/ are RFC 3161 and are base64 encoded. To check one
   with standard tooling:

     base64 -d < timestamps/<name> > token.tsr
     openssl ts -reply -in token.tsr -text          # read it
     openssl ts -verify -in token.tsr \\
       -queryfile <query> -CAfile <tsa-chain.pem>   # verify it

   The token attests that the referenced hash existed no later than the time it
   states. It says nothing about who created the content, which is what the
   signature above is for.


5. IF SOMETHING FAILS

   Any mismatch means the bundle you have is not the bundle that was produced.
   Report exactly which check failed; the tool names the artifact and both
   digests.
`
}

function readme (input: BundleInput, verifyCommand: string): string {
  const chain = input.policyChainJson?.length ?? 0
  return `PRM PROOF BUNDLE
================

This file is a portable evidence package. It contains a signed personal data
policy and, where applicable, the notice that was sent about it, a record of how
and when it was delivered, and any response that came back.

WHAT IT ESTABLISHES

  - what policy the issuer signed, and which exact bytes
  - when that policy took effect
  - which recipient a notice was directed to, if any
  - when and how the issuer recorded delivering it
  - what response, if any, the issuer recorded afterwards

WHAT IT DOES NOT DO

  This package records a person's stated instructions and objections. It does not
  create legal rights or obligations that do not otherwise exist, and it does not
  override a court order, a statutory mandate, or other controlling authority.

  The delivery time is asserted by the issuer. PRM does not witness delivery and
  makes no claim to. Independent corroboration, where present, comes from
  transparency log inclusion and timestamp tokens.

  A response record preserves what the recipient said and how the issuer
  characterised it. PRM does not decide whether the recipient's position is
  correct.

CONTENTS

  manifest.json                the integrity map: every artifact and its digest
  policy.json                  the signed policy
  key-events/kel.json          the issuer key history
${input.noticeJson ? '  notice.json                  the recipient-specific notice\n' : ''}${chain > 0 ? `  policy-chain/                ${chain} earlier version(s)\n` : ''}${input.deliveryJson?.length ? '  delivery/                    signed delivery record(s)\n' : ''}${input.responseJson?.length ? '  response/                    signed response record(s)\n' : ''}${input.signedTreeHeadJson ? '  log/signed-tree-head.json    transparency log head\n' : ''}${Object.keys(input.timestamps ?? {}).length ? '  timestamps/                  RFC 3161 timestamp token(s)\n' : ''}  verification/instructions.txt  how to check all of it yourself

TO VERIFY

  ${verifyCommand}

  ${VERIFICATION_NOTE}
`
}
