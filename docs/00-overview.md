# 00 — Architecture Overview

## 1. The problem, stated precisely

Today, the moment an organization observes you, **it owns the record of that observation**. Your only
levers are (a) statute, which is slow, jurisdictional, and reactive, and (b) contract, which you never
negotiated. There is no artifact you can *hand* to an observer that says, in a form both a human and a
machine can act on, "here are the terms under which the persistent record of me may exist."

PRM produces that artifact and makes it **verifiable, versioned, and evidentiary**.

PRM does **not** claim to be self-executing law. It produces three things that have real force:

1. **Notice** — a documented, timestamped communication of restrictions to a named recipient.
2. **Evidence** — a cryptographic trail that the notice existed, was delivered, and was or was not
   acknowledged.
3. **Machine-actionability** — for organizations that *do* want to comply, an unambiguous input.

Be honest about this framing everywhere in the product. Overclaiming legal effect is the fastest way
to make PRM worthless.

## 2. Trust model

The system has exactly one root of trust: **the user's Ed25519 signing key**, which never leaves the
user's devices in plaintext.

Everything else is an **accelerant**, not an authority:

| Party | Can do | Cannot do |
|---|---|---|
| **User** | Author, sign, publish, rotate, revoke, authorize | — |
| **PRM service** | Host, index, serve, timestamp, notarize, deliver | Author a policy, alter a policy, forge a key rotation, silently rewrite history |
| **Transparency log** | Prove inclusion and non-equivocation | Prove content it never saw |
| **Timestamp authority** | Prove "not later than T" | Prove authorship |
| **Recipient org** | Verify, acknowledge, dispute, comply | Alter the policy it received |

The critical adversary is **PRM itself**. Section 12 treats "malicious PRM provider" as a first-class
threat and the architecture is shaped by it.

### 2.1 How PRM is made untrusted

Three structural moves:

1. **Self-certifying account identity.** Your account ID is `SHA-256` of your *genesis key event*, not a
   row in PRM's database. PRM cannot mint or reassign it.
2. **Pre-rotation commitment.** Each key event commits to the hash of the *next* key. A rotation is only
   valid if it reveals the pre-image. PRM (or a thief with your current key) cannot rotate you.
3. **Detectable equivocation.** Every key event, policy version, authorization, and revocation is a
   leaf in an append-only Merkle log with periodically published, externally timestamped signed tree
   heads. PRM can *refuse* to serve you. It cannot show two different histories to two parties without
   producing two inconsistent tree heads — which any monitor, including your own client, detects.

The residual power PRM retains is **availability and censorship**, not authorship. That is the correct
place to land: it is recoverable (self-host, mirror, re-publish) and it is visible.

## 3. Layer map

```
┌───────────────────────────────────────────────────────────────────────────┐
│  L6  DISTRIBUTION      short URL · QR · NFC · wallet pass · PDF · email    │
│                        .well-known · public HTML page · JSON endpoint      │
├───────────────────────────────────────────────────────────────────────────┤
│  L5  VERIFICATION      @prm/verify — pure function, offline-capable        │
│                        issuer · signature · currency · revocation · time   │
├───────────────────────────────────────────────────────────────────────────┤
│  L4  EVIDENCE          personal hash chain → global Merkle log →           │
│                        signed tree heads → RFC 3161 TSA (+ OTS later)      │
├───────────────────────────────────────────────────────────────────────────┤
│  L3  RESOLUTION        identifier commitments · pairwise IDs · blinded     │
│                        lookup (no public directory, ever)                  │
├───────────────────────────────────────────────────────────────────────────┤
│  L2  DOCUMENTS         Personal Data Policy · Authorization · Revocation   │
│                        Privacy Request · Acknowledgment · Dispute          │
├───────────────────────────────────────────────────────────────────────────┤
│  L1  IDENTITY          Ed25519 keypair · Key Event Log · did:key/did:web   │
│                        passkey unwrap · mnemonic · Shamir recovery         │
└───────────────────────────────────────────────────────────────────────────┘
```

Layers 1–2 are **client-only**. Layers 4–6 are where a server earns its keep. Layer 3 is the one that
requires the most care, because a naive design turns PRM into the surveillance registry it opposes.

## 4. Core data objects

All six share one shape: a JSON document, canonicalized with **RFC 8785 (JCS)**, hashed with
**SHA-256**, signed with **Ed25519**, and identified by that hash.

| Object | Signed by | Chains to | Public? |
|---|---|---|---|
| **Key Event** (genesis / rotate / revoke / recover) | current key (+ next-key pre-image) | previous key event | yes (contains only public keys + digests) |
| **Personal Data Policy** | user | previous policy version | yes, by design (no PII) |
| **Authorization** (exception grant) | user | policy it modifies | no — delivered pairwise |
| **Revocation** | user | authorization it kills | status list is public; target may be opaque |
| **Privacy Request / Notice** | user | policy version | no — delivered to a named recipient |
| **Acknowledgment / Dispute** | recipient org | the object acknowledged | optional |

**One canonical hash, used everywhere.** `H = SHA-256(JCS(doc without "proof"))`. That same `H` is the
document ID, the QR payload fragment, the Merkle leaf input, and the RFC 3161 message imprint. Do not
invent a second digest scheme.

## 5. End-to-end flow (happy path)

```
 DEVICE (browser, never leaves)                 VERCEL                    EXTERNAL
 ──────────────────────────────                 ──────                    ────────
 1. generate Ed25519 keypair
 2. build genesis key event
    (commits H(nextKey))
 3. sign ──────────────────────────────────────► POST /api/v1/events
 4. encrypt vault (Argon2id +                       persist, append leaf
    XChaCha20-Poly1305) ───────────────────────►    to Merkle log
 5. author policy v1
 6. sign ──────────────────────────────────────► POST /api/v1/policies
                                                    persist, append leaf
                                                    ┌──────────────────► RFC 3161 TSA
                                                    │  (hourly, on tree head)
                                                    ◄──────────────────┘ token
                                                 publish:
                                                   /u/{handle}         (HTML)
                                                   /u/{handle}/policy.json
                                                   /p/{shortcode}      (edge redirect)
                                                   /.well-known/prm-policy
 7. print QR / write NFC / export PDF ◄──────────  render
 8. hand to organization ─────────────────────────────────────────────► RECIPIENT
                                                                        @prm/verify
                                                                        (offline OK)
```

## 6. What runs where

| Component | Location | Rationale |
|---|---|---|
| Key generation, signing, vault encryption | **Browser / device only** | Provider must be incapable of impersonation |
| Policy authoring UI | Next.js client component | Editing is local; only the signed result is uploaded |
| Public policy page, JSON endpoint, `.well-known` | Vercel, **Edge runtime**, cached | Static-ish reads, global latency, cheap |
| Short-URL redirect | Vercel Edge Middleware / Route Handler | Sub-10ms redirect, no DB round trip when Edge Config used |
| Signature verification API (convenience) | Vercel, **Node runtime** | Stateless, idempotent; clients should prefer local verification |
| Merkle append, tree head signing | Vercel, **Node runtime**, serialized via advisory lock | Requires Postgres and ordering |
| RFC 3161 timestamping | Vercel **Cron** → Node function | Hourly batch on tree head only |
| PDF + QR generation | Vercel Node function (assembly only — signature comes from client) | Server assembles; server never signs on the user's behalf |
| Wallet pass signing (Apple/Google) | Vercel Node function with **provider** cert | Signs the *card*, not the policy — see §04 |
| Postgres | **Neon** (Vercel Marketplace) | Serverless driver, branching aligns with preview deploys |
| Encrypted vault blobs | **Vercel Blob** | Ciphertext only; key never reaches the server |
| Local-first store | IndexedDB (web), SQLCipher (future desktop/CLI) | Offline authoring, no server dependency |

Nothing here needs Kubernetes, a queue, a VPC, or a container. The only components that could ever
outgrow Vercel are (a) the transparency log at very large scale and (b) a future OPRF resolver — both
flagged in §14.

## 7. Standards used

| Concern | Standard | Why this one |
|---|---|---|
| Signature | **Ed25519 / EdDSA (RFC 8032)** | Small keys, deterministic, no nonce footgun, ubiquitous library support |
| Canonicalization | **JCS (RFC 8785)** | Deterministic bytes without JSON-LD normalization complexity |
| Hash | **SHA-256 (FIPS 180-4)** | Universally available; matches RFC 6962 and RFC 3161 defaults |
| Key encoding | **multibase + multicodec** (`did:key`, `z6Mk…`) | Self-describing, no registry needed |
| Identity | **DID Core 1.0** (`did:key`, `did:web`) + PRM Key Event Log | Interop surface without giving up self-certification |
| Credentials | **W3C VC Data Model 2.0** + `eddsa-jcs-2022` Data Integrity | For authorizations and org-issued acknowledgments |
| Revocation | **W3C Bitstring Status List v1.0** | Standard, compressible, cache-friendly |
| Presentation | **OpenID for Verifiable Presentations (OID4VP)** | For wallet-based presentation at beta |
| Transparency log | **RFC 6962 / RFC 9162** Merkle tree semantics | Battle-tested; existing monitor tooling |
| Timestamp | **RFC 3161** (+ OpenTimestamps later) | Legally recognized, free operators, trivial client |
| Blinded lookup | **OPRF / VOPRF (RFC 9497)** | The correct primitive for "lookup without disclosure" |
| Purpose vocabulary | **W3C DPV** (Data Privacy Vocabulary), **ODRL** shapes | Reuse an ontology rather than invent one |
| Consent records | **ISO/IEC 27560:2023** consent record structure | Enterprise-legible receipts |
| Signal interop | **Global Privacy Control** | Bridges PRM to existing browser-level opt-out |

**Deliberately not used:** a custom blockchain, a bespoke DID method, JSON-LD RDF canonicalization
(`eddsa-rdfc-2022`), IAB TCF, or any proprietary policy language.

## 8. Explicit non-goals

- **No universal identifier.** PRM never mints a number that follows you across relationships. The
  account ID is public but is *only* bound to identifiers you selectively disclose.
- **No central store of personal data.** Postgres holds public keys, digests, opaque commitments, and
  ciphertext. If the database leaks entirely, it discloses that N accounts exist and what their public
  policies say — which were already public.
- **No personal data on any public ledger.** Anchoring is over Merkle roots only.
- **No enforcement fiction.** PRM does not block a camera. It documents terms and preserves proof.

## 9. Reading order

If you are implementing: **02 → 01 → 07 → 05 → 16 → 13**. Those six are sufficient to build the MVP.
Everything else is context, deferral, or later-stage detail.
