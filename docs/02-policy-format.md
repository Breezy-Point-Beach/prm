# 02 — Personal Data Policy Format

Normative schema: [`spec/schemas/prm-policy-v1.schema.json`](../spec/schemas/prm-policy-v1.schema.json)
Examples: [`spec/examples/policies/`](../spec/examples/policies/)

## 1. Design constraints

1. **One document, two audiences.** The same signed bytes must render as a readable page for a records
   clerk and parse deterministically for a vendor's ingestion job. Achieved by carrying human text
   *inside* the signed document (`humanReadable`), not alongside it.
2. **No PII in the policy.** The policy is published. It contains public keys, digests, a rights
   matrix, and optional user-chosen display text. Identifiers appear only as commitments (§03).
3. **Deterministic bytes.** Two implementations must produce the identical hash. RFC 8785 JCS, no
   floats, UTC `Z` timestamps only, no duplicate keys.
4. **Chainable.** Every version references the previous version's hash, forming a per-user policy chain
   that a third party can walk backwards and verify without PRM.
5. **Extensible without breaking verification.** Unknown top-level members must not break a verifier's
   signature check (they are inside the signed bytes), but *must* be surfaced to a human. Unknown
   **rights categories** are treated as `deny` by a conservative processor — see §6.

## 2. Document shape

```jsonc
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://rightsroot.org/spec/prm/ns/v1"
  ],
  "type": ["VerifiableCredential", "PersonalDataPolicy"],

  "id": "urn:prm:policy:uEiA7Zk...",        // = canonical hash, self-referential
  "policyChainId": "urn:prm:chain:uEiQx...", // = hash of version 1, stable forever
  "version": 3,
  "previousPolicyHash": "uEiB9Lm...",       // null iff version == 1

  "issuer": {
    "id": "prm:k4h2qz9m7bvxr3tn8w6ycpsjdf",
    "did": "did:key:z6MkfR8...",
    "keyEventLog": "https://rightsroot.com/u/ab12cd/kel.json",
    "keyEventHash": "uEiC2Wn...",           // KEL head at time of signing
    "displayName": "B. P. Beach"            // OPTIONAL, user-chosen, may be a pseudonym
  },

  "effectiveDate": "2026-09-06T00:00:00Z",
  "expirationDate": "2028-09-06T00:00:00Z", // OPTIONAL; absent = until superseded
  "supersedes": "uEiB9Lm...",

  "jurisdictions": ["US-CA", "US", "EU"],   // ISO 3166-1/-2; declared, not adjudicated

  "rules": [ /* see §3 */ ],
  "exceptions": [ /* see §4 */ ],
  "identifierCommitments": [ /* see §03 */ ],

  "requests": {                              // standing statutory requests, if any
    "deletionOnPurposeCompletion": true,
    "doNotSellOrShare": true,                // CCPA/CPRA analogue
    "globalPrivacyControl": true             // interop signal
  },

  "humanReadable": {
    "mediaType": "text/markdown",
    "language": "en",
    "text": "I permit initial observation and immediate lawful comparison..."
  },

  "legalNotice": "This document is a notice of restrictions... (OPTIONAL, user-supplied)",

  "distribution": {
    "canonicalUrl":  "https://rightsroot.com/u/ab12cd",
    "machineUrl":    "https://rightsroot.com/u/ab12cd/policy.json",
    "shortUrl":      "https://rightsroot.com/p/9fK2xQ",
    "statusList":    "https://rightsroot.com/status/1#42"
  },

  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-09-06T14:07:33Z",
    "verificationMethod": "did:key:z6MkfR8...#z6MkfR8...",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3MvGc..."                 // multibase base58btc Ed25519 signature
  }
}
```

### Canonicalization and hashing — normative

```
bytes  = JCS( document with "id" AND "proof" members removed ) // RFC 8785, PRM profile
digest = SHA-256(bytes)                                        // 32 bytes
id     = "urn:prm:policy:u" + base64url_nopad(0x12 0x20 || digest)   // multihash, "u" multibase
sig    = Ed25519_sign(K_sign, "PRM-POLICY-v1\x00" || digest)   // domain-separated
```

Two details that matter:

- **`id` is self-referential**, so it cannot be inside the bytes it identifies. Computing the digest
  with `id` present-but-set-to-a-placeholder is a trap that produces a different value in every
  implementation. The rule is simply: **`id` and `proof` are both omitted from the hashed bytes.**
  See [`spec/NORMATIVE.md` §2](../spec/NORMATIVE.md) for the full non-hashed-member table covering
  every document type — `logInclusion` on ledger entries is the one most often missed.
- **Domain separation.** Sign `"PRM-POLICY-v1\x00" || digest`, not the digest alone, so a policy
  signature can never be replayed as an authorization signature. Each object type has its own prefix.

> **Decision — JCS + detached digest signing, not JSON-LD RDF canonicalization.**
> *Why:* deterministic bytes with a 200-line dependency instead of a full RDF stack.
> *Threat:* signature substitution / canonicalization mismatch across implementations.
> *MVP:* yes. *Standard:* RFC 8785; `eddsa-jcs-2022` is the registered W3C cryptosuite for exactly this.
> *Simpler alternative:* compact JWS over the raw JSON string (no canonicalization). Rejected: any
> re-serialization (a proxy, a database round-trip, `JSON.parse`/`stringify`) breaks the signature.
> We additionally emit a **detached JWS** form for transport (§04), but the JCS digest is authoritative.

## 3. The rights matrix

`rules[]` is the machine-actionable core. One entry per processing category.

```jsonc
{
  "category": "prm:retention",
  "decision": "deny",                    // allow | deny | conditional
  "conditions": {                        // present iff decision == "conditional"
    "maxRetention": "P0D",               // ISO 8601 duration
    "purposes":     ["dpv:FraudPreventionAndDetection"],
    "recipients":   ["prm:none"],        // or list of org identifiers / classes
    "jurisdictions":["US-CA"],
    "requiresLegalProcess": true,
    "note": "Retention only for the duration of an active hotlist match."
  },
  "basisAcknowledged": ["statutory-override"],  // categories the user concedes may be overridden
  "note": "Free-text, shown in the human rendering."
}
```

### 3.1 Category vocabulary (`prm:` namespace, v1)

Mapped to W3C DPV terms where a mapping exists, so enterprise privacy tooling can ingest it.

| Category | Meaning | DPV alignment |
|---|---|---|
| `prm:observation` | The initial act of sensing/recording | `dvp:Collect` |
| `prm:transactional` | Use strictly necessary to complete the interaction the person initiated | `dpv:ServiceProvision` |
| `prm:retention` | Persisting the record beyond the transaction | `dpv:Store` |
| `prm:location-history` | Retaining time-stamped location observations as a series | `dpv:Store` + `dpv:Location` |
| `prm:correlation` | Joining this record to records from other databases/sources | `dpv:Combine` |
| `prm:profiling` | Building a behavioral profile | `dpv:Profiling` |
| `prm:inference` | Deriving new attributes not directly observed | `dpv:Infer` |
| `prm:third-party-sharing` | Disclosure to another controller | `dpv:Share` |
| `prm:sale` | Disclosure for monetary consideration | `dpv:Sell` |
| `prm:commercialization` | Any commercial exploitation short of sale | `dpv:CommercialInterest` |
| `prm:advertising` | Targeting, measurement, audience construction | `dpv:Advertising` |
| `prm:ai-training` | Inclusion in training/fine-tuning/evaluation corpora | `dpv:AlgorithmicLogic` |
| `prm:biometric` | Face, gait, voice, iris, or other biometric processing | `dpv:Biometric` |
| `prm:law-enforcement` | Disclosure to or query by law enforcement | `dpv:LegalCompliance` |
| `prm:emergency` | Use in imminent threat-to-life situations | `dpv:ProtectionOfNaturalPerson` |
| `prm:deletion` | Affirmative deletion once purpose completes | `dpv:Erase` |

Categories are **URIs**, so a jurisdiction or industry can define `xyz:` extensions without a central
registry. A verifier encountering an unknown category MUST surface it and SHOULD treat it as `deny`
for conservative processing (fail-closed). Record this in the schema's `$comment` and the SDK docs.

### 3.2 Two things the vocabulary deliberately does *not* do

- **It does not encode legal conclusions.** `prm:law-enforcement: deny` is a *statement of the person's
  position*, not an assertion that a warrant is invalid. The `basisAcknowledged` field exists so a user
  can say "I deny this, and I acknowledge a lawful order overrides me" without weakening the rest.
- **It does not attempt purpose-limitation logic.** Purposes are declared, not evaluated. A policy
  engine that reasons over purposes is a §14 item.

## 4. Exceptions

Two forms, and the distinction matters:

- **Inline exceptions** (`exceptions[]`) — public, standing carve-outs, e.g. "my employer may retain
  badge access records for 90 days." Visible to everyone who reads the policy.
- **Authorization records** (§06) — private, per-organization grants delivered pairwise, referenced in
  the policy only by `authorizationSetHash` (a Merkle root over the set), so the *existence* of grants
  is provable without disclosing *who* holds them.

Default to authorization records. Inline exceptions leak relationships.

## 5. Versioning

```
v1 ──hash──► v2 ──hash──► v3 (current)
 │            │            │
 └── leaf ────┴── leaf ────┴── leaf  →  Merkle transparency log  →  RFC 3161 token
```

- `policyChainId` = hash of v1. Stable identity for "this person's policy," across all versions.
- `previousPolicyHash` makes the chain walkable in reverse from any version.
- Old versions stay hosted at `/u/{handle}/v/{n}.json` and remain independently verifiable forever.
  **Never delete a superseded version** — its evidentiary value is the point.
- The current version is discoverable at `/u/{handle}/policy.json` and via the status list.

A recipient who received v2 in March and is asked in July whether they complied can prove exactly which
version they held, and a third party can confirm v2 existed on that date. That is the whole product.

## 6. Human-readable rendering

The `humanReadable.text` field is **inside the signed bytes**, so the prose and the machine rules cannot
drift. The web page, the PDF, and the wallet card all render from it.

Generate a default draft from the rules matrix (deterministic template in `@prm/schema`), let the user
edit, and re-sign. If the user's prose contradicts the matrix, that is the user's choice — but the UI
should flag the divergence before signing. Do not silently regenerate prose on re-sign.

## 7. Minimum viable policy

The smallest valid document — this is what the MVP's default template produces:

```jsonc
{
  "@context": ["https://www.w3.org/ns/credentials/v2","https://rightsroot.org/spec/prm/ns/v1"],
  "type": ["VerifiableCredential","PersonalDataPolicy"],
  "policyChainId": "urn:prm:chain:uEiQx...",
  "version": 1,
  "previousPolicyHash": null,
  "issuer": { "id": "prm:k4h2...", "did": "did:key:z6Mk...", "keyEventHash": "uEiC2..." },
  "effectiveDate": "2026-09-06T00:00:00Z",
  "jurisdictions": ["US"],
  "rules": [ { "category": "prm:sale", "decision": "deny" } ],
  "proof": { "...": "..." }
}
```

Everything else is optional. Keep it that way; a policy that is hard to author does not get authored.
