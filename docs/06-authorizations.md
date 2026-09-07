# 06 — Authorization and Exception System

Normative schema: [`spec/schemas/prm-authorization-v1.schema.json`](../spec/schemas/prm-authorization-v1.schema.json)

## 1. Purpose

A policy is a default. An **Authorization** is a signed, scoped, expiring carve-out granted to one named
organization. Without it, PRM is an all-or-nothing refusal instrument, which is both unrealistic and
easy to dismiss. The ability to say *"yes, you specifically, for this, until then"* is what makes a
restrictive default credible.

## 2. Anatomy

```jsonc
{
  "@context": ["https://www.w3.org/ns/credentials/v2","https://rightsroot.org/spec/prm/ns/v1"],
  "type": ["VerifiableCredential","PRMAuthorization"],
  "id": "urn:prm:authz:uEiD4Qm...",

  "policyChainId": "urn:prm:chain:uEiQx...",
  "boundPolicyHash": "uEiA7Zk...",         // the EXACT policy version this modifies

  "grantee": {
    "name": "City of Whittier Police Department",
    "domain": "whittierpd.org",
    "did": "did:web:whittierpd.org",
    "contact": "records@whittierpd.org"
  },

  "subjectRef": {
    "pairwiseId": "b7k2m9qx4vn8",          // unlinkable across grantees
    "disclosedIdentifiers": [
      { "namespace": "us-license-plate", "value": "US-CA-0EXAMPLE", "salt": "k9Xq..." }
    ]
  },

  "purposes":       ["dpv:FraudPreventionAndDetection", "prm:active-investigation"],
  "categories":     ["prm:retention", "prm:correlation"],
  "dataCategories": ["plate-read", "location"],

  "issued":  "2026-09-10T00:00:00Z",
  "expires": "2026-12-09T00:00:00Z",       // REQUIRED
  "maxRetention": "P90D",
  "onwardSharing": "prohibited",

  "revocation": {
    "statusListCredential": "https://rightsroot.com/status/1",
    "statusListIndex": 4211,
    "statusPurpose": "revocation"
  },
  "receiptRequested": true,
  "proof": { /* Ed25519, domain prefix "PRM-AUTHZ-v1\x00" */ }
}
```

## 3. Five design rules

**(1) Expiry is mandatory.** The schema has no way to express a perpetual grant. Consent that never
lapses is the failure mode of every consent system ever built. Re-granting is a two-tap operation; make
that the path of least resistance.

**(2) Grants bind to a policy *version*, not a chain.** `boundPolicyHash` pins the exact document. If
the user publishes a stricter v4, an existing grant issued against v3 does not silently widen or narrow
— the grantee is told "the underlying policy changed; here is a re-issued grant" or the grant simply
runs to expiry under its original terms. Ambiguity here is where disputes come from.

**(3) Grants are delivered pairwise, not published.** The policy publishes only
`authorizationSetHash` — a Merkle root over the digests of currently valid grants. That proves *"I have
granted N exceptions and here is a commitment to the set"* without revealing to the world which
organizations you deal with. A specific grantee can be given an inclusion proof against that root to
confirm their grant is part of the user's live set.

> **Decision — Merkle-root commitment over grants instead of publishing them.**
> *Why:* the list of organizations you've granted access to is itself a sensitive relationship graph.
> *Threat:* correlation attacks, data scraping, relationship disclosure. *MVP:* commitment field
> defined; inclusion proofs at beta. *Standard:* RFC 6962 Merkle proofs. *Simpler alternative:* publish
> grants inline (`exceptions[]` in the policy) — supported, but documented as leaking relationships.

**(4) Revocation is immediate and checkable.** Every grant carries a Bitstring Status List entry. Flipping
the bit is a client-signed operation that produces a `authorization.revoked` ledger entry; the status
list is regenerated and cached with a 5-minute TTL. Also push a webhook to the grantee if they
registered one (§09) — but never *depend* on the push; the pull-based status list is authoritative.

**(5) Every grant produces a receipt.** On acceptance the grantee returns a signed **consent receipt**
structured per **ISO/IEC 27560:2023**, referencing the authorization digest. Both sides now hold
matching evidence. If the grantee will not sign a receipt, the user's ledger still records
`authorization.granted` plus the delivery evidence, which is one-sided but still probative.

## 4. Lifecycle

```
  draft ──sign──► issued ──deliver──► accepted ──┬──► expired      (time)
                    │                            ├──► revoked      (user action, status bit)
                    │                            └──► superseded   (re-grant, new digest)
                    └──► rejected  (grantee declines; recorded as a dispute entry)
```

Every transition writes one ledger entry. The user's grant history is therefore reconstructible and
provable years later — which is exactly what you need in a records dispute.

## 5. UX constraint that shapes the schema

An authorization must be issuable in under 30 seconds on a phone, from a template. The realistic flow:

1. Scan the organization's QR or pick from recent counterparties.
2. Choose a template: *Employer* / *Healthcare* / *Financial* / *Law enforcement — active investigation*
   / *Custom*.
3. Adjust duration with a slider (default 90 days).
4. Biometric unlock → sign → deliver.

Templates live in `@prm/schema` as versioned, hash-identified presets so that "I granted the standard
90-day investigation exception" is a checkable statement rather than a recollection. Ship 5 templates
in the MVP; resist adding a policy-authoring language.

## 6. Delegation (deferred)

Guardians, powers of attorney, executors, and parents acting for minors are real requirements and are
**not** in the MVP. The hook exists: the KEL supports a `delegation` event type registering another
account as an authorized signer with a scope and expiry. Designing the scope language properly requires
legal input per jurisdiction — §14.
