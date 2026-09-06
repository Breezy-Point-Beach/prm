# 09 — Enterprise Integration

## 1. Integration ladder

The design goal is that **every rung is useful on its own**, so an organization is never facing an
all-or-nothing project.

| Rung | Effort | What they get |
|---|---|---|
| 0. Receive email + PDF | none | Human-readable notice, evidence trail exists whether they like it or not (§10) |
| 1. Publish `/.well-known/prm-receiver` | 1 static file | PRM clients deliver notices to the right endpoint; they look responsive |
| 2. Verify with `@prm/verify` | ~1 hour | They can prove a policy was authentic when they acted on it |
| 3. Poll or receive webhooks | ~1 day | Their records stay current; revocations reach them |
| 4. Enforce in their pipeline | project-sized | Actual compliance, and a defensible audit story |

Sell rung 1. Everything above it follows from self-interest once they have a documented notice they
cannot claim they never received.

## 2. REST API

Base: `https://api.prm.app/v1`. JSON only. Versioned in the path. All responses include
`X-PRM-Log-Tree-Size` so a client can pin log state.

### Public / unauthenticated (cacheable, no rate concerns)

```http
GET  /v1/policies/{policyDigest}            → the signed policy (immutable, cache forever)
GET  /v1/accounts/{accountId}/kel           → key event log
GET  /v1/accounts/{accountId}/policy        → current policy for an account
GET  /v1/status/{listId}                    → Bitstring Status List credential
GET  /v1/log/sth                            → latest signed tree head
GET  /v1/log/proof?leaf={digest}            → inclusion proof
GET  /v1/log/consistency?from={m}&to={n}    → consistency proof
GET  /.well-known/prm-log                   → log metadata + log public key
```

### Authenticated (organization credentials)

```http
POST /v1/verify                             → convenience verification; "authoritative": false
POST /v1/receipts                           → submit a signed acknowledgment / consent receipt
POST /v1/acknowledgments                    → acknowledge a delivered notice
GET  /v1/subscriptions                      → list webhook subscriptions
POST /v1/subscriptions                      → subscribe to changes for accounts you hold a grant from
GET  /v1/audit/export?from=&to=             → your own interaction history, signed by PRM
POST /v1/resolve                            → k-anonymous / blinded lookup (§03, gated, opt-in only)
```

**Deliberately absent:** any endpoint that enumerates accounts, searches by identifier without a
blinded token, or returns anything about a user who has not interacted with the caller. Write this in
the API docs as a stated non-capability, so an integrator does not go looking.

`POST /v1/verify` returns `"authoritative": false` in the body, always. The SDK logs a warning if an
integrator uses it in an enforcement path instead of local verification.

## 3. Webhooks

```jsonc
POST https://city.gov/api/prm/hook
X-PRM-Signature: t=1757169600,v1=<hex HMAC-SHA256>
X-PRM-Delivery: 01J8...ULID
{
  "type": "authorization.revoked",
  "occurredAt": "2026-09-06T15:04:05Z",
  "subject": { "pairwiseId": "b7k2m9qx4vn8" },       // never accountId
  "data": { "authorizationDigest": "uEiD4Qm...", "policyChainId": "urn:prm:chain:uEiQx..." },
  "logInclusion": { "leafIndex": 148223, "treeSize": 148224, "rootHash": "uEiC9Xk..." }
}
```

Event types: `policy.published` · `policy.superseded` · `authorization.granted` ·
`authorization.revoked` · `notice.sent` · `request.deletion` · `key.rotated`.

Rules:
- **Signature over `timestamp + "." + rawBody`** with a per-subscription secret; reject if the
  timestamp is more than 5 minutes old (replay defence — see §12).
- **At-least-once with a ULID delivery id**; consumers must be idempotent. Say so loudly in the SDK.
- Retry with exponential backoff for 24 h, then disable and email the endpoint owner.
- **Webhooks are a latency optimization, never the source of truth.** Every webhook payload is
  independently confirmable by pulling the referenced object and its inclusion proof. An integrator who
  trusts an unverified webhook has a forgery problem the moment their endpoint URL leaks.
- Subscriptions are **scoped to grants**: an organization can only subscribe to subjects who granted
  them an authorization. No open firehose.

## 4. Consent / authorization receipts

Structured per **ISO/IEC 27560:2023**, referenced by digest, signed by the organization:

```jsonc
{
  "type": ["VerifiableCredential", "PRMConsentReceipt"],
  "issuer": "did:web:breezypointmn.gov",
  "receiptOf": "uEiD4Qm...",                  // authorization or notice digest
  "receivedAt": "2026-09-10T14:22:00Z",
  "disposition": "accepted",                   // accepted | rejected | partial | acknowledged
  "appliedCategories": ["prm:retention"],
  "declined": [
    { "category": "prm:correlation", "reason": "statutory-retention", "citation": "Minn. Stat. §13.82" }
  ],
  "retentionApplied": "P90D",
  "systemsAffected": ["alpr-primary", "records-warehouse"],
  "contact": "records@breezypointmn.gov",
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "...": "..." }
}
```

The `declined[]` array is the most important part of the design. An organization that partially
complies and says *why*, with a citation, is far more likely to respond at all than one facing a
binary accept/reject. It also produces a much more useful evidentiary record than silence — for both
sides. Make partial compliance easy.

## 5. SDKs

| Package | Runtime | Scope |
|---|---|---|
| `@prm/verify` | Node 20+, browsers, Deno, Bun, Workers | Pure verification. Zero deps beyond `@noble/*`. **Ship first.** |
| `@prm/sdk` | Node 20+ | API client, webhook signature verification, receipt issuance |
| `@prm/schema` | isomorphic | Types, JSON Schemas, normalization rules, templates |
| `prm` (CLI) | Node 20+ | `verify`, `keygen`, `sign`, `proof`, `serve` — for ops teams and for CI |

Python and Go ports at enterprise stage — municipal and vendor stacks are heavily Java/.NET/Python, so
a WASM build of `@prm/verify` is the pragmatic bridge and should be evaluated before writing native
ports.

**Every SDK must run verification with no network access in its test suite.** Make it a CI job.

## 6. Authentication

- **Organizations:** OAuth 2.0 client credentials → short-lived JWT (15 min), `Authorization: Bearer`.
  Optional mTLS for enforcement-path integrations. `did:web`-based proof-of-possession as an
  alternative for orgs that already have a DID.
- **Users:** never used for API auth. The user's key signs documents; it does not authenticate sessions.
  App sessions use passkey/WebAuthn against the PRM app, and a compromised session **cannot** produce a
  signature (the key requires a separate unlock). Keep those two boundaries distinct in the code.
- **Webhooks:** shared secret HMAC, rotatable, with an overlap window.

## 7. Rate limiting

| Endpoint class | Anonymous | Authenticated org | Notes |
|---|---|---|---|
| Static/cached reads | 600/min/IP | 6,000/min | Mostly served from CDN cache anyway |
| `/v1/verify` | 60/min/IP | 1,200/min | |
| `/v1/resolve` | **denied** | 60/min, quota'd, **billable** | Deliberately expensive; enumeration defence |
| Writes (receipts, acks) | denied | 300/min | |

Implement with Upstash Redis (Vercel Marketplace) via a sliding window; put the Vercel WAF in front for
IP-level abuse. Rate limiting on `/v1/resolve` is a **security control, not a cost control** — comment
it as such so nobody relaxes it during a performance push.

## 8. Privacy-preserving design rules for the API

1. Responses key on `pairwiseId`, never `accountId`, for anything an organization receives.
2. No endpoint returns data about a subject with whom the caller has no established relationship.
3. Query logs retain IP + endpoint for **7 days** for abuse handling, then aggregate-only.
4. Publish a **transparency report**: query volumes, resolve attempts, and any legal-process requests
   received, quarterly.
5. `/v1/audit/export` returns only the caller's own interactions, PRM-signed so it is usable as
   evidence by them too.
6. **Warrant canary** on the log metadata endpoint. Cheap to maintain, and consistent with the posture.
