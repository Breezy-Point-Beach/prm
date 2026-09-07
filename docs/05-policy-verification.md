# 05 — Policy Verification

## 1. The bar

The test this layer must pass: **a recipient with a cached copy of the policy, the KEL, and one signed
tree head can complete a full verification with rightsroot.com unreachable and DNS for rightsroot.com returning
NXDOMAIN.** If that is not true, PRM is a central authority.

## 2. The six checks

`@prm/verify` implements exactly these, in order, and returns a structured result rather than a boolean.

### Check 1 — Document integrity

```
canonical = JCS(document minus "id" and "proof")
digest    = SHA-256(canonical)
assert digest == multihash_decode(document.id)          // if id present
```
*Catches:* transport corruption, silent re-serialization, tampering.

### Check 2 — Signature

```
key = resolve(proof.verificationMethod)                 // from the KEL, not from a PRM API
assert Ed25519_verify(key, "PRM-POLICY-v1\x00" || digest, proof.proofValue)
```
*Catches:* forgery, cross-object signature replay (via domain separation).

### Check 3 — Issuer authority *at signing time*

This is the check most implementations get wrong.

```
kel = fetch(issuer.keyEventLog) or use cached copy
assert kel is a valid hash chain from genesis
assert accountId == base32(SHA-256(JCS(kel[0] minus proof)))       // self-certifying
for each rotation event: assert SHA-256(newKey) ∈ previous.nextKeyDigests
                         assert two valid signatures (outgoing + revealed)
event = the KEL event referenced by issuer.keyEventHash
assert proof.verificationMethod ∈ event.keys
assert event is not superseded by a revocation of that key
       effective BEFORE this document's log-inclusion time
```

The last clause is the important semantic: **revocation is time-scoped, like a CRL.** A policy signed
and logged in March remains verifiable after a June key revocation. Anything else would destroy the
evidentiary value of the archive, which is the product.

*Catches:* key substitution by a malicious provider, account takeover with a stolen key, retroactive
repudiation.

### Check 4 — Currency (is this the latest version?)

```
GET /u/{handle}/policy.json  →  latest.version, latest.policyChainId
assert latest.policyChainId == received.policyChainId
if latest.version > received.version: WARN "superseded"
walk previousPolicyHash from latest back to received  → proves the chain is continuous
```

If the network is unavailable, return `currency: "unknown"` — **not** `"current"`. A verifier must be
able to distinguish "confirmed latest" from "could not check." Enterprise integrations should treat
`unknown` older than their freshness SLA as a trigger to re-fetch, not as a compliance failure.

### Check 5 — Revocation status

Bitstring Status List v1.0: fetch `distribution.statusList`, decode the GZIP'd bitstring, test the
index. One HTTP fetch covers up to ~131k entries; cache for 5 minutes.

*Catches:* an authorization or policy the issuer has withdrawn.

### Check 6 — Existence at a point in time

```
assert Merkle inclusion proof of SHA-256(entry) against signedTreeHead.rootHash
assert Ed25519_verify(logPublicKey, signedTreeHead)                // key from /.well-known/prm-log
assert RFC3161_verify(timestampToken, over: signedTreeHead.rootHash)
assert timestampToken.genTime ≥ policy.effectiveDate               // sanity
```

Yielding: *"this exact document was included in a log whose root was independently timestamped by
{TSA} at {time}."* See §08.

## 3. Result shape

Return a graded result, never a bare boolean — a verifier that collapses six independent facts into
one bit will make the wrong decision when the network is down.

```ts
type VerificationResult = {
  integrity:  'valid' | 'invalid'
  signature:  'valid' | 'invalid' | 'unknown-key'
  issuer:     'authorized' | 'revoked-at-signing' | 'not-in-kel' | 'kel-unavailable'
  currency:   'current' | 'superseded' | 'unknown'
  revocation: 'active' | 'revoked' | 'unknown'
  timestamp:  { proven: boolean; notLaterThan?: string; source?: 'rfc3161' | 'ots' | 'none' }
  warnings:   string[]           // unknown categories, unknown top-level members, clock skew
  summary:    'verified' | 'verified-with-warnings' | 'failed'
}
```

`summary: 'verified'` requires checks 1–3 to pass. Checks 4–6 degrade to warnings when offline,
because an offline verifier is a supported and expected case (roadside, records office, air-gapped
archive review).

## 4. Verification without trusting PRM

Four independent escape hatches, in increasing order of independence:

1. **Local verification.** `@prm/verify` is a pure library with no network calls in its core path. The
   PRM verification API endpoint is a *convenience*, and its response is not authoritative — the docs
   and the SDK must say so, and the API response includes `"authoritative": false`.
2. **Self-hosted publication.** The user serves the policy and KEL from their own domain
   (`/.well-known/prm-policy`). PRM is then not in the path at all.
3. **Third-party log monitors.** The transparency log's tree heads and entries are public. Anyone can
   mirror it and detect equivocation. Publish a reference monitor in the repo (`packages/monitor`) so
   this is a real capability rather than a theoretical one.
4. **External timestamps.** RFC 3161 tokens are verifiable against the TSA's certificate chain with
   standard tooling (`openssl ts -verify`), with no PRM involvement whatsoever.

> **Decision — verification library is pure and offline-first.**
> *Why:* it is the operative proof of the whole thesis. *Threat:* malicious PRM provider; PRM as a
> single point of failure or coercion. *MVP:* yes — this is non-negotiable and shapes package
> boundaries. *Standard:* RFC 8032, RFC 8785, RFC 6962, RFC 3161, W3C Bitstring Status List.
> *Simpler alternative:* a hosted verify API only — rejected; it makes PRM the authority.

## 5. Reference CLI behaviour

```console
$ npx @prm/verify ./policy.json --kel ./kel.json --offline
✔ integrity     digest uEiA7Zk… matches document id
✔ signature     Ed25519 by did:key:z6MkfR8… valid
✔ issuer        key #k1 authorized in KEL seq 2 (rotation 2026-08-14T00:00:00Z)
                account prm:k4h2qz9m7bvxr3tn8w6ycpsjdf self-certifies from genesis ✓
⚠ currency      unknown (offline)
⚠ revocation    unknown (offline)
✔ timestamp     not later than 2026-09-06T15:00:11Z (FreeTSA, RFC 3161)
  warnings      1 unknown category: "xyz:drone-imagery" — treat as deny

VERIFIED WITH WARNINGS
```

Exit codes: `0` verified, `1` verified-with-warnings, `2` failed, `3` malformed input. Scriptable, so
an organization can wire it into an ingestion pipeline in an afternoon.

## 6. What verification does *not* establish

State these plainly in the SDK README, because overclaiming here is a legal and reputational risk:

- **Not identity.** A verified policy proves *an account* authored it, not that the account belongs to
  any named human. Binding to a legal identity requires either selective disclosure of identifiers
  (§03) or an external attestation, and PRM does no KYC.
- **Not legal effect.** Verification proves authorship and existence. Whether the terms bind the
  recipient is a question of law and jurisdiction.
- **Not receipt.** Verification says nothing about whether the recipient ever saw it. That is what
  §07's delivery entries and §10's evidence chain are for.
