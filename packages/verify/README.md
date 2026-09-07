# @prm/verify

Independent verification of PRM artifacts. **Never contacts PRM, or anything else.**

```console
npm i @prm/verify
```

```ts
import { verifyPolicy, verifyBundle } from '@prm/verify'

const result = verifyPolicy(policyJson, { keyEventLog })
// result.summary === 'verified' | 'verified-with-warnings' | 'failed'
```

Or from the command line, with no install:

```console
npx @prm/cli verify policy.json --kel kel.json --offline
npx @prm/cli verify evidence.prmproof
```

## Why this package exists

PRM's central claim is that **the provider does not need to be trusted for a person to remain the
authority over their own policy.** That claim is only true if a recipient can verify a policy without
asking PRM anything.

So this package has no HTTP client, no `fetch`, no filesystem access, and no PRM API dependency. Every
input a verification needs is passed in by the caller. Its only dependencies are `@prm/crypto` and
`@prm/schema`, and CI fails the build if that ever changes or if a network call appears in the source.

Its test suite sabotages `fetch`, `XMLHttpRequest`, `WebSocket`, `http.request` and `https.request`
before running, so a network call cannot pass unnoticed. The same verification has been confirmed
inside a Linux network namespace with no interfaces at all.

## Results are graded, never a bare boolean

```ts
{
  integrity:  'valid' | 'invalid'
  signature:  'valid' | 'invalid' | 'unknown-key'
  issuer:     'authorized' | 'revoked-at-signing' | 'not-in-kel' | 'kel-unavailable'
  currency:   'current' | 'superseded' | 'unknown'
  revocation: 'active' | 'revoked' | 'unknown'
  timestamp:  { proven: boolean, notLaterThan?: string, source?: 'rfc3161' | 'ots' }
  warnings:   string[]
  errors:     string[]
  summary:    'verified' | 'verified-with-warnings' | 'failed'
}
```

Integrity, signature, and issuer authority are **required** — they are computable offline. Currency,
revocation, and timestamp degrade to warnings when they cannot be checked, because offline
verification is a supported case: a roadside stop, a records office, an archive review years later.

**`unknown` is not `current`.** Collapsing those two is the mistake this shape exists to prevent.

## What verification establishes, and what it does not

It proves that a specific account authored a specific document, that the signing key was authorized at
the time, and — given a proof bundle — that the document existed no later than an independently
attested time.

It does **not** prove the account belongs to any named person (PRM does no KYC), that the terms bind
the recipient (a question of law), or that the recipient ever received it (that is what delivery
evidence in a `.prmproof` bundle is for).

## API

| Function | Verifies |
|---|---|
| `verifyPolicy(doc, opts)` | A policy: integrity, signature, issuer authority, currency, revocation, timestamp |
| `verifyPolicyChain(policies)` | A version chain links correctly — defeats policy substitution |
| `verifyKeyEventLog(events)` | Self-certifying account id, chain continuity, **pre-rotation commitments** |
| `verifyAuthorization(doc, opts)` | A grant, its expiry, and selective identifier disclosure |
| `verifyLedgerChain(entries)` | An append-only personal ledger |
| `verifyLogInclusion(entry, sth)` | RFC 6962 inclusion proof against a signed tree head |
| `verifySignedTreeHead(sth, key)` | A tree head under the log's published key |
| `verifyBundle(bundle)` | A complete `.prmproof` evidence bundle |

Licence: Apache-2.0.
