# PRM — Personal Rights Management

> **A person remains the root authority over the persistent digital representation of themselves.**

PRM lets an individual create, sign, publish, update, and share a **machine-readable personal data
policy** describing how information *about them* may be retained, aggregated, correlated, shared,
profiled, commercialized, used for AI training, or otherwise processed **after initial observation**.

The design goal that governs every decision in this repository:

> **The PRM provider does not need to be trusted for the user to remain the authority over their own
> policy.**

That is a technical claim, not a slogan. It is made true by four properties:

| Property | Mechanism |
|---|---|
| PRM cannot **author** a policy for you | Every policy is signed by an Ed25519 key that exists only on your devices |
| PRM cannot **silently swap** your key | Key history is a hash-chained, self-certifying log with pre-rotation commitments (KERI-style) |
| PRM cannot **rewrite history** | Append-only RFC 6962 Merkle transparency log + signed tree heads + external timestamps |
| PRM cannot **be required** to verify | Verification is a pure function over signed bytes; a third party can verify offline with `@prm/verify` and no PRM API call |

PRM is a **publisher and evidence service**, not a permission oracle. If it disappears, your policy
files, signatures, ledger, and proofs remain independently verifiable.

---

## Documentation map

| # | Document | Covers |
|---|---|---|
| 00 | [Architecture overview](docs/00-overview.md) | Layer map, trust model, data flow, what runs where |
| 01 | [Identity & key management](docs/01-identity-and-keys.md) | Key generation, storage, hardware backing, rotation, recovery, key event log |
| 02 | [Personal Data Policy format](docs/02-policy-format.md) | JSON schema, rights vocabulary, canonicalization, signing, versioning |
| 03 | [Identity resolution](docs/03-identity-resolution.md) | Binding identifiers without a public directory; commitments, OPRF, pairwise IDs |
| 04 | [Policy sharing](docs/04-policy-sharing.md) | Public page, short URL, QR, NFC, wallet pass, PDF, `.well-known` |
| 05 | [Policy verification](docs/05-policy-verification.md) | Issuer, signature, currency, revocation, history, timestamp — without trusting PRM |
| 06 | [Authorizations & exceptions](docs/06-authorizations.md) | Signed grants, scope, expiry, revocation, consent receipts |
| 07 | [Audit ledger](docs/07-audit-ledger.md) | Personal hash chain + global Merkle transparency log, proofs |
| 08 | [Timestamping](docs/08-timestamping.md) | RFC 3161 vs transparency logs vs blockchain anchoring; recommendation |
| 09 | [Enterprise integration](docs/09-enterprise-integration.md) | REST API, webhooks, receipts, SDKs, auth, rate limits |
| 10 | [No-integration fallback](docs/10-no-integration-fallback.md) | How PRM works against organizations that never integrate |
| 11 | [ALPR / Flock use case](docs/11-alpr-use-case.md) | End-to-end worked example, first demonstration case |
| 12 | [Threat model](docs/12-threat-model.md) | 12 named adversaries, mitigations, residual risk |
| 13 | [MVP](docs/13-mvp.md) | Smallest useful version, scope boundary, acceptance criteria |
| 14 | [Future architecture](docs/14-future-architecture.md) | What is deliberately deferred and why |
| 15 | [Repository structure](docs/15-repo-structure.md) | Breezy-Point-Beach monorepo, branches, env, secrets, CI |
| 16 | [Vercel deployment](docs/16-vercel-deployment.md) | App Router, runtimes, env vars, Postgres, crypto placement rules |
| 17 | [GitHub workflow](docs/17-github-workflow.md) | Branch → PR → preview → tests → main → production |
| 18 | [Implementation roadmap](docs/18-roadmap.md) | Prototype → MVP → public beta → enterprise |
| — | [Decision register](docs/decisions.md) | Every major decision: why, threat solved, MVP?, standard, simpler alternative |
| — | [Legal review](docs/legal-review.md) | Two template phrases awaiting an attorney's view, and what is settled |
| — | [Original brief](docs/brief.md) | The requirements this architecture answers |

## Normative artifacts

| Path | What it is |
|---|---|
| [spec/NORMATIVE.md](spec/NORMATIVE.md) | **Normative rules.** Canonicalization, non-hashed members, domain separation, derivations. Takes precedence over `docs/`. |
| [spec/schemas/](spec/schemas/) | JSON Schema (draft 2020-12) for policy, authorization, key event, ledger entry |
| [spec/examples/](spec/examples/) | Sample signed policies (including the ALPR case), authorizations, ledger entries |
| [spec/test-vectors/](spec/test-vectors/) | Canonicalization + signature vectors any implementation must reproduce |

## Status

Design complete; implementation not started. See [docs/18-roadmap.md](docs/18-roadmap.md).
Target home: `github.com/Breezy-Point-Beach/prm`, deployed via Vercel.
