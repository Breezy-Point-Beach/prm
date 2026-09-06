# 18 — Implementation Roadmap

Four stages. Each has an exit criterion that is a demonstrable fact, not a feeling.

---

## Stage 1 — Prototype (≈3 weeks)

**Goal:** prove the cryptographic core is sound and reproducible before any UI exists.

- `@prm/crypto` — Ed25519, JCS, SHA-256, HKDF, multibase; matches `spec/test-vectors/` byte-for-byte.
- `@prm/schema` — types, JSON Schemas, normalization rules.
- `@prm/verify` — offline verification of policies and key events.
- `prm` CLI — `keygen`, `sign`, `verify`.
- Key Event Log with pre-rotation, exercised by tests.
- No web app, no database, no Vercel.

**Exit:** a second implementation (or the same code re-run from a clean clone) reproduces every digest
and signature in `spec/`, and `prm verify` succeeds with the network disabled.

*Much of this stage is already specified and test-vectored in [`spec/`](../spec/), which is why the
estimate is short.*

---

## Stage 2 — MVP (≈8–10 weeks)

**Goal:** one person can do the full §13 loop, end to end, for real.

Weeks 1–2 packages · 3 CLI · 4–5 web authoring and publishing · 6 Merkle log + cron timestamping ·
7 PDF/QR/notice packet · 8 authorizations + ledger UI · 9 hardening + CI · 10 buffer for recovery UX.

**Exit:** all seven §13.5 acceptance criteria pass, including criterion 4 (zero occurrences of a test
identifier anywhere server-side) and criterion 5 (a `.prmproof` bundle still verifies after the
deployment is deleted).

**The real milestone:** deliver a signed ALPR policy to one actual municipality and record whatever
comes back. Do this in week 10, not after launch. What returns will change the roadmap more than any
internal decision.

---

## Stage 3 — Public beta (≈3 months)

**Goal:** many users, several engaged organizations, evidence the model works socially and not just
cryptographically.

| Add | Why now |
|---|---|
| Social recovery (Shamir 2-of-3) | Accidental key loss is the dominant real failure (§12 T12) |
| Multi-device via encrypted vault sync | Second most common support issue |
| Mobile wallet pass + NFC card | ALPR field usage demands something physical |
| Webhooks + `.well-known/prm-receiver` probe | The first integrating organization needs a push channel |
| Consent receipts (ISO 27560) | Turns one-sided notice into two-sided record |
| Log witnesses (`@prm/monitor`) | Closes the T4 split-view residual |
| OpenTimestamps second anchor | Independence from TSA lifetimes |
| Per-relationship policy variants | Closes the T2 correlation limit |
| Jurisdiction templates (2–3 US states) | Lawyer-authored, versioned, hash-identified |
| Publish-notification channel | Detection for T3 stolen-key abuse |

**Deliberately still absent:** identifier lookup of any kind, ZK proofs, decentralized storage,
automated statutory requests.

**Exit:** ≥3 organizations acknowledging notices; ≥1 third party independently running a log monitor;
a documented case where a user granted and later revoked an exception and the grantee honoured it.

That middle criterion is the one that proves decentralization is real rather than rhetorical. Do not
declare beta complete without it.

---

## Stage 4 — Enterprise-ready (≈6 months)

**Goal:** an organization can integrate deeply, and PRM can be audited by someone hostile.

- `@prm/sdk` + WASM build of `@prm/verify` for JVM/.NET/Python consumers.
- OAuth client credentials, mTLS option, org dashboards, audit export.
- OPRF resolver (§03.4) **with a published governance model** — federated, rate-limited, transparent.
  Do not ship the resolver before the governance document.
- Automated statutory privacy requests, one jurisdiction at a time, with counsel.
- Third-party security audit, focused on: client key handling, canonicalization, the Merkle log, and
  the T1 drift surface.
- Formal spec document suitable for independent implementation; consider a CG/IETF submission for the
  policy format.
- Legal/governance structure for the transparency log (§12 T1) — the point at which "we won't become a
  registry" needs to be a constraint on the entity, not a promise from a person.

**Exit:** an independent implementation of `@prm/verify` written from the spec alone passes the
conformance vectors.

---

## Sequencing risks

1. **Building the app before the packages.** The app is easy and satisfying; the packages are the
   product. Inverted order produces crypto shaped by UI convenience, which is how canonicalization bugs
   get shipped.
2. **Adding lookup early.** It will feel necessary the first time an organization asks "how do we find
   someone's policy?" The correct answer is "you don't — they hand it to you." Holding that line
   through Stage 3 is the single highest-leverage discipline in this plan.
3. **Deferring recovery UX.** It is unglamorous and it will cause more user harm than any attack in
   §12. Budget week 10 for it and expect to use it.
4. **Overclaiming legal effect** in marketing before Stage 3 evidence exists. One overstated claim,
   repeated by a journalist, makes every records officer treat the project as adversarial noise.
