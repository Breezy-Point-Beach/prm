# 14 — Future Architecture

Everything here is deliberately deferred. Each entry states the **trigger** that should promote it,
because "later" without a trigger becomes "never" or "prematurely."

## 1. Deferred capabilities

### Zero-knowledge proofs — *defer to post-beta*
**Use:** prove "my policy denies AI training" without revealing the rest; prove an identifier is in a
committed set without disclosing it; prove policy properties to a verifier who learns nothing else.
**Why wait:** salted commitments + selective disclosure (§03.1) cover the actual MVP requirements at a
fraction of the complexity. ZK adds a proving system, a trusted setup decision, circuit auditing, and
proof sizes that break QR delivery.
**Trigger:** a verifier population that needs property-level disclosure without document disclosure —
realistically, regulated industries. **Standard when it lands:** BBS+ / `bbs-2023` Data Integrity
cryptosuite for selective disclosure, which is on the W3C track and interoperates with the VC model
already in use. Prefer it over a bespoke SNARK.

### Mobile wallet — *defer to beta*
**Use:** OID4VP presentation, offline verification at a roadside, Secure Enclave key storage.
**Why wait:** the web app with a passkey covers 90% of the value. Native adds app-store review, two
codebases, and the P-256/Ed25519 mismatch (§01.4).
**Trigger:** ALPR field usage showing that a browser-based QR flow fails in practice.
**Standard:** OID4VP + OpenID4VCI; ISO 18013-5 if mDL interop ever matters.

### Decentralized storage — *defer indefinitely*
**Use:** policy availability if PRM disappears.
**Why wait:** the failure mode is already addressed by (a) self-hosting at
`/.well-known/prm-policy`, (b) the user's local copy, (c) the recipient's copy, and (d) `.prmproof`
bundles. IPFS/Arweave adds pinning economics and a permanence property that conflicts with erasure.
**Trigger:** evidence that self-hosting is too hard for real users. **Simpler alternative that should
be tried first:** a "publish to your own GitHub Pages" one-click export. Nearly free, uses
infrastructure users already trust, and produces a real second copy.

### Enterprise SDKs beyond `@prm/verify` — *defer to enterprise stage*
**Trigger:** the third organization asking. Not the first — the first should be served by hand, so
you learn what the SDK should be. **Note:** evaluate a WASM build of `@prm/verify` before writing
native Java/.NET/Python ports; municipal stacks are heterogeneous and one WASM artifact may cover most.

### Municipal integrations — *defer to public beta*
**Trigger:** one municipality volunteering. Until then, §10 is the product. Build the
`.well-known/prm-receiver` probe now (cheap) so the on-ramp exists when someone wants it.

### Large-scale policy resolution — *defer to post-beta*
**Use:** an ALPR vendor checking millions of plates against PRM.
**Why wait:** it is the T1/T9 risk concentrated into one feature. It must not ship before OPRF (§03.4),
federated resolvers, and a published abuse policy exist.
**Trigger:** OPRF shipped **and** a written governance model for resolver operation. Treat this as the
single most dangerous roadmap item; it is where a well-intentioned PRM turns into the registry.

### Automated statutory privacy requests — *defer to public beta*
**Use:** generate a CCPA/CPRA/GDPR request from the policy, track the statutory clock, escalate.
**Why wait:** requires per-jurisdiction legal review and correct deadline logic; getting it wrong
produces confidently incorrect legal claims, which is worse than not shipping it.
**Trigger:** legal counsel engaged for at least one jurisdiction. Ship one jurisdiction well (start
with California or the user's home state) rather than ten approximately.

### Blockchain anchoring — *defer to beta, as a second anchor only*
OpenTimestamps over the daily root, additive to RFC 3161. Never a dependency, never per-event, never
carrying personal data. **Trigger:** a counterparty questioning TSA independence, or archival
requirements beyond a TSA certificate's lifetime.

### Multi-jurisdiction policy engines — *defer indefinitely*
**Use:** automatically reconciling a policy against the law where an observation occurred.
**Why wait:** this is a legal-reasoning system wearing an architecture costume. It will be wrong,
confidently, in ways that harm users. **What to do instead:** jurisdiction-specific *templates*
authored by lawyers, versioned and hash-identified, with the user selecting one. Templates are honest
about being drafting aids; an engine implies adjudication.

### Delegation, guardianship, estates — *defer to enterprise stage*
The KEL `delegation` event type exists as the hook. The scope language needs jurisdiction-specific
legal input. Real demand exists (minors, incapacity, decedents' data) — it is deferred for competence,
not importance.

## 2. The one component with a plausible path off Vercel

**The transparency log.** Everything else in this architecture is comfortably serverless indefinitely.
The log is the exception because it is inherently sequential and grows without bound.

Order of escalation:
1. **Now:** Postgres advisory lock, single-writer append (§07.3.2). Fine to millions of entries.
2. **If append rate becomes the constraint:** batch — accumulate for 1 s, append a subtree.
3. **If the tree outgrows Postgres:** move to a dedicated log implementation (Trillian, or Sigstore's
   Rekor as a hosted alternative) on a small VM. **Not** Kubernetes; one machine with a replica.
4. **If independence becomes the requirement:** publish to an existing public transparency log rather
   than operating one.

Option 4 deserves early evaluation — **using Sigstore Rekor as the log instead of operating one** would
remove the T4 split-view residual risk almost entirely, at the cost of an external dependency and less
control over entry format. It is a genuinely attractive simplification that should be revisited before
scaling the self-hosted log.

## 3. Things that should never be built

- A central database of identifiers, under any privacy framing.
- Key escrow, "just in case," including an opt-in default-on variant.
- Personal data on a public ledger.
- An enforcement claim PRM cannot back — e.g. presenting policy delivery as legally binding consent
  withdrawal in jurisdictions where it is not.
- Automated bulk notice sending without a human in the loop (§10.4).
- A universal PRM identifier that organizations are encouraged to key on.

Keep this list in the repo and cite it in PR review. Architectural drift happens one reasonable pull
request at a time.
