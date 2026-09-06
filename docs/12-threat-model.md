# 12 — Threat Model

Scope: the PRM system itself. Out of scope: the recipient organization's internal security, the
lawfulness of their processing, and endpoint compromise of a fully rooted user device (noted where it
changes a conclusion).

Residual-risk ratings assume the **MVP** feature set unless stated.

---

## T1 — PRM becomes a central surveillance registry

**Attack.** PRM accumulates identifiers, relationships, and query logs and becomes the highest-value
target in the ecosystem — by design drift, acquisition, or subpoena.

**Why it is the top threat.** It is the failure mode that does not look like a failure. Every step is
individually reasonable: "add lookup so orgs can find policies," "store the plate so we can match,"
"log queries for abuse detection."

**Mitigations.** Push-first architecture (§03.2). Identifier commitments with per-identifier salts, so
the server never holds an identifier. Pairwise IDs so grantees cannot join records. Lookup opt-in and
off by default. Query logs at 7-day retention. Quarterly transparency report + warrant canary.
Structural: the schema has no field for a raw identifier on the server side, so storing one requires a
deliberate schema change that shows up in review.

**Residual.** Medium and *permanent*. This is a governance risk more than a technical one. Concrete
countermeasure to adopt early: publish the database schema, and add a CI check that fails if a column
named like an identifier appears outside an allowlist. Consider a legal structure (nonprofit steward,
or a foundation holding the log) before the incentive to defect exists.

---

## T2 — Correlation attacks

**Attack.** Two organizations compare records and determine they concern the same person; or a global
observer correlates policy fetches, log-append timing, and short-URL resolutions.

**Mitigations.** Pairwise IDs. No `accountId` in webhooks or org-facing responses. Batched hourly
anchoring so timing leaks nothing per-user (§08.4). Cached, CDN-served policy reads so fetches do not
reach an origin log. Opaque log leaves.

**Residual.** Medium. The honest limit stated in §03.2: presenting the *same* public policy to two
organizations lets them correlate on `policyChainId`. Mitigation (per-relationship policy variants) is
a beta item. Users doing high-risk work should be told this plainly, not reassured.

---

## T3 — Stolen signing key

**Attack.** Malware or device theft yields `K_sign`; attacker signs a permissive policy replacing the
user's restrictive one.

**Mitigations.** Pre-rotation commitment (§01.5.1) — the attacker **cannot rotate**, so they cannot
lock the user out; the user rotates using `K_next` and revokes. Key at rest requires a passkey/passphrase
unlock, so mere file exfiltration is insufficient. Time-scoped revocation invalidates the attacker's
signatures from the revocation instant while preserving the user's earlier history.

**Residual.** Low-to-medium. Window of exposure is from theft to detection. Detection is the weak
point — add an optional "notify me on every publish" channel (email/push on a new policy version) so an
unexpected publication is visible. Cheap; put it in the MVP.

*Verified by test vector:* `a stolen current key CANNOT rotate to an attacker key`.

---

## T4 — Malicious PRM provider

**Attack.** PRM forges a policy, substitutes a key, backdates an event, hides a version, or shows
different histories to different parties.

**Mitigations.**

| Attack | Blocked by |
|---|---|
| Forge a policy | No server-side signing key; verification is over the user's Ed25519 signature |
| Substitute a key | Self-certifying `accountId` + pre-rotation commitments in a hash-chained KEL |
| Backdate | RFC 3161 tokens from an independent TSA over the tree head |
| Rewrite history | Consistency proofs; any party holding an old STH can demonstrate the break |
| Split view | Client STH pinning (MVP), external anchoring (MVP), third-party witnesses (beta) |
| Hide a version | Detectable if the user monitors their own inclusion proofs |

**Residual.** **Censorship and availability, which are not mitigated.** PRM can refuse to serve a
user's policy or stop appending their entries. Recovery: self-hosting via `/.well-known/prm-policy`
(§04.3a) and log mirrors. Say this plainly — claiming otherwise would be false.

---

## T5 — Malicious recipient

**Attack.** An organization claims it received an older/weaker policy version, or forges an
acknowledgment, or claims it never received a notice.

**Mitigations.** Every version is content-addressed and independently timestamped, so "which version
existed when" is not the recipient's word against the user's. Delivery evidence is third-party attested
(USPS, DKIM, HTTP response hashes). Acknowledgments are signed by the org's own key, and an unsigned
claim carries correspondingly less weight.

**Residual.** Low for existence, medium for receipt when the org refuses signed receipts and the user
used only email. Guidance: certified mail for anything that matters.

---

## T6 — Replay attacks

**Attack.** A revoked authorization is replayed to a grantee; a webhook is replayed; a policy signature
is reused on a different document type.

**Mitigations.** Mandatory `expires` on every authorization. Bitstring Status List for revocation with
a 5-minute cache TTL. Webhook signatures cover `timestamp + body` with a 5-minute freshness window and
a ULID delivery id for idempotency. **Domain separation** — each document type signs under its own
prefix (`PRM-POLICY-v1\x00`, `PRM-AUTHZ-v1\x00`, …), so a signature from one type is invalid on another.

**Residual.** Low. Note the honest gap: a grantee who does not check the status list gets stale
authority until `expires`. That is why expiry is mandatory rather than optional.

*Verified by test vector:* `domain separation: a policy signature is not valid as an authorization`.

---

## T7 — Fake policies

**Attack.** Someone publishes a policy claiming to be another person, either to impersonate or to
discredit ("look, this person's policy allows everything").

**Mitigations.** A policy proves *account* authorship, never human identity — stated explicitly in
§05.6 and in every rendering. Binding to a real person requires selective identifier disclosure, which
requires the salt, which requires the vault.

**Residual.** **Medium and inherent.** PRM does no KYC, deliberately. An organization that needs
assurance that the policy's author is the person whose plate it names has exactly one mechanism:
the disclosed identifier + salt opening a commitment. Even that proves knowledge of the identifier,
not lawful association with it. Do not oversell; document that registration-based attestation is a
§14 item and that the first-party use case (a person asserting terms about themselves) does not
require it.

---

## T8 — Policy substitution

**Attack.** An attacker (or a compromised short-URL service) serves a different, weaker policy at the
user's URL.

**Mitigations.** QR codes and printed cards carry a **digest prefix** alongside the URL (§04.4), so
substitution is detectable against the physical artifact. `ETag` = policy digest. Policy chains: a
substituted policy cannot produce a valid `previousPolicyHash` chain back to a v1 the recipient has
already seen. Inclusion proofs bind a version to a timestamped log.

**Residual.** Low, provided verifiers check the chain rather than fetching a single document. The SDK
must make chain-walking the default, not an option.

*Verified by test vector:* `tamper detection: flipping one rule invalidates the signature`.

---

## T9 — Identifier enumeration

**Attack.** Iterate plates/emails/phones against a lookup endpoint to build a directory of PRM users
and their identifiers.

**Mitigations.** No lookup at all in the MVP. If enabled: memory-hard KDF, 3-byte k-anonymous prefixes,
authenticated + quota'd + billable `/v1/resolve`, and no anonymous access. OPRF blinding post-beta
makes offline enumeration impossible.

**Residual.** Medium *if lookup is ever enabled at k-anonymity only* — §03.3 states the cost honestly
(~3.2 CPU-years per namespace, which a well-funded adversary can afford). This is the strongest reason
to keep lookup off by default and to prioritize OPRF before any large-scale lookup launch.

---

## T10 — Data scraping

**Attack.** Crawl `/u/*` to harvest every published policy, display name, and commitment set.

**Mitigations.** Handles are random (not sequential, not name-derived), so there is nothing to
enumerate. `displayName` is optional and defaults to empty. Policies contain no PII by construction.
Rate limiting + Vercel WAF. `X-Robots-Tag: noindex` unless the user opts into indexing.

**Residual.** Low. Accept it: published policies are *meant* to be public. The control that matters is
that a scraped corpus contains no identifiers — verified by the `no PII in the published policy` test
vector, which should run in CI against generated policies.

---

## T11 — Blockchain deanonymization

**Attack.** Per-user or per-event chain anchoring creates a permanent public timing side channel
correlating anchors with real-world events.

**Mitigations.** No personal data on any ledger, ever. Anchoring is over hourly Merkle roots only, so
the artifact is one value per hour independent of user count or activity. Bitcoin anchoring (OTS) is
beta and additive, never a dependency.

**Residual.** Very low, *and it stays that way only if batching is preserved*. §08.4 marks batching as
a privacy control, not an optimization, precisely so nobody "improves" latency into per-event anchoring.

---

## T12 — Account recovery abuse

**Attack.** An attacker socially engineers recovery to seize an account — the classic break in every
consumer key system.

**Mitigations.** **PRM has no recovery capability at all.** There is no support-driven reset path,
because there is no escrowed key. Recovery requires a pre-committed `K_rec` whose digest was published
in the KEL at genesis. Shamir shares are encrypted to guardians' public keys, so PRM cannot use them
even if it stored them. Every recovery event is public in the KEL, so a takeover is visible to anyone
watching, including the user.

**Residual.** Low for attack, **high for accidental loss** — which is the real risk. The dominant
failure mode of this design is a user losing their mnemonic and their account permanently. Countermeasures
are product, not crypto: force a backup step before publishing a first policy, verify the mnemonic by
challenge, prompt for a second device, and prompt for guardians at beta. Budget real design time here;
it will affect more users than every other threat on this list combined.

---

## Cross-cutting: what an attacker gains from a total Vercel + Postgres compromise

Worth stating as a single answer, because it is the question every reviewer asks:

**They obtain:** public keys, published policies (already public), opaque ledger leaf hashes, encrypted
vault blobs they cannot decrypt, handle→account mappings, org API credentials, the log signing key
`K_log`, and any wallet-pass provider certificates.

**They can:** deny service, censor, serve stale content, forge tree heads (detectably), and mint fake
wallet cards (which fail on resolution).

**They cannot:** read a vault, decrypt evidence artifacts, learn a raw identifier, forge a policy or
authorization, impersonate a user, or alter any past user-signed document.

That gap between the two lists is the architecture's whole purpose. Any proposed change that narrows
it should be rejected or escalated.
