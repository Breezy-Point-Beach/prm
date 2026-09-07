# 11 — Demonstration Case: ALPR / Flock-style Systems

Sample policy: [`spec/examples/policies/policy-v1.json`](../spec/examples/policies/policy-v1.json)
Sample authorization: [`spec/examples/authorizations/example-grant.json`](../spec/examples/authorizations/example-grant.json)

## 1. Why this is the right first case

- **The line is intuitive.** "You may look at my plate; you may not keep a two-year map of my
  movements" is a distinction almost everyone grasps in one sentence. No privacy vocabulary required.
- **It is asymmetric today.** The person has no mechanism at all. Any mechanism is an improvement.
- **The counterparties are enumerable and public.** Municipalities and their vendors are identifiable,
  have public records obligations, and have published contact points.
- **The identifier is clean.** A license plate is a stable, self-known, normalizable identifier that
  the person can assert without a third-party attestation.
- **It produces a repeatable artifact.** One well-run case becomes a template thousands of people can
  execute in five minutes.

Note that plate ownership is asserted, not proven, and a plate identifies a vehicle rather than a
person. PRM does not attempt to resolve that; the policy speaks for its issuer, and the disclosed
identifier is the issuer's claim about a vehicle they operate. Registration-based attestation is a
§14 item.

## 2. The policy expressed

The user's position, in PRM terms:

| Category | Decision | Conditions |
|---|---|---|
| `prm:observation` | **allow** | Lawful capture in a public place is conceded |
| `prm:transactional` | **conditional** | Immediate comparison against a lawfully constituted hotlist |
| `prm:retention` | **conditional** | `maxRetention: PT0S` on a non-hit; hits retained per active investigation |
| `prm:location-history` | **deny** | No time-series movement record |
| `prm:correlation` | **deny** | No joining to other databases or agency systems |
| `prm:profiling` | **deny** | |
| `prm:inference` | **deny** | No derived pattern-of-life, no "unusual movement" scoring |
| `prm:third-party-sharing` | **deny** | No cross-agency, no regional/national sharing network |
| `prm:sale` | **deny** | |
| `prm:commercialization` | **deny** | |
| `prm:advertising` | **deny** | |
| `prm:ai-training` | **deny** | Includes vendor model improvement on retained reads |
| `prm:biometric` | **deny** | Vehicle occupant imagery |
| `prm:law-enforcement` | **conditional** | `requiresLegalProcess: true`; `basisAcknowledged: ["court-order","statutory-override"]` |
| `prm:emergency` | **allow** | Imminent threat to life, time-limited |
| `prm:deletion` | **conditional** | Delete non-hit reads immediately; hit reads on case closure |

Two details that make this policy hard to dismiss:

1. **It concedes observation and emergency use.** A blanket refusal reads as unserious and gets filed
   under "activist mail." A policy that grants the legitimate uses and objects to the accumulation is
   engaging with the actual system, and is far harder to wave away.
2. **It acknowledges lawful override.** `basisAcknowledged: ["court-order", "statutory-override"]` on
   the law-enforcement rule concedes the point that a records officer would otherwise use to dismiss
   the entire document.

## 3. End-to-end walkthrough

### Step 1 — Author and sign (client, ~3 min)

The user picks the **"ALPR / Vehicle Movement"** template, adds their plate, and signs. Locally:

```
salt        = HKDF(S_bind, info="prm/v1/salt/us-license-plate/US-CA-0EXAMPLE")[0..16]
commitment  = SHA-256("us-license-plate" ‖ 0x00 ‖ "US-CA-0EXAMPLE" ‖ 0x00 ‖ salt)
digest      = SHA-256(JCS(policy minus id, proof))
proofValue  = Ed25519(K_sign, "PRM-POLICY-v1\x00" ‖ digest)
```

The plate never leaves the device. The published policy contains only `commitment`.

### Step 2 — Publish and prove existence (~5 s)

```
POST /api/v1/policies { policy }
  → validate schema, verify signature, reject if the key isn't authorized in the KEL
  → store; append SHA-256(ledgerEntry) as a Merkle leaf
  → return { inclusionProof, signedTreeHead }
Cron (≤1 h) → RFC 3161 token over the tree root
```

The user now holds a proof bundle showing the policy existed at a specific time — **before** any
subsequent dispute about what they had asked for and when.

### Step 3 — Identify recipients

Two per municipality, and both matter:

- **The agency** — the data controller, subject to public-records law and local oversight.
- **The vendor** — operator of the retention infrastructure and the sharing network, and often the
  party that actually performs the retention, correlation, and model training the policy objects to.

The app maintains a community-maintained recipient directory (a JSON file in the repo, PR-able) with
addresses, privacy contacts, published retention periods, and whether the agency has adopted a policy.
That directory is about **organizations**, never about people — it is the inverse of a surveillance
registry and should be framed that way.

### Step 4 — Deliver

Probe `https://{agency-domain}/.well-known/prm-receiver`:

- **Present** → `POST` the notice to their endpoint; store the HTTP response and its body hash.
- **Absent** (the realistic case) → generate the §10 notice packet and deliver by **certified mail** to
  the records custodian and **email** to the published privacy address, both in one flow.

Ledger: `notice.sent` × 2, with channel, recipient, tracking number, and packet digest.

### Step 5 — Record the response

| Outcome | Ledger entry | Follow-up |
|---|---|---|
| Signed consent receipt | `acknowledgment.received`, disposition `accepted`/`partial` | Store their signed receipt; verify their key |
| Human email reply | `acknowledgment.received`, raw `.eml` preserved with DKIM intact | Parse manually; user classifies |
| Statutory refusal with citation | `acknowledgment.received`, disposition `rejected` + citation | Prompt user: accept, or `dispute.raised` |
| Green card returned, no substantive reply | `notice.delivered` only | After window: non-response record |
| Nothing at all | `acknowledgment.received`, disposition `none` after N days | Prompt for second notice |

### Step 6 — Grant a narrow exception (the credibility move)

If the agency responds that they need retention for an active investigation, the user can issue a
90-day authorization scoped to `prm:retention` + `prm:correlation`, for that agency only, with
`onwardSharing: "prohibited"` and the plate disclosed via `subjectRef.disclosedIdentifiers` so the
agency can actually apply it in their system.

This is the interaction that distinguishes PRM from a form letter: **a person can negotiate, in
machine-checkable terms, and revoke later with one tap.** Revocation flips a status-list bit, writes a
ledger entry, and fires a webhook if they subscribed.

### Step 7 — The evidentiary trail

```
policy v1 (signed) ──┐
                     ├─► ledger entry #12 policy.published ──┐
plate commitment  ───┘                                       │
                                                             ├─► Merkle leaf 148223
notice packet (signed) ─► ledger #13 notice.sent ────────────┤
USPS green card scan   ─► ledger #14 notice.delivered ───────┤
agency email reply     ─► ledger #15 acknowledgment.received ┘
                                                             │
                                        signed tree head (treeSize 148224)
                                                             │
                                        RFC 3161 token, FreeTSA, 2026-09-06T16:00Z
```

Every link is independently checkable. The claim the user can make eighteen months later — *"on
September 6, 2026, I delivered a signed objection to persistent retention; you received it on
September 11; you did not respond; here is third-party proof of all three"* — is verifiable by a
records officer, a journalist, a regulator, or opposing counsel, **with PRM offline**.

## 4. What this does not achieve

- It does not stop the camera, and it does not delete anything by itself.
- A municipality can lawfully decline, and often will.
- Statutory retention mandates override the policy in some jurisdictions; the policy says so itself.

What it *does* achieve is turning a diffuse objection into a **specific, dated, verifiable,
individually-attributable record** — at a scale where a thousand of them arriving at one agency becomes
a public-records story, an oversight-board agenda item, and a procurement question. That is the theory
of change, and the architecture should be judged against it.

## 5. Metrics for the demonstration

Judge the pilot on: notices delivered with verified receipt; response rate; **partial-compliance rate**
(the most informative number, and the one that shows the `declined[]` design working); time to
response; and the number of independent verifications performed by third parties against the log. That
last one is the real proof the decentralization claim is not theater.
