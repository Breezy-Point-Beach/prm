# 03 — Identity Resolution

> This is the layer where PRM most easily becomes the thing it opposes. A naive "look up the policy for
> plate ABC123" endpoint **is** a surveillance registry. Everything below exists to avoid building one.

## 1. The problem

An organization holds an identifier — a plate, an email, a phone number, a device ID — and needs the
policy attached to the person behind it. The obvious design is a lookup table. The obvious design is
disqualifying, for three reasons:

1. It creates the universal tracking identifier the project exists to prevent.
2. Identifier spaces are small and enumerable. US plates are ~10⁸ per state; phone numbers ~10¹⁰; email
   addresses are guessable from breach corpora. Any hash-keyed directory is a *rainbow table waiting to
   be built*.
3. Even a perfectly private lookup discloses the fact of a query. "Which agency asked about which
   plate" is itself sensitive.

## 2. The reframe that solves most of it

**PRM is push-first, not pull-first.**

The primary mode is: *the person presents their policy to the organization* — QR at a traffic stop, a
signed PDF attached to a records request, a link in an email footer, an NFC card handed across a
counter, an API call from an app the person authorized. In push mode there is **no lookup at all**: the
organization receives the policy and a pairwise reference, and stores it against its own record.

Lookup is a **fallback** for the case where an organization already holds an identifier and wants to
check for a policy proactively. Design it so it can be turned off entirely and the product still works.

> **Decision — push-first architecture.**
> *Why:* eliminates the registry for the majority of real interactions. *Threat:* central surveillance
> registry, identifier enumeration, query-pattern disclosure. *MVP:* yes — MVP ships push only.
> *Standard:* n/a (architectural). *Simpler alternative:* a lookup directory — rejected on principle.

## 3. Four mechanisms, in order of preference

### 3.1 Identifier commitments + selective disclosure (MVP)

The policy carries **commitments**, never identifiers:

```
salt_i      = random 16 bytes, unique per identifier, stored only in the user's vault
commitment  = SHA-256( namespace || 0x00 || normalize(identifier) || 0x00 || salt_i )
```

Published in the policy as `identifierCommitments[]`. Because the salt is 128 bits of entropy and never
published, the commitment is **not** brute-forceable even though the identifier space is tiny. That is
the entire point of the salt, and it is why a bare `SHA-256(plate)` is unacceptable.

To prove "this policy covers plate ABC123" to a specific organization, the user includes
`{namespace, value, salt}` in the **Authorization** or notice delivered *to that organization only*
(`subjectRef.disclosedIdentifiers`). The organization recomputes the commitment and confirms it appears
in the signed policy. Nobody else can.

Properties: no online oracle, no directory, offline-verifiable, per-identifier granularity, and
revocable by rotating the salt in a new policy version.

**Normalization is normative** and lives in `@prm/schema`, because a commitment that depends on
whitespace or case is useless:

| Namespace | Normalization |
|---|---|
| `email` | lowercase; trim; **no** gmail dot/plus stripping (that is a policy decision, not a normalization) |
| `phone` | E.164, digits only, leading `+` |
| `us-license-plate` | `US-{state}-{alnum uppercase, no spaces/dashes}` e.g. `US-MN-ABC123` |
| `vin` | uppercase, 17 chars, ISO 3779 |
| `device-id` | as issued, case-sensitive, no transformation |
| `account-id` | `{issuer-domain}:{id}`, issuer lowercased |

### 3.2 Pairwise identifiers (MVP)

For every relationship, derive a per-organization subject reference:

```
pairwiseId = base32( HKDF-SHA256(S_bind, salt=granteeId, info="prm/v1/pairwise")[0..16] )
```

Two organizations comparing notes cannot tell that their `pairwiseId`s refer to the same person — the
values are unlinkable without `S_bind`. The user can still recognize and revoke each relationship,
because the derivation is deterministic from their own secret.

This is the same construction as OIDC pairwise subject identifiers, which is a useful thing to say to
enterprise reviewers.

> **Decision — pairwise subject IDs, no global user number.**
> *Why:* the account ID is public, so it must never be the thing organizations key on.
> *Threat:* correlation attacks, cross-database joins. *MVP:* yes. *Standard:* OIDC Core pairwise
> subject identifier pattern, RFC 5869. *Simpler alternative:* use `accountId` everywhere — that
> recreates the universal identifier and is prohibited.

Note the honest limit: if a person hands the *same* signed public policy to two organizations, those
two can correlate on `policyChainId`. Pairwise IDs protect the subject reference, not the policy
document. Mitigations: (a) the policy contains no PII, so correlation yields "these two records belong
to the same PRM account," not a name; (b) offer **per-relationship policy variants** (same rules, distinct
chain) for high-sensitivity users at beta. Document the limit rather than pretending it away.

### 3.3 k-anonymous prefix lookup (beta, optional, off by default)

If proactive lookup is genuinely needed:

```
h        = Argon2id(pepper_ns || namespace || normalize(identifier), t=3, m=64MiB, p=1) → 32B
client sends h[0..2]                       (3 bytes → ~16.7M buckets)
server returns every (h_full_suffix → policy pointer) in that bucket
client matches locally
```

Modeled directly on the Have I Been Pwned range API. The server never learns which identifier was
queried, only a 3-byte prefix shared with ~1/16M of the keyspace.

The memory-hard KDF is what makes offline enumeration expensive: at ~100 ms/hash, a full US-state plate
space (10⁸) costs ~3.2 CPU-years per namespace. **Be honest in the docs: that is a real cost for a
script kiddie and a rounding error for a well-funded adversary.** Prefix lookup raises the price of
enumeration; it does not prevent it. It is therefore optional, per-user opt-in, and per-namespace.

### 3.4 Blinded lookup via OPRF (post-beta, the correct answer)

RFC 9497 (V)OPRF. The client blinds the identifier, the resolver evaluates with a key it holds, the
client unblinds to get a deterministic lookup token:

```
client:   blinded = Blind(normalize(identifier))
resolver: evaluated = Evaluate(k_oprf, blinded)          // learns nothing about the input
client:   token = Finalize(identifier, evaluated)        // deterministic, unforgeable offline
client:   GET /resolve/{token}
```

Because computing a token requires a round trip, **offline enumeration is impossible** — the adversary
is reduced to online queries, which are rate-limited, authenticated, logged, and billable. This is a
qualitative improvement over §3.3, not a quantitative one.

Cost: the resolver becomes an online dependency and a target. Mitigate by (a) **federating** resolvers
so PRM is not the only one, (b) rotating `k_oprf` on a schedule so tokens expire, (c) publishing query
volume transparency reports, and (d) fronting it with **Oblivious HTTP (RFC 9458)** so the resolver
cannot link queries to requester IPs.

> **Decision — OPRF deferred, not skipped.**
> *Why:* it is the only construction that actually stops enumeration, but it adds an online oracle and
> a key-rotation regime. *Threat:* identifier enumeration, data scraping. *MVP:* no. *Standard:*
> RFC 9497, RFC 9458. *Simpler alternative:* §3.3 prefix lookup, shipped first, with the enumeration
> cost stated plainly to users.

## 4. What we deliberately do not build

| Rejected | Why |
|---|---|
| Public searchable directory | It is the surveillance registry, restated |
| Bare `SHA-256(identifier)` index | Enumerable in minutes for plates and phone numbers |
| Bloom filter of all identifiers | Leaks membership, still enumerable, no revocation |
| Identifier-keyed DNS / `.well-known` per identifier | Publishes the identifier space to every resolver operator |
| Blockchain registry of identifiers | Permanent, global, undeletable disclosure — a hard prohibition |
| Zero-knowledge set membership | Correct but heavy; §14 revisits it once the rest is proven |

## 5. Where does the salt live, and what happens if it's lost?

`salt_i` lives in the user's encrypted vault, backed up by the mnemonic (it is derived, not random, in
practice: `salt_i = HKDF(S_bind, info="prm/v1/salt/" || namespace || normalize(identifier))[0..16]`).
Deriving rather than randomizing means the salt is reproducible from the seed alone, so vault loss does
not orphan the commitments. Recompute and you're whole.

Trade-off: a party who learns `S_bind` can open **all** commitments. Acceptable, because `S_bind`
compromise implies vault compromise, which already implies signing-key compromise.

## 6. Resolution flow summary

```
Does the org already have a relationship with the person?
├── YES → they hold a pairwiseId + a stored policy version.  No lookup. ✅ (MVP)
└── NO
    ├── Person is present → QR / NFC / link push. No lookup. ✅ (MVP)
    ├── Org holds an identifier and person opted into discovery
    │   ├── prefix lookup (k-anonymous, opt-in, per-namespace)  (beta)
    │   └── OPRF blinded lookup (federated, rate-limited)       (post-beta)
    └── Org holds an identifier and person did NOT opt in
        └── No result. This is the correct answer, not a gap.
```

The last branch is worth defending explicitly in the product copy: **non-discoverability is a feature.**
A user who wants to be findable opts in per namespace; the default is invisible.
