# Decision Register

Every major architectural decision, with: **why it is needed**, **what threat it solves**, **whether the
MVP requires it**, **the open standard used**, and **the simpler alternative** that was considered.

Threat IDs reference [12 — Threat Model](12-threat-model.md).

---

## Identity and keys

| # | Decision | Why | Threat | MVP? | Standard | Simpler alternative (and why not) |
|---|---|---|---|---|---|---|
| D1 | Ed25519 signing keys, generated and held client-side only | Provider must be structurally unable to impersonate the user | T4, T7 | **Yes** | RFC 8032 | Server-side signing with an HSM — kills the entire premise |
| D2 | Self-certifying account id = `SHA-256(genesis key event)` | Identity not issued by PRM and not reassignable | T4 | **Yes** | multihash/multibase; KERI concept | A database UUID — PRM becomes the identity authority |
| D3 | KERI-style pre-rotation commitment | A stolen key cannot take over the account | T3, T4 | **Yes** — retrofitting is a migration | Ed25519 + SHA-256 (no KERI stack) | `did:key` with no rotation — key theft becomes unrecoverable |
| D4 | All keys derived from one 32-byte seed via HKDF | One backup artifact; rotation needs no new backup | T12 (loss) | **Yes** | RFC 5869, BIP-39 | Four independent keys — four backups, users make zero |
| D5 | Passkey (WebAuthn PRF) unlocks the key; does not *become* the key | Hardware-backed protection without pretending WebAuthn can sign arbitrary bytes | T3 | **Yes** (Tier A/B) | WebAuthn L3 PRF, RFC 9106 Argon2id | Sign with the passkey directly — technically impossible for detached signatures |
| D6 | No provider recovery path; no key escrow, even opt-in-by-default | The "cannot impersonate" claim must be unconditional | T12, T4 | **Yes** | SLIP-39 / Shamir (beta) | Email-based reset — hands impersonation to PRM and to any mailbox compromise |
| D7 | Revocation is time-scoped (CRL semantics) | Revoking a key must not destroy the evidentiary value of past signatures | T3, T5 | **Yes** | X.509 CRL semantics | Invalidate everything on rotation — destroys the archive, which is the product |
| D8 | Algorithm-tagged key entries (`Ed25519`, `ES256`) | Secure Enclave device keys and future PQ algorithms become rotations, not redesigns | — | **Yes** (schema only) | COSE/JOSE alg identifiers | Hardcode Ed25519 — forces a breaking change later |

## Policy format

| # | Decision | Why | Threat | MVP? | Standard | Simpler alternative |
|---|---|---|---|---|---|---|
| D9 | JCS canonicalization + detached digest signing | Deterministic bytes across implementations without an RDF stack | T8 | **Yes** | RFC 8785, `eddsa-jcs-2022` | Compact JWS over the raw string — any re-serialization breaks it |
| D10 | Domain-separated signatures (`PRM-POLICY-v1\x00` …) | A signature of one document type cannot be replayed as another | T6 | **Yes** | Standard construction | One signing context — enables cross-type replay |
| D11 | `id` and `proof` excluded from the hashed bytes | Resolves the self-referential-identifier trap | T8 | **Yes** | — | Include `id` with a placeholder — the classic interop bug |
| D12 | Human-readable prose carried *inside* the signed document | Prose and machine rules cannot drift apart | T5, T8 | **Yes** | — | Separate HTML page — the two versions diverge, and disputes follow |
| D13 | Rights categories are URIs; unknown ones are fail-closed (`deny`) | Extensible without a central registry; conservative by default | — | **Yes** | W3C DPV alignment, ODRL shapes | A fixed enum — no extension path for jurisdictions or industries |
| D14 | `basisAcknowledged` field (conceding lawful override) | A policy that ignores lawful override is dismissed wholesale | — | **Yes** | — | Absolute denials — rhetorically satisfying, practically ignored |
| D15 | Policy chain via `previousPolicyHash`; old versions never deleted | "What did your policy say on date X" is answerable by a third party | T5, T8 | **Yes** | Hash chain | Latest-only — destroys the evidentiary case |
| D16 | Timestamps are UTC, `Z`, second precision, no fractional seconds | Canonicalization determinism | T8 | **Yes** | RFC 3339 | Free-form ISO 8601 — same instant, different bytes, different signature |

## Identity resolution

| # | Decision | Why | Threat | MVP? | Standard | Simpler alternative |
|---|---|---|---|---|---|---|
| D17 | **Push-first**: the person presents the policy; lookup is a fallback | Eliminates the registry for most real interactions | **T1**, T9 | **Yes** | — (architectural) | A lookup directory — this *is* the surveillance registry |
| D18 | Identifier commitments with 128-bit per-identifier salts | Small identifier spaces (plates, phones) are otherwise trivially enumerable | T1, T9, T10 | **Yes** | SHA-256 commitment | Bare `SHA-256(identifier)` — enumerable in minutes |
| D19 | Salts derived from `S_bind`, not random | Commitments survive vault loss; reproducible from the seed alone | T12 (loss) | **Yes** | RFC 5869 | Random salts — vault loss orphans every commitment |
| D20 | Pairwise per-organization subject identifiers | Two grantees cannot join their records on a PRM value | **T2** | **Yes** | OIDC pairwise subject pattern | Use `accountId` everywhere — recreates the universal identifier |
| D21 | Lookup deferred; k-anonymous prefix at beta, OPRF post-beta | Only OPRF actually prevents offline enumeration | T1, T9 | **No** | RFC 9497 OPRF, RFC 9458 OHTTP | Ship prefix lookup now — the enumeration cost is real but affordable to a funded adversary |

## Evidence, log, and time

| # | Decision | Why | Threat | MVP? | Standard | Simpler alternative |
|---|---|---|---|---|---|---|
| D22 | Personal hash chain **and** global Merkle tree | Chain gives per-user ordering; tree gives inclusion + consistency proofs | T4, T5 | **Yes** | RFC 6962 / 9162 | Chain only, timestamped daily — cannot prove non-equivocation |
| D23 | Global log leaves are opaque 32-byte hashes | The log can be fully public because it discloses nothing | T1, T2, T10 | **Yes** | RFC 6962 | Log the documents — recreates a central data store |
| D24 | RFC 3161 timestamping applied to **tree heads**, not events | One token timestamps the whole tree; batching is a privacy control | T4, **T11** | **Yes** | RFC 3161 | Per-event timestamps — a permanent per-user timing side channel |
| D25 | Two independent TSAs | One operator's compromise or shutdown must not orphan the archive | T4 | **Yes** | RFC 3161 | One TSA — single point of evidentiary failure |
| D26 | OpenTimestamps as a *second* anchor at beta; never a dependency | Survives the disappearance of every TSA and of PRM | T4 | **No** | OpenTimestamps (Bitcoin) | Direct chain writes — cost, custody, and no added property |
| D27 | Client-side STH pinning, refusing a smaller tree | Cheap detection of the naive split-view attack | T4 | **Yes** | CT gossip concept | Trust the operator — circular |
| D28 | Merkle append serialized by a Postgres advisory lock | Concurrent appends corrupt the tree; serverless has no natural ordering | correctness | **Yes** | — | A queue or a distributed log — heavy infrastructure for dozens of appends/second |
| D29 | Portable `.prmproof` bundle (policy + entry + proof + STH + token + KEL) | A proof you cannot hand over as one file will not get used | T5 | **Yes** | JSON envelope | Point people at API endpoints — useless offline and in a legal context |

## Authorizations

| # | Decision | Why | Threat | MVP? | Standard | Simpler alternative |
|---|---|---|---|---|---|---|
| D30 | `expires` is mandatory; perpetual grants are inexpressible | Consent that never lapses is every consent system's failure mode | T6 | **Yes** | — | Optional expiry — grants accumulate forever |
| D31 | Grants bind to an exact policy **version** (`boundPolicyHash`) | A new policy version must not silently re-scope an existing grant | T5, T6 | **Yes** | — | Bind to the chain — ambiguity, and disputes |
| D32 | Grants delivered pairwise; policy publishes only a Merkle root over the set | The list of organizations you deal with is a sensitive relationship graph | T2, T10 | Partial (field in MVP, proofs at beta) | RFC 6962 proofs | Publish grants inline — leaks relationships |
| D33 | Bitstring Status List for revocation | Standard, compressible, cacheable, one fetch covers ~131k entries | T6 | **Yes** | W3C Bitstring Status List v1.0 | Per-grant revocation endpoint — a lookup oracle and a correlation channel |
| D34 | Receipts model partial compliance with citations (`declined[]`) | Partial compliance is the realistic outcome and the most informative signal | T5 | Beta | ISO/IEC 27560:2023 | Binary accept/reject — organizations respond with silence instead |

## Distribution and verification

| # | Decision | Why | Threat | MVP? | Standard | Simpler alternative |
|---|---|---|---|---|---|---|
| D35 | `@prm/verify` is pure and offline-first; the hosted verify API is explicitly non-authoritative | The operative proof that PRM is not a central authority | **T4** | **Yes** | RFC 8032/8785/6962/3161 | A hosted verification API only — makes PRM the authority |
| D36 | QR carries a short URL **plus a digest prefix**, never the policy | QR capacity is ~2.9 KB; the printed digest detects substitution | T8 | **Yes** | ISO/IEC 18004 | URL only — a compromised short-link service can swap the policy |
| D37 | Separate short domain (`prm.li`) from the canonical origin | A short-link compromise cannot serve a forged policy from the trusted origin | T8 | **Yes** | — | Same domain — shared blast radius |
| D38 | PDF embeds the signed JSON (PDF/A-3) rather than carrying a PAdES signature | Keeps the user's Ed25519 proof authoritative; avoids a CA dependency | T5, T8 | **Yes** | ISO 32000 embedded files | PAdES signing — needs X.509, and Ed25519 is poorly supported in PDF readers |
| D39 | `.well-known/prm-policy` self-hosting supported from day one | Removes PRM from the trust path entirely for users who want that | T4 | **Yes** | RFC 8615 | PRM hosting only — the claim becomes unfalsifiable |
| D40 | `.well-known/prm-receiver` capability discovery for organizations | Lets an org opt in with one static file, before writing any code | cold start | **Yes** (client probe) | RFC 8615 | A PRM-hosted org registry — centralizes and goes stale |
| D41 | Wallet passes attest "PRM issued this card", never "this is the policy" | Confines provider-held signing certs to a powerless artifact | T4, T8 | **No** (beta) | PKPass / Google Wallet | Treat the pass as the policy — server key becomes authoritative |

## Platform

| # | Decision | Why | Threat | MVP? | Standard | Simpler alternative |
|---|---|---|---|---|---|---|
| D42 | Monorepo `Breezy-Point-Beach/prm` | Crypto, schema, verifier, and vectors must change atomically | correctness | **Yes** | pnpm workspaces + Turborepo | Multiple repos — a version-matrix problem a solo founder loses |
| D43 | Neon Postgres via the Vercel Marketplace | DB branching maps onto preview deploys; Edge-compatible HTTP driver | operability | **Yes** | PostgreSQL | Supabase — fine, but most of its surface goes unused here |
| D44 | Edge runtime for public reads, Node for writes/crypto-adjacent work | Latency and cache economics for reads; Node APIs where actually needed | operability | **Yes** | — | Node everywhere — slower and costlier for the highest-traffic paths |
| D45 | Route Handlers (not Server Actions) for anything with an external consumer | The CLI, SDKs, and organizations need stable, versioned, CORS-able URLs | interop | **Yes** | HTTP | Server Actions for publishing — not a public API contract |
| D46 | `K_log` is the only server-held signing key, with a documented blast radius | Forged tree heads are detectable and cannot alter user signatures | T4 | **Yes** | — | Sign user documents server-side — the premise collapses |
| D47 | Preview deployments get their own log id, log key, and database branch | A preview appending to the production tree is unrecoverable corruption | correctness | **Yes** | — | Shared environment — one bad preview destroys the log |
| D48 | CI gates on crypto vectors, schema conformance, determinism, and offline verify | Canonicalization can be broken by an innocuous-looking refactor | T8 | **Yes** | — | Unit tests only — the failure is silent and retroactive |
| D49 | `spec-conformance.yml` fails loudly if committed digests change | Forces "is this a spec version bump?" to be an explicit decision | T8 | **Yes** | — | Reviewer vigilance — insufficient at 1am |
| D50 | No Kubernetes, queues, or custom orchestration | A single technical founder must be able to operate this | operability | **Yes** | — | "Proper" infrastructure — cost and cognitive load with no benefit at this scale |

| D51 | Published policies are stored as **raw text**, never `jsonb` | `jsonb` does not preserve key order, whitespace, duplicate keys, or numeric formatting, so it cannot return the exact bytes the user signed | T4, T8 | **Yes** | — | Store `jsonb`, as `docs/13-mvp.md` originally specified — rejected: most reserializations survive JCS and would still verify, but "most" is not a property worth resting on |
| D52 | The publish API accepts signed documents as **strings**, not nested objects | An object would have to be re-serialized before storage, destroying the signed bytes at the very first hop | T4, T8 | **Yes** | — | Accept objects — quietly loses byte-exactness before anything is written down |
| D53 | After publishing, the client **fetches the artifact back and compares bytes**; a mismatch is a hard failure | A signature check alone passes a server that reserialized the document, because canonicalization erases formatting | **T4**, T8 | **Yes** | — | Trust the server's success response — the failure would be silent and permanent |
| D54 | The generated rules summary is appended to the prose **at signing time, always** | Prevents prose/rules drift structurally rather than detecting it heuristically; a stale summary would otherwise carry the same signature authority as the current rules | T5, T7 | **Yes** | — | Warn on divergence only — catches less, and depends on fragile text matching |

---

## The five load-bearing decisions

If time is short, these are the ones that must be right, because each is either unrecoverable later or
is the thing that makes the central claim true:

1. **D3 — pre-rotation commitment.** Retrofitting it is a migration of every account.
2. **D9/D10/D11 — canonicalization and domain separation.** Getting these wrong invalidates every
   signature ever produced, retroactively.
3. **D17/D18 — push-first with salted commitments.** The difference between PRM and the thing it opposes.
4. **D35 — pure offline verifier.** The operative proof that the provider need not be trusted.
5. **D23/D24 — opaque log leaves, batched anchoring.** What lets the evidence layer be fully public.
