# 07 — Audit Ledger

Normative schema: [`spec/schemas/prm-ledger-entry-v1.schema.json`](../spec/schemas/prm-ledger-entry-v1.schema.json)

## 1. Two ledgers, different jobs

The common mistake is to build one ledger and hope it serves both purposes. It cannot: one must contain
detail, the other must contain nothing.

| | **Personal ledger** | **Global transparency log** |
|---|---|---|
| Scope | One user | All users |
| Structure | Hash chain (linear) | Merkle tree (RFC 6962) |
| Contents | Entry documents with counterparties, evidence | **Opaque 32-byte leaf hashes only** |
| Storage | Local-first (IndexedDB / SQLCipher) + encrypted server backup | Postgres on Vercel, fully public |
| Signed by | User | User (leaf) + PRM log key (tree head) |
| Answers | "What did I do, to whom, with what evidence?" | "Did this exact thing exist by time T, and has history been rewritten?" |

**The global log never sees content.** Its leaves are `SHA-256(JCS(ledgerEntry))`. Someone who
downloads the entire log learns the number of events and their timing, and nothing else. That is the
property that lets the log be fully public.

> **Decision — hash chain *and* Merkle tree, not one or the other.**
> *Why:* a chain gives cheap per-user ordering and tamper-evidence; a tree gives O(log n) inclusion
> proofs and consistency proofs across the whole population. *Threat:* provider rewriting history,
> selective disclosure, equivocation. *MVP:* both, but the tree is single-operator with no gossip.
> *Standard:* RFC 6962 / RFC 9162 tree semantics. *Simpler alternative:* chain only, timestamped daily
> — viable for the prototype, but it cannot prove non-equivocation across users.

## 2. Personal hash chain

```
entry[n].previousEntryHash = SHA-256(JCS(entry[n-1] minus proof))
entry[n].proof             = Ed25519(K_sign, "PRM-LEDGER-v1\x00" || SHA-256(JCS(entry[n] minus proof)))
```

Entry types (closed set in v1):

`policy.published` · `policy.superseded` · `key.event` · `authorization.granted` ·
`authorization.revoked` · `notice.sent` · `notice.delivered` · `request.deletion` · `request.access` ·
`acknowledgment.received` · `dispute.raised` · `dispute.resolved`

Each entry names the object it concerns by digest (`subjectHash`) and never embeds it.

The `counterparty` block is the most correlating field in the system, so its handling is precise: it is
**inside the signed bytes** (the user needs it to be tamper-evident in their own record) and therefore
inside the leaf hash — which is harmless, because the leaf is a hash and discloses nothing. What must
never happen is the entry *document* reaching the server in plaintext. Server-side backup of personal
ledger entries is **ciphertext only**, encrypted with `K_vault` before upload.

## 3. Global transparency log

Standard append-only Merkle tree, RFC 6962 hashing rules (leaf `0x00 || data`, node `0x01 || l || r` —
use them exactly, so existing verifier code works).

**Signed Tree Head**, emitted every 60 seconds when there is new data, and at least hourly regardless:

```jsonc
{
  "logId": "prm-log-1",
  "treeSize": 148223,
  "rootHash": "uEiC9Xk...",
  "timestamp": "2026-09-06T15:00:00Z",
  "previousRootHash": "uEiB2Pq...",
  "signature": "<detached JWS, EdDSA, by K_log>"
}
```

Published at `/.well-known/prm-log` (metadata + `K_log` public key) and `/log/sth/latest`, plus a
paginated `/log/entries?start=&end=` so anyone can mirror the whole thing.

### 3.1 Proofs

- **Inclusion proof** — `O(log n)` sibling hashes proving leaf *i* is in the tree of size *n*. Given to
  the user at append time and embedded in the entry's `logInclusion` block, so the user carries their
  own proof and does not depend on PRM to reproduce it later.
- **Consistency proof** — proves tree of size *m* is a prefix of tree of size *n*. This is what detects
  a rewrite: if PRM ever removes or reorders a leaf, no valid consistency proof exists between the old
  and new roots, and any party holding an old STH can demonstrate it.

### 3.2 Append serialization on Vercel

Merkle append is not commutative; concurrent appends corrupt the tree. On serverless this needs an
explicit lock. Use a Postgres advisory lock:

```sql
SELECT pg_advisory_xact_lock(hashtext('prm-log-append'));
INSERT INTO log_leaves (leaf_index, leaf_hash, entry_digest)
VALUES ((SELECT COALESCE(MAX(leaf_index)+1, 0) FROM log_leaves), $1, $2);
```

Cheap and correct at MVP scale (dozens of appends/second). If append throughput ever becomes the
bottleneck, the fix is batching (accumulate for 1s, append as a subtree) — not a distributed log. Flag
in §14 as the one component with a plausible path off Vercel.

### 3.3 Split-view resistance

A single-operator log can, in principle, show different trees to different parties. Three mitigations,
in the order they should ship:

1. **Client pinning (MVP).** Every PRM client caches the highest STH it has seen and refuses a smaller
   `treeSize` or an STH failing a consistency check. Cheap, and it catches the naive attack.
2. **External anchoring (MVP).** Every STH root gets an RFC 3161 token (§08). PRM cannot backdate a
   forked history because it cannot forge the TSA's signature.
3. **Third-party witnesses (beta).** Independent parties co-sign STHs — the mechanism CT uses. Ship
   `packages/monitor` as a reference witness so an EFF-type organization can run one with `npx`.

Until (3), be explicit in the docs: *the log is tamper-evident, not tamper-proof, against its own
operator.* The user's own signatures remain unforgeable either way — the log's failure mode is
suppression and reordering, never authorship.

## 4. How historical proof actually works

The concrete question — *"prove your policy said X on 2026-09-06"* — is answered like this:

```
1. Produce the policy document           → recipient hashes it
2. Produce the ledger entry              → contains that digest as subjectHash, signed by the user
3. Produce the inclusion proof + STH     → proves the entry was in the log at treeSize N
4. Produce the RFC 3161 token over the   → proves that root existed no later than T,
   STH's rootHash                          attested by an independent third party
5. Produce the KEL                       → proves the signing key was authorized at that time
```

Chain of reasoning: *the TSA (independent) says this root existed by T; the root commits to this leaf;
the leaf is the hash of this signed entry; the entry names this policy digest; the policy verifies
under a key the KEL shows was authorized then.* No step requires trusting PRM.

Package all five as a single portable `.prmproof` bundle (a JSON envelope, ~10–20 KB) that
`@prm/verify` consumes offline. Ship it in the MVP — a proof you cannot hand to a lawyer as one file is
a proof that will not get used.

## 5. Redaction and the right to be forgotten

An append-only log and a deletion right are in genuine tension. The resolution:

- The global log contains **only hashes**, so there is nothing to redact — a hash of a deleted document
  is not personal data in any practical sense.
- The personal ledger is **user-controlled**; the user can delete their local copy at will. Doing so
  destroys their own evidence, which the UI must say clearly.
- Account closure removes the published policy, the handle mapping, and the encrypted backup. The log
  leaves remain — they are opaque and their removal would break every consistency proof ever issued.

Document this position explicitly; it is the first thing a privacy regulator will ask about, and the
answer ("we anchored hashes precisely so that erasure never conflicts with integrity") is a good one.

## 6. Storage sizing

Per user, per year, a heavy user: ~200 entries × ~1 KB = 200 KB personal (local, plus encrypted
backup). Global log: 32 bytes/leaf + index → ~10 MB per million entries. A single Neon instance handles
years of this. There is no scale story here that needs solving before it exists.
