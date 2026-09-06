# 08 — Timestamping

## 1. What must be proven

*"This document existed no later than time T, and PRM could not have backdated it."*

Note what is **not** required: proving a document existed no *earlier* than T (trivially satisfiable by
including a recent public value, and rarely useful), or a globally agreed ordering (the Merkle log
already provides ordering within PRM).

## 2. Options compared

| | **RFC 3161 TSA** | **Transparency log (self-operated)** | **OpenTimestamps / Bitcoin** | **Direct blockchain write** |
|---|---|---|---|---|
| Trust assumption | The TSA's key + its audit regime | The operator (PRM) — circular | Bitcoin's PoW; the calendar server for aggregation only | Same as OTS, worse economics |
| Independence from PRM | **Full** | None | **Full** | Full |
| Latency to proof | Seconds | Immediate | ~1–24 h (block + calendar batch) | ~10–60 min |
| Cost | Free (public TSAs) or ~$0 commercial | Hosting only | Free | $1–20 per anchor |
| Client complexity | ~100 LOC (ASN.1 request, `openssl ts -verify`) | Merkle proof code you already have | OTS library + a Bitcoin node or explorer to be fully trustless | Wallet, key custody, fee management |
| Legal familiarity | **High** — eIDAS-adjacent, used in e-signing for 20+ years | Low | Low; "blockchain" invites argument | Low |
| Failure mode | TSA cert expiry/revocation; single TSA compromise | Operator equivocation | Calendar server outage delays, does not break, existing proofs | Fee spikes; key loss |
| Long-term verifiability | Needs the TSA chain archived; renew before algorithm sunset | n/a | Excellent — verify against any Bitcoin header chain | Excellent |

## 3. Recommendation

**MVP: RFC 3161, applied to the signed tree head, not to individual events.**

```
every hour (Vercel Cron):
  sth   = current signed tree head
  imprint = SHA-256(sth.rootHash)
  token = POST to TSA (application/timestamp-query)      # FreeTSA, DigiCert, Sectigo
  store token; expose at /log/sth/{treeSize}/timestamp.tsr
```

Because the root commits to every leaf, **one token timestamps every event in the tree**. Cost is one
HTTP request per hour, and any event's proof is `inclusion proof → root → token`.

Rationale for choosing this first:

- It is the only option in the table that a court, a records custodian, or an enterprise counsel
  already recognizes. That matters more than cryptographic elegance for a product whose output is
  evidence.
- Verification uses stock `openssl`, with no PRM code and no PRM cooperation.
- It is genuinely a hundred lines: build a `TimeStampReq` (DER), POST it, store the `TimeStampResp`.
- Free public TSAs exist. Use **two** from different operators (e.g. FreeTSA + a commercial one) so a
  single TSA's compromise or shutdown does not orphan the archive. Redundancy costs one extra request.

**Beta: add OpenTimestamps as a second, independent anchor.** Daily, submit the day's final root to
OTS. This gives a proof that survives the disappearance of every TSA and every PRM server, verifiable
against the Bitcoin header chain alone. It is free, aggregated (so no per-anchor fee), and adds no
personal data to any chain — the anchored value is a 32-byte Merkle root over hashes.

**Never: direct blockchain writes, a PRM token, or per-event on-chain anchoring.** They add cost,
custody, and a permanent public record without adding any property RFC 3161 + OTS do not already
provide.

> **Decision — RFC 3161 on tree heads for MVP; OpenTimestamps as a second anchor at beta; no direct
> chain writes ever.**
> *Why:* independent proof of existence at minimum complexity and maximum legal legibility.
> *Threat:* backdating by a malicious provider; loss of evidentiary value if PRM disappears.
> *MVP:* yes (RFC 3161). *Standard:* RFC 3161; OpenTimestamps (Bitcoin). *Simpler alternative:* publish
> the daily root hash somewhere public and hard to alter — a git commit in a public GitHub repo, or an
> X/Mastodon post. Genuinely useful as a belt-and-braces third anchor and costs nothing; add it as a
> Cron job writing to `Breezy-Point-Beach/prm-log-anchors`.

## 4. Blockchain deanonymization — the reason for the constraint

If PRM ever anchored per-user or per-event values on a public chain, the timing and frequency of those
transactions would be a **permanent, global, undeletable side channel**. An observer correlating anchor
timestamps with real-world events (a traffic stop, a records request) could infer a great deal about
individuals, forever, with no possibility of erasure.

Batching every user's events into one hourly root eliminates this: the on-chain (or TSA) artifact is a
single value per hour whose contents are indistinguishable from noise, and it does not vary with how
many users are active or who they are. **The batching is a privacy control, not an optimization** —
document it that way so it is never "optimized" into per-event anchoring.

## 5. Clock hygiene

- All PRM-generated timestamps are UTC, RFC 3339, `Z`, second precision (schema-enforced for
  canonicalization determinism).
- User-device clocks are untrusted. `proof.created` is a *claim*; the TSA time is the *proof*. Any UI
  showing a date on a verified policy must show the TSA-attested time, with the claimed time secondary.
- Reject documents whose `proof.created` is more than 24 h ahead of log-append time; log and warn but
  accept ones behind (offline authoring is legitimate).
- Archive the TSA certificate chain alongside each token. A token whose signer cert has expired is
  still verifiable, but only if you kept the chain — this is the classic long-term-validation gap, and
  the fix is simply to store the chain at acquisition time.
