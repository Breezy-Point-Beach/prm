# PRM Normative Rules

This document is **normative** and takes precedence over `docs/`. Where it and the architecture
documentation disagree, this document and `spec/test-vectors/vectors.json` win.

It exists because five of the rules below were previously implicit in
`spec/test-vectors/generate.mjs` only. An independent implementer following `docs/` alone would have
produced different digests, and therefore invalid signatures. See "Audit findings" at the end.

---

## 1. Canonicalization — the PRM-JCS profile

PRM canonicalizes with **RFC 8785 (JCS)**, restricted by two additional rules:

1. **Integers only.** A PRM document MUST NOT contain a non-integer number. Implementations MUST
   throw rather than serialize one. This removes the ES6 float-serialization requirement from RFC 8785
   and, more importantly, removes an entire class of cross-implementation ambiguity.
2. **No lone surrogates.** A string containing an unpaired UTF-16 surrogate MUST be rejected, not
   escaped.

Everything else follows RFC 8785 exactly:

- Object keys sorted by **UTF-16 code unit** (not collation, not code point, not locale).
- No Unicode normalization. `"é"` (NFC) and `"é"` (NFD) are **different keys**, and NFD
  sorts first because `e` (0x65) < `é` (0xE9).
- Minimal string escaping only: `\b \t \n \f \r \" \\`, and other control characters as `\u00XX`.
  Non-ASCII characters are emitted literally as UTF-8.
- No insignificant whitespace.

## 2. Non-hashed members — **normative**

Every PRM document type excludes specific members from the bytes that get hashed and signed. These
members are added *after* signing, so including them would make the signature unverifiable.

| Document type | Members excluded from the digest |
|---|---|
| Policy | `id`, `proof` |
| Authorization | `id`, `proof` |
| Key Event | `proof` |
| Ledger Entry | `proof`, **`logInclusion`** |
| Signed Tree Head | `signature` |

```
digest(doc) = SHA-256( PRM-JCS( doc without its non-hashed members ) )
```

`logInclusion` is the one most likely to be missed: a ledger entry is signed by the user *before* it is
submitted to the transparency log, and the log's response (leaf index, tree size, root hash, inclusion
proof, signed tree head, timestamp token) is then attached to the stored entry. Hashing it would make
the entry's own digest depend on a value derived from that digest.

## 3. Multihash / multibase encoding

```
mh(digest) = "u" + base64url_nopad( 0x12 || 0x20 || digest )
```

`0x12` = sha2-256 multicodec, `0x20` = 32-byte length. Multibase prefix `u` = base64url without
padding. Public keys use multibase `z` (base58btc) over multicodec `0xed 0x01` (Ed25519).

## 4. Domain separation — **normative**

Signatures are computed over a domain-separated message, never over the bare digest:

```
message = utf8(DOMAIN) || 0x00 || digest
sig     = Ed25519_sign(key, message)
```

| Document type | `DOMAIN` |
|---|---|
| Policy | `PRM-POLICY-v1` |
| Authorization | `PRM-AUTHZ-v1` |
| Key Event | `PRM-KEYEVENT-v1` |
| Ledger Entry | `PRM-LEDGER-v1` |
| Signed Tree Head | `PRM-STH-v1` |

This is what makes a policy signature invalid as an authorization signature. Implementations MUST NOT
offer a "verify with any domain" mode.

`proofValue` is multibase base58btc (`z`-prefixed) over the raw 64-byte Ed25519 signature.

## 5. Account identifier derivation

```
accountId = "prm:" + base32_nopad_lower( digest(genesisKeyEvent) ).slice(0, 26)
```

Exactly the **first 26 characters** of the RFC 4648 base32 lower-case alphabet
(`abcdefghijklmnopqrstuvwxyz234567`), no padding. The schema permits 26–52 characters so the length can
grow in a future version; v1 emits 26.

The account identifier is a function of the genesis event alone. It is therefore self-certifying: any
party holding the genesis event can recompute it, and no server can mint or reassign one.

## 6. Policy chain identifier derivation

```
chainDigest  = SHA-256( PRM-JCS( policyV1 without id, proof, AND policyChainId ) )
policyChainId = "urn:prm:chain:" + mh(chainDigest)
```

**`policyChainId` is excluded from its own derivation** — a third exclusion beyond the §2 rule, and it
applies *only* when computing the chain identifier. It is necessary because v1 carries its own
`policyChainId`, so including it would be circular.

Note the consequence: **`chainDigest` is not equal to `digest(policyV1)`.** The v1 policy's own digest
includes the `policyChainId` member; the chain digest does not. Both values appear in
`vectors.json` under `policyChain` so implementations can check both.

Every subsequent version copies `policyChainId` verbatim. It never changes.

## 7. Version chaining

- `version` is an integer starting at 1.
- `previousPolicyHash` is `null` **if and only if** `version == 1`; otherwise it is `mh(digest(prior version))`.
- `policyChainId` is identical across all versions of a chain.

## 8. Merkle transparency log — RFC 6962 hashing

```
leafHash(entryDigest) = SHA-256( 0x00 || entryDigest )
nodeHash(left, right) = SHA-256( 0x01 || left || right )
```

Tree construction splits at the **largest power of two strictly less than n**:

```
root(leaves):
  n == 1  ->  leaves[0]
  n  > 1  ->  k = largest power of 2 with k < n
              nodeHash( root(leaves[0..k]), root(leaves[k..n]) )
```

**Inclusion proof ordering:** the proof array is ordered **deepest sibling first** (closest to the
leaf), consistent with the recursive construction. A verifier reconstructs the root by computing the
descent path top-down, then consuming the proof bottom-up. This ordering is not self-describing — get
it backwards and every proof fails.

## 9. Timestamps

All instants are RFC 3339, UTC, `Z`-suffixed, **second precision, no fractional seconds**:
`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`. This is schema-enforced because a fractional second is a
canonicalization difference and therefore a different signature.

---

## Audit findings (2026-09-06)

Discovered while implementing the core packages against the existing spec. All six were resolved by
correcting `docs/` to match the normative vectors — **no protocol change was made**, per the stated
precedence order (normative artifacts > documentation > implementation convenience).

| # | Finding | Resolution |
|---|---|---|
| C1 | `docs/02` §2 normative code block excluded only `proof`; its own prose said `id` and `proof`. The prose sentence was also garbled mid-clause. | Corrected the code block and the sentence; both now match §2 above. |
| C2 | **`logInclusion` exclusion was undocumented.** Implemented only in `verify.mjs`. An implementer following the docs would compute a different ledger-entry digest and fail every inclusion proof. | Documented in §2 as a normative non-hashed member. |
| C3 | **`policyChainId` derivation was undocumented**, including the non-obvious fact that it excludes itself and that `chainDigest != digest(v1)`. | Documented in §6; both digests published in `vectors.json`. |
| C4 | `docs/07` described the signed tree head signature as a "detached JWS", but the vector uses the same multibase base58btc Ed25519 construction as every other document, with domain `PRM-STH-v1`. | Corrected `docs/07`. One signature scheme everywhere is simpler and is what the vectors actually require. |
| C5 | `docs/01` wrote the account id truncation as `[0..26]`, ambiguous between 26 and 27 characters. | Pinned to "first 26 characters" in §5. |
| C6 | Merkle inclusion proof ordering was implicit. It caused two real test failures during spec authoring. | Documented in §8. |
