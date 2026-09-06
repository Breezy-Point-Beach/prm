# PRM Specification Artifacts

Normative schemas, worked examples, and executable test vectors.

## Contents

```
schemas/     JSON Schema (draft 2020-12) for the four signed document types
examples/    Real, signed documents — the ALPR case end to end
test-vectors/generate.mjs  regenerates examples + vectors deterministically
             verify.mjs    independent verifier (imports nothing from the generator)
             validate-schemas.mjs  ajv validation of every example
```

## Running

```console
$ node spec/test-vectors/verify.mjs           # 37 checks, no dependencies
$ node spec/test-vectors/validate-schemas.mjs # needs ajv + ajv-formats
$ node spec/test-vectors/generate.mjs         # regenerate; output must be byte-identical
```

`verify.mjs` deliberately re-implements canonicalization, hashing, signature verification, account
derivation, commitment opening, and Merkle proof checking from scratch. If it ever imports from
`generate.mjs`, it has stopped being a test.

## What the vectors demonstrate

Positive: JCS determinism · self-certifying account derivation · pre-rotation commitment ·
dual-signed rotation · policy chaining v1→v2 · commitment opening via selective disclosure ·
pairwise identifiers · personal hash chain · RFC 6962 inclusion proofs · signed tree head.

Negative (each MUST fail): tampering with a rule · replaying a policy signature as an authorization ·
rotating to a key that was never pre-committed · proving inclusion of a leaf that was never logged ·
finding a raw identifier in a published policy.

## Test keys

Every key derives from the published seed
`SHA-256("PRM TEST VECTOR SEED v1 — DO NOT USE IN PRODUCTION")` via HKDF-SHA256. They exist so
implementations can cross-check byte-for-byte. **Never use them for anything real.**

## Conformance

An implementation is conformant when `verify.mjs` passes against documents *it* produced from the same
seed, and its own verifier accepts `spec/examples/**` while rejecting each negative case above.
