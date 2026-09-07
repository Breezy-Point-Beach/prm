# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use GitHub's [private vulnerability reporting](https://github.com/Breezy-Point-Beach/prm/security/advisories/new)
on this repository, or email **security@rightsroot.com** (PGP key at `/.well-known/security.txt` once the
service is deployed).

**Response commitment:** acknowledgement within 3 business days, an assessment within 10, and a fix or
a documented mitigation plan within 90 for confirmed issues. We will credit you unless you prefer
otherwise, and we will not pursue legal action for good-faith research within the scope below.

## What we consider critical

PRM's central claim is that **the provider does not need to be trusted for a user to remain the
authority over their own policy.** Anything that falsifies that claim is critical, regardless of how
hard it is to exploit:

| Severity | Class of issue |
|---|---|
| **Critical** | Any path by which a server can produce, alter, or repudiate a user-signed document; key material reaching a server, a log, or an error report; a canonicalization ambiguity allowing two documents to share a signature; a forged inclusion proof; bypass of the pre-rotation commitment |
| **High** | Raw identifiers reaching server-side storage or logs; identifier enumeration; cross-account correlation via a PRM-supplied value; policy substitution that survives verification; account takeover via recovery |
| **Medium** | Verification accepting a revoked key outside its time scope; replay of a revoked authorization; missing rate limits on `/api/v1/resolve`; XSS on the authoring surface |
| **Low** | Availability, censorship, and denial of service — real, but by design these are recoverable (self-host, mirror) and are not trust failures |

## Explicitly in scope, and welcome

- **Canonicalization differentials.** If you can make two semantically different documents produce the
  same JCS output — or the same document produce two different outputs across implementations — that
  is our highest-value bug class. See `spec/test-vectors/`.
- **Architectural drift toward a central registry.** If a code path stores, indexes, or infers a raw
  identifier, report it as a security issue even if it is merely *planned*. See
  `docs/12-threat-model.md` T1.
- **Anything making `@prm/verify` depend on network access** in its core path.

## Out of scope

- The security of a recipient organization's own systems.
- Whether a policy has legal effect in a given jurisdiction (a legal question, not a security one).
- Compromise of a fully rooted user device, except where our design makes the consequences worse than
  they need to be.
- Reports from automated scanners without a demonstrated impact.

## Cryptographic dependencies

We pin `@noble/*` to exact versions and review those updates by hand. If you find an issue in an
upstream primitive, please report it upstream first, then tell us so we can pin around it.
