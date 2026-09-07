# Naming

> **RightsRoot is the platform. PRM is the open protocol.**
>
> RightsRoot puts the individual back at the root of their data rights.

## The five names, and what each one means

| | Name | Use it for |
|---|---|---|
| **Product** | RightsRoot | The app, the account, the public policy page, the notice generator. What a person uses. |
| **Protocol** | PRM — Personal Rights Management | The document format, the signatures, the verification rules. What a machine speaks. |
| **Operator** | Breezy Point Beach LLC | The legal entity running RightsRoot. |
| **Specification** | rightsroot.org | The open standard, the philosophy, the threat model, the implementation guidance. |
| **Application** | rightsroot.com | Where a person creates, signs, publishes, and shares. |

## Why the separation is load-bearing

It is not branding tidiness. The project's central claim is that **the provider does not need to be
trusted**, and that claim is much harder to believe when the protocol and the operator are the same
name. A specification that lives at a neutral address, that a competitor can implement without
depending on us, is what makes "verify it yourself" credible.

Practically: someone can implement PRM, verify RightsRoot-published policies, and never touch
rightsroot.com. That has to be visibly true, not merely technically true.

## Canonical URLs

```
rightsroot.com/u/{handle}                 a person's public policy page
rightsroot.com/u/{handle}/policy.json     the signed policy, current
rightsroot.com/u/{handle}/v/{n}.json      an immutable version
rightsroot.com/u/{handle}/kel.json        the issuer's key history
rightsroot.com/u/{handle}/qr.svg          QR: canonical URL + policy digest
rightsroot.com/p/{code}                   short link

rightsroot.org/spec/prm                   the PRM specification
rightsroot.org/spec/prm/ns/v1             the JSON-LD context namespace
rightsroot.org/spec/prm/schemas/…         JSON Schemas
```

The namespace `https://rightsroot.org/spec/prm/ns/v1` appears inside every signed document. It moved
there from `prm.dev`, a domain this project never controlled — a context URI pointing at a domain a
third party could register is an integrity problem, not a cosmetic one. See decision D71.

## How to write it

**Do:**

- "Published with RightsRoot."
- "PRM is the open protocol RightsRoot implements."
- "Verify it with any PRM implementation."
- "A PRM policy", "a PRM notice", "a `.prmproof` bundle".

**Don't:**

- "RightsRoot protocol" — the protocol is PRM.
- "PRM app" — the app is RightsRoot.
- "PRM verifies your policy" — verification is something *anyone* does; PRM is the format that makes
  it possible.

## In the notice packet

A notice going to a records officer leads with **Personal Rights Management**, because that is what
the document *is*, and because the settled legal language already uses the term. RightsRoot appears
as provenance in the verification section, alongside the specification URL — so a technical reviewer
can find the standard, and a non-technical reader is not asked to learn a brand first.

## Package names

Workspace packages keep the `@prm/*` scope: they implement the protocol, and `@prm/verify` is a
protocol verifier that ought to be usable by anyone, including people with no relationship to
RightsRoot.

**Unverified:** whether the `@prm` npm scope is actually available. If it is not, the fallback is
`@rightsroot/prm-*` — the scope name changes, the import surface does not. Worth checking before the
first publish, since renaming a scope afterwards is disruptive.

## Repository

The repository is `Breezy-Point-Beach/prm`. It holds both the specification and the implementation
today. If `rightsroot.org` ever needs to be built and deployed separately, `spec/` and `docs/` are
already the natural split — see `docs/15-repo-structure.md`.
