## What

<!-- One or two sentences. -->

## Why

<!-- The problem, not the solution. -->

---

## Crypto / spec impact

- [ ] No changes to canonicalization, signing, hashing, or the document schemas
- [ ] Changes present — spec version bumped, vectors regenerated, migration documented in `docs/decisions.md`

> A change to canonicalization or the signing construction invalidates **every signature ever
> produced**, retroactively. If `spec/test-vectors/vectors.json` or `spec/examples/**` changed, that is
> a spec version bump (v1 → v2), not an edit. Add the `spec-version-bump` label to acknowledge it.

## Privacy impact

- [ ] No new personal data stored server-side
- [ ] No new raw identifier reaches a server, a log, or an error report
- [ ] No new server-held key material (see `.env.example`, "NEVER ADD")

> Both of these failure modes are silent. A PR that adds an identifier column or a server-side signing
> path looks like ordinary work. See `docs/12-threat-model.md` T1.

## Checks

- [ ] `pnpm test` passes locally (vectors, schema conformance, determinism)
- [ ] Preview deployment verified manually, if this touches the app
