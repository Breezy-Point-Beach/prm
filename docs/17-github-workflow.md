# 17 — GitHub Workflow (Breezy-Point-Beach)

## 1. The loop

```
local dev  →  feature branch  →  pull request  →  Vercel preview  →  CI  →  merge to main  →  production
    ↑                                                    │
    └────────────────── fix ◄────────────────────────────┘
```

Concretely:

```console
$ gh repo clone Breezy-Point-Beach/prm && cd prm
$ cp .env.example .env.local     # or: vercel env pull .env.local
$ pnpm install && pnpm db:migrate && pnpm dev

$ git switch -c feat/policy-pdf
$ pnpm test && pnpm spec:check   # run the crypto gates locally; they are fast
$ git commit -S -m "feat(pdf): embed signed policy JSON as a PDF/A-3 attachment"
$ git push -u origin feat/policy-pdf && gh pr create --fill
#   → Vercel comments the preview URL
#   → CI runs lint, types, unit, spec vectors, offline verify, E2E against the preview
$ gh pr merge --squash
#   → main deploys to production
```

Commits are **signed** (`git config commit.gpgsign true`, or `gpg.format = ssh` with an SSH signing
key — simpler to set up and sufficient). A project about signature verification with unsigned commits
is not a good look, and branch protection enforces it anyway.

## 2. GitHub Actions

Four workflows. Templates ready to copy are in [`docs/templates/`](templates/).

### `ci.yml` — every PR and push to main

```yaml
name: CI
on:
  pull_request:
  push: { branches: [main] }
concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: pnpm }
      - run: pnpm install --frozen-lockfile

      - name: Lint
        run: pnpm lint
      - name: Format
        run: pnpm format:check
      - name: Types
        run: pnpm typecheck
      - name: Package boundaries          # @prm/verify must not depend on network code
        run: pnpm lint:boundaries
      - name: Unit tests
        run: pnpm test:unit

      # ── The checks specific to this project ──────────────────────────────
      - name: Crypto test vectors
        run: node spec/test-vectors/verify.mjs
      - name: Schema conformance
        run: node spec/test-vectors/validate-schemas.mjs
      - name: Deterministic generation
        run: node spec/test-vectors/check-reproducible.mjs
      - name: Offline verification
        run: pnpm --filter @prm/verify test:offline
      - name: No key material in the client bundle
        run: pnpm build:web && pnpm check:bundle-secrets

      - name: Secret scan
        uses: gitleaks/gitleaks-action@v2
```

### `spec-conformance.yml` — guards the signature-breaking surface

Triggered only on changes to `spec/**`, `packages/crypto/**`, `packages/verify/**`,
`packages/ledger/**`. It re-runs the vectors **and** asserts that committed example digests have not
changed:

```yaml
- name: Assert published digests are unchanged
  run: |
    git fetch origin main --depth=1
    if ! git diff --quiet origin/main -- spec/examples spec/test-vectors/vectors.json; then
      echo "::error::Canonical digests changed. This invalidates every signature ever produced."
      echo "If intentional, this is a SPEC VERSION BUMP (v1 → v2), not an edit."
      exit 1
    fi
```

This is the most valuable check in the repository. Canonicalization is the load-bearing detail of the
whole design, and it can be broken by something as innocuous as changing a key name or a sort function.
Making that failure loud and explicit — with the words "spec version bump" in the error — is what keeps
a solo founder from shipping it at 1am.

### `codeql.yml` — SAST on `main` and weekly (JS/TS).

### `dependency-review.yml` — blocks PRs introducing known-vulnerable or license-incompatible deps.
Plus Dependabot (`.github/dependabot.yml`) grouping minor/patch updates weekly, with security updates
immediate. Pin `@noble/*` exactly and review those bumps by hand — that is the code the entire trust
model rests on.

## 3. E2E against the preview

Playwright runs against the Vercel preview URL, obtained from the deployment status:

```yaml
  e2e:
    needs: verify
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: patrickedqvist/wait-for-vercel-preview@v1.3.2
        id: preview
        with: { token: ${{ secrets.GITHUB_TOKEN }}, max_timeout: 600 }
      - run: pnpm exec playwright test
        env:
          BASE_URL: ${{ steps.preview.outputs.url }}
          VERCEL_AUTOMATION_BYPASS_SECRET: ${{ secrets.VERCEL_AUTOMATION_BYPASS_SECRET }}
```

The bypass secret is needed because previews are protected (§16.4). The critical E2E path:
**create keys → author → sign → publish → fetch `/policy.json` → verify offline → assert the test plate
appears nowhere in the response or the logs.**

## 4. Branch protection on `main`

| Setting | Value |
|---|---|
| Require pull request | ✅ (1 approval; self-approval disabled → use a review from a second account or accept the friction) |
| Required status checks | `verify`, `e2e`, `codeql`, `dependency-review` |
| Require branches up to date | ✅ |
| Require signed commits | ✅ |
| Require linear history | ✅ |
| Allow force push / deletions | ✗ |
| Include administrators | ✅ |
| CODEOWNERS review | ✅ for `/spec/`, `/packages/crypto/`, `/packages/verify/` |

On the solo-founder reality: requiring an approving review when you are the only committer is either
theater or an obstacle. The honest configuration is **required status checks + signed commits + linear
history + CODEOWNERS on the crypto paths**, without a required approval, until there is a second
engineer. Keep "include administrators" on — the point is to stop *yourself* from pushing to main at
2am, and that is a real risk.

## 5. Pull request template

```markdown
## What
## Why

## Crypto/spec impact
- [ ] No changes to canonicalization, signing, hashing, or the schema
- [ ] Changes present — spec version bumped, vectors regenerated, migration documented

## Privacy impact
- [ ] No new personal data stored server-side
- [ ] No new identifier reaches a server
- [ ] No new server-held key material

## Checks
- [ ] `pnpm spec:check` passes locally
- [ ] Preview deployment verified manually
```

Those two impact sections exist because both failure modes are silent. A PR that adds an identifier
column or a server-side signing path will otherwise look like ordinary work.

## 6. Releases

- Changesets for package versioning; `pnpm changeset` in any PR touching `packages/*`.
- On merge to `main`, a release workflow publishes changed packages to npm with **provenance**
  (`npm publish --provenance`), which gives consumers a verifiable link from the tarball back to this
  repo and commit. Appropriate for a verification library other people are asked to trust.
- Tag `v0.x.y`; generate release notes from squashed commit subjects.
- `@prm/verify` gets published before anything else, and its README leads with offline verification.

## 7. Repository hygiene

- `SECURITY.md` with a disclosure address and a stated response window.
- `docs/decisions.md` (the register) updated in the same PR as any architectural change.
- Issue templates for `spec-question`, `security` (pointing to private reporting), and `integration`.
- Enable GitHub private vulnerability reporting.
- `LICENSE`: Apache-2.0 for the code (patent grant matters for a standards-adjacent project);
  CC-BY-4.0 for `docs/` and `spec/` so the format can be implemented and quoted freely.
