# Templates

Copy-ready configuration referenced by [15 — Repository Structure](../15-repo-structure.md),
[16 — Vercel Deployment](../16-vercel-deployment.md), and
[17 — GitHub Workflow](../17-github-workflow.md).

## Already live

`.github/workflows/spec-conformance.yml` is **active**. The `spec/` tree is real and its vectors pass
today, so the check that guards them runs from the first commit. It is the highest-value check in the
repository.

`.env.example`, `.gitignore`, `.github/CODEOWNERS`, `.github/dependabot.yml`, the PR template, and the
issue templates are also live at their proper paths.

## Staged here until there is code to run them against

| Template | Move to | When |
|---|---|---|
| `ci.yml` | `.github/workflows/ci.yml` | With the first PR that adds `packages/` — it runs lint, typecheck, unit tests, boundary checks, and E2E, none of which exist yet |
| `vercel.json` | `vercel.json` (repo root) | With the first PR that adds `apps/web/` — the cron paths 404 until the route handlers exist |

```console
cp docs/templates/ci.yml      .github/workflows/ci.yml
cp docs/templates/vercel.json vercel.json
```

They live here rather than in place because a workflow referencing `pnpm lint` in a repo with no lint
script fails on every push, and a `vercel.json` declaring crons against non-existent routes produces
hourly errors. Both would train you to ignore red builds, which is the opposite of what the
spec-conformance gate is for.

When you move `ci.yml` into place, widen the `paths:` filter in `spec-conformance.yml` to include
`packages/crypto/**`, `packages/verify/**`, `packages/ledger/**`, and `packages/schema/**`.
