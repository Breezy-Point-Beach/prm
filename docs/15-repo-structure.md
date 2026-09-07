# 15 — Repository Structure (Breezy-Point-Beach)

## 1. One repository, not five

**Recommendation: a single monorepo at `github.com/Breezy-Point-Beach/prm`.**

Why: the crypto library, schema, verifier, CLI, and web app must stay byte-compatible. A canonicalization
change that lands in `@prm/crypto` without the matching test-vector update in `spec/` breaks every
signature ever produced. In a monorepo that is one atomic PR with one CI run. Across five repos it is a
version-matrix problem that a solo founder will lose.

Split later, and only for a specific reason:

| Repo | When to split it out |
|---|---|
| `Breezy-Point-Beach/prm` | — (start here; contains everything) |
| `Breezy-Point-Beach/prm-spec` | When outside parties implement the spec and need a stable, small, slow-moving repo to watch |
| `Breezy-Point-Beach/prm-log-anchors` | Immediately — see §08.3; a tiny public repo of daily root hashes, append-only, as a free third anchor |
| `Breezy-Point-Beach/prm-receivers` | When the community-maintained organization directory (§11.3) outgrows a JSON file |

## 2. Layout

```
prm/
├── apps/
│   ├── web/                      Next.js 15 App Router — the PRM application
│   │   ├── app/
│   │   │   ├── (marketing)/                  landing, docs, about
│   │   │   ├── (app)/                        authenticated app shell
│   │   │   │   ├── create/  author/  share/  authorizations/  ledger/
│   │   │   ├── u/[handle]/                   PUBLIC policy page   (edge, cached)
│   │   │   │   ├── page.tsx
│   │   │   │   ├── policy.json/route.ts
│   │   │   │   ├── v/[n]/route.ts
│   │   │   │   ├── kel.json/route.ts
│   │   │   │   └── policy.pdf/route.ts       (node)
│   │   │   ├── p/[code]/route.ts             short URL redirect  (edge)
│   │   │   ├── status/[listId]/route.ts      Bitstring Status List (edge)
│   │   │   ├── .well-known/prm-log/route.ts  log metadata + K_log public key
│   │   │   └── api/v1/…                      REST API            (node)
│   │   ├── components/  lib/  middleware.ts
│   │   └── e2e/                              Playwright
│   └── docs/                     Optional: the docs/ tree rendered (Nextra/Fumadocs)
│
├── packages/
│   ├── crypto/                   @prm/crypto   Ed25519, JCS, SHA-256, HKDF, Argon2id, multibase
│   ├── schema/                   @prm/schema   types, JSON Schemas, normalization, templates
│   ├── verify/                   @prm/verify   PURE verification — zero network in the core path
│   ├── ledger/                   @prm/ledger   hash chain + RFC 6962 Merkle tree + proofs
│   ├── cli/                      prm           keygen, sign, verify, proof, serve
│   ├── sdk/                      @prm/sdk      enterprise API client + webhook verification
│   ├── pdf/                      @prm/pdf      notice packet assembly (no signing)
│   └── monitor/                  @prm/monitor  reference log witness/mirror (§07.3.3)
│
├── spec/                         NORMATIVE — schemas, examples, test vectors  (already populated)
├── docs/                         this architecture documentation
├── .github/
│   ├── workflows/                ci.yml, codeql.yml, spec-conformance.yml, dependency-review.yml
│   ├── CODEOWNERS
│   └── pull_request_template.md
├── .env.example
├── turbo.json  pnpm-workspace.yaml  package.json  tsconfig.base.json
└── vercel.json
```

### Dependency rule (enforced in CI)

```
schema ← crypto ← ledger ← verify ← { cli, sdk, web }
```

`@prm/verify` may depend on `crypto`, `schema`, `ledger`. It may **not** depend on `sdk`, `web`, or any
HTTP client. Enforce with `eslint-plugin-boundaries` or a dependency-cruiser rule; this is the package
boundary that keeps the "verification doesn't need PRM" claim true.

## 3. Naming

- **Org:** `Breezy-Point-Beach`
- **Primary repo:** `prm` — short, and `Breezy-Point-Beach/prm` reads well.
- **npm scope:** `@prm/*` if available, else `@breezy-point-beach/prm-*` with `@prm/*` reserved later.
  Check availability before writing import paths everywhere; renaming a scope later is tedious.
- **Vercel projects:** `prm-web` (production), previews auto-named per branch.
- **Domains:** `rightsroot.com` (product: the app, policy pages, short links) and
  `rightsroot.org` (the open PRM specification and documentation). Short links live at
  `rightsroot.com/p/{code}` rather than on a separate domain — see the note on D37 in
  `docs/decisions.md`.

## 4. Branch strategy

**Trunk-based.** `main` is always deployable and always deployed.

```
main ──────●───────●───────●──────►  production (auto-deploy)
            \     / \     /
     feat/policy-pdf   fix/jcs-sorting     short-lived, squash-merged, preview per PR
```

- Branch names: `feat/…`, `fix/…`, `docs/…`, `chore/…`, `spec/…`.
- Squash merge only; linear history. The commit subject becomes the changelog entry.
- Tag releases `v0.1.0` (semver). Packages version together via Changesets.
- No `develop` branch, no release branches, no GitFlow. One person does not need a release train.
- **Exception:** anything touching canonicalization, signing, or the schema goes on a `spec/…` branch
  and requires the conformance workflow to pass. See §5.

## 5. Environment variables

`.env.example` is the contract. If a variable is not in it, it does not exist.

```bash
# ─── Database ────────────────────────────────────────────────────────────────
# Neon (Vercel Marketplace). Pooled URL for serverless; direct URL for migrations.
DATABASE_URL="postgresql://user:pass@ep-xxx-pooler.region.aws.neon.tech/prm?sslmode=require"
DATABASE_URL_UNPOOLED="postgresql://user:pass@ep-xxx.region.aws.neon.tech/prm?sslmode=require"

# ─── Public configuration (safe in the client bundle) ────────────────────────
NEXT_PUBLIC_APP_URL="http://localhost:3000"
NEXT_PUBLIC_SHORT_URL_BASE="http://localhost:3000/p"
NEXT_PUBLIC_LOG_ID="prm-log-dev"
NEXT_PUBLIC_LOG_PUBLIC_KEY="z6Mk…"      # public half of K_log; clients verify tree heads with it

# ─── Transparency log signing (THE ONLY SERVER-HELD SIGNING KEY) ─────────────
# Ed25519 private key, base64. Compromise lets an attacker forge TREE HEADS ONLY —
# it cannot forge, alter, or repudiate any user-signed document. Rotate quarterly;
# publish every historical log key at /.well-known/prm-log so old heads stay verifiable.
LOG_SIGNING_KEY_B64=""

# ─── Timestamping ────────────────────────────────────────────────────────────
TSA_PRIMARY_URL="https://freetsa.org/tsr"
TSA_SECONDARY_URL="https://timestamp.digicert.com"
CRON_SECRET=""                           # guards /api/cron/*; Vercel sends it as a bearer token

# ─── Storage ─────────────────────────────────────────────────────────────────
BLOB_READ_WRITE_TOKEN=""                 # Vercel Blob — stores CIPHERTEXT ONLY

# ─── Rate limiting ───────────────────────────────────────────────────────────
UPSTASH_REDIS_REST_URL=""
UPSTASH_REDIS_REST_TOKEN=""

# ─── Optional, beta ──────────────────────────────────────────────────────────
APPLE_PASS_CERT_B64=""                   # signs wallet CARDS, never policies
APPLE_PASS_CERT_PASSWORD=""
GOOGLE_WALLET_SERVICE_ACCOUNT_JSON=""
RESEND_API_KEY=""                        # notice delivery + publish notifications

# ─── NEVER SET, IN ANY ENVIRONMENT ───────────────────────────────────────────
# There is no variable for a user signing key, seed, vault key, recovery share, or
# identifier salt. If a PR introduces one, that PR is rejected. See docs/01 §8.
```

### Handling

| Where | How |
|---|---|
| Local | `.env.local` (gitignored), seeded from `.env.example`, or `vercel env pull` |
| Preview | Vercel project env, scoped to Preview; a **separate** Neon branch and a **separate** dev log key |
| Production | Vercel project env, scoped to Production, marked Sensitive |
| CI | GitHub Actions secrets; CI never touches production data and uses ephemeral test keys |

**Preview deployments must never share the production log key or database.** A preview writing to the
production Merkle tree corrupts it irreversibly. Enforce by asserting at boot that
`NEXT_PUBLIC_LOG_ID` matches the expected value for `VERCEL_ENV`, and fail closed.

## 6. Secrets management

- Vercel encrypted env vars are sufficient for the MVP. Mark everything sensitive as Sensitive so it
  cannot be read back from the dashboard.
- Rotate `LOG_SIGNING_KEY_B64` quarterly. Keep every historical public key published so historical tree
  heads remain verifiable — rotation must not invalidate the archive.
- Enable **GitHub secret scanning + push protection** on the org.
- Add `gitleaks` to CI as a second net, since push protection only catches known provider patterns and
  an Ed25519 key in base64 is not one of them.
- No secrets in `NEXT_PUBLIC_*`. Add a CI check that greps the built client bundle for the private-key
  variable names — a build-time assertion is worth more than a convention.

## 7. CI checks (gate on all of these)

| Check | Tool | Blocking |
|---|---|---|
| Lint | ESLint + `eslint-plugin-boundaries` | ✅ |
| Format | Prettier `--check` | ✅ |
| Types | `tsc --noEmit`, strict | ✅ |
| Unit tests | Vitest | ✅ |
| **Crypto test vectors** | `node spec/test-vectors/verify.mjs` | ✅ |
| **Schema conformance** | `node spec/test-vectors/validate-schemas.mjs` | ✅ |
| **Determinism** | `node spec/test-vectors/check-reproducible.mjs` | ✅ |
| **Offline verification** | `@prm/verify` suite with network disabled | ✅ |
| **No-PII scan** | grep build output + seeded preview logs for test identifiers | ✅ |
| E2E | Playwright against the preview URL | ✅ |
| Secret scan | gitleaks + GitHub push protection | ✅ |
| Dependency review | `actions/dependency-review-action` + Dependabot | ✅ |
| SAST | CodeQL (JS/TS) | ✅ on `main`, weekly |
| Bundle size | `@next/bundle-analyzer` budget | ⚠️ warn |

The four bolded checks are the ones specific to this project. They are what stop a well-meaning
refactor from silently invalidating every signature in existence.

## 8. Branch protection on `main`

- Require a PR; no direct pushes (including for the owner — set it and leave it).
- Require all blocking checks above.
- Require branches up to date before merge.
- Require **signed commits** — the project's entire premise is signature verification.
- Require linear history; squash merge only.
- Include administrators.
- `CODEOWNERS`: `/spec/ /packages/crypto/ /packages/verify/` require explicit review even when solo —
  it forces a deliberate second look at the code where a bug is unrecoverable.
