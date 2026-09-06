# 16 — Vercel Deployment Architecture

## 1. The rule that governs everything else

> **Cryptographic authority never touches Vercel.**

Vercel hosts, renders, indexes, caches, assembles, and timestamps. It does not hold, derive, or use any
key that could speak for a user. Everything below follows from that.

### Where each cryptographic operation runs

| Operation | Client (browser/device) | Vercel | Never on a server |
|---|---|---|---|
| Ed25519 keypair generation | ✅ | ✗ | |
| Mnemonic generation / display | ✅ | ✗ | |
| Vault key derivation (Argon2id / WebAuthn PRF) | ✅ | ✗ | |
| Vault encryption / decryption | ✅ | ✗ | |
| **Signing a policy** | ✅ | ✗ | |
| **Signing an authorization** | ✅ | ✗ | |
| **Signing a key event** | ✅ | ✗ | |
| **Signing a ledger entry** | ✅ | ✗ | |
| Identifier salt derivation, commitment | ✅ | ✗ | |
| Pairwise ID derivation | ✅ | ✗ | |
| Evidence artifact encryption | ✅ | ✗ | |
| JCS canonicalization + digest | ✅ | ✅ (independent recompute) | |
| **Signature verification** | ✅ | ✅ | |
| Merkle append + inclusion proofs | ✅ (verify) | ✅ (build) | |
| **Tree head signing (`K_log`)** | ✗ | ✅ | |
| RFC 3161 request/response | ✗ | ✅ | |
| PDF/QR assembly | ✅ or ✅ | ✅ | |
| Wallet pass signing (provider cert) | ✗ | ✅ | |
| — | | | **user seed, `K_sign`, `K_next`, `K_rec`, `K_vault`, `S_bind`, identifier salts, plaintext evidence** |

Only two signing keys exist server-side: `K_log` (tree heads) and the optional wallet-pass provider
certs. Neither can produce a user document. Keep this table in the repo and diff it in review — if a
new row appears in the middle column, that is an architectural change, not an implementation detail.

## 2. App Router layout and runtime selection

| Route | Runtime | Why |
|---|---|---|
| `app/u/[handle]/page.tsx` | **Edge** | Read-mostly, globally cached, no DB when served from cache |
| `app/u/[handle]/policy.json/route.ts` | **Edge** | Same; `ETag` = digest, `CORS: *` |
| `app/u/[handle]/v/[n]/route.ts` | **Edge** | Immutable, cached permanently |
| `app/u/[handle]/kel.json/route.ts` | **Edge** | Small, cacheable |
| `app/p/[code]/route.ts` | **Edge** | Short-URL redirect; Edge Config lookup, no DB round trip |
| `app/status/[listId]/route.ts` | **Edge** | Bitstring status list, 5-min cache |
| `app/.well-known/prm-log/route.ts` | **Edge** | Static metadata |
| `app/u/[handle]/policy.pdf/route.ts` | **Node** | PDF assembly needs Node APIs |
| `app/api/v1/policies/route.ts` (POST) | **Node** | Postgres write + Merkle append |
| `app/api/v1/events/route.ts` (POST) | **Node** | Postgres write |
| `app/api/cron/*` | **Node** | TSA (raw sockets/ASN.1), batch DB work |
| `app/(app)/**` authoring UI | Client components | All key material is client-side by definition |

Edge caveats worth knowing before you commit: no Node built-ins, no long-lived TCP (so the Neon
serverless HTTP driver, not `pg`), and a smaller bundle budget. `@noble/*` runs fine on Edge, which is
why it was chosen over WebCrypto-only code.

## 3. Server Actions vs Route Handlers

Clean rule, applied consistently:

- **Server Actions** — mutations initiated by the PRM web UI itself: claim a handle, save a draft,
  request a short link, update notification preferences. Ergonomic, typed, CSRF-protected by Next.js.
- **Route Handlers (`/api/v1/*`)** — anything with an external consumer: publishing signed documents,
  the enterprise API, `.well-known`, webhooks in and out. These need stable URLs, explicit versioning,
  content negotiation, CORS, and independent rate limiting. Server Actions give you none of that and
  their invocation contract is not a public API.

**Publishing a signed policy is a Route Handler, not a Server Action**, even though it is triggered
from the UI — because the CLI and future SDKs must use the identical endpoint, and because it must be
callable by a user who has abandoned the web app entirely.

Server Actions must never receive key material. Enforce with a lint rule flagging any action parameter
named like a secret, plus code review on `app/(app)/**`.

## 4. Preview deployments

Every PR gets a preview. Configuration that makes them safe:

- **Separate Neon branch per preview.** The Neon Vercel integration creates a database branch per
  deployment; use it. Never point a preview at production data.
- **Separate log identity.** Preview sets `NEXT_PUBLIC_LOG_ID=prm-log-preview` and a distinct
  `LOG_SIGNING_KEY_B64`. Assert at boot that the log id matches `VERCEL_ENV`, and refuse to start
  otherwise. A preview appending to the production tree is an unrecoverable corruption.
- **`X-Robots-Tag: noindex`** on all preview deployments.
- **Vercel Deployment Protection** on previews so they are not publicly reachable.
- Preview URL is posted to the PR automatically; Playwright E2E runs against it.

## 5. Production

- `main` → production, auto-deploy.
- Custom domains: `prm.app` (apex + `www` redirect), `prm.li` (short links).
- Skew protection on, so a client mid-session does not hit a mismatched deployment.
- Instant rollback via the Vercel dashboard; because the log is append-only, a rollback of application
  code never rewinds evidence.

## 6. Vercel Cron

```jsonc
// vercel.json
{
  "crons": [
    { "path": "/api/cron/timestamp",     "schedule": "0 * * * *" },   // hourly RFC 3161 over the tree head
    { "path": "/api/cron/status-lists",  "schedule": "*/5 * * * *" }, // regenerate revocation bitstrings
    { "path": "/api/cron/anchor-daily",  "schedule": "0 3 * * *" },   // beta: OTS + push root to prm-log-anchors
    { "path": "/api/cron/notice-windows","schedule": "0 9 * * *" }    // prompt users when a response window elapses
  ]
}
```

Guard every cron route with `CRON_SECRET` (Vercel sends it as a bearer token) and make them idempotent
— crons can fire twice. The hourly timestamp job is the one that actually matters; alert if it fails
twice consecutively, because a gap in timestamping is a gap in the evidentiary chain.

Hobby-plan cron granularity is limited to daily; the hourly and 5-minute schedules require Pro. Budget
for Pro from the start — this is a $20/month dependency, not an architectural one.

## 7. Managed PostgreSQL

**Recommendation: Neon**, via the Vercel Marketplace.

Why over the alternatives:
- **Database branching maps onto preview deployments**, which is the single most useful property here
  given how much of this system is schema-sensitive.
- Serverless HTTP driver (`@neondatabase/serverless`) works on Edge; `pg` does not.
- Scale-to-zero suits low early traffic.
- Provisioned through Vercel, so `DATABASE_URL` is injected automatically per environment.

Supabase is the reasonable alternative if you later want its auth/storage/realtime — but PRM
deliberately does not use hosted auth for signing identity, so most of that surface is unused. Choose
Neon and keep the dependency small.

Connection handling: pooled URL for request paths, unpooled for migrations (Drizzle or Prisma; Drizzle
is lighter and its SQL-first model suits a schema this small). Keep transactions short — the Merkle
append advisory lock (§07.3.2) is the only contended path, and it must not wrap an HTTP call to a TSA.

## 8. Object storage

**Vercel Blob** for encrypted vault backups and encrypted evidence artifacts. Ciphertext only; the
server never holds a decryption key. Use random, unguessable pathnames; never derive a path from an
identifier. Set a size cap per account and a total quota, since evidence artifacts (scans, PDFs) are
the one unbounded input.

## 9. Signed file generation

The subtlety: PDFs are assembled on the server, but the **signature inside them is produced on the
client**. Flow:

1. Client signs the policy → uploads the signed JSON.
2. Client requests `/u/{handle}/policy.pdf`.
3. Server fetches the signed JSON, renders the human text, embeds the **unmodified signed bytes** as a
   PDF attachment, draws the QR and prints the digest.
4. Client (or the verifier) can extract the attachment and confirm it matches the published document.

The server must never re-serialize the signed JSON when embedding it — embed the exact bytes it
received. Re-serialization is the most likely way to break signatures in this whole system; add a test
that round-trips a PDF and re-verifies the extracted attachment.

## 10. Security headers

```ts
// next.config.ts — applied to all routes
const csp = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",         // Argon2id WASM; NO unsafe-inline, NO unsafe-eval
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "require-trusted-types-for 'script'"
].join('; ')
```

Plus: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Permissions-Policy: geolocation=(), camera=(self), microphone=()` (camera for QR scanning),
`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` — except the
public policy JSON endpoints, which need `CORS: *` and `Cross-Origin-Resource-Policy: cross-origin` so
third-party verifiers can fetch them.

CSP matters more here than in a typical app: an XSS on the authoring page is an attacker holding an
unlocked signing key. Adopt `require-trusted-types-for 'script'` early, before the codebase grows
patterns that make it hard.

## 11. Rate limiting

Two layers:
- **Vercel WAF / Firewall** for IP-level abuse, bot rules, and Attack Mode. Zero code.
- **Upstash Redis sliding window** in Route Handlers for per-endpoint and per-org quotas (§09.7).

`/api/v1/resolve` limits are a security control, not a cost control — comment them as such.

## 12. Logging and auditability

- Structured JSON logs; **never** log request bodies on document-publish endpoints (they contain
  policies, which are public, but the same code path may later carry authorizations, which are not).
- Add a redaction allowlist and a unit test asserting known-sensitive field names never appear in log
  output.
- Retain request logs 7 days, then aggregate-only (§09.8). Vercel's log drains can go to a provider,
  but check its retention defaults — a well-meaning observability integration is a plausible route to
  accidentally building T1.
- The transparency log is the audit trail that matters; application logs are for operations only, and
  should never be treated as evidence.
- Alert on: cron timestamp failure ×2, Merkle append error, tree-head signature failure, log-id/env
  mismatch at boot.

## 13. Avoiding sensitive key material in Vercel env vars

`LOG_SIGNING_KEY_B64` is the one unavoidable server-side secret. Options, in order:

1. **MVP: Vercel encrypted env var, marked Sensitive, rotated quarterly.** Acceptable because the blast
   radius is forged tree heads — detectable, and powerless against user signatures. Document the blast
   radius next to the variable so nobody quietly expands its use.
2. **Beta: an external KMS** (AWS KMS / GCP KMS) with sign-only access. Removes the key from the
   platform entirely; costs one network hop per tree head, which is fine at hourly cadence.
3. **Post-beta: external witnesses** (§07.3.3), which reduce the value of stealing `K_log` to near
   zero, since a forged head that no witness co-signs is visibly illegitimate.

Wallet-pass certificates (beta) get the same treatment and the same explicit blast-radius note: they
sign cards, not policies.

## 14. What can never run on Vercel

Nothing in the MVP. Looking further out, two candidates:

- **A very large transparency log** — see §14.2. Escalation path documented; not Kubernetes.
- **An OPRF resolver** — wants a stable key, careful rate limiting, and ideally federation across
  operators. Could run on Vercel initially, but its governance (who operates it, under what policy)
  matters far more than its hosting.

Everything else — the app, the API, the log at realistic scale, timestamping, PDF generation, status
lists — is a comfortable fit for Vercel indefinitely.
