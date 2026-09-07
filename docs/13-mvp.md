# 13 — MVP

**Definition of done:** one person can generate keys locally, sign a policy about ALPR retention,
publish it at a public URL with a QR code and a PDF, prove it existed at a point in time, grant and
revoke an exception, and hand a records officer a document that a third party can verify **with
rightsroot.com switched off**.

If a feature is not required for that sentence, it is not in the MVP.

## 1. In scope

| # | Capability | Notes |
|---|---|---|
| 1 | Client-side Ed25519 key generation | `@noble/curves`, in-browser, never transmitted |
| 2 | Passkey (WebAuthn PRF) or passphrase vault | Argon2id + XChaCha20-Poly1305 |
| 3 | 24-word mnemonic backup, verified by challenge | **Blocking step** before first publish |
| 4 | Genesis key event with pre-rotation + recovery commitments | Cheap now, a migration later |
| 5 | Policy authoring from the ALPR template | 5 templates total, no policy language |
| 6 | JCS canonicalization + signing | `@prm/crypto`, shared by web/CLI/verify |
| 7 | Publish: `/u/{handle}` HTML + `/u/{handle}/policy.json` | Edge, cached |
| 8 | Version history at `/u/{handle}/v/{n}.json` | Immutable, cached permanently |
| 9 | Short URL + QR with digest prefix | Separate short domain |
| 10 | Signed PDF packet with embedded JSON | §04.7 structure |
| 11 | Signed authorization records + revocation | Bitstring Status List |
| 12 | Personal hash-chain ledger | Local-first, encrypted server backup |
| 13 | Merkle transparency log + signed tree heads | Postgres advisory lock for append |
| 14 | RFC 3161 timestamping via Vercel Cron | Two TSAs |
| 15 | `.prmproof` bundle export | The single-file artifact for a lawyer |
| 16 | `@prm/verify` + `prm` CLI, offline-capable | Published to npm from day one |
| 17 | `/.well-known/prm-log` + self-host instructions | Proves PRM is optional |
| 18 | GitHub → Vercel preview → production pipeline | §16, §17 |

## 2. Explicitly out of scope

Zero-knowledge proofs · identifier lookup of any kind · OPRF · mobile apps · wallet passes · NFC
writing · decentralized storage · blockchain anchoring · enterprise SDK beyond `@prm/verify` ·
webhooks · multi-device sync · social recovery · delegation · policy-engine reasoning over purposes ·
multi-jurisdiction templates beyond US · i18n · organization accounts.

Two of these deserve a note because they look like MVP material:

- **Webhooks are out** because there are no integrated organizations yet. Building a push channel with
  no subscribers is pure speculation. The pull endpoints exist; add push when someone asks.
- **Lookup is out** for the reasons in §03 and §12. Shipping without it is a feature, and it is much
  easier to add later than to remove.

## 3. Screens

Seven. Resist an eighth.

1. **Create** — generate keys, show mnemonic, verify mnemonic, set passkey/passphrase.
2. **Author** — pick template, toggle rules, edit prose, preview both renderings.
3. **Sign & publish** — biometric unlock, sign, publish, show the proof.
4. **My policy** — public preview, QR, PDF download, version history, self-host instructions.
5. **Share** — copy short URL, download PDF, generate the notice packet, record delivery.
6. **Authorizations** — grant (5 templates, duration slider), list, revoke.
7. **Ledger** — chronological entries, proof status, export `.prmproof` / evidence ZIP.

## 4. Data model (Postgres, MVP)

```sql
-- No table in this schema stores a raw personal identifier. That is an invariant, not an accident.

create table accounts (
  account_id      text primary key,          -- prm:… self-certifying, derived from genesis
  handle          text unique not null,       -- random, non-sequential, non-name-derived
  genesis_digest  text not null,
  created_at      timestamptz not null default now()
);

create table key_events (
  account_id      text not null references accounts(account_id),
  sequence        int  not null,
  event_digest    text not null unique,
  previous_digest text,
  document        jsonb not null,             -- public keys and digests only
  created_at      timestamptz not null default now(),
  primary key (account_id, sequence)          -- one event per sequence: equivocation is impossible
);

create table policies (
  digest          text primary key,
  account_id      text not null references accounts(account_id),
  chain_id        text not null,
  version         int  not null,
  previous_digest text,
  -- RAW TEXT, not jsonb. jsonb does not preserve key order, whitespace, duplicate keys, or
  -- numeric formatting, so it cannot return the exact bytes the user signed. See decision D51.
  -- Add a generated jsonb column alongside if indexing is ever needed; never serve from it.
  policy_json     text  not null,             -- published by design; contains no PII
  published_at    timestamptz not null default now(),
  unique (chain_id, version)
);

create table ledger_leaves (
  leaf_index      bigint primary key,
  leaf_hash       bytea  not null,            -- 32 opaque bytes; the log learns nothing
  entry_digest    text   not null unique,
  account_id      text   references accounts(account_id),
  appended_at     timestamptz not null default now()
);

create table tree_heads (
  tree_size       bigint primary key,
  root_hash       bytea not null,
  previous_root   bytea,
  signature       text  not null,             -- by K_log
  timestamp_token bytea,                      -- RFC 3161, attached by cron
  tsa_name        text,
  created_at      timestamptz not null default now()
);

create table vault_blobs (
  account_id      text primary key references accounts(account_id),
  blob_url        text not null,              -- Vercel Blob; CIPHERTEXT ONLY
  updated_at      timestamptz not null default now()
);

create table status_lists (
  list_id         int primary key,
  bitstring       bytea not null,             -- gzip'd Bitstring Status List
  updated_at      timestamptz not null default now()
);

create table short_links (
  code            text primary key,
  target          text not null,
  created_at      timestamptz not null default now()
);
```

Seven tables. `account_id` is the only cross-table join key, and it is public and self-certifying.

## 5. Acceptance criteria

Each is a test, not a checkbox.

1. `node spec/test-vectors/verify.mjs` passes against documents produced by the *web app*, not just the
   generator.
2. `npx @prm/verify policy.json --offline` succeeds with the network disabled and DNS blackholed.
3. A policy published through the UI produces an RFC 3161 token within one hour, verifiable with
   `openssl ts -verify` and no PRM code.
4. Grepping the server's request logs, database, and error reports for the test plate `US-CA-0EXAMPLE`
   returns **zero** hits after a full end-to-end run. Automate this as a CI test against a seeded
   preview deployment.
5. Deleting the Vercel deployment leaves a previously exported `.prmproof` bundle fully verifiable.
6. A fresh clone + documented env vars + `pnpm dev` runs locally in under 10 minutes.
7. Restoring from mnemonic on a second browser reproduces the same `accountId` and can sign a v2 that
   chains to v1.

Criterion 4 is the one that will actually catch drift toward T1. Write it early.

## 6. Effort

Roughly 8–10 weeks for one experienced full-stack engineer, assuming the crypto packages come first:

| Week | Focus |
|---|---|
| 1–2 | `@prm/crypto`, `@prm/schema`, `@prm/verify` + test vectors (already largely specified in `spec/`) |
| 3 | CLI; offline verification proven |
| 4–5 | Next.js app: create, author, sign, publish |
| 6 | Merkle log, tree heads, Cron + RFC 3161 |
| 7 | PDF, QR, notice packet, `.prmproof` export |
| 8 | Authorizations, status list, ledger UI |
| 9 | Hardening, acceptance criteria, CI, security review |
| 10 | Buffer — it will be needed for recovery UX (§12 T12) |

Build the packages before the app. The app is the easy part; the packages are the product.
