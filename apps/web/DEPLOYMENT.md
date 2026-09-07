# Deploying to Vercel

## Required environment variables

| Variable | Where from | Why |
|---|---|---|
| `BLOB_READ_WRITE_TOKEN` | Vercel → Storage → Blob | Signed artifacts, stored at digest-derived keys |
| `DATABASE_URL` | Neon (Vercel Marketplace) | The alias layer: which digest a handle's version N points at |

**Both, or neither.** With only one set — or with `VERCEL=1` and neither — the app refuses to start.
Falling back to filesystem storage on Vercel would *appear* to work: publishes would succeed, and
every artifact would vanish on the next cold start. A loud failure at boot is much cheaper than
discovering that a week later.

Local development needs neither. `pnpm dev` uses a filesystem store that requires no configuration.

## Database schema

```sql
-- Also exported as SCHEMA_SQL from lib/storage/blob.ts
create table if not exists published_policies (
  handle             text        not null,
  version            integer     not null,
  account_id         text        not null,
  policy_chain_id    text        not null,
  policy_digest      text        not null,
  policy_byte_digest text        not null,
  policy_location    text        not null,
  policy_byte_length integer     not null,
  kel_byte_digest    text        not null,
  kel_location       text        not null,
  content_type       text        not null,
  published_at       timestamptz not null default now(),
  primary key (handle, version)
);
create index if not exists published_policies_account on published_policies (account_id);
```

Note what is **not** there: any column that could hold a policy. The signed artifact never enters the
database, which makes decision D51 structurally impossible to violate rather than merely discouraged.

## The storage rule

> Storage may index metadata about an artifact, but the authoritative signed artifact itself is an
> immutable byte sequence.

Concretely:

- Artifacts live at `artifacts/policy/<byteDigest>` — the **address is derived from the content**.
- Writes are refused unless `SHA-256(bytes) == declaredDigest`.
- Reads are refused unless `SHA-256(returned) == requestedDigest`.
- Storage is **write-once**. A new policy version is a new object; the old one remains forever.

Two digests, and they are not the same thing:

| | Meaning | Changes when |
|---|---|---|
| `policyDigest` | Protocol identity — `SHA-256(JCS(policy minus id, proof))` | The document's *meaning* changes |
| `policyByteDigest` | Storage address — `SHA-256(exact bytes)` | *Any* byte changes, including whitespace |

Addressing artifacts by `policyDigest` would give a reserialized document the same storage key as the
original, reopening the substitution hole. See decision D55.

## Replacing the storage backend

Any new adapter must pass `runStorageContract` **and** `runHostileBackendContract` in
`lib/storage/contract.ts`, and be registered in `test/storage.test.ts`. The hostile suite corrupts
data *below* the adapter and requires every mutation to be caught: altered whitespace, reordered
keys, one changed byte, truncation, appended content, a substituted artifact, and — the subtle one —
correct semantic content that was merely reserialized.

That last case is why this suite exists. A reserialized policy still passes its PRM signature check,
because canonicalization erases formatting. Only the byte digest catches it.

## Caching

| Route | Cache-Control | Why |
|---|---|---|
| `/u/{h}/v/{n}.json` | `max-age=31536000, immutable` | A published version's bytes can never change |
| `/u/{h}/policy.json` | `max-age=60, stale-while-revalidate=600` | An alias that moves when v2 is published |
| `/u/{h}/qr.svg` | `max-age=60, stale-while-revalidate=600` | Encodes the current version's digest |

## Deployment checklist

- [ ] Blob store created, `BLOB_READ_WRITE_TOKEN` set for Production and Preview
- [ ] Neon database created, `DATABASE_URL` set, schema applied
- [ ] Preview uses a **separate** Neon branch and blob store from production
- [ ] Publish a policy, then redeploy, then confirm the artifact is byte-identical
- [ ] Confirm `/u/{h}/v/1.json` still returns v1 after publishing v2
- [ ] Confirm no raw identifier appears in logs, the database, or any published artifact
