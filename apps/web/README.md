# @prm/web

The PRM application. Three screens and one public artifact.

```console
pnpm install
pnpm build            # workspace packages must be built first
pnpm --filter @prm/web dev
```

Open http://localhost:3000. No configuration is required for local development.

## What this app does

**Create → author → sign → publish → independently verify.**

1. **Create** — the signing key is generated in the browser, shown as 24 words, and sealed with a
   passphrase. The backup challenge is blocking: you cannot continue without proving you wrote the
   phrase down, because there is no recovery path we can offer you.
2. **Author** — starts from the California ALPR template. Terms are edited in the matrix; the
   explanation is yours to write. A generated summary of the terms is appended when you sign, so the
   prose and the machine-readable rules cannot drift apart.
3. **Sign & publish** — sign locally, verify locally, publish, then **download the published document
   and compare it byte for byte** against what was signed.

## What the server is allowed to receive

Only two things: the already-signed policy bytes, and the public key event log.

Never: draft contents, the license plate or any raw identifier, the mnemonic, the vault, the vault
key, or any signing material. The plate is used on-device to compute a salted commitment; the
published policy carries only that commitment.

## The property this app exists to protect

> The browser signs bytes A. The server stores bytes A. The browser retrieves bytes A.

Any server-side mutation — reserialization, key reordering, whitespace changes, added or stripped
fields, or substitution — makes the publish fail visibly, and "publish succeeded" is not shown until
the returned bytes match exactly.

This is stronger than checking the signature. JSON canonicalization erases formatting, so a
reserialized document still verifies; only a byte comparison catches it. `test/roundtrip.test.ts`
covers each of those mutations, including the reserialization case where the signature stays valid
and the byte check is what fails.

## Storage

`lib/store.ts` defines the interface. Development uses a filesystem store that needs no setup;
Vercel's filesystem is read-only, so the Postgres driver arrives with the deployment PR.

Published policies are stored as **raw text**, never `jsonb` — see decision D51. `jsonb` does not
preserve key order, whitespace, duplicate keys, or numeric formatting, so it cannot hand back the
bytes that were signed.

## Not in this release

PDF, QR codes, wallet passes, authorizations, the transparency log, timestamping, and version
history UI. Those layer on top of a signing path that is already proven, rather than destabilizing it.
