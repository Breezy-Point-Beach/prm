# 01 — User Identity and Key Management

## 1. Requirement

The provider must be **structurally incapable** of impersonating the user. Not "contractually
prohibited" — incapable. This drives every choice below.

## 2. Key material

| Key | Algorithm | Lives where | Purpose |
|---|---|---|---|
| **Root signing key** `K_sign` | Ed25519 | Device only, encrypted at rest | Signs policies, authorizations, key events, ledger entries |
| **Pre-rotation key** `K_next` | Ed25519 | Device + recovery shares, **never used to sign until rotation** | Makes rotation unforgeable by a thief holding `K_sign` |
| **Recovery key** `K_rec` | Ed25519 | Offline / Shamir-split among guardians | Signs recovery events when both above are lost |
| **Vault key** `K_vault` | 256-bit symmetric | Derived, never stored bare | Encrypts the local vault and any server-side backup blob |
| **Binding secret** `S_bind` | 256-bit | Inside vault | Derives per-identifier salts and pairwise IDs (§03) |
| **Log key** `K_log` | Ed25519 | **Server** (PRM) | Signs tree heads only — compromise forges timestamps, not policies |

Note the asymmetry: `K_log` is the *only* server-held signing key, and its blast radius is bounded to
"can produce an inconsistent tree head," which monitors detect and which cannot alter any user
signature.

## 3. Key generation

**Client-side, always.** In the browser:

```ts
// packages/crypto/src/keys.ts
import { ed25519 } from '@noble/curves/ed25519'
import { randomBytes } from '@noble/hashes/utils'

// 32-byte seed is the canonical secret; the mnemonic encodes exactly this.
const seed = randomBytes(32)                  // crypto.getRandomValues under the hood
const pub  = ed25519.getPublicKey(seed)
```

Use `@noble/curves` rather than WebCrypto for the MVP. WebCrypto Ed25519 is now widely available but
not uniformly, and `@noble` gives byte-identical behaviour in the browser, Node, the CLI, and the
verification library — which matters because the same test vectors must pass in all four.

**Derivation.** All keys derive from one 32-byte master seed via HKDF-SHA256 with distinct info
strings, so a single mnemonic backs up everything:

```
master_seed (32B, from mnemonic)
 ├─ HKDF(info="prm/v1/sign/0")     → K_sign     (rotation index 0)
 ├─ HKDF(info="prm/v1/sign/1")     → K_next     (rotation index 1)
 ├─ HKDF(info="prm/v1/recovery")   → K_rec
 └─ HKDF(info="prm/v1/binding")    → S_bind
```

Rotation to index *n+1* derives `sign/n+1` from the same seed, so rotation does **not** require a new
backup — an important usability property. A user who suspects seed compromise (not just device
compromise) must generate a *new* seed and perform a recovery event instead.

> **Decision — deterministic derivation from one seed.**
> *Why:* one backup artifact instead of four. *Threat:* backup fatigue → users skip backup → permanent
> account loss (the most common real-world failure, far more common than key theft).
> *MVP:* yes. *Standard:* RFC 5869 HKDF, BIP-39 mnemonic encoding. *Simpler alternative:* one key, no
> pre-rotation — rejected, it makes key theft unrecoverable.

## 4. Key storage on device

Three tiers, in preference order. The app picks the best available and tells the user which tier they
are on.

### Tier A — Passkey-wrapped (recommended default, web)

The seed is encrypted with a key derived from a **WebAuthn PRF extension** output, and the ciphertext
is stored in IndexedDB. Unlocking requires the platform authenticator (Touch ID / Face ID / Windows
Hello / hardware key), so the seed is protected by the Secure Enclave / TPM **even though the seed
itself is not inside it**.

```ts
const assertion = await navigator.credentials.get({
  publicKey: { challenge, allowCredentials: [cred],
    extensions: { prf: { eval: { first: utf8('prm/v1/vault') } } } }
})
const prf = assertion.getClientExtensionResults().prf.results.first  // 32B
const K_vault = hkdf(sha256, prf, salt, 'prm/v1/vault', 32)
```

**Why not sign directly with the passkey?** Because WebAuthn signatures are computed over
`authenticatorData || SHA-256(clientDataJSON)` — the authenticator will not sign arbitrary bytes you
choose. You cannot produce a detached signature over a policy document with it. Even where an
authenticator supports COSE alg `-8` (EdDSA), the signed payload is still the WebAuthn envelope. So:
**use the passkey to unlock the key, not to be the key.** This is the single most common design error
in this space and it is worth stating in code comments.

### Tier B — Passphrase-wrapped

Argon2id (m=64 MiB, t=3, p=1) over a user passphrase → `K_vault` → XChaCha20-Poly1305 over the seed.
Fallback when PRF is unavailable (older Safari, Firefox without a platform authenticator).

### Tier C — Ephemeral / session only

Seed held in memory for one session, mnemonic shown once and required for any future use. Useful for
kiosk or "try it" flows. Must be visibly labeled as such.

### Native (post-MVP)

On iOS/Android, generate a **non-extractable P-256 key in the Secure Enclave / StrongBox** and use it
to wrap the Ed25519 seed, or use it as a *second* signing key registered in the key event log. Note
the constraint: Secure Enclave supports P-256, not Ed25519. Two honest options:

1. **Wrap** the Ed25519 seed with an Enclave-held P-256 key (seed still transiently in app memory), or
2. Register a **P-256 device key** as an additional authorized signer in the key event log and let the
   policy carry an ES256 proof from that device.

Option 2 is stronger (seed never reconstructed on that device) and is why the key event log allows a
**set** of authorized keys with per-key algorithms rather than exactly one Ed25519 key. Ship option 1
in the first native release, option 2 at enterprise stage.

> **Decision — device key storage tiers.**
> *Why:* hardware backing where available, never a hard requirement. *Threat:* stolen device, malware
> reading IndexedDB. *MVP:* Tier A + B. *Standard:* WebAuthn L3 PRF extension, RFC 9106 Argon2.
> *Simpler alternative:* passphrase only — acceptable for prototype, weak against phishing/keyloggers.

## 5. The Key Event Log (KEL)

This is the mechanism that makes the account **self-certifying**. It is a small, per-user, hash-chained
log of key events, modeled on KERI and `did:plc` but deliberately reduced to the minimum.

```jsonc
{
  "type": "prm/KeyEvent/v1",
  "eventType": "genesis",          // genesis | rotation | recovery | revocation | delegation
  "sequence": 0,
  "previousEventHash": null,       // hash of prior event; null only for genesis
  "created": "2026-09-06T14:02:11Z",
  "keys": [                        // currently authorized signing keys
    { "id": "#k0", "alg": "Ed25519", "publicKeyMultibase": "z6Mkf...", "use": ["assertion"] }
  ],
  "nextKeyDigests": [ "u3Q9vX..." ],   // SHA-256 of the NEXT public key(s) — pre-rotation commitment
  "recoveryKeyDigests": [ "uH7bK..." ],
  "threshold": 1,
  "services": [ { "type": "PRMPublisher", "endpoint": "https://prm.app/u/ab12cd" } ],
  "proof": { /* Ed25519 signature by the current key(s) */ }
}
```

**Account identifier:**

```
accountId = "prm:" + base32-nopad-lower( SHA-256( JCS(genesisEvent) ) )[0..26]
          → e.g. prm:k4h2qz9m7bvxr3tn8w6ycpsjdf
```

Derived from content, so no registry mints it and PRM cannot reassign it.

**Interop aliases** (same key, different serialization — all resolvable to the same public key):

- `did:key:z6Mkf…` — for offline verification with existing DID tooling. Cannot express rotation.
- `did:web:prm.app:u:ab12cd` — for discovery. Its DID document is *derived from* the KEL and includes
  the KEL URL and current event hash. **A verifier that trusts `did:web` alone is trusting PRM's DNS
  and hosting; a verifier that walks the KEL is not.** Say this in the docs and make `@prm/verify`
  walk the KEL by default.

### 5.1 Pre-rotation: why it matters

Rotation event `n+1` is valid **only if** `SHA-256(newPublicKey)` equals a `nextKeyDigests` entry
committed in event `n`, *and* the event is signed by the key authorized in event `n`.

Consequence: an attacker who steals your current signing key **cannot take over your account**. They
can sign fraudulent policies until you rotate, but they cannot lock you out, because they lack the
pre-image of the next-key commitment. That converts a catastrophic compromise into a bounded,
time-limited one. This is the single highest-value property in the whole identity layer and it costs
about 40 lines of code.

> **Decision — KERI-style pre-rotation.**
> *Why:* bounds key theft. *Threat:* stolen key → permanent account takeover; malicious provider →
> silent key substitution. *MVP:* **yes** — it is cheap and retrofitting it later is a migration.
> *Standard:* KERI concept, implemented with plain Ed25519 + SHA-256 (no KERI stack dependency).
> *Simpler alternative:* `did:key` with no rotation at all — acceptable only for a throwaway prototype.

### 5.2 Equivocation detection

Every KEL event is also a leaf in the global transparency log (§07). Because a given `accountId` may
have only one event at each `sequence`, two conflicting events at the same sequence are visible proof
of misbehaviour by whoever published them. `@prm/verify` fetches the KEL, checks the chain, and checks
inclusion proofs against a signed tree head. Clients should cache the last-seen tree head and refuse to
silently accept a *smaller* one (a "split view" detector, same idea as CT gossip).

## 6. Key rotation

Routine rotation (recommended annually, or on device loss, or on suspicion):

1. Derive `K_{n+1}` from the master seed at index *n+1*; derive `K_{n+2}` for the new commitment.
2. Build rotation event: `sequence = n+1`, `previousEventHash`, new `keys`, new `nextKeyDigests`.
3. Sign with `K_n` **and** `K_{n+1}` (dual signature proves possession of the pre-committed key).
4. Publish to KEL, append to transparency log, timestamp.
5. Re-sign the **current** policy version with the new key and publish it as a new policy version whose
   only change is the proof. Older policy versions stay valid because verification is time-scoped
   (§05): a signature is valid if the signing key was authorized *at the time the event was logged*.

**Do not invalidate historical policies on rotation.** That would destroy the evidentiary value of
everything you signed before. Time-scoped validation is the correct semantic and must be in
`@prm/verify` from day one.

## 7. Backup and recovery

Layered, user-selectable. Present as a checklist with a completion state, not a wizard step you can skip.

| Method | Artifact | Recovers | Trust cost |
|---|---|---|---|
| **Mnemonic** (default) | 24-word BIP-39 phrase encoding the 32-byte seed | Everything | None (user's problem to store) |
| **Encrypted vault file** | `.prmvault` — Argon2id + XChaCha20-Poly1305 | Everything incl. history | None |
| **Passkey on a second device** | Additional PRF-wrapped copy | Everything | None |
| **Shamir social recovery** | 2-of-3 shares, each encrypted to a guardian's public key | `K_rec` only | Guardian collusion |
| **Provider-assisted handle recovery** | PRM re-points `/u/{handle}` after a valid recovery event | Handle/short URL only | PRM availability only |

### 7.1 What PRM must never do

PRM must not hold a Shamir share by default, must not hold an escrowed seed, and must not be able to
publish a valid recovery event. If PRM could, the "cannot impersonate" claim is false.

An **opt-in custodial share** may be offered later for users who explicitly accept the tradeoff, but it
must (a) be off by default, (b) be recorded as a `delegation` event in the KEL so it is *publicly
visible in the user's own key history*, and (c) still require a second share. A verifier can then see
that this account is partially custodial and weigh it accordingly. Making the trust downgrade
**visible and cryptographically legible** is the design requirement.

### 7.2 Recovery flow (seed lost, guardians available)

1. New device generates a fresh seed `S'` → `K'_sign`, `K'_next`.
2. Guardians decrypt and return shares → reconstruct `K_rec`.
3. Build `recovery` event: `sequence = n+1`, new keys, new commitments, signed by `K_rec`.
4. Verify `SHA-256(K_rec.pub)` matches a `recoveryKeyDigests` entry from an earlier event.
5. Publish, timestamp, notify. Verifiers see a legitimate recovery in the chain.

### 7.3 Compromise flow (key stolen, seed intact)

Rotate immediately (§6) and publish a `revocation` event listing the compromised key and an
`effectiveFrom` instant. `@prm/verify` then rejects signatures from that key that were **first logged
after** the revocation's log inclusion time, while preserving the validity of everything logged before.
This is exactly the X.509 CRL semantic and it is the right one.

If the **seed** is compromised, `K_next` is also compromised — pre-rotation gives no protection. The
only remedy is the recovery key (kept offline, derived from the seed only at genesis and then written
down/split). This is why the recovery key must be split *at onboarding*, not derived on demand.

> **Decision — layered recovery, no provider escrow.**
> *Why:* the core claim depends on it. *Threat:* account recovery abuse (§12), malicious insider.
> *MVP:* mnemonic + encrypted vault file. Shamir at beta. *Standard:* BIP-39, SLIP-39 (for native
> Shamir), RFC 9106. *Simpler alternative:* email-based reset — **prohibited**, it hands impersonation
> to whoever controls the mailbox and to PRM.

## 8. Anti-impersonation checklist

An implementation is only compliant if all of these are true. Put this in CI as an architectural test
where possible, and in the security review checklist otherwise.

- [ ] No API endpoint accepts an unsigned policy, authorization, or key event.
- [ ] No server code path can produce an Ed25519 signature over a user document.
- [ ] `K_sign`, `K_next`, `K_rec`, and the master seed never appear in a request body, log line, error
      report, or analytics event.
- [ ] The server rejects a KEL event whose pre-rotation commitment does not match.
- [ ] Verification succeeds with the PRM API fully unreachable, given a cached policy + KEL + tree head.
- [ ] The account identifier is recomputable from the genesis event by a third party.

## 9. Open issues

- **Multi-device without seed sharing.** Option 2 in §4 (per-device keys in the KEL) is the clean
  answer but adds threshold logic. MVP ships single-seed, multi-device-by-vault-import.
- **Handle squatting.** `/u/{handle}` is a PRM-assigned convenience name and is *not* identity. Make
  the UI show the `accountId` fingerprint next to the handle so users learn the distinction.
- **Post-quantum.** Ed25519 is not PQ-safe. The KEL's `keys` array is algorithm-tagged, so adding
  ML-DSA (FIPS 204) as a second authorized key later is a rotation, not a redesign. No action now.
