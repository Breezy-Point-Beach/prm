import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { argon2id } from '@noble/hashes/argon2'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { randomBytes } from '@noble/hashes/utils'
import { base64urlnopad } from '@scure/base'

/**
 * The encrypted vault — docs/01 §4.
 *
 * Holds the master seed and everything derived from it. Encrypted on the user's device with a key
 * that never leaves it, and stored as ciphertext only. The server may hold this blob; it can do
 * nothing with it.
 *
 * THE INVARIANT THIS FILE EXISTS TO ENFORCE:
 *   the plaintext seed is never serialized, never logged, never sent anywhere.
 *
 * Anything that would break it belongs in a different file, and probably in a different product.
 */

export const VAULT_VERSION = 1
export const VAULT_MEDIA_TYPE = 'application/prm-vault+json'

/** How the vault key was derived. Recorded so a vault can be opened years later. */
export type KdfKind = 'argon2id' | 'webauthn-prf'

/**
 * Argon2id parameters — RFC 9106.
 *
 * 64 MiB / t=3 / p=1 is the RFC's recommended second option, and is about as much as a phone browser
 * tolerates without the tab being killed. Parameters are STORED IN THE VAULT so they can be raised
 * for new vaults without orphaning old ones — a vault written today must still open in ten years.
 */
export interface Argon2Params {
  m: number
  t: number
  p: number
}

export const DEFAULT_ARGON2: Argon2Params = { m: 65536, t: 3, p: 1 }

export interface EncryptedVault {
  vault: number
  mediaType: typeof VAULT_MEDIA_TYPE
  kdf: KdfKind
  /** Present for argon2id. base64url. */
  salt?: string
  argon2?: Argon2Params
  /** WebAuthn credential id this vault is bound to, for prf vaults. base64url. */
  credentialId?: string
  /** 24-byte XChaCha20 nonce, base64url. */
  nonce: string
  /** XChaCha20-Poly1305 ciphertext with the AEAD tag appended, base64url. */
  ciphertext: string
  createdAt: string
  updatedAt: string
  /**
   * Non-secret account identifier, so a UI can show which account a vault file belongs to without
   * unlocking it. Derived from the genesis event, which is public.
   */
  accountId?: string
  /** Free-form label the user chose, e.g. "laptop". Never a device fingerprint. */
  label?: string
}

/** The decrypted contents. Handle only in memory; never persist or transmit. */
export interface VaultContents {
  masterSeed: Uint8Array
  accountId?: string
  createdAt: string
  /** Anything else the client wants sealed alongside the seed: ledger, drafts, salts. */
  data?: Record<string, unknown>
}

export class VaultError extends Error {}
export class WrongPassphraseError extends VaultError {
  constructor () {
    super('could not unlock the vault: wrong passphrase, or the file is damaged')
    this.name = 'WrongPassphraseError'
  }
}

const b64 = { enc: (b: Uint8Array) => base64urlnopad.encode(b), dec: (s: string) => base64urlnopad.decode(s) }
const enc = new TextEncoder()
const dec = new TextDecoder()

/** Derive a 32-byte vault key from a passphrase. Deliberately slow. */
export function deriveVaultKeyFromPassphrase (
  passphrase: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2
): Uint8Array {
  if (passphrase.length === 0) throw new VaultError('passphrase is empty')
  return argon2id(enc.encode(passphrase.normalize('NFKC')), salt, {
    m: params.m, t: params.t, p: params.p, dkLen: 32
  })
}

/**
 * Derive a vault key from a WebAuthn PRF output.
 *
 * The PRF result is already high-entropy, so this is HKDF rather than a slow KDF — stretching a
 * uniformly random 32 bytes buys nothing.
 *
 * Note on why the passkey UNLOCKS the key rather than BEING the key: WebAuthn signs over
 * `authenticatorData || SHA-256(clientDataJSON)`, never bytes you choose, so it cannot produce a
 * detached signature over a policy. Using it to wrap the seed gets the hardware protection without
 * pretending it can do something it cannot. This is the single most common design error in this
 * space; see docs/01 §4.
 */
export function deriveVaultKeyFromPrf (prfOutput: Uint8Array, salt: Uint8Array): Uint8Array {
  if (prfOutput.length < 32) throw new VaultError('PRF output is too short')
  return hkdf(sha256, prfOutput, salt, enc.encode('prm/v1/vault'), 32)
}

export interface CreateVaultOptions {
  contents: VaultContents
  key: Uint8Array
  kdf: KdfKind
  salt?: Uint8Array
  argon2?: Argon2Params
  credentialId?: Uint8Array
  label?: string
  now?: Date
}

export function sealVault (opts: CreateVaultOptions): EncryptedVault {
  const { contents, key, kdf } = opts
  if (key.length !== 32) throw new VaultError(`vault key must be 32 bytes, got ${key.length}`)
  if (contents.masterSeed.length !== 32) {
    throw new VaultError(`master seed must be 32 bytes, got ${contents.masterSeed.length}`)
  }

  const nonce = randomBytes(24)
  const plaintext = enc.encode(JSON.stringify({
    masterSeed: b64.enc(contents.masterSeed),
    accountId: contents.accountId,
    createdAt: contents.createdAt,
    data: contents.data
  }))
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext)
  plaintext.fill(0)

  const iso = (opts.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z')
  return {
    vault: VAULT_VERSION,
    mediaType: VAULT_MEDIA_TYPE,
    kdf,
    ...(opts.salt ? { salt: b64.enc(opts.salt) } : {}),
    ...(kdf === 'argon2id' ? { argon2: opts.argon2 ?? DEFAULT_ARGON2 } : {}),
    ...(opts.credentialId ? { credentialId: b64.enc(opts.credentialId) } : {}),
    nonce: b64.enc(nonce),
    ciphertext: b64.enc(ciphertext),
    createdAt: iso,
    updatedAt: iso,
    ...(contents.accountId ? { accountId: contents.accountId } : {}),
    ...(opts.label ? { label: opts.label } : {})
  }
}

export function openVault (vault: EncryptedVault, key: Uint8Array): VaultContents {
  if (vault.vault !== VAULT_VERSION) {
    throw new VaultError(`unsupported vault version ${vault.vault}`)
  }
  if (key.length !== 32) throw new VaultError(`vault key must be 32 bytes, got ${key.length}`)

  let plaintext: Uint8Array
  try {
    plaintext = xchacha20poly1305(key, b64.dec(vault.nonce)).decrypt(b64.dec(vault.ciphertext))
  } catch {
    // AEAD failure is indistinguishable between a wrong key and a tampered blob, and that is correct:
    // both mean "do not trust these bytes".
    throw new WrongPassphraseError()
  }

  let parsed: { masterSeed: string; accountId?: string; createdAt: string; data?: Record<string, unknown> }
  try {
    parsed = JSON.parse(dec.decode(plaintext))
  } catch {
    throw new VaultError('vault decrypted but its contents are not valid JSON')
  } finally {
    plaintext.fill(0)
  }

  const masterSeed = b64.dec(parsed.masterSeed)
  if (masterSeed.length !== 32) throw new VaultError('vault contains a malformed master seed')

  return {
    masterSeed,
    ...(parsed.accountId ? { accountId: parsed.accountId } : {}),
    createdAt: parsed.createdAt,
    ...(parsed.data ? { data: parsed.data } : {})
  }
}

/** Open with a passphrase, using the parameters recorded in the vault itself. */
export function openVaultWithPassphrase (vault: EncryptedVault, passphrase: string): VaultContents {
  if (vault.kdf !== 'argon2id') {
    throw new VaultError(`this vault is unlocked with ${vault.kdf}, not a passphrase`)
  }
  if (!vault.salt) throw new VaultError('vault is missing its KDF salt')
  const key = deriveVaultKeyFromPassphrase(passphrase, b64.dec(vault.salt), vault.argon2 ?? DEFAULT_ARGON2)
  try {
    return openVault(vault, key)
  } finally {
    key.fill(0)
  }
}

export function createPassphraseVault (
  contents: VaultContents,
  passphrase: string,
  opts: { argon2?: Argon2Params; label?: string; now?: Date } = {}
): EncryptedVault {
  const salt = randomBytes(16)
  const params = opts.argon2 ?? DEFAULT_ARGON2
  const key = deriveVaultKeyFromPassphrase(passphrase, salt, params)
  try {
    return sealVault({
      contents, key, kdf: 'argon2id', salt, argon2: params,
      ...(opts.label ? { label: opts.label } : {}),
      ...(opts.now ? { now: opts.now } : {})
    })
  } finally {
    key.fill(0)
  }
}

/** Re-seal existing contents under a new key — for changing a passphrase or adding a device. */
export function rekeyVault (
  vault: EncryptedVault,
  currentKey: Uint8Array,
  next: Omit<CreateVaultOptions, 'contents'>
): EncryptedVault {
  const contents = openVault(vault, currentKey)
  try {
    const resealed = sealVault({ ...next, contents })
    return { ...resealed, createdAt: vault.createdAt }
  } finally {
    contents.masterSeed.fill(0)
  }
}

/**
 * Assert a value is safe to send to a server or write to a log.
 *
 * Used at the boundaries. It is a backstop, not a substitute for not having the seed there in the
 * first place — but a cheap backstop on the one mistake that would end the project.
 */
export function assertNoSecrets (value: unknown, context = 'value'): void {
  const seen = new WeakSet<object>()
  const forbidden = ['masterseed', 'privatekey', 'seed', 'mnemonic', 'passphrase', 'bindingsecret', 'recoverykey']

  const walk = (v: unknown, path: string): void => {
    if (v === null || typeof v !== 'object') return
    if (seen.has(v as object)) return
    seen.add(v as object)
    if (Array.isArray(v)) {
      v.forEach((item, i) => walk(item, `${path}[${i}]`))
      return
    }
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (forbidden.includes(k.toLowerCase().replace(/[_-]/g, ''))) {
        throw new VaultError(
          `${context} contains a secret field "${k}" at ${path || '(root)'} — this must never leave the device`)
      }
      walk(val, path ? `${path}.${k}` : k)
    }
  }
  walk(value, '')
}
