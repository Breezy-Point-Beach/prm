import { deriveVaultKeyFromPrf } from './vault.js'

/**
 * WebAuthn PRF adapter — the Tier A vault unlock from docs/01 §4.
 *
 * The passkey UNLOCKS the seed; it does not replace it. WebAuthn signs over
 * `authenticatorData || SHA-256(clientDataJSON)`, never bytes the caller chooses, so it cannot
 * produce a detached signature over a policy document. Even an authenticator supporting COSE alg -8
 * (EdDSA) signs the WebAuthn envelope, not the policy. Using it to wrap the seed gets Secure Enclave /
 * TPM protection without pretending it can do something it cannot.
 *
 * Browser-only. Every function here degrades to a clear error in Node so a server bundle that
 * mistakenly imports it fails loudly rather than silently.
 */

export const PRF_INPUT = 'prm/v1/vault'

export class WebAuthnUnavailableError extends Error {}
export class PrfUnsupportedError extends Error {
  constructor () {
    super(
      'This device or browser did not return a PRF result. PRM will use a passphrase-protected vault ' +
      'instead, which is equally secure against a stolen file but relies on your passphrase strength.')
    this.name = 'PrfUnsupportedError'
  }
}

export function isWebAuthnAvailable (): boolean {
  return typeof globalThis !== 'undefined' &&
    typeof (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.create === 'function'
}

/** Is a platform authenticator (Touch ID, Windows Hello, Android biometrics) present? */
export async function isPlatformAuthenticatorAvailable (): Promise<boolean> {
  if (!isWebAuthnAvailable()) return false
  try {
    const PKC = (globalThis as unknown as {
      PublicKeyCredential: { isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean> }
    }).PublicKeyCredential
    return (await PKC.isUserVerifyingPlatformAuthenticatorAvailable?.()) ?? false
  } catch {
    return false
  }
}

function requireWebAuthn (): void {
  if (!isWebAuthnAvailable()) {
    throw new WebAuthnUnavailableError(
      'WebAuthn is not available here. In a browser this means the device has no platform ' +
      'authenticator; in Node it means this module was imported on the server, which it must not be.')
  }
}

const utf8 = (s: string) => new TextEncoder().encode(s)

export interface RegisterPasskeyOptions {
  /** Relying party id — the site domain. */
  rpId?: string
  rpName?: string
  /** Shown in the OS prompt. A handle or label, never an email or legal name. */
  userLabel: string
  /** Opaque, stable per account. The account id is a good choice: public and non-correlating. */
  userId: Uint8Array
}

export interface PasskeyRegistration {
  credentialId: Uint8Array
  /** True when the authenticator confirmed PRF support. */
  prfSupported: boolean
}

/**
 * Register a passkey for vault unlock.
 *
 * `residentKey: 'required'` so the credential is discoverable and the user does not have to remember
 * which account a device belongs to. `userVerification: 'required'` because the whole point is that
 * unlocking the seed needs biometrics or a PIN, not merely possession of the device.
 */
export async function registerPasskey (opts: RegisterPasskeyOptions): Promise<PasskeyRegistration> {
  requireWebAuthn()
  const challenge = crypto.getRandomValues(new Uint8Array(32))

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: opts.rpId, name: opts.rpName ?? 'PRM' },
      user: { id: opts.userId, name: opts.userLabel, displayName: opts.userLabel },
      // ES256 then EdDSA. Only used to create the credential; PRM never verifies these signatures.
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        userVerification: 'required'
      },
      timeout: 120_000,
      attestation: 'none',
      extensions: { prf: { eval: { first: utf8(PRF_INPUT) } } }
    } as PublicKeyCredentialCreationOptions
  }) as PublicKeyCredential | null

  if (!credential) throw new WebAuthnUnavailableError('passkey registration was cancelled')

  const ext = credential.getClientExtensionResults() as { prf?: { enabled?: boolean } }
  return {
    credentialId: new Uint8Array(credential.rawId),
    prfSupported: ext.prf?.enabled === true
  }
}

/**
 * Unlock: get the PRF output for an existing credential and derive the vault key.
 *
 * The returned key should be used immediately and then zeroed. Never persist it.
 */
export async function getVaultKeyFromPasskey (
  credentialId: Uint8Array,
  salt: Uint8Array,
  opts: { rpId?: string } = {}
): Promise<Uint8Array> {
  requireWebAuthn()
  const challenge = crypto.getRandomValues(new Uint8Array(32))

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: opts.rpId,
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      timeout: 120_000,
      extensions: { prf: { eval: { first: utf8(PRF_INPUT) } } }
    } as PublicKeyCredentialRequestOptions
  }) as PublicKeyCredential | null

  if (!assertion) throw new WebAuthnUnavailableError('unlock was cancelled')

  const ext = assertion.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer } }
  }
  const first = ext.prf?.results?.first
  if (!first) throw new PrfUnsupportedError()

  const prf = new Uint8Array(first)
  try {
    return deriveVaultKeyFromPrf(prf, salt)
  } finally {
    prf.fill(0)
  }
}

/**
 * Decide which vault tier this device can offer.
 *
 * The UI must tell the user which tier they are on. "Protected by Touch ID" and "protected by a
 * passphrase you must remember" are materially different promises, and users should know which one
 * they have.
 */
export async function detectVaultTier (): Promise<'passkey' | 'passphrase'> {
  return (await isPlatformAuthenticatorAvailable()) ? 'passkey' : 'passphrase'
}
