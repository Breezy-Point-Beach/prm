import type { KeyEvent, UtcInstant } from '@prm/schema'
import {
  deriveAccountKeys, deriveAccountId, buildProof, digest, keyPairFromSeed,
  encodeMultihash, hash, decodePublicKey, type AccountKeys
} from '@prm/crypto'
import { generateMasterSeed } from '@prm/crypto'
import { generateBackupPhrase, seedFromPhrase, phraseFromSeed } from './mnemonic.js'

/**
 * Account creation, rotation, and recovery — docs/01 §5-§7.
 *
 * Everything here runs on the user's device. Nothing in this file may be given a network client.
 */

const iso = (d: Date): UtcInstant => d.toISOString().replace(/\.\d{3}Z$/, 'Z') as UtcInstant

export interface NewAccount {
  /** SHOW ONCE, then discard from memory. The user must write this down. */
  backupPhrase: string
  masterSeed: Uint8Array
  keys: AccountKeys
  genesis: KeyEvent
  accountId: string
}

export interface CreateAccountOptions {
  /** Restore an existing account instead of creating one. */
  phrase?: string
  deviceLabel?: string
  publisherEndpoint?: string
  now?: Date
  /** Injectable for tests only. */
  seed?: Uint8Array
}

/**
 * Create (or restore) an account and its genesis key event.
 *
 * The genesis event commits to BOTH the next signing key and the recovery key. Both commitments must
 * exist from the very first event: a commitment cannot be added retroactively, so an account created
 * without them can never rotate safely or be recovered. This is why recovery is not an opt-in extra.
 */
export function createAccount (opts: CreateAccountOptions = {}): NewAccount {
  const backupPhrase = opts.phrase ?? (opts.seed ? phraseFromSeed(opts.seed) : generateBackupPhrase())
  const masterSeed = opts.phrase ? seedFromPhrase(opts.phrase) : (opts.seed ?? seedFromPhrase(backupPhrase))
  const keys = deriveAccountKeys(masterSeed, 0)
  const created = iso(opts.now ?? new Date())

  const genesis: KeyEvent = {
    type: 'prm/KeyEvent/v1',
    eventType: 'genesis',
    sequence: 0,
    previousEventHash: null,
    created,
    keys: [{
      id: '#k0',
      alg: 'Ed25519',
      publicKeyMultibase: keys.signing.publicKeyMultibase,
      use: ['assertion', 'authentication'],
      ...(opts.deviceLabel ? { device: opts.deviceLabel } : {})
    }],
    nextKeyDigests: [keys.next.publicKeyDigest],
    recoveryKeyDigests: [keys.recovery.publicKeyDigest],
    threshold: 1,
    ...(opts.publisherEndpoint
      ? { services: [{ type: 'PRMPublisher', endpoint: opts.publisherEndpoint }] }
      : {}),
    proof: []
  }
  genesis.proof = [buildProof(genesis, {
    privateKey: keys.signing.privateKey,
    publicKey: keys.signing.publicKey,
    kind: 'keyEvent',
    created
  })]

  return { backupPhrase, masterSeed, keys, genesis, accountId: deriveAccountId(genesis) }
}

/** Restore from a backup phrase. Must reproduce the identical account id. */
export function restoreAccount (phrase: string, opts: Omit<CreateAccountOptions, 'phrase'> = {}): NewAccount {
  return createAccount({ ...opts, phrase })
}

export interface RotateOptions {
  masterSeed: Uint8Array
  /** The full key event log so far, oldest first. */
  events: KeyEvent[]
  deviceLabel?: string
  now?: Date
  /** Mark the outgoing key compromised from this instant. Omit for a routine rotation. */
  revokeFrom?: UtcInstant
  revokeReason?: 'compromise' | 'superseded' | 'device-loss' | 'unspecified'
}

/**
 * Rotate to the pre-committed next key.
 *
 * Signed TWICE: once by the outgoing key (proving continuity of control) and once by the newly
 * revealed key (proving possession of the pre-image the previous event committed to). A thief holding
 * only the current key can produce the first signature but not a key matching the commitment, which
 * is what bounds key theft to a window instead of a takeover.
 */
export function rotateKeys (opts: RotateOptions): KeyEvent {
  const { masterSeed, events } = opts
  if (events.length === 0) throw new Error('cannot rotate without a genesis event')

  const sorted = [...events].sort((a, b) => a.sequence - b.sequence)
  const previous = sorted[sorted.length - 1] as KeyEvent
  const nextIndex = countRotations(sorted) + 1

  const current = deriveAccountKeys(masterSeed, nextIndex - 1)
  const incoming = deriveAccountKeys(masterSeed, nextIndex)

  // Refuse to build an event the verifier would reject. Failing here, with a clear message, beats
  // publishing an invalid rotation and discovering it when the account is already unusable.
  if (!previous.nextKeyDigests.includes(incoming.signing.publicKeyDigest)) {
    throw new Error(
      'the derived next key does not match the pre-rotation commitment in the previous event. ' +
      'The master seed does not correspond to this key event log.')
  }

  const created = iso(opts.now ?? new Date())
  const event: KeyEvent = {
    type: 'prm/KeyEvent/v1',
    eventType: 'rotation',
    sequence: previous.sequence + 1,
    previousEventHash: digest(previous, 'keyEvent'),
    created,
    keys: [{
      id: `#k${nextIndex}`,
      alg: 'Ed25519',
      publicKeyMultibase: incoming.signing.publicKeyMultibase,
      use: ['assertion', 'authentication'],
      ...(opts.deviceLabel ? { device: opts.deviceLabel } : {})
    }],
    nextKeyDigests: [incoming.next.publicKeyDigest],
    recoveryKeyDigests: previous.recoveryKeyDigests ?? [incoming.recovery.publicKeyDigest],
    threshold: 1,
    ...(opts.revokeFrom
      ? {
          revokedKeys: [{
            publicKeyMultibase: current.signing.publicKeyMultibase,
            effectiveFrom: opts.revokeFrom,
            reason: opts.revokeReason ?? 'compromise'
          }]
        }
      : {}),
    ...(previous.services ? { services: previous.services } : {}),
    proof: []
  }

  event.proof = [
    buildProof(event, {
      privateKey: current.signing.privateKey, publicKey: current.signing.publicKey,
      kind: 'keyEvent', created
    }),
    buildProof(event, {
      privateKey: incoming.signing.privateKey, publicKey: incoming.signing.publicKey,
      kind: 'keyEvent', created
    })
  ]
  return event
}

export interface RecoverOptions {
  /** Reconstructed recovery key seed — from an offline backup or Shamir shares. */
  recoverySeed: Uint8Array
  /** A fresh master seed for the account going forward. */
  newMasterSeed: Uint8Array
  events: KeyEvent[]
  deviceLabel?: string
  now?: Date
}

/**
 * Recover an account when the master seed is lost or compromised.
 *
 * Signed by the pre-committed recovery key, which is why that key must be split or stored offline AT
 * ONBOARDING: if the master seed leaks, the pre-rotation key leaks with it, and this is the only
 * remaining path. PRM cannot perform this operation — it holds no share and no escrow — which is
 * exactly what makes the impersonation claim true.
 */
export function recoverAccount (opts: RecoverOptions): KeyEvent {
  const { recoverySeed, newMasterSeed, events } = opts
  const sorted = [...events].sort((a, b) => a.sequence - b.sequence)
  const previous = sorted[sorted.length - 1]
  if (!previous) throw new Error('cannot recover without an existing key event log')

  const recoveryKey = keyPairFromSeed(recoverySeed)
  const committed = new Set(previous.recoveryKeyDigests ?? [])
  if (!committed.has(recoveryKey.publicKeyDigest)) {
    throw new Error(
      'this recovery key was never committed in the key event log. Recovery is only possible with ' +
      'the key whose digest was published at account creation.')
  }

  const fresh = deriveAccountKeys(newMasterSeed, 0)
  const created = iso(opts.now ?? new Date())

  const event: KeyEvent = {
    type: 'prm/KeyEvent/v1',
    eventType: 'recovery',
    sequence: previous.sequence + 1,
    previousEventHash: digest(previous, 'keyEvent'),
    created,
    keys: [{
      id: `#r${previous.sequence + 1}`,
      alg: 'Ed25519',
      publicKeyMultibase: fresh.signing.publicKeyMultibase,
      use: ['assertion', 'authentication'],
      ...(opts.deviceLabel ? { device: opts.deviceLabel } : {})
    }],
    nextKeyDigests: [fresh.next.publicKeyDigest],
    recoveryKeyDigests: [fresh.recovery.publicKeyDigest],
    threshold: 1,
    ...(previous.services ? { services: previous.services } : {}),
    proof: []
  }

  event.proof = [
    buildProof(event, {
      privateKey: recoveryKey.privateKey, publicKey: recoveryKey.publicKey,
      kind: 'keyEvent', created
    }),
    buildProof(event, {
      privateKey: fresh.signing.privateKey, publicKey: fresh.signing.publicKey,
      kind: 'keyEvent', created
    })
  ]
  return event
}

/** How many rotations have happened, i.e. the current signing key's derivation index. */
export function countRotations (events: KeyEvent[]): number {
  return events.filter((e) => e.eventType === 'rotation').length
}

/**
 * Work out which derivation index a log's current key corresponds to.
 *
 * A recovery resets the master seed, so indices restart. Callers holding a seed from before a
 * recovery cannot sign for the account, and this returns null to say so rather than guessing.
 */
export function currentKeyIndex (events: KeyEvent[], masterSeed: Uint8Array): number | null {
  const sorted = [...events].sort((a, b) => a.sequence - b.sequence)
  const head = sorted[sorted.length - 1]
  if (!head) return null
  const authorized = new Set(head.keys.map((k) => k.publicKeyMultibase))
  for (let i = 0; i <= sorted.length; i++) {
    if (authorized.has(deriveAccountKeys(masterSeed, i).signing.publicKeyMultibase)) return i
  }
  return null
}

/** Does this seed control the account as of the log head? */
export function seedControlsAccount (events: KeyEvent[], masterSeed: Uint8Array): boolean {
  return currentKeyIndex(events, masterSeed) !== null
}

export { generateMasterSeed, deriveAccountId, encodeMultihash, hash, decodePublicKey }
