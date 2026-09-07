/**
 * Storage contract.
 *
 * THE RULE:
 *   Storage may index metadata about an artifact, but the authoritative signed artifact itself is an
 *   immutable, opaque byte sequence. It is never parsed, never re-serialized, and never updated.
 *
 * TWO DIGESTS, AND THEY ARE NOT THE SAME. This distinction is the whole reason content addressing
 * works here, and getting it wrong would silently reopen the hole PR 5 closed:
 *
 *   policyDigest  SHA-256(PRM-JCS(policy minus id, proof)) — the PROTOCOL identity. Stable across
 *                 reserialization by design, because canonicalization erases formatting.
 *   byteDigest    SHA-256(the exact bytes)                 — the STORAGE identity. Changes if a
 *                 single space moves.
 *
 * Artifacts are addressed by byteDigest. Addressing them by policyDigest would give a reserialized
 * document the same storage key as the original, which is precisely the substitution the round-trip
 * check exists to catch.
 */

export type ArtifactKind = 'policy' | 'key-event-log'

export interface ArtifactRef {
  kind: ArtifactKind
  /** Multibase multihash of the raw bytes. The storage address. */
  byteDigest: string
  /** Backend-specific location, e.g. a blob pathname. Opaque to callers. */
  location: string
  byteLength: number
  contentType: string
}

/**
 * Content-addressed, WRITE-ONCE artifact storage.
 *
 * Implementations must:
 *   - reject a write whose bytes do not hash to the declared digest
 *   - reject a read whose returned bytes do not hash to the requested digest
 *   - never mutate an existing artifact; a new policy is a new object, and the old one remains
 */
export interface ArtifactStore {
  put (kind: ArtifactKind, bytes: Uint8Array, declaredByteDigest: string): Promise<ArtifactRef>
  get (byteDigest: string): Promise<Uint8Array>
  has (byteDigest: string): Promise<boolean>
}

/** Metadata about published artifacts. Indexable, queryable, and never authoritative. */
export interface PolicyRecord {
  handle: string
  accountId: string
  policyChainId: string
  version: number
  /** Protocol identity of the policy. */
  policyDigest: string
  /** Storage address of the policy bytes. */
  policyByteDigest: string
  policyLocation: string
  policyByteLength: number
  /** Storage address of the key event log bytes. */
  kelByteDigest: string
  kelLocation: string
  publishedAt: string
  contentType: string
}

export interface MetadataStore {
  publish (record: PolicyRecord): Promise<void>
  currentVersion (handle: string): Promise<PolicyRecord | null>
  version (handle: string, version: number): Promise<PolicyRecord | null>
  versions (handle: string): Promise<PolicyRecord[]>
  handleOwner (handle: string): Promise<string | null>
}

/** What the application uses. A pairing of the two, so adapters can mix and match. */
export interface Storage {
  readonly name: string
  readonly artifacts: ArtifactStore
  readonly metadata: MetadataStore
}

export class StorageError extends Error {}

export class DigestMismatchError extends StorageError {
  constructor (
    public readonly expected: string,
    public readonly actual: string,
    context: string
  ) {
    super(
      `${context}: content does not match its digest. Expected ${expected}, computed ${actual}. ` +
      'The storage backend returned different bytes than were written. Treat this artifact as corrupt.')
    this.name = 'DigestMismatchError'
  }
}

export class ImmutabilityError extends StorageError {
  constructor (byteDigest: string) {
    super(
      `Refusing to overwrite artifact ${byteDigest}. Artifacts are write-once: a new policy version ` +
      'is a new object, and previously published bytes remain available forever.')
    this.name = 'ImmutabilityError'
  }
}

export class ArtifactNotFoundError extends StorageError {
  constructor (byteDigest: string) {
    super(`No artifact stored at ${byteDigest}`)
    this.name = 'ArtifactNotFoundError'
  }
}
