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

/**
 * Which log leaf a published policy's ledger entry became.
 *
 * The server never sees the ledger entry itself (docs/07 §1: the global log holds only opaque
 * hashes). What it records is the ENTRY DIGEST the client appended and the leaf it landed at, keyed
 * by policy digest, so the public policy page can point a reader at the inclusion proof and the
 * timestamp token. Both digests are already public; the link between them reveals only what the
 * page's publishedAt already does.
 */
export interface PolicyLogLink {
  policyDigest: string
  accountId: string
  entryDigest: string
  leafIndex: number
  linkedAt: string
}

export interface MetadataStore {
  publish (record: PolicyRecord): Promise<void>
  currentVersion (handle: string): Promise<PolicyRecord | null>
  version (handle: string, version: number): Promise<PolicyRecord | null>
  versions (handle: string): Promise<PolicyRecord[]>
  handleOwner (handle: string): Promise<string | null>
  recordLogLink (link: PolicyLogLink): Promise<void>
  logLink (policyDigest: string): Promise<PolicyLogLink | null>
}

// ---- transparency log --------------------------------------------------------

export interface LogLeaf {
  leafIndex: number
  /** Multihash of the RFC 6962 leaf hash. Opaque: SHA-256(0x00 || entryDigest). */
  leafHash: string
  appendedAt: string
}

export interface TreeHeadRecord {
  treeSize: number
  /** The signed tree head, as the EXACT JSON text that was signed and will be served. */
  sthJson: string
  createdAt: string
}

export interface TimestampRecord {
  treeSize: number
  /** Short operator label, e.g. "freetsa". Doubles as the file stem in a .prmproof. */
  tsa: string
  /** The TSA's full TimeStampResp, base64 — what `openssl ts -verify -in` reads. */
  tokenBase64: string
  /** genTime from the token, RFC 3339. */
  genTime: string
  acquiredAt: string
  /** The TSA's certificate chain, PEM, archived at acquisition (docs/08 §5). */
  chainPem?: string
}

/**
 * The global transparency log — docs/07 §3.
 *
 * Implementations must:
 *   - assign leaf indices contiguously from 0, in append order, under concurrency
 *   - treat append as IDEMPOTENT on leafHash: the same leaf appended twice is one leaf
 *   - never remove or reorder a leaf; a tree head, once stored, never changes
 */
export interface LogStore {
  append (leafHash: string, appendedAt: string): Promise<LogLeaf>
  /** Every leaf, ordered by index. The tree is small at this scale (docs/07 §6). */
  leaves (): Promise<LogLeaf[]>
  size (): Promise<number>
  putTreeHead (record: TreeHeadRecord): Promise<void>
  treeHead (treeSize: number): Promise<TreeHeadRecord | null>
  latestTreeHead (): Promise<TreeHeadRecord | null>
  putTimestamp (record: TimestampRecord): Promise<void>
  timestamps (treeSize: number): Promise<TimestampRecord[]>
  /** The most recently acquired token, whatever tree size it covers. */
  latestTimestamp (): Promise<TimestampRecord | null>
}

/** What the application uses. A pairing of the three, so adapters can mix and match. */
export interface Storage {
  readonly name: string
  readonly artifacts: ArtifactStore
  readonly metadata: MetadataStore
  readonly log: LogStore
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
