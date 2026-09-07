/**
 * TypeScript types for the four signed PRM document types.
 *
 * These mirror spec/schemas/*.json. The schemas are normative; if these types and the schemas ever
 * disagree, the schemas win and these types are the bug.
 */

/** Multibase 'u' + multihash(0x12,0x20,sha256) — e.g. "uEiBE9fuWQ…" */
export type Multihash = string
/** RFC 3339 UTC, second precision, 'Z'-suffixed. Fractional seconds are a canonicalization bug. */
export type UtcInstant = string
/** Self-certifying account id — "prm:" + 26 base32 chars derived from the genesis key event. */
export type AccountId = string

export type Decision = 'allow' | 'deny' | 'conditional'

/** The v1 core vocabulary. Extension categories are any other URI. */
export type CoreCategory =
  | 'prm:observation'
  | 'prm:transactional'
  | 'prm:retention'
  | 'prm:location-history'
  | 'prm:correlation'
  | 'prm:profiling'
  | 'prm:inference'
  | 'prm:third-party-sharing'
  | 'prm:sale'
  | 'prm:commercialization'
  | 'prm:advertising'
  | 'prm:ai-training'
  | 'prm:biometric'
  | 'prm:law-enforcement'
  | 'prm:emergency'
  | 'prm:deletion'

export type Category = CoreCategory | (string & {})

export type LegalBasis = 'statutory-override' | 'court-order' | 'vital-interest' | 'contract'

export interface RuleConditions {
  /** ISO 8601 duration. "PT0S" means no retention beyond the transaction. */
  maxRetention?: string
  purposes?: string[]
  /** "prm:none" denies all recipients. */
  recipients?: string[]
  jurisdictions?: string[]
  requiresLegalProcess?: boolean
  requiresNotice?: boolean
  note?: string
}

export interface Rule {
  category: Category
  decision: Decision
  /** Required when decision === 'conditional'. */
  conditions?: RuleConditions
  /** Bases the issuer concedes may lawfully override this rule. Stating them strengthens the rest. */
  basisAcknowledged?: LegalBasis[]
  note?: string
}

export interface DataIntegrityProof {
  type: 'DataIntegrityProof'
  cryptosuite: 'eddsa-jcs-2022'
  created: UtcInstant
  verificationMethod: string
  proofPurpose: 'assertionMethod'
  /** Multibase base58btc over the raw 64-byte Ed25519 signature. */
  proofValue: string
  previousProof?: string
}

export interface IdentifierCommitment {
  namespace: string
  /** SHA-256(namespace || 0x00 || normalized || 0x00 || salt). Openable only with the salt. */
  commitment: Multihash
  /** Low-entropy display hint. Increases correlation risk; off by default. */
  hint?: string
}

export interface PolicyIssuer {
  id: AccountId
  did: string
  keyEventLog?: string
  /** Digest of the KEL event that authorized the signing key. */
  keyEventHash: Multihash
  /** Optional, user-chosen, may be a pseudonym. Never required. */
  displayName?: string
}

export interface InlineException {
  organization: string
  organizationId?: string
  purposes: string[]
  categories: Category[]
  expires?: UtcInstant
  note?: string
}

export interface PolicyDistribution {
  canonicalUrl?: string
  machineUrl?: string
  shortUrl?: string
  statusList?: string
}

export interface Policy {
  '@context': string[]
  type: string[]
  /** Self-referential; excluded from the hashed bytes. */
  id?: string
  policyChainId: string
  version: number
  previousPolicyHash: Multihash | null
  supersedes?: Multihash
  issuer: PolicyIssuer
  effectiveDate: UtcInstant
  expirationDate?: UtcInstant
  jurisdictions: string[]
  rules: Rule[]
  exceptions?: InlineException[]
  /** Merkle root over currently valid private authorizations. Proves grants exist without naming them. */
  authorizationSetHash?: Multihash
  identifierCommitments?: IdentifierCommitment[]
  requests?: {
    deletionOnPurposeCompletion?: boolean
    doNotSellOrShare?: boolean
    globalPrivacyControl?: boolean
    accessRequestContact?: string
  }
  /** Carried INSIDE the signed bytes so prose and rules cannot drift. */
  humanReadable?: { mediaType: 'text/markdown' | 'text/plain'; language: string; text: string }
  legalNotice?: string
  distribution?: PolicyDistribution
  /** Excluded from the hashed bytes. */
  proof: DataIntegrityProof
  [k: string]: unknown
}

export interface AuthorizationGrantee {
  name: string
  id?: string
  did?: string
  domain?: string
  contact?: string
}

export interface DisclosedIdentifier {
  namespace: string
  value: string
  /** base64url; opens the matching identifierCommitment in the policy. */
  salt: string
}

export interface Authorization {
  '@context': string[]
  type: string[]
  id?: string
  policyChainId: string
  /** The EXACT policy version this grant modifies. A new version does not silently re-scope it. */
  boundPolicyHash: Multihash
  grantee: AuthorizationGrantee
  subjectRef?: {
    /** HKDF(S_bind, granteeId) — unlinkable across grantees. */
    pairwiseId?: string
    disclosedIdentifiers?: DisclosedIdentifier[]
  }
  purposes: string[]
  categories: Category[]
  dataCategories?: string[]
  issued: UtcInstant
  notBefore?: UtcInstant
  /** REQUIRED. Perpetual grants are not expressible by design. */
  expires: UtcInstant
  maxRetention?: string
  onwardSharing?: 'prohibited' | 'processors-only' | 'named-only'
  onwardRecipients?: string[]
  revocation?: {
    statusListCredential: string
    statusListIndex: number
    statusPurpose?: 'revocation'
  }
  receiptRequested?: boolean
  note?: string
  proof: DataIntegrityProof
}

export type KeyEventType = 'genesis' | 'rotation' | 'recovery' | 'revocation' | 'delegation'
export type KeyAlg = 'Ed25519' | 'ES256'

export interface AuthorizedKey {
  id: string
  alg: KeyAlg
  publicKeyMultibase: string
  use?: Array<'assertion' | 'authentication' | 'capability'>
  /** User-facing label only. No device fingerprinting. */
  device?: string
}

export interface KeyEvent {
  type: 'prm/KeyEvent/v1'
  eventType: KeyEventType
  sequence: number
  previousEventHash: Multihash | null
  created: UtcInstant
  keys: AuthorizedKey[]
  /** PRE-ROTATION COMMITMENT. A rotation is valid only if it reveals a key digested here. */
  nextKeyDigests: Multihash[]
  recoveryKeyDigests?: Multihash[]
  threshold: number
  revokedKeys?: Array<{
    publicKeyMultibase: string
    /** CRL semantics: signatures logged BEFORE this instant remain valid. */
    effectiveFrom: UtcInstant
    reason?: 'compromise' | 'superseded' | 'device-loss' | 'unspecified'
  }>
  services?: Array<{ type: string; endpoint: string }>
  /** A rotation carries TWO proofs: the outgoing key and the newly revealed pre-committed key. */
  proof: DataIntegrityProof[]
}

export type LedgerEntryType =
  | 'policy.published'
  | 'policy.superseded'
  | 'key.event'
  | 'authorization.granted'
  | 'authorization.revoked'
  | 'notice.sent'
  | 'notice.delivered'
  | 'request.deletion'
  | 'request.access'
  | 'acknowledgment.received'
  | 'dispute.raised'
  | 'dispute.resolved'

export interface LogInclusion {
  logId: string
  leafIndex: number
  treeSize: number
  rootHash: Multihash
  inclusionProof: Multihash[]
  signedTreeHead?: string
  /** base64 RFC 3161 TimeStampToken over rootHash. */
  timestampToken?: string
}

export interface LedgerEntry {
  type: 'prm/LedgerEntry/v1'
  accountId: AccountId
  sequence: number
  previousEntryHash: Multihash | null
  recorded: UtcInstant
  entryType: LedgerEntryType
  /** Digest of the object this entry concerns. The object itself is NOT embedded. */
  subjectHash: Multihash
  /** Local-only. The most correlating field in the system; never sync in plaintext. */
  counterparty?: {
    name?: string
    id?: string
    channel?: 'api' | 'email' | 'webform' | 'postal' | 'in-person' | 'qr' | 'nfc'
  }
  evidence?: Array<{
    kind: string
    digest: Multihash
    storedAt?: string
    note?: string
  }>
  /** Attached AFTER signing. Excluded from the digest — see spec/NORMATIVE.md §2. */
  logInclusion?: LogInclusion
  proof: DataIntegrityProof
}

export interface SignedTreeHead {
  logId: string
  treeSize: number
  rootHash: Multihash
  timestamp: UtcInstant
  previousRootHash?: Multihash
  /** Excluded from the hashed bytes. Domain "PRM-STH-v1". */
  signature: string
}

export type PrmDocument = Policy | Authorization | KeyEvent | LedgerEntry
