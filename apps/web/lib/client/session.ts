'use client'

import type { KeyEvent, Rule } from '@prm/schema'
import type { AccountKeys } from '@prm/crypto'
import {
  createPassphraseVault, openVaultWithPassphrase, type EncryptedVault
} from '@prm/vault'
import { deriveAccountKeys } from '@prm/crypto'

/**
 * Browser-side session state.
 *
 * WHAT LIVES WHERE, and why:
 *
 *   localStorage  the ENCRYPTED vault (ciphertext), the genesis key event (public), the handle,
 *                 and the working draft. All of this survives a reload; none of it is secret except
 *                 the vault, which is useless without the passphrase.
 *
 *   memory only   the unlocked master seed and derived keys. Cleared on reload, on lock, and on tab
 *                 close. Never written to storage, never serialized, never sent anywhere.
 *
 *   the server    nothing from this module. Not the draft, not the vault, not the seed.
 *
 * localStorage rather than IndexedDB: the vault is a few hundred bytes of ciphertext and the draft is
 * a few kilobytes of the user's own text. IndexedDB earns its complexity when the ledger and evidence
 * artifacts arrive in a later PR; it does not earn it here.
 */

const KEY = {
  vault: 'prm.vault.v1',
  genesis: 'prm.genesis.v1',
  handle: 'prm.handle.v1',
  draft: 'prm.draft.v1',
  published: 'prm.published.v1',
  notices: 'prm.notices.v1'
} as const

/** Unlocked material. Module-scoped so it cannot be reached from a serialized structure. */
let unlocked: { masterSeed: Uint8Array; keys: AccountKeys } | null = null

export function isUnlocked (): boolean {
  return unlocked !== null
}

export function requireKeys (): AccountKeys {
  if (!unlocked) throw new Error('The vault is locked. Unlock it before signing.')
  return unlocked.keys
}

export function unlockWithPassphrase (passphrase: string): AccountKeys {
  const vault = getVault()
  if (!vault) throw new Error('No vault on this device.')
  const contents = openVaultWithPassphrase(vault, passphrase)
  const keys = deriveAccountKeys(contents.masterSeed, 0)
  unlocked = { masterSeed: contents.masterSeed, keys }
  return keys
}

export function setUnlocked (masterSeed: Uint8Array): AccountKeys {
  const keys = deriveAccountKeys(masterSeed, 0)
  unlocked = { masterSeed, keys }
  return keys
}

export function lock (): void {
  unlocked?.masterSeed.fill(0)
  unlocked = null
}

// ---- persisted, non-secret (plus the encrypted vault) -----------------------

function read<T> (key: string): T | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = window.localStorage.getItem(key)
    return raw === null ? null : (JSON.parse(raw) as T)
  } catch {
    return null
  }
}

function write (key: string, value: unknown): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // A full or disabled localStorage must not take down signing. The user keeps their phrase.
  }
}

export const getVault = (): EncryptedVault | null => read<EncryptedVault>(KEY.vault)
export const getGenesis = (): KeyEvent | null => read<KeyEvent>(KEY.genesis)
export const getHandle = (): string | null => read<string>(KEY.handle)

export function saveAccount (opts: {
  vault: EncryptedVault
  genesis: KeyEvent
  handle?: string
}): void {
  write(KEY.vault, opts.vault)
  write(KEY.genesis, opts.genesis)
  if (opts.handle) write(KEY.handle, opts.handle)
}

export function saveHandle (handle: string): void {
  write(KEY.handle, handle)
}

export function sealAccount (
  masterSeed: Uint8Array,
  passphrase: string,
  accountId: string
): EncryptedVault {
  return createPassphraseVault(
    { masterSeed, accountId, createdAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') },
    passphrase,
    { label: 'this device' }
  )
}

export function hasAccount (): boolean {
  return getVault() !== null && getGenesis() !== null
}

// ---- working draft ----------------------------------------------------------

export interface PolicyDraftState {
  rules: Rule[]
  narrative: string
  jurisdictions: string[]
  effectiveDate: string
  plate?: string
  displayName?: string
}

export const getDraft = (): PolicyDraftState | null => read<PolicyDraftState>(KEY.draft)
export const saveDraft = (draft: PolicyDraftState): void => write(KEY.draft, draft)

export interface NoticeState {
  noticeDigest: string
  recipientName: string
  issued: string
  manifestDigest: string
  /** Signed artifacts, kept as EXACT strings so nothing is re-serialized on the way to a download. */
  noticeJson: string
  bundleJson: string
  deliveryJson?: string
  responseJson?: string
}

export interface PublishedState {
  handle: string
  digest: string
  version: number
  policyUrl: string
  canonicalUrl: string
  publishedAt: string
}

export const getPublished = (): PublishedState | null => read<PublishedState>(KEY.published)
export const savePublished = (state: PublishedState): void => write(KEY.published, state)

export const getNotices = (): NoticeState[] => read<NoticeState[]>(KEY.notices) ?? []

export function saveNotice (notice: NoticeState): void {
  const existing = getNotices().filter((n) => n.noticeDigest !== notice.noticeDigest)
  write(KEY.notices, [...existing, notice])
}

/** Wipe everything this device holds. Irreversible without the backup phrase. */
export function forgetEverything (): void {
  lock()
  if (typeof window === 'undefined') return
  for (const k of Object.values(KEY)) window.localStorage.removeItem(k)
}
