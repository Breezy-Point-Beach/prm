import { generateMnemonic, mnemonicToEntropy, entropyToMnemonic, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'

/**
 * Mnemonic backup — docs/01 §7.
 *
 * The 24-word phrase encodes the 32-byte master seed DIRECTLY (BIP-39 entropy, not the BIP-39 seed
 * derivation). Every PRM key derives from that seed via HKDF, so one phrase restores the account,
 * every rotation index, the recovery key, and every identifier salt.
 *
 * Deliberately NOT using BIP-39's PBKDF2 seed derivation. That function maps a mnemonic plus an
 * optional passphrase to a 64-byte seed, which is right for hierarchical wallets and wrong here: it
 * would make the phrase a *derivation input* rather than a *transcription of the secret*, so a user
 * could not verify by inspection that the phrase and the seed correspond. Round-tripping raw entropy
 * keeps the relationship exact and checkable.
 */

export class MnemonicError extends Error {}

/** 24 words = 256 bits of entropy = exactly one 32-byte master seed. */
export const MNEMONIC_WORDS = 24

export function generateBackupPhrase (): string {
  return generateMnemonic(wordlist, 256)
}

export function seedFromPhrase (phrase: string): Uint8Array {
  const normalized = normalizePhrase(phrase)
  if (!validateMnemonic(normalized, wordlist)) {
    const words = normalized.split(' ').filter(Boolean)
    if (words.length !== MNEMONIC_WORDS) {
      throw new MnemonicError(
        `expected ${MNEMONIC_WORDS} words, got ${words.length}`)
    }
    const unknown = words.filter((w) => !wordlist.includes(w))
    if (unknown.length > 0) {
      throw new MnemonicError(
        `not in the BIP-39 word list: ${unknown.slice(0, 3).join(', ')}${unknown.length > 3 ? '...' : ''}`)
    }
    // Right length, all real words, still invalid: the checksum failed, which almost always means
    // two words were swapped or one was mistyped into another valid word.
    throw new MnemonicError(
      'checksum failed — the words are all valid but the phrase is not. Check the order, and check ' +
      'for lookalike words (e.g. "quick" vs "quit").')
  }
  const entropy = mnemonicToEntropy(normalized, wordlist)
  if (entropy.length !== 32) {
    throw new MnemonicError(`expected 32 bytes of entropy, got ${entropy.length}`)
  }
  return entropy
}

export function phraseFromSeed (seed: Uint8Array): string {
  if (seed.length !== 32) throw new MnemonicError(`expected a 32-byte seed, got ${seed.length}`)
  return entropyToMnemonic(seed, wordlist)
}

/** Lower-case, collapse whitespace. Users paste from all sorts of places. */
export function normalizePhrase (phrase: string): string {
  return phrase.normalize('NFKD').toLowerCase().trim().replace(/\s+/g, ' ')
}

export function isValidPhrase (phrase: string): boolean {
  try {
    seedFromPhrase(phrase)
    return true
  } catch {
    return false
  }
}

/**
 * Pick word positions to challenge during the backup check.
 *
 * The first publish is blocked until the user proves they wrote the phrase down. Positions are chosen
 * with a CSPRNG rather than fixed, so a user cannot learn "it always asks for 3, 9, 17" and record
 * only those.
 */
export function backupChallengePositions (count = 3, total = MNEMONIC_WORDS): number[] {
  if (count > total) throw new MnemonicError('cannot challenge more positions than there are words')
  const chosen = new Set<number>()
  const rand = new Uint32Array(1)
  while (chosen.size < count) {
    crypto.getRandomValues(rand)
    // Rejection-sample to avoid modulo bias. It matters less here than in key generation, but
    // biased "random" positions in a security check are the kind of detail that gets cited later.
    const limit = Math.floor(0x100000000 / total) * total
    if ((rand[0] as number) >= limit) continue
    chosen.add(((rand[0] as number) % total) + 1)
  }
  return [...chosen].sort((a, b) => a - b)
}

/** Check a challenge response. Compares normalized words, never the whole phrase. */
export function checkBackupChallenge (
  phrase: string,
  answers: Array<{ position: number; word: string }>
): { ok: boolean; wrong: number[] } {
  const words = normalizePhrase(phrase).split(' ')
  const wrong: number[] = []
  for (const { position, word } of answers) {
    if (words[position - 1] !== normalizePhrase(word)) wrong.push(position)
  }
  return { ok: wrong.length === 0, wrong }
}
