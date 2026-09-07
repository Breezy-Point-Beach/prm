import { describe, expect, it } from 'vitest'
import {
  generateBackupPhrase, seedFromPhrase, phraseFromSeed, isValidPhrase, normalizePhrase,
  backupChallengePositions, checkBackupChallenge, MnemonicError, MNEMONIC_WORDS,
  createPassphraseVault, openVaultWithPassphrase, openVault, sealVault, rekeyVault,
  deriveVaultKeyFromPassphrase, deriveVaultKeyFromPrf, assertNoSecrets,
  VaultError, WrongPassphraseError,
  createAccount, restoreAccount, rotateKeys, recoverAccount, seedControlsAccount, currentKeyIndex
} from '../src/index.js'
import { verifyKeyEventLog } from '@prm/verify'
import { deriveAccountKeys, deriveRecoveryKey, digest } from '@prm/crypto'

// Fast Argon2 params for tests only. Production uses 64 MiB, which is ~1s per unlock.
const FAST = { m: 512, t: 1, p: 1 }
const NOW = new Date('2026-09-15T12:00:00Z')

describe('backup phrase', () => {
  it('generates 24 words that round-trip to the same seed', () => {
    const phrase = generateBackupPhrase()
    expect(phrase.split(' ')).toHaveLength(MNEMONIC_WORDS)
    const seed = seedFromPhrase(phrase)
    expect(seed).toHaveLength(32)
    expect(phraseFromSeed(seed)).toBe(phrase)
  })

  it('generates a different phrase each time', () => {
    const phrases = new Set(Array.from({ length: 20 }, () => generateBackupPhrase()))
    expect(phrases.size).toBe(20)
  })

  it('accepts messy user input', () => {
    const phrase = generateBackupPhrase()
    const messy = `  ${phrase.toUpperCase().replace(/ /g, '\n  ')}  `
    expect(seedFromPhrase(messy)).toEqual(seedFromPhrase(phrase))
    expect(normalizePhrase(messy)).toBe(phrase)
  })

  it('gives a specific error for the wrong word count', () => {
    expect(() => seedFromPhrase('abandon abandon abandon')).toThrow(/expected 24 words, got 3/)
  })

  it('names the words that are not in the word list', () => {
    const words = generateBackupPhrase().split(' ')
    words[5] = 'notaword'
    expect(() => seedFromPhrase(words.join(' '))).toThrow(/not in the BIP-39 word list: notaword/)
  })

  it('explains a checksum failure in terms a user can act on', () => {
    const words = generateBackupPhrase().split(' ')
    const tmp = words[3] as string
    words[3] = words[4] as string
    words[4] = tmp
    // A swap usually breaks the checksum; if it happens not to, the phrase is genuinely valid.
    if (!isValidPhrase(words.join(' '))) {
      expect(() => seedFromPhrase(words.join(' '))).toThrow(/checksum failed[\s\S]*Check the order/)
    }
  })

  it('rejects a seed that is not 32 bytes', () => {
    expect(() => phraseFromSeed(new Uint8Array(16))).toThrow(MnemonicError)
  })
})

describe('backup challenge blocks a careless first publish', () => {
  it('asks for distinct, in-range positions', () => {
    for (let i = 0; i < 50; i++) {
      const p = backupChallengePositions(3)
      expect(new Set(p).size).toBe(3)
      expect(Math.min(...p)).toBeGreaterThanOrEqual(1)
      expect(Math.max(...p)).toBeLessThanOrEqual(MNEMONIC_WORDS)
      expect([...p]).toEqual([...p].sort((a, b) => a - b))
    }
  })

  it('does not always ask the same positions', () => {
    const seen = new Set(Array.from({ length: 40 }, () => backupChallengePositions(3).join(',')))
    expect(seen.size).toBeGreaterThan(10)
  })

  it('accepts correct answers and names the wrong ones', () => {
    const phrase = generateBackupPhrase()
    const words = phrase.split(' ')
    const positions = backupChallengePositions(3)
    const right = positions.map((p) => ({ position: p, word: words[p - 1] as string }))
    expect(checkBackupChallenge(phrase, right)).toEqual({ ok: true, wrong: [] })

    const wrongOne = [...right]
    wrongOne[1] = { position: positions[1] as number, word: 'zebra' }
    const result = checkBackupChallenge(phrase, wrongOne)
    expect(result.ok).toBe(false)
    expect(result.wrong).toEqual([positions[1]])
  })

  it('is case- and whitespace-insensitive about the answer', () => {
    const phrase = generateBackupPhrase()
    const words = phrase.split(' ')
    expect(checkBackupChallenge(phrase, [{ position: 1, word: `  ${(words[0] as string).toUpperCase()} ` }]).ok)
      .toBe(true)
  })
})

describe('encrypted vault', () => {
  const contents = () => ({
    masterSeed: seedFromPhrase(generateBackupPhrase()),
    accountId: 'prm:aaaaaaaaaaaaaaaaaaaaaaaaaa',
    createdAt: '2026-09-15T12:00:00Z'
  })

  it('seals and opens with a passphrase', () => {
    const c = contents()
    const v = createPassphraseVault(c, 'correct horse battery staple', { argon2: FAST, now: NOW })
    const opened = openVaultWithPassphrase(v, 'correct horse battery staple')
    expect(opened.masterSeed).toEqual(c.masterSeed)
    expect(opened.accountId).toBe(c.accountId)
  })

  it('REJECTS the wrong passphrase', () => {
    const v = createPassphraseVault(contents(), 'right', { argon2: FAST, now: NOW })
    expect(() => openVaultWithPassphrase(v, 'wrong')).toThrow(WrongPassphraseError)
  })

  it('DETECTS tampering with the ciphertext', () => {
    const v = createPassphraseVault(contents(), 'pw', { argon2: FAST, now: NOW })
    const flipped = v.ciphertext.slice(0, -4) + (v.ciphertext.endsWith('A') ? 'BBBB' : 'AAAA')
    expect(() => openVaultWithPassphrase({ ...v, ciphertext: flipped }, 'pw')).toThrow(VaultError)
  })

  it('DETECTS a swapped nonce', () => {
    const a = createPassphraseVault(contents(), 'pw', { argon2: FAST, now: NOW })
    const b = createPassphraseVault(contents(), 'pw', { argon2: FAST, now: NOW })
    expect(() => openVaultWithPassphrase({ ...a, nonce: b.nonce }, 'pw')).toThrow(VaultError)
  })

  it('NEVER puts the seed in the serialized vault', () => {
    const c = contents()
    const v = createPassphraseVault(c, 'pw', { argon2: FAST, now: NOW })
    const serialized = JSON.stringify(v)
    const seedHex = Buffer.from(c.masterSeed).toString('hex')
    const seedB64 = Buffer.from(c.masterSeed).toString('base64url')
    expect(serialized).not.toContain(seedHex)
    expect(serialized).not.toContain(seedB64)
    expect(serialized).not.toMatch(/masterSeed/)
  })

  it('records KDF parameters so an old vault still opens after defaults change', () => {
    const v = createPassphraseVault(contents(), 'pw', { argon2: FAST, now: NOW })
    expect(v.argon2).toEqual(FAST)
    // Opening uses the vault's own recorded parameters, not today's defaults.
    expect(() => openVaultWithPassphrase(v, 'pw')).not.toThrow()
  })

  it('uses a fresh nonce and salt for every seal', () => {
    const c = contents()
    const a = createPassphraseVault(c, 'pw', { argon2: FAST, now: NOW })
    const b = createPassphraseVault(c, 'pw', { argon2: FAST, now: NOW })
    expect(a.nonce).not.toBe(b.nonce)
    expect(a.salt).not.toBe(b.salt)
    expect(a.ciphertext).not.toBe(b.ciphertext)
  })

  it('derives a PRF vault key without a slow KDF', () => {
    const prf = new Uint8Array(32).fill(7)
    const salt = new Uint8Array(16).fill(3)
    const key = deriveVaultKeyFromPrf(prf, salt)
    expect(key).toHaveLength(32)
    expect(deriveVaultKeyFromPrf(prf, salt)).toEqual(key)
    expect(deriveVaultKeyFromPrf(new Uint8Array(32).fill(8), salt)).not.toEqual(key)
  })

  it('seals and opens a PRF vault', () => {
    const c = contents()
    const key = deriveVaultKeyFromPrf(new Uint8Array(32).fill(9), new Uint8Array(16))
    const v = sealVault({
      contents: c, key, kdf: 'webauthn-prf',
      salt: new Uint8Array(16), credentialId: new Uint8Array([1, 2, 3]), now: NOW
    })
    expect(v.kdf).toBe('webauthn-prf')
    expect(openVault(v, key).masterSeed).toEqual(c.masterSeed)
  })

  it('refuses a passphrase against a PRF vault, with a useful message', () => {
    const key = deriveVaultKeyFromPrf(new Uint8Array(32).fill(9), new Uint8Array(16))
    const v = sealVault({ contents: contents(), key, kdf: 'webauthn-prf', salt: new Uint8Array(16), now: NOW })
    expect(() => openVaultWithPassphrase(v, 'pw')).toThrow(/unlocked with webauthn-prf, not a passphrase/)
  })

  it('rekeys to a new passphrase, preserving contents and creation date', () => {
    const c = contents()
    const v = createPassphraseVault(c, 'old', { argon2: FAST, now: NOW })
    const key = deriveVaultKeyFromPassphrase('old', Buffer.from(v.salt as string, 'base64url'), FAST)
    const newSalt = new Uint8Array(16).fill(5)
    const newKey = deriveVaultKeyFromPassphrase('new', newSalt, FAST)
    const rekeyed = rekeyVault(v, key, { key: newKey, kdf: 'argon2id', salt: newSalt, argon2: FAST })
    expect(openVault(rekeyed, newKey).masterSeed).toEqual(c.masterSeed)
    expect(rekeyed.createdAt).toBe(v.createdAt)
  })

  it('rejects an empty passphrase and a wrong-sized key', () => {
    expect(() => deriveVaultKeyFromPassphrase('', new Uint8Array(16), FAST)).toThrow(VaultError)
    expect(() => sealVault({ contents: contents(), key: new Uint8Array(16), kdf: 'argon2id' }))
      .toThrow(/must be 32 bytes/)
  })
})

describe('assertNoSecrets guards the boundary', () => {
  it('throws on any shape containing secret-looking fields', () => {
    expect(() => assertNoSecrets({ masterSeed: 'x' })).toThrow(/masterSeed/)
    expect(() => assertNoSecrets({ a: { b: { privateKey: 'x' } } })).toThrow(/privateKey/)
    expect(() => assertNoSecrets({ items: [{ mnemonic: 'x' }] })).toThrow(/mnemonic/)
    expect(() => assertNoSecrets({ master_seed: 'x' })).toThrow(/master_seed/)
    expect(() => assertNoSecrets({ 'binding-secret': 'x' })).toThrow(/binding-secret/)
  })

  it('allows a legitimate published document', () => {
    expect(() => assertNoSecrets({
      policy: { issuer: { id: 'prm:x', did: 'did:key:z' }, proof: { proofValue: 'z...' } }
    })).not.toThrow()
  })

  it('survives circular references', () => {
    const a: Record<string, unknown> = { x: 1 }
    a.self = a
    expect(() => assertNoSecrets(a)).not.toThrow()
  })
})

describe('account lifecycle', () => {
  it('creates an account whose genesis event verifies', () => {
    const acct = createAccount({ now: NOW, deviceLabel: 'laptop' })
    const r = verifyKeyEventLog([acct.genesis])
    expect(r.errors).toEqual([])
    expect(r.accountId).toBe(acct.accountId)
    expect(acct.accountId).toMatch(/^prm:[a-z2-7]{26}$/)
  })

  it('commits to BOTH the next key and the recovery key at genesis', () => {
    // Neither commitment can be added later, so an account without them can never rotate safely
    // or be recovered. This is why recovery is not opt-in.
    const acct = createAccount({ now: NOW })
    const keys = deriveAccountKeys(acct.masterSeed)
    expect(acct.genesis.nextKeyDigests).toEqual([keys.next.publicKeyDigest])
    expect(acct.genesis.recoveryKeyDigests).toEqual([keys.recovery.publicKeyDigest])
  })

  it('ACCEPTANCE: restoring from the phrase reproduces the same account id', () => {
    const acct = createAccount({ now: NOW, deviceLabel: 'laptop' })
    const restored = restoreAccount(acct.backupPhrase, { now: NOW, deviceLabel: 'laptop' })
    expect(restored.accountId).toBe(acct.accountId)
    expect(restored.masterSeed).toEqual(acct.masterSeed)
    expect(digest(restored.genesis, 'keyEvent')).toBe(digest(acct.genesis, 'keyEvent'))
  })

  it('restoring on a different device label still yields the same seed and keys', () => {
    // The genesis digest changes with the label (it is inside the signed bytes), so a restoring
    // client must reuse the published genesis rather than rebuild it. The KEYS are what the phrase
    // restores, and those are label-independent.
    const acct = createAccount({ now: NOW, deviceLabel: 'laptop' })
    const restored = restoreAccount(acct.backupPhrase, { now: NOW, deviceLabel: 'phone' })
    expect(restored.masterSeed).toEqual(acct.masterSeed)
    expect(restored.keys.signing.publicKeyMultibase).toBe(acct.keys.signing.publicKeyMultibase)
    expect(seedControlsAccount([acct.genesis], restored.masterSeed)).toBe(true)
  })

  it('rotates to the pre-committed key, and the log verifies', () => {
    const acct = createAccount({ now: NOW })
    const rotation = rotateKeys({ masterSeed: acct.masterSeed, events: [acct.genesis], now: NOW })
    const r = verifyKeyEventLog([acct.genesis, rotation])
    expect(r.errors).toEqual([])
    expect(rotation.proof).toHaveLength(2)
    expect(currentKeyIndex([acct.genesis, rotation], acct.masterSeed)).toBe(1)
  })

  it('rotates twice, and the whole chain still verifies', () => {
    const acct = createAccount({ now: NOW })
    const r1 = rotateKeys({ masterSeed: acct.masterSeed, events: [acct.genesis], now: NOW })
    const r2 = rotateKeys({ masterSeed: acct.masterSeed, events: [acct.genesis, r1], now: NOW })
    expect(verifyKeyEventLog([acct.genesis, r1, r2]).errors).toEqual([])
    expect(currentKeyIndex([acct.genesis, r1, r2], acct.masterSeed)).toBe(2)
  })

  it('records a revocation when rotating after a compromise', () => {
    const acct = createAccount({ now: NOW })
    const rotation = rotateKeys({
      masterSeed: acct.masterSeed, events: [acct.genesis], now: NOW,
      revokeFrom: '2026-09-15T12:00:00Z', revokeReason: 'compromise'
    })
    expect(rotation.revokedKeys?.[0]?.publicKeyMultibase).toBe(acct.keys.signing.publicKeyMultibase)
    expect(verifyKeyEventLog([acct.genesis, rotation]).valid).toBe(true)
  })

  it('REFUSES to build a rotation from a seed that does not match the log', () => {
    // Fail loudly here rather than publish an invalid rotation and discover it when the account is
    // already unusable.
    const acct = createAccount({ now: NOW })
    const stranger = createAccount({ now: NOW })
    expect(() => rotateKeys({ masterSeed: stranger.masterSeed, events: [acct.genesis], now: NOW }))
      .toThrow(/does not match the pre-rotation commitment/)
  })

  it('recovers with the pre-committed recovery key and a fresh seed', () => {
    const acct = createAccount({ now: NOW })
    const recoveryKey = deriveRecoveryKey(acct.masterSeed)
    const fresh = createAccount({ now: NOW })

    const event = recoverAccount({
      recoverySeed: recoveryKey.privateKey,
      newMasterSeed: fresh.masterSeed,
      events: [acct.genesis],
      now: NOW
    })
    const r = verifyKeyEventLog([acct.genesis, event])
    expect(r.errors).toEqual([])
    // Identity is preserved: the account id derives from genesis, which recovery does not touch.
    expect(r.accountId).toBe(acct.accountId)
    expect(seedControlsAccount([acct.genesis, event], fresh.masterSeed)).toBe(true)
    expect(seedControlsAccount([acct.genesis, event], acct.masterSeed)).toBe(false)
  })

  it('REJECTS recovery with a key that was never committed', () => {
    const acct = createAccount({ now: NOW })
    const impostor = createAccount({ now: NOW })
    expect(() => recoverAccount({
      recoverySeed: deriveRecoveryKey(impostor.masterSeed).privateKey,
      newMasterSeed: impostor.masterSeed,
      events: [acct.genesis],
      now: NOW
    })).toThrow(/never committed in the key event log/)
  })

  it('ACCEPTANCE: restore, then sign a properly chained next policy version', () => {
    // Acceptance criterion 7: recovery must reproduce the identity AND permit continued authorship.
    const acct = createAccount({ now: NOW })
    const restored = restoreAccount(acct.backupPhrase, { now: NOW })
    const rotation = rotateKeys({ masterSeed: restored.masterSeed, events: [acct.genesis], now: NOW })
    const log = [acct.genesis, rotation]
    expect(verifyKeyEventLog(log).accountId).toBe(acct.accountId)
    expect(currentKeyIndex(log, restored.masterSeed)).toBe(1)
  })
})

describe('the vault carries an account end to end', () => {
  it('create -> seal -> reopen -> rotate', () => {
    const acct = createAccount({ now: NOW, deviceLabel: 'laptop' })
    const vault = createPassphraseVault(
      { masterSeed: acct.masterSeed, accountId: acct.accountId, createdAt: '2026-09-15T12:00:00Z',
        data: { genesis: acct.genesis } },
      'a good long passphrase', { argon2: FAST, label: 'laptop', now: NOW }
    )

    // Round-trip through JSON, as it would be stored or backed up.
    const reopened = openVaultWithPassphrase(JSON.parse(JSON.stringify(vault)), 'a good long passphrase')
    expect(reopened.accountId).toBe(acct.accountId)

    const rotation = rotateKeys({ masterSeed: reopened.masterSeed, events: [acct.genesis], now: NOW })
    expect(verifyKeyEventLog([acct.genesis, rotation]).errors).toEqual([])
  })

  it('a vault file is safe to hand to a server', () => {
    const acct = createAccount({ now: NOW })
    const vault = createPassphraseVault(
      { masterSeed: acct.masterSeed, accountId: acct.accountId, createdAt: '2026-09-15T12:00:00Z' },
      'pw', { argon2: FAST, now: NOW })
    // Nothing secret-looking, and the seed is not recoverable from the serialized form.
    expect(() => assertNoSecrets(vault, 'vault blob')).not.toThrow()
    expect(JSON.stringify(vault)).not.toContain(Buffer.from(acct.masterSeed).toString('base64url'))
  })
})

describe('WebAuthn adapter fails loudly off-browser', () => {
  it('reports WebAuthn unavailable in Node rather than pretending', async () => {
    const { isWebAuthnAvailable, isPlatformAuthenticatorAvailable, detectVaultTier, registerPasskey } =
      await import('../src/webauthn.js')
    expect(isWebAuthnAvailable()).toBe(false)
    expect(await isPlatformAuthenticatorAvailable()).toBe(false)
    // Falls back to passphrase rather than leaving the caller without a vault.
    expect(await detectVaultTier()).toBe('passphrase')
    await expect(registerPasskey({ userLabel: 'x', userId: new Uint8Array(8) }))
      .rejects.toThrow(/must not/)
  })
})
