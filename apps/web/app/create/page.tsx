'use client'

import { useRouter } from 'next/navigation'
import { useMemo, useState } from 'react'
import {
  createAccount, backupChallengePositions, checkBackupChallenge, type NewAccount
} from '@prm/vault'
import { verifyKeyEventLog } from '@prm/verify'
import { sealAccount, saveAccount, setUnlocked, hasAccount } from '../../lib/client/session'
import { Steps } from '../../components/Steps'

/**
 * Create — key generation, backup, and vault.
 *
 * The whole screen runs in the browser. The seed is generated here, shown once, and sealed here.
 * Nothing on this page contacts the server, because there is nothing on this page the server may
 * legitimately see.
 *
 * The backup challenge is BLOCKING by design. The dominant failure mode of a system with no provider
 * recovery is not key theft, it is a user who skipped writing the phrase down and lost their account.
 */
type Stage = 'intro' | 'phrase' | 'challenge' | 'passphrase' | 'done'

export default function CreatePage () {
  const router = useRouter()
  const [stage, setStage] = useState<Stage>(hasAccount() ? 'done' : 'intro')
  const [account, setAccount] = useState<NewAccount | null>(null)
  const [positions, setPositions] = useState<number[]>([])
  const [answers, setAnswers] = useState<Record<number, string>>({})
  const [wrong, setWrong] = useState<number[]>([])
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const words = useMemo(() => account?.backupPhrase.split(' ') ?? [], [account])

  function generate () {
    setError(null)
    const created = createAccount({ deviceLabel: 'this device' })
    // Never publish an account whose own key event log does not verify.
    const check = verifyKeyEventLog([created.genesis])
    if (!check.valid) {
      setError(`Key generation produced an invalid genesis event: ${check.errors.join('; ')}`)
      return
    }
    setAccount(created)
    setPositions(backupChallengePositions(3))
    setStage('phrase')
  }

  function submitChallenge () {
    if (!account) return
    const result = checkBackupChallenge(
      account.backupPhrase,
      positions.map((p) => ({ position: p, word: answers[p] ?? '' }))
    )
    setWrong(result.wrong)
    if (result.ok) { setError(null); setStage('passphrase') }
  }

  async function seal () {
    if (!account) return
    setError(null)
    if (passphrase.length < 10) { setError('Use at least 10 characters.'); return }
    if (passphrase !== confirm) { setError('The two passphrases do not match.'); return }

    setBusy(true)
    // Argon2id at 64 MiB blocks the main thread for about a second. Yield first so the button state
    // paints; a frozen UI reads as a crash.
    await new Promise((r) => setTimeout(r, 30))
    try {
      const vault = sealAccount(account.masterSeed, passphrase, account.accountId)
      saveAccount({ vault, genesis: account.genesis })
      setUnlocked(account.masterSeed)
      setStage('done')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main>
      <Steps current="create" />
      <h1>Create your identity</h1>

      {stage === 'intro' && (
        <>
          <p className="muted">
            Your signing key is created in this browser and never sent anywhere. That is what lets
            anyone check your policy without trusting us — and it is also why we cannot recover it
            for you.
          </p>
          <div className="panel">
            <h3 style={{ marginTop: 0 }}>Before you start</h3>
            <p className="small">
              You will be shown 24 words. They are the <b>only</b> way to recover this account. Write
              them on paper. We will ask you for three of them before you can continue.
            </p>
            <p className="small muted">
              There is no password reset, no support recovery, and no copy on our servers. If that
              sounds severe, it is the same property that stops us impersonating you.
            </p>
          </div>
          {error && <div className="note bad small">{error}</div>}
          <div className="row"><button onClick={generate}>Generate my key</button></div>
          <p className="small muted" style={{ marginTop: '1rem' }}>
            By continuing you agree to the <a href="/terms">Terms</a>. We collect no account details
            — see <a href="/privacy">Privacy</a>.
          </p>
        </>
      )}

      {stage === 'phrase' && account && (
        <>
          <p>Write these 24 words down, in order, on paper.</p>
          <div className="words">
            {words.map((w, i) => (
              <div className="word" key={i}><b>{i + 1}</b>{w}</div>
            ))}
          </div>
          <div className="note warn small">
            Do not screenshot this, and do not put it in a password manager you access from this same
            device only. Anyone with these words controls this account.
          </div>
          <div className="row">
            <button onClick={() => setStage('challenge')}>I have written them down</button>
          </div>
        </>
      )}

      {stage === 'challenge' && account && (
        <>
          <p>Confirm you have the phrase. Type the words at these positions.</p>
          {positions.map((p) => (
            <div key={p}>
              <label htmlFor={`w${p}`}>Word {p}</label>
              <input
                id={`w${p}`} type="text" autoComplete="off" autoCapitalize="none" spellCheck={false}
                value={answers[p] ?? ''}
                onChange={(e) => setAnswers({ ...answers, [p]: e.target.value })}
              />
            </div>
          ))}
          {wrong.length > 0 && (
            <div className="note bad small">
              Not right at position{wrong.length > 1 ? 's' : ''} {wrong.join(', ')}. Check your paper.
            </div>
          )}
          <div className="row">
            <button onClick={submitChallenge}>Continue</button>
            <button className="secondary" onClick={() => setStage('phrase')}>Show the words again</button>
          </div>
        </>
      )}

      {stage === 'passphrase' && (
        <>
          <p>
            Now choose a passphrase. It encrypts your key on this device so that someone with access
            to this browser still cannot sign as you.
          </p>
          <div>
            <label htmlFor="pp">Passphrase</label>
            <input id="pp" type="password" value={passphrase} autoComplete="new-password"
              onChange={(e) => setPassphrase(e.target.value)} />
            <label htmlFor="pp2">Type it again</label>
            <input id="pp2" type="password" value={confirm} autoComplete="new-password"
              onChange={(e) => setConfirm(e.target.value)} />
          </div>
          <p className="small muted">
            This protects the key on this device. Your 24 words are what recover the account
            everywhere else.
          </p>
          {error && <div className="note bad small">{error}</div>}
          <div className="row">
            <button onClick={seal} disabled={busy}>
              {busy ? 'Encrypting...' : 'Encrypt and continue'}
            </button>
          </div>
        </>
      )}

      {stage === 'done' && (
        <>
          <div className="note ok">
            <b>Your identity exists.</b>{' '}
            <span className="small muted">
              It is stored encrypted on this device only.
            </span>
          </div>
          <p className="small muted mono">{account?.accountId ?? ''}</p>
          <p className="small muted">
            This identifier is derived from your key, not assigned by us. Anyone holding your key
            history can recompute it.
          </p>
          <div className="row">
            <button onClick={() => router.push('/author')}>Write my policy</button>
          </div>
        </>
      )}
    </main>
  )
}
