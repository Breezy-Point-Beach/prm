'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'
import {
  createAccount, backupChallengePositions, checkBackupChallenge, type NewAccount
} from '@prm/vault'
import { verifyKeyEventLog } from '@prm/verify'
import { deriveAccountId } from '@prm/crypto'
import {
  sealAccount, saveAccount, setUnlocked, hasAccount, getGenesis, getHandle, forgetEverything
} from '../../lib/client/session'
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
 *
 * THIS PAGE MUST NEVER OVERWRITE AN EXISTING VAULT. A device that already holds an identity shows
 * that identity and offers to write a policy; creating a second key is only reachable after the user
 * has explicitly forgotten the first. Both `generate` and `seal` re-check this independently of the
 * UI stage, because the stage is a rendering decision and the invariant is not.
 */
type Stage = 'intro' | 'phrase' | 'challenge' | 'passphrase' | 'done'

const FORGET_WORD = 'forget'

export default function CreatePage () {
  const router = useRouter()
  // null until mounted. localStorage does not exist during server rendering, and deciding the stage
  // from it during render made the server say "intro" while the client said "done". React discards
  // the server tree on that mismatch — and in the gap a returning user briefly saw a live "Generate
  // my key" button, which, followed through, would have replaced their vault.
  const [stage, setStage] = useState<Stage | null>(null)
  const [existing, setExisting] = useState<{ accountId: string; handle: string | null } | null>(null)
  const [account, setAccount] = useState<NewAccount | null>(null)
  const [positions, setPositions] = useState<number[]>([])
  const [answers, setAnswers] = useState<Record<number, string>>({})
  const [wrong, setWrong] = useState<number[]>([])
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [forgetText, setForgetText] = useState('')
  const [forgetOpen, setForgetOpen] = useState(false)

  const words = useMemo(() => account?.backupPhrase.split(' ') ?? [], [account])

  useEffect(() => {
    if (!hasAccount()) { setStage('intro'); return }
    const genesis = getGenesis()
    setExisting({ accountId: genesis ? deriveAccountId(genesis) : '', handle: getHandle() })
    setStage('done')
  }, [])

  function refuseOverwrite (): boolean {
    if (!hasAccount()) return false
    setError('This device already holds an identity. To create a different one, forget this device first.')
    setStage('done')
    return true
  }

  function generate () {
    setError(null)
    if (refuseOverwrite()) return
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
    if (refuseOverwrite()) return

    setBusy(true)
    // Argon2id at 64 MiB blocks the main thread for about a second. Yield first so the button state
    // paints; a frozen UI reads as a crash.
    await new Promise((r) => setTimeout(r, 30))
    try {
      const vault = sealAccount(account.masterSeed, passphrase, account.accountId)
      saveAccount({ vault, genesis: account.genesis })
      setUnlocked(account.masterSeed)
      setExisting({ accountId: account.accountId, handle: null })
      setStage('done')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  function forget () {
    if (forgetText.trim().toLowerCase() !== FORGET_WORD) return
    forgetEverything()
    setExisting(null)
    setAccount(null)
    setForgetText('')
    setForgetOpen(false)
    setError(null)
    setStage('intro')
  }

  if (stage === null) {
    return (
      <main>
        <Steps current="create" />
        <h1>Create your identity</h1>
        <div className="skeleton" aria-hidden="true" />
      </main>
    )
  }

  return (
    <main>
      <Steps current="create" />
      <h1>Create your identity</h1>

      {stage === 'intro' && (
        <>
          <p className="lede">
            Your signing key is created in this browser and never sent anywhere. That is what lets
            anyone check your policy without trusting us — and it is also why we cannot recover it
            for you.
          </p>
          <div className="panel">
            <h3>Before you start</h3>
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
          <div className="row">
            <button onClick={generate}>Generate my key</button>
            <Link href="/restore" className="btn secondary">I already have 24 words</Link>
          </div>
          <p className="small muted" style={{ marginTop: '1.25rem' }}>
            By continuing you agree to the <Link href="/terms">Terms</Link>. We collect no account
            details — see <Link href="/privacy">Privacy</Link>.
          </p>
        </>
      )}

      {stage === 'phrase' && account && (
        <>
          <p className="lede">Write these 24 words down, in order, on paper.</p>
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
          <p className="lede">Confirm you have the phrase. Type the words at these positions.</p>
          <div className="panel">
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
          </div>
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
          <p className="lede">
            Now choose a passphrase. It encrypts your key on this device so that someone with access
            to this browser still cannot sign as you.
          </p>
          <div className="panel">
            <label htmlFor="pp">Passphrase</label>
            <input id="pp" type="password" value={passphrase} autoComplete="new-password"
              onChange={(e) => setPassphrase(e.target.value)} />
            <label htmlFor="pp2">Type it again</label>
            <input id="pp2" type="password" value={confirm} autoComplete="new-password"
              onChange={(e) => setConfirm(e.target.value)} />
            <p className="small muted field-hint">
              This protects the key on this device. Your 24 words are what recover the account
              everywhere else.
            </p>
          </div>
          {error && <div className="note bad small">{error}</div>}
          <div className="row">
            <button onClick={seal} disabled={busy}>
              {busy ? 'Encrypting…' : 'Encrypt and continue'}
            </button>
          </div>
        </>
      )}

      {stage === 'done' && (
        <>
          <div className="note ok">
            <b>Your identity exists on this device.</b>{' '}
            <span className="small muted">It is stored encrypted here, and nowhere else.</span>
          </div>
          <div className="panel">
            <table>
              <tbody>
                <tr><th>Account</th><td className="mono">{account?.accountId ?? existing?.accountId ?? ''}</td></tr>
                {existing?.handle && (
                  <tr><th>Address</th><td><Link href={`/u/${existing.handle}`}>/u/{existing.handle}</Link></td></tr>
                )}
              </tbody>
            </table>
            <p className="small muted field-hint">
              This identifier is derived from your key, not assigned by us. Anyone holding your key
              history can recompute it.
            </p>
          </div>
          {error && <div className="note bad small">{error}</div>}
          <div className="row">
            <button onClick={() => router.push('/author')}>
              {existing?.handle ? 'Update my policy' : 'Write my policy'}
            </button>
            {existing?.handle && (
              <Link href="/notice" className="btn secondary">Create a notice</Link>
            )}
          </div>

          <details className="disclosure" open={forgetOpen} onToggle={(e) => setForgetOpen((e.target as HTMLDetailsElement).open)}>
            <summary className="small muted">This is not my account, or I want to start over</summary>
            <div className="panel danger-zone">
              <p className="small">
                Forgetting removes the encrypted vault, the key history, and any draft from this
                device. It does not touch anything you have published. You can get back in later with
                your 24 words at <Link href="/restore">Restore</Link>.
              </p>
              <label htmlFor="forget">Type <span className="mono">{FORGET_WORD}</span> to confirm</label>
              <input id="forget" type="text" value={forgetText} autoComplete="off" spellCheck={false}
                onChange={(e) => setForgetText(e.target.value)} />
              <div className="row">
                <button className="danger" onClick={forget}
                  disabled={forgetText.trim().toLowerCase() !== FORGET_WORD}>
                  Forget this device
                </button>
              </div>
            </div>
          </details>
        </>
      )}
    </main>
  )
}
