'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { MNEMONIC_WORDS, isValidPhrase, normalizePhrase } from '@prm/vault'
import { deriveAccountId } from '@prm/crypto'
import { restoreFromPublished, type RestoreResult } from '../../lib/client/restore'
import {
  hasAccount, getGenesis, sealAccount, saveAccount, savePublished, saveDraft, setUnlocked
} from '../../lib/client/session'
import { isValidHandle } from '../../lib/handle'
import { Steps } from '../../components/Steps'

/**
 * Restore — get back into an account from its 24 words.
 *
 * The phrase reproduces the keys. It does NOT reproduce the account id, because the id is the digest
 * of the genesis key event, and that event carries the moment and the device it was created on. So a
 * restore needs two things: the phrase, and the key history that was published. The second is public
 * and can come from this server (by handle) or from a .prmproof bundle — a user whose publisher has
 * disappeared can still get back in.
 *
 * Nothing typed here leaves the page. The lookup is a plain GET of two public documents, the same
 * request any reader of the policy page makes.
 */
type Stage = 'loading' | 'blocked' | 'phrase' | 'locate' | 'passphrase' | 'done'
type Source = 'handle' | 'files'

export default function RestorePage () {
  const [stage, setStage] = useState<Stage>('loading')
  const [existingId, setExistingId] = useState<string | null>(null)
  const [phrase, setPhrase] = useState('')
  const [source, setSource] = useState<Source>('handle')
  const [handle, setHandle] = useState('')
  const [kelText, setKelText] = useState('')
  const [policyText, setPolicyText] = useState('')
  const [result, setResult] = useState<RestoreResult | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!hasAccount()) { setStage('phrase'); return }
    const genesis = getGenesis()
    setExistingId(genesis ? deriveAccountId(genesis) : '')
    setStage('blocked')
  }, [])

  const wordCount = normalizePhrase(phrase).split(' ').filter(Boolean).length
  const phraseOk = wordCount === MNEMONIC_WORDS && isValidPhrase(phrase)

  function continueFromPhrase () {
    setError(null)
    if (!phraseOk) {
      setError(wordCount !== MNEMONIC_WORDS
        ? `That is ${wordCount} word${wordCount === 1 ? '' : 's'}; a backup phrase has ${MNEMONIC_WORDS}.`
        : 'Those words are not a valid phrase. Check the order, and check for lookalike words.')
      return
    }
    setStage('locate')
  }

  async function locate () {
    setError(null)
    setBusy(true)
    try {
      let keyEventLogJson: string
      let policyJson: string | undefined
      let usedHandle: string | undefined

      if (source === 'handle') {
        const h = handle.trim().toLowerCase()
        if (!isValidHandle(h)) throw new Error('Enter the address you published at — the part after /u/.')
        const kel = await fetch(`/u/${h}/kel.json`, { cache: 'no-store' })
        if (kel.status === 404) throw new Error(`Nothing is published at /u/${h}.`)
        if (!kel.ok) throw new Error(`Could not fetch the key history (${kel.status}).`)
        keyEventLogJson = await kel.text()
        const pol = await fetch(`/u/${h}/policy.json`, { cache: 'no-store' })
        if (pol.ok) policyJson = await pol.text()
        usedHandle = h
      } else {
        if (kelText.trim() === '') throw new Error('Paste the contents of kel.json.')
        keyEventLogJson = kelText
        policyJson = policyText.trim() === '' ? undefined : policyText
      }

      const restored = restoreFromPublished({
        phrase,
        keyEventLogJson,
        ...(policyJson !== undefined ? { policyJson } : {}),
        ...(usedHandle !== undefined ? { handle: usedHandle } : {}),
        origin: window.location.origin
      })
      setResult(restored)
      setStage('passphrase')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function seal () {
    if (!result) return
    setError(null)
    if (passphrase.length < 10) { setError('Use at least 10 characters.'); return }
    if (passphrase !== confirm) { setError('The two passphrases do not match.'); return }
    if (hasAccount()) { setError('This device already holds an identity.'); setStage('blocked'); return }

    setBusy(true)
    await new Promise((r) => setTimeout(r, 30))
    try {
      const { account, published, draft } = result
      const vault = sealAccount(account.masterSeed, passphrase, account.accountId, account.keyIndex)
      saveAccount({
        vault,
        genesis: account.genesis,
        ...(published?.handle ? { handle: published.handle } : {})
      })
      if (published) savePublished(published)
      if (draft) saveDraft(draft)
      setUnlocked(account.masterSeed, account.keyIndex)
      // The phrase has done its job. Nothing on this page needs it again.
      setPhrase('')
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
      <h1>Restore your identity</h1>

      {stage === 'loading' && <div className="skeleton" aria-hidden="true" />}

      {stage === 'blocked' && (
        <>
          <div className="note warn">
            <b>This device already holds an identity.</b>
            <div className="small muted" style={{ marginTop: '.25rem' }}>
              <span className="mono">{existingId}</span>
            </div>
          </div>
          <p className="small muted">
            Restoring would replace it. If that is what you want, forget this device first from the
            Create screen, then come back here.
          </p>
          <div className="row">
            <Link href="/create" className="btn">Go to my identity</Link>
          </div>
        </>
      )}

      {stage === 'phrase' && (
        <>
          <p className="lede">
            Enter the 24 words you wrote down. They reproduce your keys; the next step finds the
            account they belong to.
          </p>
          <div className="panel">
            <label htmlFor="phrase">Backup phrase</label>
            <textarea id="phrase" className="phrase" value={phrase} rows={4}
              autoComplete="off" autoCapitalize="none" spellCheck={false}
              placeholder="word word word …"
              onChange={(e) => setPhrase(e.target.value)} />
            <p className="small muted field-hint">
              {wordCount} of {MNEMONIC_WORDS} words
              {wordCount === MNEMONIC_WORDS ? (phraseOk ? ' — looks valid' : ' — checksum failed') : ''}.
              Typed here, checked here, never sent.
            </p>
          </div>
          {error && <div className="note bad small">{error}</div>}
          <div className="row">
            <button onClick={continueFromPhrase} disabled={!phraseOk}>Continue</button>
            <Link href="/create" className="btn secondary">I need to create one</Link>
          </div>
        </>
      )}

      {stage === 'locate' && (
        <>
          <p className="lede">
            Now the account. The phrase alone would create a <em>new</em> identity; what makes it yours
            is the key history you already published.
          </p>
          <div className="tabs" role="tablist">
            <button role="tab" aria-selected={source === 'handle'} className={source === 'handle' ? 'on' : ''}
              onClick={() => setSource('handle')}>Look it up by address</button>
            <button role="tab" aria-selected={source === 'files'} className={source === 'files' ? 'on' : ''}
              onClick={() => setSource('files')}>I have the files</button>
          </div>
          <div className="panel attached">
            {source === 'handle'
              ? (
                <>
                  <label htmlFor="handle">Your public address</label>
                  <div className="input-group">
                    <span className="prefix mono">/u/</span>
                    <input id="handle" type="text" value={handle} placeholder="user0001"
                      autoComplete="off" autoCapitalize="none" spellCheck={false}
                      onChange={(e) => setHandle(e.target.value.toLowerCase())} />
                  </div>
                  <p className="small muted field-hint">
                    Fetches the public key history and policy at that address — the same two files
                    anyone reading your page can download.
                  </p>
                </>
                )
              : (
                <>
                  <label htmlFor="kel">kel.json</label>
                  <textarea id="kel" value={kelText} rows={5} spellCheck={false}
                    placeholder="Paste the key event log — from your page, or from key-events/kel.json inside a .prmproof"
                    onChange={(e) => setKelText(e.target.value)} />
                  <label htmlFor="pol">policy.json <span className="muted">(optional)</span></label>
                  <textarea id="pol" value={policyText} rows={5} spellCheck={false}
                    placeholder="Paste the current published policy, if you have it"
                    onChange={(e) => setPolicyText(e.target.value)} />
                  <p className="small muted field-hint">
                    Works with the publisher gone. Everything is checked here; nothing is sent.
                  </p>
                </>
                )}
          </div>
          {error && <div className="note bad small">{error}</div>}
          <div className="row">
            <button onClick={locate} disabled={busy}>{busy ? 'Checking…' : 'Find my account'}</button>
            <button className="secondary" onClick={() => setStage('phrase')}>Back</button>
          </div>
        </>
      )}

      {stage === 'passphrase' && result && (
        <>
          <div className="note ok">
            <b>Found it.</b>{' '}
            <span className="small muted">This is the account your phrase controls.</span>
          </div>
          <div className="panel">
            <table>
              <tbody>
                <tr><th>Account</th><td className="mono">{result.account.accountId}</td></tr>
                {result.published && (
                  <>
                    <tr><th>Address</th><td>/u/{result.published.handle}</td></tr>
                    <tr><th>Published</th><td>version {result.published.version}</td></tr>
                  </>
                )}
              </tbody>
            </table>
            <ul className="checks small">
              {result.checks.map((c) => <li key={c}>{c}</li>)}
            </ul>
          </div>

          <p className="lede">
            Choose a passphrase for this device. It encrypts your key here; your 24 words remain the
            way back in everywhere else.
          </p>
          <div className="panel">
            <label htmlFor="pp">Passphrase</label>
            <input id="pp" type="password" value={passphrase} autoComplete="new-password"
              onChange={(e) => setPassphrase(e.target.value)} />
            <label htmlFor="pp2">Type it again</label>
            <input id="pp2" type="password" value={confirm} autoComplete="new-password"
              onChange={(e) => setConfirm(e.target.value)} />
          </div>
          {error && <div className="note bad small">{error}</div>}
          <div className="row">
            <button onClick={seal} disabled={busy}>{busy ? 'Encrypting…' : 'Encrypt and finish'}</button>
            <button className="secondary" onClick={() => { setResult(null); setStage('locate') }}>Back</button>
          </div>
        </>
      )}

      {stage === 'done' && result && (
        <>
          <div className="note ok">
            <b>Restored.</b>{' '}
            <span className="small muted">
              Same account, same identifier, on this device now.
            </span>
          </div>
          <div className="panel">
            <table>
              <tbody>
                <tr><th>Account</th><td className="mono">{result.account.accountId}</td></tr>
                {result.published && (
                  <tr>
                    <th>Address</th>
                    <td><Link href={`/u/${result.published.handle}`}>/u/{result.published.handle}</Link></td>
                  </tr>
                )}
              </tbody>
            </table>
            {result.draft && (
              <p className="small muted field-hint">
                Your published terms have been loaded as a draft. If your policy included a plate,
                enter it again on the next screen — the commitment will come out identical.
              </p>
            )}
          </div>
          <div className="row">
            <Link href="/author" className="btn">
              {result.published ? 'Update my policy' : 'Write my policy'}
            </Link>
            {result.published && <Link href="/notice" className="btn secondary">Create a notice</Link>}
          </div>
        </>
      )}
    </main>
  )
}
