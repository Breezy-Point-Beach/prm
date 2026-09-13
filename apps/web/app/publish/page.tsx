'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { composeHumanReadable, normalizeIdentifier, type Policy } from '@prm/schema'
import {
  digest, deriveAccountId, deriveIdentifierSalt, computeCommitment, encodeMultihash
} from '@prm/crypto'
import { verifyPolicy } from '@prm/verify'
import { buildPolicyDocument, signPolicyDocument, diffRules } from '../../lib/policy-builder'
import {
  getDraft, getGenesis, getHandle, saveHandle, savePublished, getPublished,
  unlockWithPassphrase, isUnlocked, requireKeys, hasAccount, type PublishedState
} from '../../lib/client/session'
import { Steps } from '../../components/Steps'
import { logPublishedPolicy, fetchInclusion, loggedEntryFor } from '../../lib/client/ledger'
import type { LoggedEntry } from '../../lib/client/session'
import { LogEvidence } from '../../components/LogEvidence'

/**
 * Sign & publish.
 *
 * The order of operations matters and is the point of the screen:
 *
 *   1. build and sign locally
 *   2. VERIFY LOCALLY with @prm/verify before anything is sent
 *   3. send only the already-signed bytes plus the public key event
 *   4. FETCH THE PUBLISHED ARTIFACT BACK and compare byte for byte
 *   5. report success only if step 4 matches exactly
 *
 * Step 4 is not a formality. A signature check alone would pass a server that re-serialized the
 * document, because canonicalization erases formatting — so the comparison is on raw bytes.
 *
 * UPDATES. A second version chains to the first by digest (docs/decisions.md D15). The "previous"
 * used for that chain is not taken from local storage: the CURRENT published document is fetched,
 * verified against this account's key history, and its digest, version and chain id are read from
 * the verified bytes. Local state can be stale — a restore on another device, or a publish from one —
 * and a v2 that chains to the wrong v1 is refused by the server anyway; better to never build it.
 */
type Phase = 'review' | 'unlock' | 'signing' | 'publishing' | 'checking' | 'done' | 'failed'

interface Outcome {
  digest: string
  handle: string
  policyUrl: string
  canonicalUrl: string
  version: number
  policyChainId?: string
}

interface Current {
  policy: Policy
  digest: string
}

export default function PublishPage () {
  const router = useRouter()
  const [ready, setReady] = useState(false)
  const [phase, setPhase] = useState<Phase>('review')
  const [handle, setHandle] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [log, setLog] = useState<Array<{ ok: boolean; text: string }>>([])
  const [error, setError] = useState<string | null>(null)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  /** Set when this device has already published: the next publish is an update, not a first. */
  const [current, setCurrent] = useState<Current | null>(null)
  const [changes, setChanges] = useState<string[]>([])
  const [loadingCurrent, setLoadingCurrent] = useState(false)
  /** The transparency-log record for the published policy, if this device made one. */
  const [logged, setLogged] = useState<LoggedEntry | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  useEffect(() => {
    if (!hasAccount()) { router.replace('/create'); return }
    if (!getDraft()) { router.replace('/author'); return }
    setHandle(getHandle() ?? '')
    const already = getPublished()
    if (already) { setOutcome(already); setPhase('done'); setLogged(loggedEntryFor(already.digest) ?? null) }
    setReady(true)
    // Arriving from the author screen with a published version means "publish an update": go
    // straight into update mode rather than showing the previous result and asking again.
    if (already && new URLSearchParams(window.location.search).get('update') === '1') {
      void beginUpdateFor(already.handle)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router])

  const note = (ok: boolean, text: string) => setLog((l) => [...l, { ok, text }])

  /**
   * Fetch the currently published document and verify it against this account before treating it as
   * the thing to chain to. Returns null (with an error set) if anything about it is off.
   */
  async function loadCurrent (h: string): Promise<Current | null> {
    const genesis = getGenesis()
    if (!genesis) { setError('Key history missing on this device.'); return null }
    try {
      const response = await fetch(`/u/${h}/policy.json`, { cache: 'no-store' })
      if (!response.ok) throw new Error(`the server returned ${response.status}`)
      const policy = JSON.parse(await response.text()) as Policy
      if (policy.issuer.id !== deriveAccountId(genesis)) {
        throw new Error(`/u/${h} is published by a different account`)
      }
      const check = verifyPolicy(policy, { keyEventLog: [genesis] })
      if (check.summary === 'failed') throw new Error(check.errors.join('; '))
      return { policy, digest: digest(policy, 'policy') }
    } catch (e) {
      setError(`Could not read the published version to chain to: ${(e as Error).message}`)
      return null
    }
  }

  async function beginUpdateFor (h: string) {
    setError(null)
    setLoadingCurrent(true)
    const loaded = await loadCurrent(h)
    setLoadingCurrent(false)
    if (!loaded) return
    const draft = getDraft()
    setCurrent(loaded)
    setChanges(draft ? diffRules(loaded.policy.rules, draft.rules) : [])
    setLog([])
    setPhase('review')
  }

  async function beginUpdate () {
    if (outcome) await beginUpdateFor(outcome.handle)
  }

  async function run () {
    setError(null)
    setLog([])

    const draft = getDraft()
    const genesis = getGenesis()
    if (!draft || !genesis) { setError('Draft or key history missing on this device.'); return }
    if (!/^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$/.test(handle)) {
      setError('Choose a handle: 3-32 lowercase letters, digits, or hyphens.')
      return
    }

    // For an update, re-read the published version at the moment of signing, not the one loaded when
    // the screen opened. It is the same request; the cost is nothing and the staleness window is zero.
    let previous: Current | null = null
    if (current) {
      previous = await loadCurrent(handle)
      if (!previous) return
    }

    if (!isUnlocked()) {
      setPhase('unlock')
      try {
        unlockWithPassphrase(passphrase)
      } catch (e) {
        setPhase('review')
        setError((e as Error).message)
        return
      }
    }

    setPhase('signing')
    let policyJson: string
    let policyDigest: string
    let policyChainId: string
    try {
      const keys = requireKeys()

      // Identifier commitments: the raw plate is used here and never travels.
      const commitments = []
      if (draft.plate && draft.plate.trim() !== '') {
        const value = normalizeIdentifier('us-license-plate', draft.plate)
        const salt = deriveIdentifierSalt(keys.bindingSecret, 'us-license-plate', value)
        commitments.push({
          namespace: 'us-license-plate',
          commitment: encodeMultihash(computeCommitment('us-license-plate', value, salt))
        })
      }

      const unsigned = buildPolicyDocument({
        // Recomputed from the genesis event rather than read from storage: the account id is a
        // function of that event, so deriving it is strictly safer than trusting a cached copy.
        accountId: deriveAccountId(genesis),
        did: keys.signing.did,
        keyEventHash: digest(genesis, 'keyEvent'),
        rules: draft.rules,
        jurisdictions: draft.jurisdictions,
        humanReadable: composeHumanReadable(draft.narrative, draft.rules),
        effectiveDate: `${draft.effectiveDate}T00:00:00Z`,
        ...(commitments.length > 0 ? { identifierCommitments: commitments } : {}),
        ...(draft.displayName ? { displayName: draft.displayName } : {}),
        ...(previous
          ? {
              previous: {
                policyChainId: previous.policy.policyChainId,
                digest: previous.digest,
                version: previous.policy.version
              }
            }
          : {})
      })

      const signed = signPolicyDocument(unsigned, keys.signing)
      policyJson = signed.policyJson
      policyDigest = signed.digest
      policyChainId = signed.policy.policyChainId
      note(true, `Signed version ${signed.policy.version} on this device — ${policyDigest}`)
      if (previous) note(true, `Chained to version ${previous.policy.version} — ${previous.digest}`)

      // Step 2: verify locally BEFORE anything is sent.
      const local = verifyPolicy(signed.policy, { keyEventLog: [genesis] })
      if (local.summary === 'failed') {
        setError(`The policy did not verify locally: ${local.errors.join('; ')}`)
        setPhase('failed')
        return
      }
      note(true, 'Verified locally with @prm/verify before sending')
    } catch (e) {
      setError((e as Error).message)
      setPhase('failed')
      return
    }

    setPhase('publishing')
    let result: { ok: boolean; digest?: string; policyUrl?: string; canonicalUrl?: string; version?: number; error?: string; detail?: string[] }
    try {
      const response = await fetch('/api/v1/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Only the signed bytes and the public key event log. No draft, no plate, no vault, no seed.
        body: JSON.stringify({
          handle,
          policyJson,
          keyEventLogJson: JSON.stringify([genesis])
        })
      })
      result = await response.json()
    } catch (e) {
      setError(`Could not reach the server: ${(e as Error).message}`)
      setPhase('failed')
      return
    }

    if (!result.ok) {
      setError(result.error ?? 'Publish was refused.')
      if (result.detail) for (const d of result.detail) note(false, d)
      setPhase('failed')
      return
    }
    if (result.digest !== policyDigest) {
      setError(
        `The server reported a different digest than the one signed here. ` +
        `Signed ${policyDigest}, server said ${String(result.digest)}.`)
      setPhase('failed')
      return
    }
    note(true, 'Server accepted and reported the same digest')

    // Steps 4 and 5: fetch it back and compare the actual bytes.
    setPhase('checking')
    try {
      const fetched = await fetch(`/u/${handle}/policy.json`, { cache: 'no-store' })
      const returnedBytes = await fetched.text()

      if (returnedBytes !== policyJson) {
        setError(
          'The published document is not byte-for-byte what was signed on this device. ' +
          'Publishing has been treated as failed. Do not share this URL.')
        note(false, `signed ${policyJson.length} bytes, server returned ${returnedBytes.length} bytes`)
        setPhase('failed')
        return
      }
      note(true, 'Downloaded the published policy and matched it byte for byte')

      const reverified = verifyPolicy(JSON.parse(returnedBytes), { keyEventLog: [genesis] })
      if (reverified.summary === 'failed') {
        setError(`The published document did not verify: ${reverified.errors.join('; ')}`)
        setPhase('failed')
        return
      }
      const returnedDigest = digest(JSON.parse(returnedBytes), 'policy')
      if (returnedDigest !== policyDigest) {
        setError(`Digest mismatch after download: ${returnedDigest} vs ${policyDigest}.`)
        setPhase('failed')
        return
      }
      note(true, 'Re-verified the downloaded copy independently')
    } catch (e) {
      setError(`Could not check the published document: ${(e as Error).message}`)
      setPhase('failed')
      return
    }

    const done: Outcome = {
      digest: policyDigest,
      handle,
      policyUrl: result.policyUrl ?? `/u/${handle}/policy.json`,
      canonicalUrl: result.canonicalUrl ?? `/u/${handle}`,
      version: result.version ?? 1,
      policyChainId
    }
    saveHandle(handle)
    const state: PublishedState = { ...done, publishedAt: new Date().toISOString() }
    savePublished(state)
    setOutcome(done)
    setCurrent(null)
    setPhase('done')

    // Record it in the transparency log. A failure here does not un-publish anything: the policy
    // is live and verifiable; what is missing is the independent timestamp, which can be retried.
    try {
      const keys = requireKeys()
      const entry = await logPublishedPolicy({
        accountId: deriveAccountId(genesis), policyDigest, handle, key: keys.signing
      })
      setLogged(entry)
      note(true, `Logged as leaf ${entry.leafIndex} — independent timestamp ${entry.proof?.timestampedAt ? 'attached' : 'within the hour'}`)
    } catch (e) {
      note(false, `Published, but not yet logged: ${(e as Error).message}`)
    }
  }

  async function refreshEvidence () {
    if (!logged) return
    setRefreshing(true)
    try {
      setLogged(await fetchInclusion(logged))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setRefreshing(false)
    }
  }

  if (!ready) {
    return (
      <main>
        <Steps current="publish" />
        <h1>Sign and publish</h1>
        <div className="skeleton" aria-hidden="true" />
      </main>
    )
  }

  const busy = phase === 'signing' || phase === 'publishing' || phase === 'checking' || phase === 'unlock'
  const updating = current !== null
  const nextVersion = updating ? current.policy.version + 1 : 1

  return (
    <main>
      <Steps current="publish" />
      <h1>{updating ? `Publish version ${nextVersion}` : 'Sign and publish'}</h1>

      {phase !== 'done' && (
        <>
          <p className="lede">
            You sign here, on this device. We store exactly the bytes you sign, then this page
            downloads them again and checks them.
          </p>

          {updating && (
            <div className="note info">
              <b>This is an update.</b>{' '}
              <span className="small muted">
                Version {nextVersion} will reference version {current.policy.version} by digest.
                Version {current.policy.version} stays published and immutable.
              </span>
              {changes.length > 0
                ? (
                  <ul className="small" style={{ margin: '.5rem 0 0' }}>
                    {changes.map((c) => <li key={c}>{c}</li>)}
                  </ul>
                  )
                : <div className="small muted" style={{ marginTop: '.35rem' }}>No rule decisions changed; the text or dates may have.</div>}
            </div>
          )}

          <div className="panel">
            <label htmlFor="handle">Your public address</label>
            <div className="input-group">
              <span className="prefix mono">/u/</span>
              <input id="handle" type="text" value={handle} placeholder="user0001"
                autoComplete="off" spellCheck={false} readOnly={updating}
                onChange={(e) => setHandle(e.target.value.toLowerCase())} />
            </div>
            <p className="small muted field-hint">
              {updating
                ? 'An address, once published, stays with the account that published it.'
                : 'A short name for the page. It is not your identity — your account identifier is derived from your key and cannot be reassigned.'}
            </p>

            {!isUnlocked() && (
              <>
                <label htmlFor="pp">Passphrase</label>
                <input id="pp" type="password" value={passphrase} autoComplete="current-password"
                  onChange={(e) => setPassphrase(e.target.value)} />
                <p className="small muted field-hint">Needed to unlock your signing key on this device.</p>
              </>
            )}
          </div>

          {log.length > 0 && (
            <ul className="checks panel small">
              {log.map((l, i) => (
                <li key={i} className={l.ok ? '' : 'failed'}>{l.text}</li>
              ))}
            </ul>
          )}

          {error && (
            <div className="note bad">
              <b>Publishing failed.</b>
              <div className="small" style={{ marginTop: '.3rem' }}>{error}</div>
            </div>
          )}

          <div className="row">
            <button onClick={run} disabled={busy}>
              {phase === 'signing' ? 'Signing…'
                : phase === 'publishing' ? 'Publishing…'
                : phase === 'checking' ? 'Checking what was published…'
                : phase === 'unlock' ? 'Unlocking…'
                : updating ? `Sign and publish version ${nextVersion}` : 'Sign and publish'}
            </button>
            <Link href="/author" className="btn secondary">Back to editing</Link>
            {updating && (
              <button className="ghost" onClick={() => { setCurrent(null); setError(null); setPhase('done') }}>
                Cancel update
              </button>
            )}
          </div>
        </>
      )}

      {phase === 'done' && outcome && (
        <>
          <div className="note ok">
            <b>Published, and checked.</b>
            <div className="small" style={{ marginTop: '.3rem' }}>
              The document at your address is byte-for-byte the one you signed here.
            </div>
          </div>

          <div className="panel">
            <table>
              <tbody>
                <tr><th>Address</th><td><Link href={outcome.canonicalUrl}>/u/{outcome.handle}</Link></td></tr>
                <tr><th>Machine-readable</th><td><Link href={outcome.policyUrl}>/u/{outcome.handle}/policy.json</Link></td></tr>
                <tr><th>Version</th><td>{outcome.version}</td></tr>
                <tr><th>Digest</th><td className="mono">{outcome.digest}</td></tr>
              </tbody>
            </table>
          </div>

          <LogEvidence logged={logged} onRefresh={refreshEvidence} refreshing={refreshing} />

          <h3>Anyone can check this without us</h3>
          <pre>npx @rightsroot/prm-cli verify policy.json --kel kel.json --offline</pre>
          <p className="small muted">
            Download both files from your page. Verification runs offline and does not contact PRM.
          </p>

          {error && <div className="note bad small">{error}</div>}

          <div className="row">
            <Link href="/notice" className="btn">Send this to someone</Link>
            <Link href={outcome.canonicalUrl} className="btn secondary">View my public page</Link>
            <button className="ghost" onClick={beginUpdate} disabled={loadingCurrent}>
              {loadingCurrent ? 'Reading current version…' : `Publish an update (v${outcome.version + 1})`}
            </button>
          </div>
        </>
      )}
    </main>
  )
}
