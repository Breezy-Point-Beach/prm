'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { composeHumanReadable, normalizeIdentifier } from '@prm/schema'
import {
  digest, deriveAccountId, deriveIdentifierSalt, computeCommitment, encodeMultihash
} from '@prm/crypto'
import { verifyPolicy } from '@prm/verify'
import { buildPolicyDocument, signPolicyDocument } from '../../lib/policy-builder'
import {
  getDraft, getGenesis, getHandle, saveHandle, savePublished, getPublished,
  unlockWithPassphrase, isUnlocked, requireKeys, hasAccount
} from '../../lib/client/session'
import { Steps } from '../../components/Steps'

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
 */
type Phase = 'review' | 'unlock' | 'signing' | 'publishing' | 'checking' | 'done' | 'failed'

interface Outcome {
  digest: string
  handle: string
  policyUrl: string
  canonicalUrl: string
  version: number
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

  useEffect(() => {
    if (!hasAccount()) { router.replace('/create'); return }
    if (!getDraft()) { router.replace('/author'); return }
    setHandle(getHandle() ?? '')
    const already = getPublished()
    if (already) { setOutcome(already); setPhase('done') }
    setReady(true)
  }, [router])

  const note = (ok: boolean, text: string) => setLog((l) => [...l, { ok, text }])

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
        ...(draft.displayName ? { displayName: draft.displayName } : {})
      })

      const signed = signPolicyDocument(unsigned, keys.signing)
      policyJson = signed.policyJson
      policyDigest = signed.digest
      note(true, `Signed on this device — ${policyDigest}`)

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
      version: result.version ?? 1
    }
    saveHandle(handle)
    savePublished({ ...done, publishedAt: new Date().toISOString() })
    setOutcome(done)
    setPhase('done')
  }

  if (!ready) return <main><p className="muted">Loading…</p></main>

  const busy = phase === 'signing' || phase === 'publishing' || phase === 'checking' || phase === 'unlock'

  return (
    <main>
      <Steps current="publish" />
      <h1>Sign and publish</h1>

      {phase !== 'done' && (
        <>
          <p className="muted">
            You sign here, on this device. We store exactly the bytes you sign, then this page
            downloads them again and checks them.
          </p>

          <div className="panel">
            <label htmlFor="handle">Your public address</label>
            <div className="row" style={{ marginTop: 0, gap: '.3rem' }}>
              <span className="small muted mono">/u/</span>
              <input id="handle" type="text" value={handle} placeholder="user0001"
                autoComplete="off" spellCheck={false}
                onChange={(e) => setHandle(e.target.value.toLowerCase())}
                style={{ flex: 1, minWidth: '12rem' }} />
            </div>
            <p className="small muted">
              A short name for the page. It is not your identity — your account identifier is derived
              from your key and cannot be reassigned.
            </p>

            {!isUnlocked() && (
              <>
                <label htmlFor="pp">Passphrase</label>
                <input id="pp" type="password" value={passphrase} autoComplete="current-password"
                  onChange={(e) => setPassphrase(e.target.value)} />
                <p className="small muted">Needed to unlock your signing key on this device.</p>
              </>
            )}
          </div>

          {log.length > 0 && (
            <div className="panel">
              {log.map((l, i) => (
                <div key={i} className="small" style={{ color: l.ok ? 'var(--ok)' : 'var(--bad)' }}>
                  {l.ok ? '✓' : '✗'} {l.text}
                </div>
              ))}
            </div>
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
                : 'Sign and publish'}
            </button>
            <Link href="/author"><button className="secondary">Back to editing</button></Link>
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

          <h3>Anyone can check this without us</h3>
          <pre>npx @prm/cli verify policy.json --kel kel.json --offline</pre>
          <p className="small muted">
            Download both files from your page. Verification runs offline and does not contact PRM.
          </p>

          <div className="row">
            <Link href="/notice"><button>Send this to someone</button></Link>
            <Link href={outcome.canonicalUrl}><button className="secondary">View my public page</button></Link>
          </div>
        </>
      )}
    </main>
  )
}
