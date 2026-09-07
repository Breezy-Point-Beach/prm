'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import {
  normalizeIdentifier, RECIPIENT_TYPE_LABELS, DELIVERY_METHOD_LABELS, RESPONSE_STATUS_LABELS,
  type DeliveryMethod, type Policy, type RecipientType, type ResponseStatus
} from '@prm/schema'
import { deriveIdentifierSalt, encodeSalt } from '@prm/crypto'
import { verifyProofBundle } from '@prm/verify'
import {
  buildNotice, buildDeliveryRecord, buildResponseRecord, buildProofBundle, serializeBundle,
  renderNoticePdf
} from '@prm/notice'
import {
  hasAccount, getGenesis, getHandle, getDraft, getPublished, getNotices, saveNotice,
  isUnlocked, unlockWithPassphrase, requireKeys, type NoticeState
} from '../../lib/client/session'
import { Steps } from '../../components/Steps'

/**
 * Create Notice.
 *
 * Everything happens on this device. The notice may carry the user's plate so the recipient can find
 * the right records, and that value must never reach a server — so the notice, the bundle and the
 * PDF are all built here, and only downloaded.
 *
 * The cryptography is deliberately not in the user's way. They pick a recipient and a delivery
 * method; the digests live behind a disclosure.
 */
type Phase = 'compose' | 'unlock' | 'working' | 'done'

const WHITTIER_PRESET = {
  name: 'City of Whittier Police Department',
  type: 'law-enforcement' as RecipientType,
  department: 'Records Division',
  domain: 'whittierpd.org',
  contact: 'records@whittierpd.org',
  postalAddress: '13200 Penn St, Whittier, CA 90602',
  jurisdiction: 'US-CA'
}

function download (name: string, content: string | Uint8Array, type: string): void {
  const blob = new Blob([content as BlobPart], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

export default function NoticePage () {
  const router = useRouter()
  const [ready, setReady] = useState(false)
  const [phase, setPhase] = useState<Phase>('compose')
  const [error, setError] = useState<string | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [showDetail, setShowDetail] = useState(false)

  const [recipient, setRecipient] = useState(WHITTIER_PRESET)
  const [method, setMethod] = useState<DeliveryMethod>('certified-mail')
  const [includePlate, setIncludePlate] = useState(true)
  const [result, setResult] = useState<NoticeState | null>(null)
  const [pdf, setPdf] = useState<Uint8Array | null>(null)

  // Delivery + response, recorded after the fact.
  const [deliveredAt, setDeliveredAt] = useState(new Date().toISOString().slice(0, 10))
  const [reference, setReference] = useState('')
  const [responseStatus, setResponseStatus] = useState<ResponseStatus>('acknowledged')
  const [responseDate, setResponseDate] = useState(new Date().toISOString().slice(0, 10))
  const [responseNotes, setResponseNotes] = useState('')

  useEffect(() => {
    if (!hasAccount()) { router.replace('/create'); return }
    if (!getPublished()) { router.replace('/publish'); return }
    const existing = getNotices()
    if (existing.length > 0) { setResult(existing[existing.length - 1] as NoticeState); setPhase('done') }
    setReady(true)
  }, [router])

  async function unlockIfNeeded (): Promise<boolean> {
    if (isUnlocked()) return true
    try {
      unlockWithPassphrase(passphrase)
      return true
    } catch (e) {
      setError((e as Error).message)
      setPhase('compose')
      return false
    }
  }

  async function generate () {
    setError(null)
    const published = getPublished()
    const genesis = getGenesis()
    const draft = getDraft()
    const handle = getHandle()
    if (!published || !genesis || !handle) { setError('No published policy on this device.'); return }

    setPhase('unlock')
    if (!(await unlockIfNeeded())) return
    setPhase('working')
    await new Promise((r) => setTimeout(r, 20))

    try {
      const keys = requireKeys()

      // Fetch back the EXACT published bytes. Rebuilding the policy here would produce a different
      // serialization, and the notice pins the byte digest of what was actually delivered.
      const response = await fetch(`/u/${handle}/policy.json`, { cache: 'no-store' })
      if (!response.ok) throw new Error(`could not read the published policy (${response.status})`)
      const policyJson = await response.text()
      const policy = JSON.parse(policyJson) as Policy

      const matchingIdentifiers = []
      if (includePlate && draft?.plate) {
        const value = normalizeIdentifier('us-license-plate', draft.plate)
        matchingIdentifiers.push({
          namespace: 'us-license-plate',
          value,
          salt: encodeSalt(deriveIdentifierSalt(keys.bindingSecret, 'us-license-plate', value))
        })
      }

      const notice = buildNotice({
        policy,
        policyJson,
        recipient,
        purpose: 'To place my standing personal data policy on record with the recipient.',
        ...(matchingIdentifiers.length ? { matchingIdentifiers } : {}),
        policyUrl: `${window.location.origin}/u/${handle}`
      }, keys.signing)

      const bundle = buildProofBundle({
        policy,
        policyJson,
        keyEventLogJson: JSON.stringify([genesis], null, 2),
        noticeJson: notice.json,
        noticeDigest: notice.digest,
        policyChainJson: [{ version: policy.version, json: policyJson }],
        verifyCommand: 'npx @prm/cli verify notice.prmproof'
      })

      // Verify what we just built before offering it for download. Handing someone an unverifiable
      // packet would be worse than failing here.
      const check = verifyProofBundle(bundle)
      if (!check.valid) throw new Error(`the generated bundle did not verify: ${check.errors.join('; ')}`)

      const pdfBytes = await renderNoticePdf({
        policy,
        policyJson,
        notice: notice.document,
        noticeDigest: notice.digest,
        policyDigest: notice.document.policyDigest,
        policyByteDigest: notice.document.policyByteDigest,
        manifestDigest: bundle.manifestDigest,
        verificationUrl: `${window.location.origin}/u/${handle}#sha256=${published.digest}`,
        verifyCommand: 'npx @prm/cli verify notice.prmproof',
        includeMatchingIdentifiers: matchingIdentifiers.length > 0
      })

      const state: NoticeState = {
        noticeDigest: notice.digest,
        recipientName: recipient.name,
        issued: notice.document.issued,
        manifestDigest: bundle.manifestDigest,
        noticeJson: notice.json,
        bundleJson: serializeBundle(bundle)
      }
      saveNotice(state)
      setResult(state)
      setPdf(pdfBytes)
      setPhase('done')
    } catch (e) {
      setError((e as Error).message)
      setPhase('compose')
    }
  }

  /** Re-sign the bundle with a delivery or response record appended. */
  async function addRecord (kind: 'delivery' | 'response') {
    if (!result) return
    setError(null)
    if (!(await unlockIfNeeded())) return
    try {
      const keys = requireKeys()
      const bundle = JSON.parse(result.bundleJson)
      const notice = JSON.parse(result.noticeJson)
      const policyJson = bundle.artifacts['policy.json'] as string
      const policy = JSON.parse(policyJson) as Policy

      let deliveryJson = result.deliveryJson
      let responseJson = result.responseJson

      if (kind === 'delivery') {
        deliveryJson = buildDeliveryRecord({
          notice, noticeDigest: result.noticeDigest,
          recipient: { name: recipient.name, domain: recipient.domain, contact: recipient.postalAddress },
          method,
          deliveredAt: new Date(`${deliveredAt}T12:00:00Z`),
          manifestDigest: result.manifestDigest,
          ...(reference ? { reference } : {})
        }, keys.signing).json
      } else {
        responseJson = buildResponseRecord({
          noticeDigest: result.noticeDigest,
          ...(deliveryJson ? { deliveryDigest: JSON.parse(deliveryJson).id?.replace('urn:prm:delivery:', '') } : {}),
          recipient: { name: recipient.name },
          status: responseStatus,
          ...(responseStatus === 'no-response' ? {} : { receivedAt: new Date(`${responseDate}T12:00:00Z`) }),
          ...(responseNotes ? { notes: responseNotes } : {})
        }, keys.signing).json
      }

      const rebuilt = buildProofBundle({
        policy, policyJson,
        keyEventLogJson: bundle.artifacts['key-events/kel.json'],
        noticeJson: result.noticeJson,
        noticeDigest: result.noticeDigest,
        policyChainJson: [{ version: policy.version, json: policyJson }],
        ...(deliveryJson ? { deliveryJson: [deliveryJson] } : {}),
        ...(responseJson ? { responseJson: [responseJson] } : {}),
        verifyCommand: 'npx @prm/cli verify notice.prmproof'
      })
      const check = verifyProofBundle(rebuilt)
      if (!check.valid) throw new Error(check.errors.join('; '))

      const next: NoticeState = {
        ...result,
        manifestDigest: rebuilt.manifestDigest,
        bundleJson: serializeBundle(rebuilt),
        ...(deliveryJson ? { deliveryJson } : {}),
        ...(responseJson ? { responseJson } : {})
      }
      saveNotice(next)
      setResult(next)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  if (!ready) return <main><p className="muted">Loading…</p></main>

  return (
    <main>
      <Steps current="publish" />
      <h1>Create a notice</h1>
      <p className="muted">
        A notice tells one organization about your policy. It is a separate document from the policy
        itself, so it can carry details only they need.
      </p>

      {phase !== 'done' && (
        <>
          <div className="panel">
            <h3 style={{ marginTop: 0 }}>Who is it for?</h3>
            <label htmlFor="rname">Organization</label>
            <input id="rname" type="text" value={recipient.name}
              onChange={(e) => setRecipient({ ...recipient, name: e.target.value })} />

            <label htmlFor="rtype">Type</label>
            <select id="rtype" value={recipient.type}
              onChange={(e) => setRecipient({ ...recipient, type: e.target.value as RecipientType })}>
              {Object.entries(RECIPIENT_TYPE_LABELS).map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>

            <label htmlFor="raddr">Address</label>
            <input id="raddr" type="text" value={recipient.postalAddress}
              onChange={(e) => setRecipient({ ...recipient, postalAddress: e.target.value })} />

            <label htmlFor="rcontact">Email</label>
            <input id="rcontact" type="text" value={recipient.contact}
              onChange={(e) => setRecipient({ ...recipient, contact: e.target.value })} />
          </div>

          <div className="panel">
            <h3 style={{ marginTop: 0 }}>How will you send it?</h3>
            <select aria-label="Delivery method" value={method}
              onChange={(e) => setMethod(e.target.value as DeliveryMethod)}>
              {Object.entries(DELIVERY_METHOD_LABELS).map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>

            <label style={{ display: 'flex', gap: '.5rem', alignItems: 'flex-start', marginTop: '1rem' }}>
              <input type="checkbox" checked={includePlate} style={{ width: 'auto', marginTop: '.3rem' }}
                onChange={(e) => setIncludePlate(e.target.checked)} />
              <span style={{ fontWeight: 400 }}>
                Include my license plate so they can find the right records
                <span className="small muted" style={{ display: 'block' }}>
                  It goes in the notice you hand them, and nowhere public. Your published policy
                  contains only a commitment to it.
                </span>
              </span>
            </label>
          </div>

          {!isUnlocked() && (
            <div className="panel">
              <label htmlFor="pp">Passphrase</label>
              <input id="pp" type="password" value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)} autoComplete="current-password" />
              <p className="small muted">Needed to sign the notice on this device.</p>
            </div>
          )}

          {error && <div className="note bad"><b>Could not generate.</b>
            <div className="small" style={{ marginTop: '.3rem' }}>{error}</div></div>}

          <div className="row">
            <button onClick={generate} disabled={phase === 'working' || phase === 'unlock'}>
              {phase === 'working' ? 'Generating…' : 'Generate notice packet'}
            </button>
            <Link href="/publish"><button className="secondary">Back</button></Link>
          </div>
        </>
      )}

      {phase === 'done' && result && (
        <>
          <div className="note ok">
            <b>Your notice packet is ready.</b>
            <div className="small" style={{ marginTop: '.3rem' }}>
              Addressed to {result.recipientName}. Everything was signed on this device and checked
              before download.
            </div>
          </div>

          <div className="row">
            {pdf && (
              <button onClick={() => download('prm-notice.pdf', pdf, 'application/pdf')}>
                Download PDF
              </button>
            )}
            <button className="secondary"
              onClick={() => download('notice.prmproof', result.bundleJson, 'application/json')}>
              Download .prmproof
            </button>
            <button className="secondary" onClick={() => {
              void navigator.clipboard.writeText(`${window.location.origin}/u/${getHandle()}`)
            }}>
              Copy verification link
            </button>
          </div>

          <h2>Record delivery</h2>
          <div className="panel">
            <p className="small muted" style={{ marginTop: 0 }}>
              When you have sent it, record that here. This is your own statement of what you did —
              PRM does not witness delivery and does not claim to.
            </p>
            <label htmlFor="dat">Date sent</label>
            <input id="dat" type="text" value={deliveredAt} onChange={(e) => setDeliveredAt(e.target.value)} />
            <label htmlFor="dref">Tracking or reference number (optional)</label>
            <input id="dref" type="text" value={reference} onChange={(e) => setReference(e.target.value)} />
            <div className="row">
              <button onClick={() => void addRecord('delivery')}>
                {result.deliveryJson ? 'Update delivery record' : 'Record delivery'}
              </button>
              {result.deliveryJson && <span className="small" style={{ color: 'var(--ok)' }}>recorded</span>}
            </div>
          </div>

          <h2>Record a response</h2>
          <div className="panel">
            <p className="small muted" style={{ marginTop: 0 }}>
              If they reply, record it. PRM preserves what they said and how you characterized it. It
              does not decide whether their position is correct.
            </p>
            <label htmlFor="rs">What happened</label>
            <select id="rs" value={responseStatus}
              onChange={(e) => setResponseStatus(e.target.value as ResponseStatus)}>
              {Object.entries(RESPONSE_STATUS_LABELS).map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
            {responseStatus !== 'no-response' && (
              <>
                <label htmlFor="rd">Date received</label>
                <input id="rd" type="text" value={responseDate} onChange={(e) => setResponseDate(e.target.value)} />
              </>
            )}
            <label htmlFor="rn">Notes (optional)</label>
            <input id="rn" type="text" value={responseNotes} onChange={(e) => setResponseNotes(e.target.value)} />
            <div className="row">
              <button onClick={() => void addRecord('response')}>
                {result.responseJson ? 'Update response record' : 'Record response'}
              </button>
              {result.responseJson && <span className="small" style={{ color: 'var(--ok)' }}>recorded</span>}
            </div>
          </div>

          {error && <div className="note bad small">{error}</div>}

          <h2>Anyone can check this without us</h2>
          <pre>npx @prm/cli verify notice.prmproof</pre>
          <p className="small muted">
            Verification displayed by PRM is provided for convenience. The underlying artifacts are
            independently verifiable without PRM.
          </p>

          <p className="small">
            <button className="secondary" style={{ padding: '.3rem .7rem', fontSize: '.85rem' }}
              onClick={() => setShowDetail(!showDetail)}>
              {showDetail ? 'Hide' : 'Show'} proof details
            </button>
          </p>
          {showDetail && (
            <div className="panel">
              <table>
                <tbody>
                  <tr><th>Notice digest</th><td className="mono">{result.noticeDigest}</td></tr>
                  <tr><th>Bundle manifest</th><td className="mono">{result.manifestDigest}</td></tr>
                  <tr><th>Issued</th><td className="small">{result.issued}</td></tr>
                  <tr><th>Delivery record</th><td className="small">{result.deliveryJson ? 'signed' : 'not yet recorded'}</td></tr>
                  <tr><th>Response record</th><td className="small">{result.responseJson ? 'signed' : 'not yet recorded'}</td></tr>
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </main>
  )
}
