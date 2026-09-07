import { notFound } from 'next/navigation'
import type { KeyEvent, Policy } from '@prm/schema'
import { categoryLabel } from '@prm/schema'
import { verifyPolicy } from '@prm/verify'
import { getStorage, isValidHandle } from '../../../lib/storage'
import { readPolicyBytes, readKelBytes } from '../../../lib/publish'
import { Markdown } from '../../../components/Markdown'
import { IntegrityCheck } from './IntegrityCheck'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * The public policy page.
 *
 * Deliberately minimal. This is what a records officer opens: what the document says, who signed it,
 * how to check it, and nothing else.
 *
 * THE LANGUAGE DISTINCTION IS PERMANENT PRODUCT VOCABULARY, not decoration:
 *
 *     "Verified here for convenience. Independently verifiable by anyone."
 *
 * The status computed on this server is convenience — a reader who does not trust us must not rely
 * on it. The offline command underneath is evidence. Collapsing those two would quietly undo the
 * property the whole system exists to provide, so the wording stays as it is.
 */
function formatDate (iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC'
  })
}

export default async function PublicPolicyPage (
  { params }: { params: Promise<{ handle: string }> }
) {
  const { handle } = await params
  if (!isValidHandle(handle)) notFound()

  const storage = await getStorage()
  const record = await storage.metadata.currentVersion(handle)
  if (!record) notFound()

  const history = await storage.metadata.versions(handle)

  let policy: Policy
  let keyEventLog: KeyEvent[]
  try {
    policy = JSON.parse(await readPolicyBytes(storage, record)) as Policy
    keyEventLog = JSON.parse(await readKelBytes(storage, record)) as KeyEvent[]
  } catch (e) {
    // Storage returned bytes that did not match their digest. Show nothing rather than something
    // that might not be what was signed.
    return (
      <main>
        <h1>Unavailable</h1>
        <div className="note bad">
          <b>This document failed its integrity check and has not been displayed.</b>
          <p className="small" style={{ marginTop: '.4rem' }}>{(e as Error).message}</p>
        </div>
      </main>
    )
  }

  const result = verifyPolicy(policy, { keyEventLog })
  const permitted = policy.rules.filter((r) => r.decision === 'allow')
  const conditional = policy.rules.filter((r) => r.decision === 'conditional')
  const objected = policy.rules.filter((r) => r.decision === 'deny')
  const failed = result.summary === 'failed'

  return (
    <main>
      <p className="small muted" style={{ margin: 0 }}>Personal Rights Management</p>
      <h1>Policy v{policy.version}</h1>
      <p className="muted small">
        Effective {formatDate(policy.effectiveDate)}
        {policy.expirationDate ? ` · expires ${formatDate(policy.expirationDate)}` : ''}
        {' · '}{policy.jurisdictions.join(', ')}
      </p>

      <IntegrityCheck handle={handle} servedDigest={record.policyDigest} />

      <div className={`note ${failed ? 'bad' : 'ok'}`}>
        <b>{failed
          ? 'This document did not verify.'
          : 'Verified here for convenience. Independently verifiable by anyone.'}</b>
        <div className="small muted" style={{ marginTop: '.25rem' }}>
          {failed
            ? result.errors.join('; ')
            : 'This check ran on our server, so treat it as convenience rather than proof. The command below contacts nobody.'}
        </div>
      </div>

      <h2>Standing permissions</h2>
      {permitted.length === 0 && conditional.length === 0
        ? <p className="small muted">Nothing is permitted unconditionally.</p>
        : (
          <ul className="small">
            {permitted.map((r) => <li key={r.category}>{categoryLabel(r.category)}</li>)}
            {conditional.map((r) => (
              <li key={r.category}>
                {categoryLabel(r.category)}
                <span className="muted"> — only under stated conditions</span>
              </li>
            ))}
          </ul>
          )}

      <h2>Objections</h2>
      <ul className="small">
        {objected.map((r) => <li key={r.category}>{categoryLabel(r.category)}</li>)}
      </ul>

      {policy.humanReadable?.text && (
        <>
          <h2>In the issuer&rsquo;s words</h2>
          <div className="panel"><Markdown text={policy.humanReadable.text} /></div>
        </>
      )}

      <h2>Version history</h2>
      <div className="panel">
        {[...history].reverse().map((v) => (
          <div key={v.version} style={{ paddingBottom: '.8rem', marginBottom: '.8rem',
            borderBottom: v.version === history[0]?.version ? 'none' : '1px solid var(--line)' }}>
            <div>
              <b>{v.version === record.version ? `Current — v${v.version}` : `v${v.version}`}</b>
              <span className="muted small">  {formatDate(v.publishedAt)}</span>
            </div>
            <div className="small muted mono" style={{ marginTop: '.2rem' }}>{v.policyDigest}</div>
            <div className="small" style={{ marginTop: '.3rem' }}>
              <a href={`/u/${handle}/v/${v.version}.json`}>v{v.version}.json</a>
              <span className="muted"> · immutable</span>
            </div>
          </div>
        ))}
        <p className="small muted" style={{ margin: 0 }}>
          Previous versions are immutable. Once published, a version&rsquo;s bytes never change — a new
          policy is a new document that references the one before it.
        </p>
      </div>

      <h2>Share</h2>
      <div className="panel">
        <div style={{ display: 'flex', gap: '1.2rem', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={`/u/${handle}/qr.svg`} alt={`QR code linking to this policy`}
            width={160} height={160} style={{ background: '#fff', borderRadius: 8, padding: 8 }} />
          <div className="small" style={{ flex: 1, minWidth: '14rem' }}>
            <p style={{ marginTop: 0 }}>
              The code carries the policy digest as well as the address, so a reader can tell whether
              the document they receive is the one this code refers to.
            </p>
            <div className="mono" style={{ fontSize: '.72rem' }}>
              /u/{handle}#sha256={record.policyDigest}
            </div>
          </div>
        </div>
      </div>

      <h2>Details</h2>
      <div className="panel">
        <table>
          <tbody>
            <tr><th>Account</th><td className="mono">{policy.issuer.id}</td></tr>
            <tr><th>Policy digest</th><td className="mono">{record.policyDigest}</td></tr>
            <tr><th>Stored bytes</th><td className="mono">{record.policyByteDigest}</td></tr>
            <tr><th>Published</th><td className="small">{record.publishedAt}</td></tr>
            <tr>
              <th>Documents</th>
              <td className="small">
                <a href={`/u/${handle}/policy.json`}>policy.json</a>
                {' · '}
                <a href={`/u/${handle}/kel.json`}>kel.json</a>
                {' · '}
                <a href={`/u/${handle}/qr.svg`}>qr.svg</a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2>Check this yourself</h2>
      <p className="small muted">
        The status above was computed on this server, so treat it as convenience. If you would rather
        not take our word for it, download both documents and verify them offline. It contacts nobody.
      </p>
      <pre>npx @prm/cli verify policy.json --kel kel.json --offline</pre>

      <p className="small muted" style={{ marginTop: '2rem' }}>
        This document records the issuer&rsquo;s instructions and the date they were given. It does not
        by itself establish that every restriction is enforceable under the law of any jurisdiction.
      </p>
    </main>
  )
}
