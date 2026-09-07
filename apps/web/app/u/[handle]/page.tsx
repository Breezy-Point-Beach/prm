import { notFound } from 'next/navigation'
import type { KeyEvent, Policy } from '@prm/schema'
import { categoryLabel } from '@prm/schema'
import { verifyPolicy } from '@prm/verify'
import { getStore, isValidHandle } from '../../../lib/store'
import { Markdown } from '../../../components/Markdown'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * The public policy page.
 *
 * Deliberately minimal. This is the artifact a records officer opens, so it shows what the document
 * says, who signed it, and how to check it — and nothing else. No dashboard, no branding, and no
 * claim about enforceability.
 *
 * The verification status shown here is a CONVENIENCE. It is computed on our server, so a reader who
 * does not trust us should not rely on it; the page says so and gives them the command to run
 * instead. Presenting a server-side check as authoritative would quietly undo the whole point.
 */
export default async function PublicPolicyPage (
  { params }: { params: Promise<{ handle: string }> }
) {
  const { handle } = await params
  if (!isValidHandle(handle)) notFound()

  const record = await getStore().getCurrent(handle)
  if (!record) notFound()

  const policy = JSON.parse(record.policyJson) as Policy
  const keyEventLog = JSON.parse(record.keyEventLogJson) as KeyEvent[]
  const result = verifyPolicy(policy, { keyEventLog })

  const permitted = policy.rules.filter((r) => r.decision === 'allow')
  const conditional = policy.rules.filter((r) => r.decision === 'conditional')
  const objected = policy.rules.filter((r) => r.decision === 'deny')

  return (
    <main>
      <p className="small muted" style={{ margin: 0 }}>Personal Rights Management</p>
      <h1>Policy v{policy.version}</h1>
      <p className="muted small">
        Effective {policy.effectiveDate.slice(0, 10)}
        {policy.expirationDate ? ` · expires ${policy.expirationDate.slice(0, 10)}` : ''}
        {' · '}{policy.jurisdictions.join(', ')}
      </p>

      <div className={`note ${result.summary === 'failed' ? 'bad' : 'ok'}`}>
        <b>
          {result.summary === 'failed'
            ? 'This document did not verify.'
            : 'Signature verified.'}
        </b>
        <div className="small muted" style={{ marginTop: '.25rem' }}>
          {result.summary === 'failed'
            ? result.errors.join('; ')
            : 'Signed by the account below, whose identifier is derived from its own key history.'}
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

      <h2>Details</h2>
      <div className="panel">
        <table>
          <tbody>
            <tr><th>Account</th><td className="mono">{policy.issuer.id}</td></tr>
            <tr><th>Digest</th><td className="mono">{record.digest}</td></tr>
            <tr><th>Published</th><td className="small">{record.publishedAt}</td></tr>
            <tr>
              <th>Documents</th>
              <td className="small">
                <a href={`/u/${handle}/policy.json`}>policy.json</a>
                {' · '}
                <a href={`/u/${handle}/kel.json`}>kel.json</a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2>Check this yourself</h2>
      <p className="small muted">
        The status above was computed on this server. If you would rather not take our word for it,
        download both documents and verify them offline. It does not contact us.
      </p>
      <pre>npx @prm/cli verify policy.json --kel kel.json --offline</pre>

      <p className="small muted" style={{ marginTop: '2rem' }}>
        This document records the issuer&rsquo;s instructions and the date they were given. It does not
        by itself establish that every restriction is enforceable under the law of any jurisdiction.
      </p>
    </main>
  )
}
