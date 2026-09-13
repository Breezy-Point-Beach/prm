'use client'

import type { LoggedEntry } from '../lib/client/session'

/**
 * What the transparency log and the timestamp authorities say about a published policy.
 *
 * Two facts, kept visibly separate: that the policy's ledger entry is IN the log (immediate), and
 * that an independent authority has attested WHEN that tree existed (hourly). Neither is claimed
 * before it is true.
 */
export function LogEvidence ({ logged, onRefresh, refreshing }: {
  logged: LoggedEntry | null
  onRefresh: () => void
  refreshing: boolean
}) {
  if (!logged) {
    return (
      <div className="note info small">
        <b>Not yet in the transparency log.</b>{' '}
        <span className="muted">This policy was published before logging existed, or the append failed. Republishing an update will log it.</span>
      </div>
    )
  }
  const inc = logged.entry.logInclusion
  const proof = logged.proof
  return (
    <>
      <h3>Independent evidence</h3>
      <div className="panel">
        <table>
          <tbody>
            <tr>
              <th>Transparency log</th>
              <td>
                {inc
                  ? <>Leaf {inc.leafIndex} in <span className="mono">{inc.logId}</span>, tree size {inc.treeSize}</>
                  : <>Appended as leaf {logged.leafIndex}; proof pending</>}
              </td>
            </tr>
            <tr>
              <th>Timestamp</th>
              <td>
                {proof?.timestampedAt
                  ? (
                    <>
                      <b>{proof.timestampedAt}</b>
                      <span className="small muted"> — attested by {proof.authorities.map((a) => a.tsa).join(' and ')} (RFC 3161)</span>
                    </>
                    )
                  : <span className="muted">Pending. A token is requested within the hour; it will attach itself here and to any notice packet you build after that.</span>}
              </td>
            </tr>
          </tbody>
        </table>
        <p className="small muted field-hint">
          The log holds only a hash of your ledger entry. The authority signs only the log&rsquo;s tree
          head. Neither learns what you published; both let anyone prove it existed by that time.
        </p>
        <div className="row" style={{ marginTop: '.6rem' }}>
          <button className="secondary" onClick={onRefresh} disabled={refreshing}>
            {refreshing ? 'Checking…' : 'Check for a timestamp'}
          </button>
        </div>
      </div>
    </>
  )
}
