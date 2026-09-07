'use client'

import { useEffect, useState } from 'react'
import { digest } from '@prm/crypto'

/**
 * Checks the retrieved policy against the digest carried in the URL fragment.
 *
 * The fragment comes from wherever the reader got the link — a QR code on a card, a printed notice,
 * an email. It is an EXPECTATION formed elsewhere, so comparing it against what this page actually
 * fetched detects substitution by the hosting layer.
 *
 * This runs in the reader's browser, not on our server, and the fragment is never transmitted to us.
 * It is still convenience rather than proof: a compromised page could lie about the comparison. The
 * page says so, and points at the offline command. What this catches is a swapped ARTIFACT, which is
 * the more likely failure than a swapped application.
 */
export function IntegrityCheck ({ handle, servedDigest }: { handle: string; servedDigest: string }) {
  const [expected, setExpected] = useState<string | null>(null)
  const [retrieved, setRetrieved] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fragment = /(?:^|[#&])sha256=([A-Za-z0-9_-]+)/.exec(window.location.hash)
    if (!fragment) return
    const want = fragment[1] as string
    setExpected(want)

    let cancelled = false
    void (async () => {
      try {
        const response = await fetch(`/u/${handle}/policy.json`, { cache: 'no-store' })
        if (!response.ok) throw new Error(`could not fetch the policy (${response.status})`)
        const parsed = JSON.parse(await response.text())
        if (!cancelled) setRetrieved(digest(parsed, 'policy'))
      } catch (e) {
        if (!cancelled) setError((e as Error).message)
      }
    })()
    return () => { cancelled = true }
  }, [handle])

  if (expected === null) return null

  const match = retrieved !== null && retrieved === expected
  const settled = retrieved !== null || error !== null

  return (
    <div className={`note ${!settled ? '' : match ? 'ok' : 'bad'}`}>
      <b>
        {!settled ? 'Checking the document against your link…'
          : match ? 'This is the document your link expected.'
          : 'This is NOT the document your link expected.'}
      </b>
      <table style={{ marginTop: '.5rem' }}>
        <tbody>
          <tr><th>Expected</th><td className="mono">{expected}</td></tr>
          <tr><th>Retrieved</th><td className="mono">{retrieved ?? (error ?? '…')}</td></tr>
          <tr>
            <th>Match</th>
            <td>{!settled ? '…' : match ? 'yes' : 'NO — do not rely on this page'}</td>
          </tr>
        </tbody>
      </table>
      {settled && !match && (
        <p className="small" style={{ marginTop: '.5rem' }}>
          The digest in your link does not match the document served here. Either the link refers to
          an older version, or this page is serving something else. Verify offline before relying on
          it.
        </p>
      )}
    </div>
  )
}
