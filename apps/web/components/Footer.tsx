import Link from 'next/link'

/**
 * Site footer.
 *
 * Carries the privacy and terms links, and restates the one thing a user most needs to know before
 * they create a key: nobody can recover it for them.
 */
export function Footer () {
  return (
    <footer style={{
      maxWidth: '46rem', margin: '0 auto', padding: '2rem 1.25rem 3rem',
      borderTop: '1px solid var(--line)', fontSize: '.82rem'
    }}>
      <p className="muted" style={{ marginTop: 0 }}>
        <Link href="/privacy">Privacy</Link>
        {' · '}
        <Link href="/terms">Terms</Link>
        {' · '}
        <a href="https://rightsroot.org/spec/prm">PRM specification</a>
        {' · '}
        <a href="https://github.com/Breezy-Point-Beach/prm">Source</a>
      </p>
      <p className="muted" style={{ marginBottom: 0 }}>
        No account, no cookies, no analytics. Your signing key never leaves your device — which also
        means we cannot recover it for you.
      </p>
      <p className="muted" style={{ marginBottom: 0 }}>
        RightsRoot is operated by Breezy Point Beach LLC. PRM is an open protocol.
      </p>
    </footer>
  )
}
