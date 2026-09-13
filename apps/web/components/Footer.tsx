import Link from 'next/link'

/**
 * Site footer.
 *
 * Carries the privacy and terms links, and restates the one thing a user most needs to know before
 * they create a key: nobody can recover it for them.
 */
export function Footer () {
  return (
    <footer className="site-footer">
      <div className="links">
        <Link href="/privacy">Privacy</Link>
        <Link href="/terms">Terms</Link>
        <Link href="/restore">Restore</Link>
        <a href="https://rightsroot.org/spec/prm">PRM specification</a>
        <a href="https://github.com/Breezy-Point-Beach/prm">Source</a>
      </div>
      <p>
        No account, no cookies, no analytics. Your signing key never leaves your device — which also
        means we cannot recover it for you.
      </p>
      <p>RightsRoot is operated by Breezy Point Beach LLC. PRM is an open protocol.</p>
    </footer>
  )
}
