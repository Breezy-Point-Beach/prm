import Link from 'next/link'

export function Header () {
  return (
    <header className="site-header">
      <div className="site-header-inner">
        <Link href="/" className="brand">
          <span className="brand-mark" aria-hidden="true" />
          RightsRoot
        </Link>
        <nav className="site-nav" aria-label="Site">
          <Link href="/create">Create</Link>
          <Link href="/restore">Restore</Link>
          <a href="https://rightsroot.org/spec/prm">Specification</a>
        </nav>
      </div>
    </header>
  )
}
