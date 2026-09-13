import Link from 'next/link'

export default function Home () {
  return (
    <main>
      <section className="hero">
        <p className="eyebrow">Personal Rights Management</p>
        <h1>Your data policy. Signed by you, checkable by anyone.</h1>
        <p className="lede">
          Create a personal data policy, sign it on this device, and publish it somewhere anyone can
          check — without having to trust us.
        </p>
        <div className="row">
          <Link href="/create" className="btn">Create my policy</Link>
          <Link href="/restore" className="btn secondary">Restore from 24 words</Link>
        </div>
      </section>

      <div className="grid-3">
        <div className="panel">
          <p className="eyebrow">1 · Create</p>
          <h3>A key that never leaves</h3>
          <p className="small muted">
            Your signing key is generated here, in this browser. We never see it, so we can never
            sign as you.
          </p>
        </div>
        <div className="panel">
          <p className="eyebrow">2 · Author</p>
          <h3>Say what you permit</h3>
          <p className="small muted">
            Start from the California ALPR template. Allow, condition, or object to each use, in
            terms a machine reads and words a person does.
          </p>
        </div>
        <div className="panel">
          <p className="eyebrow">3 · Sign &amp; publish</p>
          <h3>Exactly the bytes you signed</h3>
          <p className="small muted">
            You sign on this device. We store the signed bytes, then this app downloads them again
            and checks them against what you signed.
          </p>
        </div>
      </div>

      <div className="panel">
        <h3>Don&rsquo;t trust us. Verify it.</h3>
        <p className="small muted">
          Anything published here can be checked offline with an open-source verifier and no request
          to this site. If RightsRoot disappeared tomorrow, your documents would still verify.
        </p>
        <pre>npx @rightsroot/prm-cli verify policy.json --kel kel.json --offline</pre>
      </div>

      <p className="small muted" style={{ marginTop: '2rem' }}>
        This records your instructions and the date you gave them. It does not create legal rights
        that do not already exist.
      </p>
      <p className="small muted">
        RightsRoot is the platform. <b>PRM — Personal Rights Management</b> is the open protocol it
        implements; the specification lives at{' '}
        <a href="https://rightsroot.org/spec/prm">rightsroot.org/spec/prm</a>, and anything published
        here can be verified by any implementation of it.
      </p>
    </main>
  )
}
