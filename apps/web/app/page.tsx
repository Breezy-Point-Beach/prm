import Link from 'next/link'

export default function Home () {
  return (
    <main>
      <h1>RightsRoot</h1>
      <p className="muted">
        Create a personal data policy, sign it on this device, and publish it somewhere anyone can
        check — without having to trust us.
      </p>
      <p className="small muted">
        RightsRoot puts the individual back at the root of their data rights.
      </p>

      <div className="panel">
        <h2 style={{ marginTop: 0 }}>How this works</h2>
        <ol className="small">
          <li><b>Create.</b> Your signing key is generated here, in this browser, and never leaves it.</li>
          <li><b>Author.</b> Start from the California ALPR template and say what you permit and object to.</li>
          <li><b>Sign &amp; publish.</b> You sign on this device. We store exactly the bytes you signed.</li>
        </ol>
        <p className="small muted">
          After publishing, this app downloads the policy back from the server and checks it byte for
          byte against what you signed. If anything differs, the publish is reported as failed.
        </p>
      </div>

      <div className="row">
        <Link href="/create"><button>Start</button></Link>
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
