import Link from 'next/link'

export default function Home () {
  return (
    <main>
      <h1>Personal Rights Management</h1>
      <p className="muted">
        Create a personal data policy, sign it on this device, and publish it somewhere anyone can
        check — without having to trust us.
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
    </main>
  )
}
