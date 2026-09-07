import Link from 'next/link'

export const metadata = {
  title: 'Terms — RightsRoot',
  description: 'The terms on which RightsRoot is provided, including what it does not do.'
}

/**
 * Terms of service.
 *
 * Kept short and readable on purpose. The one section that matters most to a user is the key-loss
 * warning, so it is near the top rather than buried in a limitation-of-liability block.
 *
 * NOT REVIEWED BY A LAWYER. Flagged in docs/legal-review.md. The warranty and liability sections in
 * particular are the parts that need professional attention before this carries real weight.
 */
export default function TermsPage () {
  return (
    <main>
      <p className="small muted" style={{ margin: 0 }}>RightsRoot</p>
      <h1>Terms of Service</h1>
      <p className="muted small">Last updated 7 September 2026</p>

      <p>
        RightsRoot is operated by Breezy Point Beach LLC. By using it you agree to these terms. They
        are short because the service is narrow.
      </p>

      <h2>What RightsRoot does</h2>
      <p>
        RightsRoot helps you create a personal data policy, sign it with a key held on your own
        device, publish it at a public address, and generate notices about it. The document format is
        PRM, an open protocol; anything you publish can be verified by any implementation of it,
        including ones we do not operate.
      </p>

      <div className="note warn">
        <b>We cannot recover your key. Nobody can.</b>
        <div className="small" style={{ marginTop: '.3rem' }}>
          Your signing key is created on your device and never sent to us. If you lose your 24-word
          backup phrase and your device, your account is gone permanently. There is no password
          reset, no support recovery, and no copy on our servers. This is the same property that
          prevents us from acting as you, and it cannot be had one way without the other. Write the
          phrase down and keep it somewhere safe.
        </div>
      </div>

      <h2>What RightsRoot does not do</h2>
      <ul className="small">
        <li>
          It does not create legal rights or obligations that do not otherwise exist. A policy
          records your instructions and objections and the date you made them.
        </li>
        <li>
          It does not compel anyone to honour your policy, and it does not override a court order, a
          statutory mandate, or other controlling legal authority.
        </li>
        <li>
          It does not give legal advice. The templates are drafting aids. If the outcome matters,
          talk to a lawyer.
        </li>
        <li>
          It does not verify who you are. A signature proves an account authored a document. It does
          not prove that account belongs to any named person.
        </li>
        <li>
          It does not witness delivery. A delivery record states what you say you did, and is
          evidence of your claim rather than proof of receipt.
        </li>
      </ul>

      <h2>Your responsibilities</h2>
      <ul className="small">
        <li>Keep your backup phrase and passphrase safe. They are the account.</li>
        <li>Publish only statements about yourself and data relating to you.</li>
        <li>
          Do not use RightsRoot to harass anyone, to impersonate anyone, or to make claims you know
          to be false. Sending a notice is a communication with a real recipient; treat it that way.
        </li>
        <li>Do not attempt to disrupt the service or the ability of others to use it.</li>
      </ul>

      <h2>Publishing</h2>
      <p className="small">
        A published policy is public and can be read, copied, and archived by anyone. We serve back
        exactly the bytes you signed. We may remove content that is unlawful or that violates these
        terms, and we may remove a handle that is being used to impersonate someone.
      </p>

      <h2>Availability</h2>
      <p className="small">
        RightsRoot is provided as-is, with no guarantee of uptime, and it may change or stop. That is
        deliberately survivable: anything you have published or exported can be verified without us,
        so the disappearance of this service does not invalidate your documents. Keep your own copies
        of anything that matters — particularly your <span className="mono">.prmproof</span> bundles.
      </p>

      <h2>No warranty</h2>
      <p className="small">
        The service is provided &ldquo;as is&rdquo; and &ldquo;as available&rdquo;, without
        warranties of any kind, express or implied, including merchantability, fitness for a
        particular purpose, and non-infringement. We do not warrant that the service will be
        uninterrupted, error-free, or that it will achieve any particular result with any recipient.
      </p>

      <h2>Limitation of liability</h2>
      <p className="small">
        To the maximum extent permitted by law, Breezy Point Beach LLC is not liable for indirect,
        incidental, special, consequential, or exemplary damages, or for loss of data, keys, or
        profits, arising from your use of RightsRoot. Nothing here limits liability that cannot be
        limited by law.
      </p>
      <p className="small muted">
        In plain terms: if you lose your backup phrase, we cannot get your account back and we are not
        responsible for that loss. We told you as clearly as we know how.
      </p>

      <h2>Ending it</h2>
      <p className="small">
        You can stop at any time; ask us to remove a published policy and prove you control the key by
        signing the request. We may suspend access for a violation of these terms. Your keys and your
        exported artifacts remain yours and remain verifiable either way.
      </p>

      <h2>Changes</h2>
      <p className="small">
        These terms may change. The current version and its full history are public in the
        repository, with the date above.
      </p>

      <h2>Governing law</h2>
      <p className="small">
        These terms are governed by the laws of the State of California, without regard to conflict of
        law rules.
      </p>

      <h2>Contact</h2>
      <p className="small">
        Breezy Point Beach LLC — <a href="mailto:legal@rightsroot.com">legal@rightsroot.com</a>.
      </p>

      <div className="row" style={{ marginTop: '2rem' }}>
        <Link href="/privacy"><button className="secondary">Privacy</button></Link>
        <Link href="/"><button className="secondary">Home</button></Link>
      </div>
    </main>
  )
}
