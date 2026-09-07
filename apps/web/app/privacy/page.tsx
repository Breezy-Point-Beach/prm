import Link from 'next/link'

export const metadata = {
  title: 'Privacy — RightsRoot',
  description: 'What RightsRoot receives, what it never receives, and how to check either claim yourself.'
}

/**
 * The privacy policy.
 *
 * Written to be ACCURATE rather than flattering. A privacy product that overstates its own privacy
 * is both a consumer-protection problem and self-defeating: the whole thesis is that claims should
 * be checkable, so every claim here is one a reader can verify — by reading the source, by watching
 * the network tab, or by running the verifier.
 *
 * Specifically, this page does NOT say "we collect nothing". That would be false: the hosting
 * provider sees an IP address, as it must to deliver a page. Saying so plainly costs nothing and
 * makes the rest believable.
 */
export default function PrivacyPage () {
  return (
    <main>
      <p className="small muted" style={{ margin: 0 }}>RightsRoot</p>
      <h1>Privacy</h1>
      <p className="muted small">Last updated 7 September 2026</p>

      <div className="note ok">
        <b>There is no account, no email address, no password on our servers, no cookie, and no
        analytics.</b>
        <div className="small muted" style={{ marginTop: '.3rem' }}>
          Every claim on this page is one you can check yourself. Where we cannot make a claim
          honestly, we say so instead of rounding it off.
        </div>
      </div>

      <h2>What never reaches us</h2>
      <p>
        Your signing key is generated in your browser and never leaves the device it was created on.
        Neither does anything derived from it. We cannot sign as you, we cannot read your vault, and
        we cannot recover your account — not as a policy choice, but because we do not have the
        material required to do any of it.
      </p>
      <ul className="small">
        <li>Your private signing key, and every key derived from it</li>
        <li>Your 24-word backup phrase</li>
        <li>Your vault passphrase</li>
        <li>The contents of your vault</li>
        <li>Your license plate, email address, or any other raw identifier</li>
        <li>Policy drafts, while you are still writing them</li>
        <li>Notices you generate, and the recipients you address them to</li>
        <li>Delivery records, response records, and any evidence you attach</li>
        <li>The PDF you download</li>
      </ul>
      <p className="small muted">
        Notices and their PDFs are built in your browser and downloaded directly. They are never
        uploaded. That is why a notice can carry your plate while your published policy cannot.
      </p>

      <h2>What we receive, and only when you press publish</h2>
      <ul className="small">
        <li>
          <b>The signed policy you chose to publish.</b> It is a public document by design. It
          contains no raw identifiers — only salted cryptographic commitments, which cannot be
          reversed to recover the value behind them.
        </li>
        <li>
          <b>Your public key history.</b> Public keys and digests. This is what lets anyone confirm
          you signed your own policy.
        </li>
        <li>
          <b>A handle you choose,</b> such as the name in <span className="mono">/u/yourname</span>.
          It does not have to relate to your real identity, and we do not ask whether it does.
        </li>
      </ul>
      <p className="small muted">
        We store the signed bytes exactly as you produced them, and serve them back unchanged. We do
        not parse, rewrite, enrich, or index the contents.
      </p>

      <h2>What our hosting provider sees</h2>
      <p>
        This is the part most privacy policies leave out. RightsRoot runs on Vercel. Like any web
        host, Vercel processes your IP address and request details in order to deliver the page and
        to defend against abuse. We do not add to that, we do not query it, and we do not join it to
        anything you publish — but we would be misleading you if we claimed nobody sees an IP.
      </p>
      <p className="small muted">
        If that matters for your situation, you can reach this site over Tor or a VPN, and you can
        verify any published policy entirely offline without contacting us at all.
      </p>

      <h2>No analytics, and how to confirm it</h2>
      <p>
        There is no analytics script, no session recording, no tag manager, no advertising pixel, and
        no third-party resource of any kind. The page loads only its own JavaScript.
      </p>
      <p className="small muted">
        Check it: open your browser&rsquo;s network tab and load any page here. Every request goes to
        this domain. Or read the source — the repository is public.
      </p>

      <h2>Cookies</h2>
      <p>None. We do not set any, for any purpose, including &ldquo;essential&rdquo; ones.</p>
      <p className="small muted">
        Your browser stores your encrypted vault and your drafts in local storage on your own device.
        That never leaves your machine and is not readable by us. Clearing your browser data deletes
        it, and without your backup phrase it cannot be recovered.
      </p>

      <h2>Publishing is a public act</h2>
      <p>
        A published policy is meant to be read. Anyone with the link can fetch it, and search engines
        or archives may copy it. It contains no raw identifiers, but it is permanent in the sense that
        anything public is permanent.
      </p>
      <p className="small muted">
        Two honest limits. If you give the same published policy to two organizations, those two can
        tell they received the same document. And if you tell someone your handle, you have linked
        yourself to it — we cannot undo that.
      </p>

      <h2>Deletion</h2>
      <p>
        You can ask us to remove a published policy and its handle, and we will. Because there is no
        account, tell us the handle and prove you control the key by signing the request — that is the
        only way we can tell it is yours.
      </p>
      <p className="small muted">
        We cannot delete copies other people already downloaded, and we would not claim otherwise.
        Anything you delivered to a recipient is in their hands.
      </p>

      <h2>Children</h2>
      <p>
        RightsRoot is not directed at children, and we have no way to know a user&rsquo;s age because
        we ask nothing about you.
      </p>

      <h2>Changes</h2>
      <p>
        If this policy changes materially, the change will be visible in the public repository&rsquo;s
        history alongside the date above. There is no mailing list to notify, because we do not have
        your email address.
      </p>

      <h2>Contact</h2>
      <p className="small">
        RightsRoot is operated by Breezy Point Beach LLC. Privacy questions:{' '}
        <a href="mailto:privacy@rightsroot.com">privacy@rightsroot.com</a>.
      </p>

      <div className="row" style={{ marginTop: '2rem' }}>
        <Link href="/terms"><button className="secondary">Terms of Service</button></Link>
        <Link href="/"><button className="secondary">Home</button></Link>
      </div>
    </main>
  )
}
