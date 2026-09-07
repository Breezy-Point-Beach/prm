# 04 — Policy Sharing and Distribution

The policy is only useful if it reaches people. Six channels, all carrying the **same signed bytes**.

## 1. Channel matrix

| Channel | Payload | Verifiable offline? | MVP | Runs on |
|---|---|---|---|---|
| Public HTML page | rendered `humanReadable` + embedded JSON-LD | via linked JSON | ✅ | Vercel Edge, cached |
| Machine endpoint | full signed JSON | ✅ | ✅ | Vercel Edge, cached, CORS `*` |
| Short URL | 302 → canonical | n/a | ✅ | Vercel Edge / Edge Config |
| QR code | short URL + digest prefix | partially | ✅ | client render + server PNG/SVG |
| Downloadable PDF | human text + embedded signed JSON attachment | ✅ | ✅ | Vercel Node |
| Email / form attachment | `.prmpolicy.json` + PDF | ✅ | ✅ | client or Node |
| `.well-known` | policy or pointer, at the user's own domain | ✅ | ✅ | static or Edge |
| NFC card | NDEF URI record → short URL | no | beta | write from phone |
| Wallet pass | Apple `.pkpass` / Google Wallet object | no (card ≠ policy) | beta | Vercel Node + provider certs |

## 2. URL structure

```
https://rightsroot.com/u/{handle}                     human page (HTML)
https://rightsroot.com/u/{handle}/policy.json         current signed policy (application/prm-policy+json)
https://rightsroot.com/u/{handle}/v/{n}.json          historical version n, immutable,permanently cacheable
https://rightsroot.com/u/{handle}/kel.json            key event log
https://rightsroot.com/u/{handle}/ledger.json         public ledger entries + inclusion proofs
https://rightsroot.com/u/{handle}/policy.pdf          rendered PDF with embedded signed JSON
https://rightsroot.com/u/{handle}/qr.svg             QR: canonical URL + policy digest
https://rightsroot.com/p/{code}                       short URL
https://rightsroot.com/.well-known/prm-log            log metadata + log public key
https://rightsroot.com/status/{listId}                Bitstring Status List credential
```

**Content negotiation on `/u/{handle}`:** `Accept: application/json` → the signed policy;
`text/html` → the page. Plus an unambiguous `Link` header so a crawler finds the machine form:

```
Link: <https://rightsroot.com/u/ab12cd/policy.json>; rel="alternate"; type="application/prm-policy+json"
```

Register the media types `application/prm-policy+json` and `application/prm-authorization+json`; use
`+json` structured-syntax suffix so generic tooling still parses them.

## 3. `.well-known` — two distinct uses

Do not conflate these.

**(a) The individual's own domain.** A person who controls `alice.example` publishes:

```
https://alice.example/.well-known/prm-policy       → signed policy (or 302 to it)
https://alice.example/.well-known/did.json         → did:web document derived from their KEL
```

This is the strongest form: the policy is served from a domain the person controls, so PRM is not in
the trust path at all. Support it from day one via a documented copy-this-file flow — it costs almost
nothing and it is the clearest demonstration that PRM is optional.

**(b) The organization's domain.** An organization publishes its own capability descriptor:

```
https://city.gov/.well-known/prm-receiver
{
  "version": 1,
  "acknowledgmentEndpoint": "https://city.gov/api/prm/ack",
  "privacyRequestEndpoint": "https://city.gov/privacy/requests",
  "contact": "mailto:privacy@city.gov",
  "supportedCategories": ["prm:retention","prm:third-party-sharing","prm:sale"],
  "publicKeys": [ { "alg": "Ed25519", "publicKeyMultibase": "z6Mk..." } ]
}
```

A PRM client fetches this before delivering a notice. If present → API delivery. If absent → §10
fallback. This is the hook that makes integration *incremental*: an organization can support PRM by
publishing one static JSON file before writing any code.

> **Decision — `.well-known` capability discovery.**
> *Why:* lets organizations opt in progressively with zero infrastructure. *Threat:* none directly;
> it reduces the "nobody has integrated" cold-start problem. *MVP:* define the format, implement the
> client-side probe. *Standard:* RFC 8615 well-known URIs. *Simpler alternative:* a PRM-hosted registry
> of organizations — rejected, it centralizes and it goes stale.

## 4. QR codes

**Do not put the policy in the QR.** A version-40 QR holds ~2,953 bytes in binary mode at EC level L; a
real policy is 2–8 KB and grows. Instead:

```
https://rightsroot.com/p/9fK2xQ#uEiA7Zk
             ^short   ^first 8 chars of the policy digest
```

The digest fragment lets a scanner detect substitution *after* fetching: resolve the URL, hash the
policy, confirm the prefix matches what was physically printed on the card in the person's hand. It
also survives the short-URL service being compromised — an attacker who redirects the code cannot make
the digest match.

Use EC level **M** (15%) for printed cards, **Q** (25%) for a phone screen shown in daylight, and
always render the digest prefix as human-readable text under the code so it can be checked by eye.

Offline-capable variant (beta): a second, denser QR encoding a **compact CBOR policy digest + detached
JWS + issuer key**, enough to verify authorship offline without fetching. Roughly 300–400 bytes,
comfortably inside QR capacity. Useful for roadside scenarios with no connectivity.

## 5. NFC

NTAG213/215/216 with a single NDEF **URI record** pointing at the short URL. NTAG215's 504 usable bytes
are enough for the URL plus a short text record with the digest prefix. Writable from any modern phone;
no app required to read — the OS opens the URL.

Do not attempt to store the policy on the tag. Do not use tag UIDs as identifiers (a fixed, readable
UID is a tracking beacon — an NFC card that can be read by anyone who brushes past you is a genuine
threat, so the card should carry only a URL that is *already* public).

## 6. Wallet passes

Apple Wallet requires a Pass Type ID certificate; Google Wallet requires a service-account-signed JWT.
Both mean **PRM holds a signing key on the server** for this feature. That is acceptable *only* because
of a strict separation:

> The wallet pass is a **pointer and a rendering**. It is not the policy and it carries no authority.
> The pass contains: display name (optional), policy digest, short URL, QR, and version. Its signature
> attests "PRM issued this card," not "this is the person's policy." Verification always resolves to
> the signed policy.

Keep those provider certs in a KMS or Vercel-encrypted env vars, note them explicitly in §16's
"server-held key material" inventory, and make sure their compromise cannot forge a policy — it can
only forge a *card*, which any verifier will catch on resolution.

## 7. PDF

The PDF must be self-contained evidence. Structure:

1. Page 1: the `humanReadable` text, rendered.
2. A visible header block: `accountId`, policy version, effective date, **full digest in hex**, and the
   QR code.
3. The complete signed JSON **embedded as a file attachment** (PDF/A-3 style `EmbeddedFile`), so a
   verifier can extract and check the actual signed bytes.
4. A short "How to verify this document" appendix with the `npx @prm/verify` one-liner.

**On PAdES/X.509 signing:** a cryptographic PDF signature requires an X.509 certificate chain, and
Ed25519 in PDF signatures is not broadly supported by Acrobat and friends. Do not fight this. The
authority is the embedded signed JSON, not a PDF signature widget. If a counterparty demands a PAdES
signature later, obtain an organizational cert and apply it *in addition* — as a PRM attestation of
issuance, never as a substitute for the user's Ed25519 proof.

> **Decision — PDF carries embedded signed JSON rather than a PAdES signature.**
> *Why:* preserves the user's own signature as authoritative; avoids a CA dependency and an RSA/ECDSA
> detour. *Threat:* fake policies, policy substitution — the digest is printed and the signed bytes
> travel with the document. *MVP:* yes. *Standard:* PDF/A-3 embedded files, ISO 32000.
> *Simpler alternative:* plain PDF with a printed hash — acceptable for the prototype.

## 8. Caching and integrity

| Path | Cache-Control | Notes |
|---|---|---|
| `/u/{h}/v/{n}.json` | `public, max-age=31536000, immutable` | content-addressed, never changes |
| `/u/{h}/policy.json` | `public, max-age=60, stale-while-revalidate=600` | must reflect a new version quickly |
| `/u/{h}` (HTML) | `public, max-age=60, s-maxage=300` | |
| `/status/{id}` | `public, max-age=300` | revocation latency budget: 5 min |
| `/p/{code}` | `public, max-age=3600` | Edge Config lookup, no DB |

Serve `ETag` = policy digest on every JSON response. A client can then revalidate with `If-None-Match`
and get a 304 without transferring the document — cheap currency checking.

## 9. Delivery receipts

Every outbound share creates a ledger entry (§07) of type `notice.sent`, and, where the channel
supports it, a follow-up `notice.delivered` carrying the digest of the transport evidence (SMTP
`Message-ID` + DKIM-signed response, HTTP 2xx response with its body hash, USPS tracking record,
certified-mail return receipt scan). The evidence artifacts are stored encrypted; only their digests
go in the entry. See §10 for the no-integration case, which is where receipts matter most.
