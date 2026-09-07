# Whittier, California — worked example

The first real-world PRM test: a notice to the **City of Whittier Police Department** about a standing
California ALPR policy.

```console
pnpm --filter @prm/example-whittier generate    # placeholder identifiers, committed output
pnpm --filter @prm/example-whittier test        # generate, then verify with the network sabotaged
node examples/whittier/generate.mjs --local     # your real values, written to ./local/ (gitignored)
```

## The chain this produces

```
Standing California ALPR policy      policy.json          public, no raw identifiers
        |
        v
Recipient-specific notice            notice.json          carries the plate, for Whittier only
        |
        v
Notice PDF                           notice.pdf           what you actually mail
        |
        v
Proof bundle                         notice.prmproof      single-file, independently verifiable
        |
        v
Delivery record                      delivery.json        what you say you sent, and when
        |
        v
Response record                      response.json        what came back, if anything
```

## What this notice is, and is not

It is a **notice and an evidentiary artifact**. It records a standing policy, directs it at a named
recipient, and preserves what happened next.

It is **not a records request**. It does not ask about retention periods, sharing lists, access logs,
contracts, technical capability, or legal authority. Those questions are handled through separate
correspondence; repeating them here would turn a focused notice into a second information request and
invite it to be routed and answered as one. `verify.mjs` fails the build if that language creeps back
in.

It does not assert that the recipient is obliged to do anything. `buildNotice` refuses to sign text
containing phrases like "you must comply" or "legally binding", and the verifier checks the generated
notice for them.

## No private data lives here

Committed artifacts use the placeholder plate `US-CA-0EXAMPLE`. Real values are entered at generation
time via `--local` and written only to `examples/whittier/local/`, which is gitignored.

`verify.mjs` enforces this. It fails if the committed artifacts carry a non-placeholder plate, if a
raw identifier appears in any published file, if the plate appears anywhere in the bundle other than
`notice.json`, or if a `local/` directory has been committed.

**The plate appears in exactly one artifact**: the notice delivered to the named agency. The published
policy carries only a salted commitment to it, so nobody else can work out what it is, and the agency
can still confirm the policy covers the right vehicle.

## The offline acceptance test

`verify.mjs` sabotages `fetch`, `XMLHttpRequest`, `WebSocket`, `http.request` and `https.request`
before importing anything, with a control test proving the sabotage bites. It then establishes, using
only the portable files:

- the policy signature is valid, and the issuer key chain self-certifies
- the notice references the correct policy by **both** digests
- delivery and response records reference the correct notice
- every manifest entry matches its artifact byte for byte
- no private identifier reached any published artifact

and that tampering is detected: a modified policy, reserialized policy bytes, a modified manifest, a
missing artifact, an artifact smuggled in without a manifest entry, and a modified delivery timestamp.
A control test confirms the untouched bundle still verifies.

The same bundle has been verified by the CLI inside a Linux network namespace with no interfaces.

## Verifying, as a recipient

```console
npx @prm/cli verify notice.prmproof
```

No PRM service is contacted, and none is trusted. `verification/instructions.txt` inside the bundle
explains every check, including how to verify RFC 3161 timestamp tokens with `openssl` when present.

## Two digests, and why both are recorded

| | Identifies | Changes when |
|---|---|---|
| Policy digest | the document | its meaning changes |
| Byte digest | the exact bytes | any byte moves, including whitespace |

A reserialized policy keeps its policy digest but gets a different byte digest. Recording both lets
the issuer show not only which policy was issued, but which exact file was delivered.

While building this example, the offline suite caught a real instance: the generator was appending a
trailing newline when writing `policy.json`, so the file on disk no longer matched the byte digest the
notice pinned. A recipient running the very check the notice invites would have seen a mismatch.

## Relationship to the normative test vectors

These artifacts are **not** normative test vectors and do not participate in the digest guard. The
vectors in `spec/` are deliberately synthetic and jurisdiction-neutral: they pin the wire format, not
any jurisdiction's law.
