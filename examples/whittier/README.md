# Whittier, California — worked example

The first real-world PRM test: a notice to the **City of Whittier Police Department** and its ALPR
vendor, using the production California ALPR template.

```console
pnpm --filter @prm/example-whittier generate    # placeholder identifiers, committed output
pnpm --filter @prm/example-whittier test        # generate, then verify
node examples/whittier/generate.mjs --local     # your real values, written to ./local/ (gitignored)
```

## No private data lives here

The committed artifacts use the placeholder plate `US-CA-0EXAMPLE` and `user0001@example.org`.
Bryan's actual plate, address, phone, and email are entered at generation time on his own machine and
are written only to `examples/whittier/local/`, which is gitignored.

`verify.mjs` enforces this: it fails if the committed artifacts contain a non-placeholder plate, if a
raw identifier appears in any published file, or if a `local/` directory has been committed.

## What gets generated

| File | Published? | Contents |
|---|---|---|
| `policy.json` | **yes** | The signed policy. Contains salted *commitments* to the plate and email — never the values |
| `kel.json` | **yes** | Key history proving the policy was signed by this account |
| `ledger.json` | no | What was sent, to whom, with what delivery evidence |
| `signed-tree-head.json` | **yes** | Transparency log head. Opaque hashes only |
| `authorization-whittier-pd.json` | no — delivered to one recipient | Discloses the plate to Whittier PD **and to nobody else** |
| `evidence.prmproof` | no — handed over deliberately | Single-file bundle a lawyer or records officer can verify offline |
| `notice.md` | — | The cover letter |

The plate appears in exactly one artifact: the authorization delivered to the named agency. That is
the selective-disclosure design working — the agency can confirm which vehicle the notice concerns,
and no PRM server ever holds the value.

## The argument the policy makes

**Authorized:** the plate scan itself, the immediate hotlist comparison at the moment of capture, use
tied to a valid individualized investigation with legal process, and genuine emergencies.

**Objected to:** retention of non-hit reads, historical movement storage and search, aggregation,
cross-database correlation, cross-agency and network sharing, profiling, derived movement inference,
sale, commercialization, advertising, AI/model training, and biometric processing of occupants.

The line is the moment of comparison. Everything before it is conceded; everything after it is
addressed separately. That distinction is what makes the notice answerable on its merits rather than
dismissible as a blanket refusal.

## On legal effect

The policy states **standing authorization, objection, non-consent, and requested restrictions**. It
does not claim PRM creates rights, that every restriction binds the recipient, or that non-compliance
is unlawful. California has ALPR-specific statute (Civil Code § 1798.90.5 et seq.), but whether any
particular restriction is enforceable is a question for a lawyer and a court.

The cover letter also makes a **records request** — the agency's ALPR usage and privacy policy,
reads associated with the vehicle, the retention period for non-hits, and the list of agencies and
networks the data has been shared with. A request has a defined process and tends to get answered;
an objection alone may not.

## Verifying, as a recipient

```console
npx @prm/cli verify evidence.prmproof
```

No PRM service is contacted, and none is trusted. This works with `prm.app` unreachable.

## Relationship to the normative test vectors

These artifacts are **not** normative test vectors and do not participate in the digest guard. They
illustrate the flow and are validated by CI, so they can be regenerated freely as the template
evolves. The vectors in `spec/` are deliberately synthetic and jurisdiction-neutral: they pin the wire
format, not any jurisdiction's law.
