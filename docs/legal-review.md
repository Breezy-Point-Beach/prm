# Open questions for legal review

Two phrases in the California ALPR template need an attorney's view before a notice built from it is
sent to a real recipient. Both are **unchanged in the code** — they are flagged here rather than
edited, because guessing at the answer is worse than asking.

Everything else in the packet has been reviewed and is considered settled. See
`packages/schema/src/notice-language.ts` for the wording that is deliberately fixed.

---

## 1. The law-enforcement rule may read as an affirmative 60-day authorization

**Current rule** (`packages/schema/src/templates/alpr.ts`, `prm:law-enforcement`):

```ts
{
  category: 'prm:law-enforcement',
  decision: 'conditional',
  conditions: {
    requiresLegalProcess: true,
    requiresNotice: true,
    maxRetention: 'P60D',
    purposes: ['prm:active-investigation']
  },
  basisAcknowledged: ['court-order', 'statutory-override']
}
```

**How it renders in the notice:**

> Law-enforcement use — retention limited to 60 days; requires legal process; requires written notice
> to me; only for: active investigation.

**The concern.** A recipient could reasonably read that as *"the issuer affirmatively permits law
enforcement to retain his ALPR data for 60 days whenever there is legal process and an active
investigation."* If the agency already possesses independent legal authority, the issuer does not need
to grant anything — and a voluntary grant could later be quoted back as:

> "His own policy expressly authorized 60-day retention."

**The position this template was meant to express** is closer to:

- hotlist comparison → not objected to
- no hit → delete
- individualized investigation backed by independent legal authority → **that authority governs**, and
  the issuer neither grants nor withholds anything

Those are subtly but materially different.

**Question for counsel:** is it better to state a conditional permission with a retention ceiling, or
to say nothing affirmative and simply acknowledge that independent legal authority governs? Does
stating a ceiling help (it documents a limit the issuer asked for) or hurt (it manufactures a
permission that did not previously exist)?

**A partial mitigation already applied.** The PDF previously grouped `conditional` rules under
"Generally permitted or acknowledged", which made a conditional rule read as an affirmative grant.
It now renders three distinct groups:

- Not objected to
- **Not objected to, but only on these terms**
- Objected to absent separate legal authority or my authorization

That reduces the misreading. It does **not** resolve the substantive question, which is whether the
rule should assert a retention ceiling at all.

---

## 2. Emergency use requires written notice, which may not be feasible

**Current rule** (`prm:emergency`):

```ts
{
  category: 'prm:emergency',
  decision: 'conditional',
  conditions: { requiresNotice: true, note: 'Imminent threat to life, for the duration...' },
  basisAcknowledged: ['vital-interest']
}
```

**How it renders:** "Emergency use — requires written notice to me."

**The concern.** An emergency exception may arise where contemporaneous notice is not feasible, or
where disclosure is itself temporarily restricted. Asking for something the recipient cannot lawfully
or practically do invites the whole rule to be dismissed.

**Possible alternative** for counsel to weigh:

> subject to applicable notice requirements after the emergency, where legally permitted

**Question for counsel:** is a qualified after-the-fact notice request more defensible than an
unqualified one? Is asking for notice at all useful here, or does it weaken the objection?

---

## What is settled and should not change

These were reviewed and are considered correct. Adding further defensive language would start to
undermine the document.

**The requested treatment.** Establishes the position without bluffing about legal authority:

> Please associate this Personal Rights Management policy with records reasonably identifiable as
> relating to me and honor the stated instructions and objections to the extent permitted by
> applicable law, policy, contract, and technical capability.

**The non-consent fallback.** The strongest sentence in the packet:

> If any portion of this policy cannot or will not be honored, this notice should still be treated as
> a record of my express position and non-consent regarding those downstream uses.

**The disclaimer level.** It appears in the introductory explanation, in the Legal Effect section, and
in the footer of every page. That is enough. More would read as defensiveness.

**The appendix.** Being explicit about what the signatures do *not* prove — that they establish no
real-world identity, and do not prove delivery — makes the system more credible, not less.

---

## Changing a rule after review

The template lives in `packages/schema/src/templates/alpr.ts`. Editing it changes what NEW policies
say; it does not and cannot alter a policy that has already been signed, and it is not a protocol
change. Existing notices remain verifiable exactly as issued.

The rendering layer (`packages/schema/src/presentation.ts`) can only change wording, never a decision
or a condition. A test asserts that. So if the answer is purely "say it differently", that is a
presentation change; if it is "ask for something different", that is a template change.
