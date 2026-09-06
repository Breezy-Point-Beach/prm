---
name: Specification question or ambiguity
about: Something in spec/ or docs/ is unclear, underspecified, or contradictory
labels: spec
---

**Which document / section**

<!-- e.g. docs/02-policy-format.md §2, or spec/schemas/prm-policy-v1.schema.json -->

**The ambiguity**

<!-- What could two implementers reasonably read differently? -->

**Does it affect the canonical bytes?**

- [ ] Yes — two implementations could produce different digests for the same document
- [ ] No — presentation, naming, or documentation only

<!-- If yes, this is high priority: it breaks cross-implementation verification. -->
