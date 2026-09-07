# Notice of Personal Data Policy

**To:** City of Whittier Police Department
**Attn:** Records Division / Custodian of Records
**Address:** Records Division, Whittier Police Department, 13200 Penn St, Whittier, CA 90602
**Copy to:** ALPR system vendor (as identified in the agency contract) — privacy@example-alpr-vendor.com

**From:** PRM account `prm:eob7fei7x3ji5vnqu4kezaeh65`
**Date:** 2026-09-15
**Re:** Personal data policy and records request concerning automated license plate reader data

---

I am writing about automated license plate reader (ALPR) data your department collects, and about
records associated with one vehicle I operate.

Enclosed is my personal data policy. In short: **I do not object to the plate scan itself, or to the
immediate hotlist comparison at the moment of capture.** I do object to what happens afterwards — the
retention of reads that produced no match, the accumulation of those reads into a searchable history
of my movements, their correlation with other databases, their disclosure to other agencies or
sharing networks, their use in profiling or movement inference, and their use in training machine
learning models.

The enclosed document is signed and independently timestamped, so that you or any third party can
confirm precisely what it said and on what date, without relying on me or on any service.

**I would also like to request, as a separate matter:**

1. A copy of your ALPR usage and privacy policy.
2. The reads currently associated with the vehicle identified in the enclosed authorization.
3. Your retention period for reads that produce no hotlist match.
4. A list of the agencies, networks, or vendors with whom ALPR data has been shared.

I recognize that some of what I have asked for may be subject to statutory requirements that override
my preferences, and that some restrictions I have stated may not be ones you are obliged to honour. I
am not asserting otherwise. A partial response that tells me which restrictions your systems can and
cannot honour, and why, is more useful to me than no response.

## Enclosures

| File | What it is |
|---|---|
| `policy.json` | The signed policy. Digest `uEiC9_iVQZ_-ozuxuwrl4Uzo79pURYmwFNpB156ELrcV-rg` |
| `kel.json` | The key history proving the policy was signed by this account |
| `authorization-whittier-pd.json` | Identifies the vehicle to you, and to no one else |
| `evidence.prmproof` | A single-file evidence bundle covering all of the above |
| `notice.md` | This letter |

## Verifying this notice independently

No PRM service is required, and none is trusted:

```
npx @prm/cli verify evidence.prmproof
```

Vehicle identified to you: `US-CA-0EXAMPLE`
(The published policy contains only a salted commitment to this value. Disclosing it to you does not
disclose it to anyone else, and no PRM server holds it.)

---

*This document records my instructions and the date I gave them. It does not purport to create legal
rights that do not already exist.*
