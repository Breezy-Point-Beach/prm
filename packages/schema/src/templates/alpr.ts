import type { Rule } from '../types.js'

/**
 * ALPR / automated license plate reader policy template — California.
 *
 * This is the production, user-facing template and the basis of PRM's first real-world test: a
 * notice to the City of Whittier, California and its ALPR provider. See examples/whittier/.
 *
 * Three properties are deliberate, and each exists because the alternative fails in practice:
 *
 *  1. It CONCEDES the legitimate uses — lawful observation in a public place, the immediate hotlist
 *     comparison, use tied to a genuine individualized investigation, and emergencies. A blanket
 *     refusal reads as unserious and gets filed under activist mail. A policy that engages with how
 *     the system actually works has to be answered on the merits.
 *
 *  2. It separates the MOMENT of observation from everything downstream. The scan is not the
 *     objection; the persistent database built from scans is. That line is the whole argument, and
 *     it is one most people grasp in a sentence.
 *
 *  3. It ACKNOWLEDGES lawful override. Conceding that a court order or a statutory mandate outranks
 *     the issuer removes the easiest reason to dismiss the document, and costs nothing the issuer
 *     could have enforced anyway.
 *
 * ON LEGAL EFFECT — read before editing the prose.
 *
 * This template expresses standing authorization, objection, non-consent, and requested restrictions.
 * It does NOT assert that PRM creates rights, that every restriction binds the recipient, or that
 * non-compliance is unlawful. California has ALPR-specific statute (Civil Code section 1798.90.5 et
 * seq.) and a private right of action, but whether any particular restriction is enforceable is a
 * question of law for a lawyer and a court, not something this file may decide. Overstating it is the
 * fastest way to make the whole project dismissible, so the wording stays careful on purpose.
 */

export interface AlprTemplateOptions {
  /**
   * State subdivision for the jurisdiction field, ISO 3166-2 style without the country prefix.
   * Defaults to CA because that is where the first deployment is; the template is not CA-only.
   */
  state?: string
  /** Retention ceiling for a read tied to an active, individualized investigation. */
  investigationRetention?: string
  /** Ask for written notice when an override (legal process or emergency) is exercised. */
  requestNoticeOnOverride?: boolean
}

export function alprRules (opts: AlprTemplateOptions = {}): Rule[] {
  const {
    state = 'CA',
    investigationRetention = 'P60D',
    requestNoticeOnOverride = true
  } = opts
  const jurisdiction = `US-${state}`

  return [
    // ---- Standing authorization: what I do not object to ----------------------
    {
      category: 'prm:observation',
      decision: 'allow',
      note: 'I do not object to the lawful capture of my plate in a public place at the moment it occurs.'
    },
    {
      category: 'prm:transactional',
      decision: 'conditional',
      conditions: {
        maxRetention: 'PT0S',
        purposes: ['prm:hotlist-comparison'],
        jurisdictions: [jurisdiction],
        note:
          'Immediate comparison against a lawfully constituted hotlist at the moment of capture. ' +
          'This is the use I authorize; it completes when the comparison completes.'
      }
    },
    // UNDER LEGAL REVIEW — see docs/legal-review.md §1.
    //
    // As written this may read as an affirmative grant: "the issuer permits 60-day retention whenever
    // there is legal process and an active investigation." If the agency already has independent
    // legal authority, the issuer need not grant anything, and a voluntary grant could be quoted back
    // as "his own policy expressly authorized 60-day retention."
    //
    // The intended position is closer to: that authority governs, and the issuer neither grants nor
    // withholds. Do not change this without counsel's answer.
    {
      category: 'prm:law-enforcement',
      decision: 'conditional',
      conditions: {
        requiresLegalProcess: true,
        requiresNotice: requestNoticeOnOverride,
        maxRetention: investigationRetention,
        purposes: ['prm:active-investigation'],
        jurisdictions: [jurisdiction],
        note:
          'Use tied to a valid, individualized investigative purpose, retained only for as long as ' +
          'that specific investigation requires.'
      },
      basisAcknowledged: ['court-order', 'statutory-override']
    },
    // UNDER LEGAL REVIEW — see docs/legal-review.md §2.
    //
    // An unqualified notice requirement may be infeasible: an emergency can arise where
    // contemporaneous notice is impossible, or where disclosure is temporarily restricted. Asking for
    // something the recipient cannot lawfully do invites the rule to be dismissed. A qualified
    // after-the-fact form may be more defensible.
    {
      category: 'prm:emergency',
      decision: 'conditional',
      conditions: {
        requiresNotice: requestNoticeOnOverride,
        note: 'An imminent threat to life, for the duration of that emergency only.'
      },
      basisAcknowledged: ['vital-interest']
    },

    // ---- Objection: everything downstream of the observation -----------------
    {
      category: 'prm:retention',
      decision: 'conditional',
      conditions: {
        maxRetention: 'PT0S',
        recipients: ['prm:none'],
        note:
          'A read that produced no hotlist match has served its purpose at the instant of comparison. ' +
          'I do not consent to its retention beyond that moment.'
      }
    },
    {
      category: 'prm:location-history',
      decision: 'deny',
      note:
        'I object to the storage of my vehicle observations as a time-series location history, and to ' +
        'historical search of such a record.'
    },
    {
      category: 'prm:correlation',
      decision: 'deny',
      note:
        'I object to aggregating these reads with one another or correlating them with records held in ' +
        'other databases or systems.'
    },
    {
      category: 'prm:profiling',
      decision: 'deny',
      note: 'I object to the construction of any behavioral profile from where my vehicle has been.'
    },
    {
      category: 'prm:inference',
      decision: 'deny',
      note:
        'I object to derived movement inference: pattern-of-life analysis, travel prediction, ' +
        'anomaly or "unusual movement" scoring, and association analysis based on co-location.'
    },
    {
      category: 'prm:third-party-sharing',
      decision: 'deny',
      note:
        'I object to disclosure to other agencies and to participation in any regional, statewide, ' +
        'federal, or commercial sharing network.'
    },
    { category: 'prm:sale', decision: 'deny', note: 'I do not consent to the sale of these records.' },
    {
      category: 'prm:commercialization',
      decision: 'deny',
      note: 'I do not consent to commercial exploitation of these records by an agency or its vendor.'
    },
    { category: 'prm:advertising', decision: 'deny' },
    {
      category: 'prm:ai-training',
      decision: 'deny',
      note:
        'I object to the inclusion of these records in the training, fine-tuning, or evaluation of any ' +
        'machine learning model, including vendor product development.'
    },
    {
      category: 'prm:biometric',
      decision: 'deny',
      note: 'I object to biometric processing of imagery of vehicle occupants.'
    },
    {
      category: 'prm:deletion',
      decision: 'conditional',
      conditions: {
        maxRetention: 'PT0S',
        requiresNotice: false,
        note:
          'I request deletion of non-hit reads immediately, and of investigation-related reads on ' +
          'closure of the specific matter that justified retaining them.'
      }
    }
  ]
}

/**
 * Default prose, carried INSIDE the signed bytes so the words and the machine rules cannot drift.
 *
 * Written to be read by a records clerk in under two minutes. No legal threats: a notice that reads
 * as a demand gets routed to legal and dies, while one that reads as a records request gets processed.
 */
export function alprHumanReadable (opts: { agency?: string; state?: string } = {}): string {
  const agency = opts.agency ?? 'your agency'
  const stateName = opts.state === 'CA' || opts.state === undefined ? 'California' : opts.state

  return `# Personal Data Policy — Automated License Plate Reader Records

## What I authorize

I do not object to the lawful photographing of my vehicle's license plate in a public place, nor to
the immediate comparison of that plate against a lawfully constituted hotlist at the moment of
capture. I understand that is what the system is for, and I am not asking ${agency} to stop operating
it.

Where there is a valid, individualized investigative purpose supported by appropriate legal process,
or a genuine emergency involving an imminent threat to life, I do not object to the use of a read
about my vehicle for the duration of that specific matter.

## What I object to and do not consent to

Everything that happens after the moment of comparison is a separate act, and I address it separately.
I object to, and do not consent to:

- retention of a read that produced no hotlist match, beyond the instant of comparison;
- storage of my vehicle observations as a historical location record, and search of such a record;
- aggregation of these reads with one another to reconstruct my movements over time;
- correlation of these reads with records held in other databases or systems;
- disclosure to other agencies, or to any regional, statewide, federal, or commercial sharing network;
- behavioral profiling, and derived movement inference such as pattern-of-life analysis, travel
  prediction, or "unusual movement" scoring;
- sale, commercial exploitation, or advertising use;
- inclusion in the training, fine-tuning, or evaluation of any machine learning model, including
  vendor product development;
- biometric processing of imagery of vehicle occupants.

## What this document is, and is not

This is a record of my instructions and the date on which I gave them. It is signed and independently
timestamped so that a third party can confirm exactly what it said and when it existed.

It does not purport to create rights that do not already exist, and I make no claim here about which
of these restrictions ${stateName} law obliges you to honour. Where a court order or a specific
statutory mandate requires something I have objected to, I acknowledge that it governs, and I ask only
for written notice and for retention limited to what that basis actually requires.

## What I am asking of you

Please confirm receipt, and tell me which of these restrictions your systems can and cannot honour,
and why. A partial answer with a citation is more useful to me than no answer.

I would also like to know what reads you currently hold that are associated with my vehicle, how long
you retain them, and with whom they have been shared.`
}

export const TEMPLATES = {
  alpr: {
    id: 'prm:template:alpr:v2',
    label: 'License plate readers (ALPR)',
    summary:
      'Authorizes the scan and the immediate hotlist check. Objects to retention of non-hits, ' +
      'movement history, aggregation, cross-agency sharing, correlation, profiling, derived movement ' +
      'inference, sale, advertising, AI training, and biometric processing.',
    rules: alprRules,
    humanReadable: alprHumanReadable,
    defaultJurisdictions: (state = 'CA') => [`US-${state}`, 'US'],
    jurisdictionHint: 'Your state, e.g. US-CA.'
  }
} as const

export type TemplateId = keyof typeof TEMPLATES
