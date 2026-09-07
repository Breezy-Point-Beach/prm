import type { Rule } from '../types.js'

/**
 * ALPR / automated license plate reader policy template.
 *
 * This is the first meaningful PRM template and the demonstration case in docs/11.
 *
 * Two properties make it hard to dismiss, and both are deliberate:
 *
 *  1. It CONCEDES the legitimate uses — lawful observation, the immediate hotlist check, genuine
 *     emergencies. A blanket refusal reads as unserious and gets filed under activist mail. A policy
 *     that engages with how the system actually works has to be answered on the merits.
 *
 *  2. It ACKNOWLEDGES lawful override on the law-enforcement rule. Conceding that a court order or a
 *     statutory mandate outranks the issuer removes the single easiest reason to dismiss the whole
 *     document, at the cost of nothing the issuer could have enforced anyway.
 */

export interface AlprTemplateOptions {
  /** Retain hit reads for the duration of an active investigation, expressed as an ISO 8601 duration. */
  hitRetention?: string
  /** Require written notice when an emergency or legal-process exception is exercised. */
  requireNoticeOnOverride?: boolean
}

export function alprRules (opts: AlprTemplateOptions = {}): Rule[] {
  const { hitRetention = 'P90D', requireNoticeOnOverride = true } = opts

  return [
    // ---- Potentially permitted -------------------------------------------------
    {
      category: 'prm:observation',
      decision: 'allow',
      note: 'I do not contest the lawful capture of my plate in a public place.'
    },
    {
      category: 'prm:transactional',
      decision: 'conditional',
      conditions: {
        maxRetention: 'PT0S',
        purposes: ['prm:hotlist-comparison'],
        note: 'Immediate comparison against a lawfully constituted hotlist at the moment of capture.'
      }
    },
    {
      category: 'prm:law-enforcement',
      decision: 'conditional',
      conditions: {
        requiresLegalProcess: true,
        requiresNotice: requireNoticeOnOverride,
        maxRetention: hitRetention,
        purposes: ['prm:active-investigation'],
        note:
          'Use tied to a valid, individualized investigative purpose. Retention limited to the ' +
          'duration of that investigation.'
      },
      basisAcknowledged: ['court-order', 'statutory-override']
    },
    {
      category: 'prm:emergency',
      decision: 'conditional',
      conditions: {
        requiresNotice: requireNoticeOnOverride,
        note: 'Imminent threat to life, for the duration of the emergency only.'
      },
      basisAcknowledged: ['vital-interest']
    },

    // ---- Objected to unless separately authorized -------------------------------
    {
      category: 'prm:retention',
      decision: 'conditional',
      conditions: {
        maxRetention: 'PT0S',
        recipients: ['prm:none'],
        note: 'Delete a non-hit read immediately. A read that produced no match has served its purpose.'
      }
    },
    {
      category: 'prm:location-history',
      decision: 'deny',
      note: 'No time-series record of my movements, and no historical movement search.'
    },
    {
      category: 'prm:correlation',
      decision: 'deny',
      note: 'No joining these reads to other databases or agency systems.'
    },
    {
      category: 'prm:profiling',
      decision: 'deny',
      note: 'No behavioral profile built from where my vehicle has been.'
    },
    {
      category: 'prm:inference',
      decision: 'deny',
      note: 'No pattern-of-life analysis, no anomalous-movement scoring, no derived travel inference.'
    },
    {
      category: 'prm:third-party-sharing',
      decision: 'deny',
      note: 'No cross-agency sharing and no participation in a regional or national sharing network.'
    },
    { category: 'prm:sale', decision: 'deny' },
    { category: 'prm:commercialization', decision: 'deny' },
    { category: 'prm:advertising', decision: 'deny' },
    {
      category: 'prm:ai-training',
      decision: 'deny',
      note: 'Including vendor model development or improvement using reads of my vehicle.'
    },
    {
      category: 'prm:biometric',
      decision: 'deny',
      note: 'No processing of imagery of vehicle occupants.'
    },
    {
      category: 'prm:deletion',
      decision: 'conditional',
      conditions: {
        maxRetention: 'PT0S',
        note: 'Delete non-hit reads immediately; delete investigation-related reads on case closure.'
      }
    }
  ]
}

/**
 * Default prose. Carried inside the signed bytes so the words and the machine rules cannot drift.
 * The user may edit it before signing; the UI flags divergence but does not prevent it.
 */
export function alprHumanReadable (): string {
  return `# Personal Data Policy — Vehicle Movement Records

I consent to the lawful observation of my vehicle's license plate in public places, and to the
immediate comparison of that plate against a lawfully constituted hotlist at the moment of capture.

I object to the persistent retention of any read that does not result in a match. I object to the
construction of a historical record of my movements, to searching such a record, to correlating these
reads with other databases, to disclosing them to other agencies or to any regional or national
sharing network, to their sale or commercial exploitation, to their use in behavioral profiling or
derived inference, and to their inclusion in the training or evaluation of any machine learning model.

I acknowledge that a court order or a specific statutory mandate may lawfully override these
objections, and I do not assert otherwise. Where such a basis exists, I request written notice and
retention limited to what that basis actually requires.

In an emergency involving an imminent threat to life, I consent to the use of this data for the
duration of that emergency.

This document records my instructions and the date on which they were made. Please confirm receipt and
state which of these restrictions your systems can and cannot honour.`
}

export const TEMPLATES = {
  alpr: {
    id: 'prm:template:alpr:v1',
    label: 'License plate readers (ALPR)',
    summary:
      'Permits the scan and the immediate hotlist check. Objects to retention of non-hits, movement ' +
      'history, sharing, profiling, sale, and AI training.',
    rules: alprRules,
    humanReadable: alprHumanReadable,
    jurisdictionHint: 'Add your state, e.g. US-CA.'
  }
} as const

export type TemplateId = keyof typeof TEMPLATES
