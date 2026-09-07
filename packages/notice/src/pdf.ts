import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from 'pdf-lib'
import QRCode from 'qrcode'
import type { Notice, Policy, Rule } from '@prm/schema'
import {
  categoryLabel, machineSummary, PRM_EXPLANATION, OBSERVATION_DISTINCTION,
  VERIFICATION_NOTE, RECIPIENT_TYPE_LABELS
} from '@prm/schema'

/**
 * The human-readable notice packet.
 *
 * THE PDF IS A REPRESENTATION, NOT THE NORMATIVE DOCUMENT. Everything it says about the policy is
 * derived from the signed policy passed in — there is no second, hand-authored description of the
 * rules anywhere in this file, because a second description is a description that drifts. If you find
 * yourself about to write a sentence stating what the policy permits, derive it instead.
 *
 * The main body is written for a records officer or an attorney who will not read an appendix.
 * Cryptographic detail lives at the back.
 *
 * Runs in the browser: the notice may carry a private matching identifier, and sending that to a
 * server to render a PDF would break the invariant the whole system rests on.
 */

const PAGE = { width: 612, height: 792 }
const MARGIN = 56
const CONTENT_WIDTH = PAGE.width - MARGIN * 2

const INK = rgb(0.1, 0.1, 0.095)
const MUTED = rgb(0.42, 0.42, 0.39)
const RULE = rgb(0.85, 0.85, 0.82)
const DENY = rgb(0.55, 0.12, 0.13)
const ALLOW = rgb(0.11, 0.38, 0.27)

export interface NoticePdfInput {
  /** The signed policy. All policy statements in the PDF derive from this. */
  policy: Policy
  /** The exact policy bytes, so the byte digest shown is the delivered serialization. */
  policyJson: string
  notice: Notice
  noticeDigest: string
  policyDigest: string
  policyByteDigest: string
  manifestDigest?: string
  verificationUrl?: string
  verifyCommand?: string
  /** Include the private matching identifier section. Off unless the recipient needs it. */
  includeMatchingIdentifiers?: boolean
  generatedAt?: Date
}

interface Cursor { page: PDFPage; y: number; pageNumber: number }

interface Fonts { regular: PDFFont; bold: PDFFont; italic: PDFFont; mono: PDFFont }

export async function renderNoticePdf (input: NoticePdfInput): Promise<Uint8Array> {
  const doc = await PDFDocument.create()
  doc.setTitle(`Personal Rights Management notice — policy v${input.policy.version}`)
  doc.setSubject('Personal data policy notice')
  doc.setProducer('PRM')
  doc.setCreator('PRM')

  const fonts: Fonts = {
    regular: await doc.embedFont(StandardFonts.Helvetica),
    bold: await doc.embedFont(StandardFonts.HelveticaBold),
    italic: await doc.embedFont(StandardFonts.HelveticaOblique),
    mono: await doc.embedFont(StandardFonts.Courier)
  }

  const cursor: Cursor = { page: doc.addPage([PAGE.width, PAGE.height]), y: PAGE.height - MARGIN, pageNumber: 1 }
  const newPage = (): void => {
    cursor.page = doc.addPage([PAGE.width, PAGE.height])
    cursor.y = PAGE.height - MARGIN
    cursor.pageNumber += 1
  }
  const space = (needed: number): void => { if (cursor.y - needed < MARGIN + 24) newPage() }

  // ---- 1. Cover / identification -------------------------------------------
  await coverSection(doc, cursor, fonts, input, space)

  // ---- 2. Short PRM explanation --------------------------------------------
  heading(cursor, fonts, 'What this is', space)
  paragraph(cursor, fonts, PRM_EXPLANATION, space)
  paragraph(cursor, fonts, OBSERVATION_DISTINCTION, space)

  // ---- 3. Standing policy summary ------------------------------------------
  heading(cursor, fonts, 'My policy', space)
  paragraph(cursor, fonts,
    'The following is generated from the machine-readable policy identified above. It is not a ' +
    'separate summary that could drift from the signed document.', space, { italic: true })
  policySection(cursor, fonts, input.policy, space)

  // ---- 4. Requested treatment ----------------------------------------------
  heading(cursor, fonts, 'What I am asking', space)
  paragraph(cursor, fonts, input.notice.requestedTreatment, space)

  // ---- 5. Legal effect ------------------------------------------------------
  heading(cursor, fonts, 'Legal effect', space)
  paragraph(cursor, fonts, input.notice.legalEffect, space)

  // ---- 6/7/8. Verification, digests, QR ------------------------------------
  await verificationSection(doc, cursor, fonts, input, space)

  // ---- 9. Recipient-specific identifier ------------------------------------
  if (input.includeMatchingIdentifiers && input.notice.matchingIdentifiers?.length) {
    heading(cursor, fonts, 'Records this concerns', space)
    paragraph(cursor, fonts,
      'Provided so you can associate this policy with the correct records. It does not appear in my ' +
      'published policy, which contains only a cryptographic commitment to it.', space, { italic: true })
    for (const id of input.notice.matchingIdentifiers) {
      keyValue(cursor, fonts, id.namespace.replace(/-/g, ' '), id.value, space, { mono: true })
    }
  }

  // ---- 10. Technical appendix ----------------------------------------------
  newPage()
  appendixSection(cursor, fonts, input, space)

  footers(doc, fonts)
  return doc.save()
}

// ---------------------------------------------------------------------------

async function coverSection (
  doc: PDFDocument, c: Cursor, f: Fonts, input: NoticePdfInput, space: (n: number) => void
): Promise<void> {
  const { notice, policy } = input

  c.page.drawText('PERSONAL RIGHTS MANAGEMENT', {
    x: MARGIN, y: c.y, size: 9, font: f.bold, color: MUTED
  })
  c.y -= 22
  c.page.drawText('Notice of personal data policy', {
    x: MARGIN, y: c.y, size: 19, font: f.bold, color: INK
  })
  c.y -= 10
  divider(c)
  c.y -= 16

  const generated = (input.generatedAt ?? new Date()).toISOString().slice(0, 10)
  keyValue(c, f, 'To', notice.recipient.name, space, { bold: true })
  if (notice.recipient.department) keyValue(c, f, '', notice.recipient.department, space)
  if (notice.recipient.postalAddress) keyValue(c, f, '', notice.recipient.postalAddress, space)
  keyValue(c, f, 'Recipient type', RECIPIENT_TYPE_LABELS[notice.recipient.type] ?? notice.recipient.type, space)
  c.y -= 6
  keyValue(c, f, 'From', notice.issuer.displayName ?? 'PRM account holder', space, { bold: true })
  keyValue(c, f, 'PRM account', notice.issuer.id, space, { mono: true })
  c.y -= 6
  keyValue(c, f, 'Policy version', `v${policy.version}`, space)
  keyValue(c, f, 'Effective', policy.effectiveDate.slice(0, 10), space)
  keyValue(c, f, 'Notice issued', notice.issued.slice(0, 10), space)
  keyValue(c, f, 'Packet generated', generated, space)
  c.y -= 10
  divider(c)
  c.y -= 14
}

function policySection (c: Cursor, f: Fonts, policy: Policy, space: (n: number) => void): void {
  const rows = machineSummary(policy)
  const group = (decision: Rule['decision']) => rows.filter((r) => r.decision === decision)

  const allowed = [...group('allow'), ...group('conditional')]
  if (allowed.length > 0) {
    subheading(c, f, 'Generally permitted or acknowledged', space, ALLOW)
    for (const row of allowed) {
      bullet(c, f, row.label, row.conditions, space)
    }
    c.y -= 6
  }

  const denied = group('deny')
  if (denied.length > 0) {
    subheading(c, f, 'Objected to absent separate legal authority or my authorization', space, DENY)
    for (const row of denied) bullet(c, f, row.label, row.conditions, space)
    c.y -= 6
  }

  // Silence is not permission, and a reader should be told so explicitly.
  const addressed = new Set(policy.rules.map((r) => r.category))
  const silent = machineSummary({ rules: [] } as unknown as Policy)
  void silent
  const missing = ['prm:observation', 'prm:retention', 'prm:sale', 'prm:ai-training']
    .filter((cat) => !addressed.has(cat))
  if (missing.length > 0) {
    subheading(c, f, 'Not addressed by this policy', space, MUTED)
    bullet(c, f, missing.map((m) => categoryLabel(m)).join(', '), 'treat as not authorized', space)
  }
}

async function verificationSection (
  doc: PDFDocument, c: Cursor, f: Fonts, input: NoticePdfInput, space: (n: number) => void
): Promise<void> {
  space(200)
  heading(c, f, 'How to check this yourself', space)
  paragraph(c, f, VERIFICATION_NOTE, space)

  const qrTarget = input.verificationUrl ?? ''
  if (qrTarget) {
    // Drawn as vector modules rather than an embedded image: crisp at any size, and no PNG encoder,
    // which keeps this working identically in a browser and in Node.
    const qr = QRCode.create(qrTarget, { errorCorrectionLevel: 'M' })
    const modules = qr.modules
    const size = 108
    const scale = size / modules.size
    const qrX = PAGE.width - MARGIN - size
    const qrY = c.y - size + 12

    c.page.drawRectangle({
      x: qrX - 6, y: qrY - 6, width: size + 12, height: size + 12, color: rgb(1, 1, 1)
    })
    for (let row = 0; row < modules.size; row++) {
      for (let col = 0; col < modules.size; col++) {
        if (!modules.get(row, col)) continue
        c.page.drawRectangle({
          x: qrX + col * scale,
          y: qrY + (modules.size - 1 - row) * scale,
          width: scale, height: scale, color: INK
        })
      }
    }
    const savedY = c.y
    c.y = savedY
    wrapped(c, f, `Public page: ${qrTarget}`, space, {
      size: 8, font: f.mono, color: MUTED, width: CONTENT_WIDTH - size - 24
    })
    c.y = Math.min(c.y, qrY - 12)
  }

  paragraph(c, f, 'To verify independently, without contacting PRM:', space)
  monoBlock(c, f, input.verifyCommand ?? 'npx @prm/cli verify notice.prmproof', space)
  c.y -= 4
}

function appendixSection (c: Cursor, f: Fonts, input: NoticePdfInput, space: (n: number) => void): void {
  heading(c, f, 'Technical appendix', space)
  paragraph(c, f,
    'Nothing in this appendix is needed to read the notice. It is here so a technical reviewer can ' +
    'check the document without relying on anything PRM says.', space, { italic: true })

  subheading(c, f, 'Identifiers', space)
  keyValue(c, f, 'Policy digest', input.policyDigest, space, { mono: true, small: true })
  keyValue(c, f, 'Policy byte digest', input.policyByteDigest, space, { mono: true, small: true })
  keyValue(c, f, 'Notice digest', input.noticeDigest, space, { mono: true, small: true })
  if (input.manifestDigest) {
    keyValue(c, f, 'Bundle manifest', input.manifestDigest, space, { mono: true, small: true })
  }
  keyValue(c, f, 'Policy chain', input.policy.policyChainId, space, { mono: true, small: true })
  keyValue(c, f, 'Signing key', input.notice.issuer.did, space, { mono: true, small: true })

  c.y -= 8
  subheading(c, f, 'Why there are two policy digests', space)
  paragraph(c, f,
    'The policy digest identifies the document. It is computed over a canonical form, so reformatting ' +
    'the JSON does not change it. The byte digest identifies the exact bytes delivered, and does ' +
    'change if a single character moves. Recording both means this notice pins not only which policy ' +
    'was issued, but which exact file you received.', space)

  c.y -= 8
  subheading(c, f, 'What a signature here does and does not prove', space)
  paragraph(c, f,
    'The signatures prove that the holder of this PRM account authored these documents, and that ' +
    'they have not been altered since. They do not prove the account belongs to any named person: ' +
    'PRM performs no identity checking. They also do not prove this notice reached you — the ' +
    'delivery record states what the sender asserts, not what PRM witnessed.', space)

  c.y -= 8
  subheading(c, f, 'This PDF is not the signed document', space)
  paragraph(c, f,
    'This file is a human-readable rendering. The signed artifacts are the JSON documents identified ' +
    'above. If this PDF and those documents ever disagree, the signed documents govern, and the ' +
    'digests printed here are what tie the two together.', space)
}

// ---- primitives -----------------------------------------------------------

function divider (c: Cursor): void {
  c.page.drawLine({
    start: { x: MARGIN, y: c.y }, end: { x: PAGE.width - MARGIN, y: c.y },
    thickness: 0.75, color: RULE
  })
}

function heading (c: Cursor, f: Fonts, text: string, space: (n: number) => void): void {
  space(60)
  c.y -= 12
  c.page.drawText(text, { x: MARGIN, y: c.y, size: 12.5, font: f.bold, color: INK })
  c.y -= 16
}

function subheading (
  c: Cursor, f: Fonts, text: string, space: (n: number) => void, color = MUTED
): void {
  space(40)
  c.y -= 4
  c.page.drawText(text, { x: MARGIN, y: c.y, size: 9.5, font: f.bold, color })
  c.y -= 14
}

function paragraph (
  c: Cursor, f: Fonts, text: string, space: (n: number) => void,
  opts: { italic?: boolean } = {}
): void {
  wrapped(c, f, text, space, {
    size: 10,
    font: opts.italic ? f.italic : f.regular,
    color: opts.italic ? MUTED : INK
  })
  c.y -= 6
}

function wrapped (
  c: Cursor, f: Fonts, text: string, space: (n: number) => void,
  opts: { size?: number; font?: PDFFont; color?: ReturnType<typeof rgb>; width?: number; indent?: number } = {}
): void {
  const size = opts.size ?? 10
  const font = opts.font ?? f.regular
  const color = opts.color ?? INK
  const width = opts.width ?? CONTENT_WIDTH
  const indent = opts.indent ?? 0
  const lineHeight = size * 1.42

  for (const rawLine of text.split('\n')) {
    if (rawLine.trim() === '') { c.y -= lineHeight * 0.5; continue }
    let line = ''
    for (const word of rawLine.split(/\s+/)) {
      const candidate = line ? `${line} ${word}` : word
      if (font.widthOfTextAtSize(candidate, size) > width - indent && line) {
        space(lineHeight)
        c.page.drawText(line, { x: MARGIN + indent, y: c.y, size, font, color })
        c.y -= lineHeight
        line = word
      } else {
        line = candidate
      }
    }
    if (line) {
      space(lineHeight)
      c.page.drawText(line, { x: MARGIN + indent, y: c.y, size, font, color })
      c.y -= lineHeight
    }
  }
}

function bullet (
  c: Cursor, f: Fonts, label: string, detail: string, space: (n: number) => void
): void {
  space(20)
  c.page.drawText('•', { x: MARGIN + 4, y: c.y, size: 10, font: f.regular, color: MUTED })
  wrapped(c, f, label, space, { size: 10, indent: 18 })
  if (detail) {
    wrapped(c, f, detail, space, { size: 8.5, font: f.italic, color: MUTED, indent: 18 })
  }
  c.y -= 2
}

function keyValue (
  c: Cursor, f: Fonts, key: string, value: string, space: (n: number) => void,
  opts: { bold?: boolean; mono?: boolean; small?: boolean } = {}
): void {
  const size = opts.small ? 8 : 10
  space(size * 1.6)
  if (key) {
    c.page.drawText(key, { x: MARGIN, y: c.y, size: opts.small ? 8 : 9, font: f.regular, color: MUTED })
  }
  const valueX = MARGIN + 108
  const font = opts.mono ? f.mono : opts.bold ? f.bold : f.regular
  const maxWidth = CONTENT_WIDTH - 108
  // Long digests must wrap rather than run off the page.
  if (font.widthOfTextAtSize(value, size) > maxWidth) {
    let remaining = value
    let first = true
    while (remaining.length > 0) {
      let take = remaining.length
      while (take > 1 && font.widthOfTextAtSize(remaining.slice(0, take), size) > maxWidth) take--
      space(size * 1.5)
      c.page.drawText(remaining.slice(0, take), {
        x: valueX, y: c.y, size, font, color: first ? INK : MUTED
      })
      c.y -= size * 1.5
      remaining = remaining.slice(take)
      first = false
    }
  } else {
    c.page.drawText(value, { x: valueX, y: c.y, size, font, color: INK })
    c.y -= size * 1.6
  }
}

function monoBlock (c: Cursor, f: Fonts, text: string, space: (n: number) => void): void {
  space(30)
  c.page.drawRectangle({
    x: MARGIN - 6, y: c.y - 7, width: CONTENT_WIDTH + 12, height: 20, color: rgb(0.96, 0.96, 0.94)
  })
  c.page.drawText(text, { x: MARGIN, y: c.y, size: 9, font: f.mono, color: INK })
  c.y -= 24
}

function footers (doc: PDFDocument, f: Fonts): void {
  const pages = doc.getPages()
  pages.forEach((page, i) => {
    page.drawText(
      'This document records the issuer\'s instructions. It does not create legal obligations that do not otherwise exist.',
      { x: MARGIN, y: 30, size: 6.5, font: f.italic, color: MUTED })
    page.drawText(`${i + 1} of ${pages.length}`, {
      x: PAGE.width - MARGIN - 34, y: 30, size: 6.5, font: f.regular, color: MUTED
    })
  })
}
