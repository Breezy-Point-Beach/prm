#!/usr/bin/env node
/**
 * Inlines spec/schemas/*.json into src/generated/schemas.ts.
 *
 * spec/schemas/ is the single source of truth. Copying by hand would drift; importing across the
 * workspace boundary would break the published package. So we generate, and CI asserts the generated
 * file is up to date (`pnpm generate && git diff --exit-code`).
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SPEC = path.resolve(HERE, '../../../spec/schemas')
const OUT = path.resolve(HERE, '../src/generated/schemas.ts')

const names = {
  'prm-policy-v1.schema.json': 'policySchema',
  'prm-authorization-v1.schema.json': 'authorizationSchema',
  'prm-key-event-v1.schema.json': 'keyEventSchema',
  'prm-ledger-entry-v1.schema.json': 'ledgerEntrySchema',
  'prm-notice-v1.schema.json': 'noticeSchema',
  'prm-delivery-v1.schema.json': 'deliverySchema',
  'prm-response-v1.schema.json': 'responseSchema'
}

let out = `// GENERATED FILE — do not edit.
// Source: spec/schemas/*.json  ·  Regenerate: pnpm --filter @prm/schema generate
/* eslint-disable */\n\n`

for (const [file, ident] of Object.entries(names)) {
  const json = JSON.parse(fs.readFileSync(path.join(SPEC, file), 'utf8'))
  out += `export const ${ident} = ${JSON.stringify(json, null, 2)} as const\n\n`
}
out += `export const allSchemas = [policySchema, authorizationSchema, keyEventSchema, ledgerEntrySchema, noticeSchema, deliverySchema, responseSchema]\n`

fs.mkdirSync(path.dirname(OUT), { recursive: true })
fs.writeFileSync(OUT, out)
console.log(`inlined ${Object.keys(names).length} schemas -> src/generated/schemas.ts`)
