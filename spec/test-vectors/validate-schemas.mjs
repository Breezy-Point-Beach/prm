#!/usr/bin/env node
/**
 * Validates every example document against its JSON Schema.
 * Requires ajv + ajv-formats (devDependencies of the monorepo root).
 *   node spec/test-vectors/validate-schemas.mjs
 */
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const SPEC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const load = p => JSON.parse(fs.readFileSync(path.join(SPEC, p), 'utf8'))
const ajv = new Ajv2020({ strict: false, allErrors: true })
addFormats(ajv)

for (const f of ['prm-policy-v1', 'prm-authorization-v1', 'prm-key-event-v1', 'prm-ledger-entry-v1']) {
  ajv.addSchema(load(`schemas/${f}.schema.json`))
}
const validator = s => ajv.getSchema(`https://prm.dev/schemas/${s}.schema.json`)

const cases = [
  ['examples/policies/alpr-policy-v1.json', 'prm-policy-v1'],
  ['examples/policies/alpr-policy-v2.json', 'prm-policy-v1'],
  ['examples/key-events/genesis.json', 'prm-key-event-v1'],
  ['examples/key-events/rotation-seq1.json', 'prm-key-event-v1'],
  ['examples/authorizations/alpr-investigation-grant.json', 'prm-authorization-v1']
]

let bad = 0
const report = (ok, label, errors) => {
  console.log(ok ? `  \x1b[32m✔\x1b[0m ${label}` : `  \x1b[31m✘\x1b[0m ${label}`)
  if (!ok) { bad++; for (const e of errors.slice(0, 8)) console.log(`      ${e.instancePath || '/'} ${e.message} ${JSON.stringify(e.params)}`) }
}

console.log('\nPRM examples — JSON Schema validation\n')
for (const [file, schema] of cases) {
  const v = validator(schema)
  report(v(load(file)), file, v.errors ?? [])
}
const lv = validator('prm-ledger-entry-v1')
for (const e of load('examples/ledger/entries.json')) {
  report(lv(e), `ledger entry #${e.sequence} (${e.entryType})`, lv.errors ?? [])
}
console.log(bad === 0 ? '\n\x1b[32mAll examples conform to their schemas.\x1b[0m\n'
                      : `\n\x1b[31m${bad} document(s) failed validation.\x1b[0m\n`)
process.exit(bad ? 1 : 0)
