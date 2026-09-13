#!/usr/bin/env node
/**
 * Precompiles spec/schemas/*.json into standalone validator functions.
 *
 * WHY THIS EXISTS: Ajv's normal mode compiles each schema by building a JavaScript source string and
 * handing it to `new Function`. In a browser that is indistinguishable from `eval`, so it requires
 * `script-src 'unsafe-eval'`. This application signs with a key held in the page, so `unsafe-eval` is
 * exactly what the Content-Security-Policy exists to forbid: an XSS with eval available is an attacker
 * running arbitrary code next to an unlocked signing key.
 *
 * Ajv's standalone mode emits the same validation code ahead of time, as ordinary module source. The
 * logic is identical; only the moment of compilation moves from run time to build time. Nothing needs
 * 'unsafe-eval' afterwards.
 *
 * The Ajv options here MUST stay identical to the ones in src/validate.ts' history, or a document that
 * validated yesterday may not validate today.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { Ajv2020 } from 'ajv/dist/2020.js'
import addFormatsModule from 'ajv-formats'
import standaloneCode from 'ajv/dist/standalone/index.js'

const addFormats = addFormatsModule.default ?? addFormatsModule

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SPEC = path.resolve(HERE, '../../../spec/schemas')
const OUT = path.resolve(HERE, '../src/generated/validators.ts')

/** Export name per schema file. These become the named exports of the generated module. */
const names = {
  'prm-policy-v1.schema.json': 'policy',
  'prm-authorization-v1.schema.json': 'authorization',
  'prm-key-event-v1.schema.json': 'keyEvent',
  'prm-ledger-entry-v1.schema.json': 'ledgerEntry',
  'prm-notice-v1.schema.json': 'notice',
  'prm-delivery-v1.schema.json': 'delivery',
  'prm-response-v1.schema.json': 'response'
}

/**
 * Runtime helpers Ajv's generated code reaches for with `require`, and how to bind each one so that
 * it behaves the same under Node's ESM loader and under a bundler.
 *
 * The two disagree about CommonJS default imports: Node hands back `module.exports` whole, while a
 * bundler honours the `__esModule` marker and hands back `module.exports.default`. `ucs2length` sets
 * that marker, so the binding has to accept either shape. Getting this wrong throws only in one of
 * the two environments, which is the kind of bug that reaches production.
 */
const runtimeImports = [
  {
    request: 'ajv-formats/dist/formats',
    specifier: 'ajv-formats/dist/formats.js',
    binding: 'ajvFormats',
    // No __esModule marker: both loaders hand back the namespace. Checked anyway.
    normalize: (id) => `${id}.fullFormats ? ${id} : ${id}.default`
  },
  {
    request: 'ajv/dist/runtime/ucs2length',
    specifier: 'ajv/dist/runtime/ucs2length.js',
    binding: 'ajvUcs2length',
    // Generated code calls `.default(...)`, so a bundler that already unwrapped it must be re-wrapped.
    normalize: (id) => `typeof ${id} === 'function' ? { default: ${id} } : ${id}`
  }
]

// Identical to the options the runtime validator used, plus code generation.
const ajv = new Ajv2020({
  strict: false,
  allErrors: true,
  allowUnionTypes: true,
  code: { source: true, esm: true }
})
addFormats(ajv)

const refs = {}
for (const [file, ident] of Object.entries(names)) {
  const schema = JSON.parse(fs.readFileSync(path.join(SPEC, file), 'utf8'))
  ajv.addSchema(schema)
  refs[ident] = schema.$id
}

let code = standaloneCode(ajv, refs)

// "use strict" is implicit in a module, and would otherwise sit above the imports.
code = code.replace(/^"use strict";/, '')

const preamble = []
for (const { request, specifier, binding, normalize } of runtimeImports) {
  const needle = `require("${request}")`
  const uses = code.split(needle).length - 1
  if (uses === 0) continue
  code = code.split(needle).join(binding)
  preamble.push(
    `import ${binding}Module from '${specifier}'`,
    `const ${binding} = ${normalize(`${binding}Module`)}`,
    ''
  )
}

const banner = `// GENERATED FILE — do not edit.
// Source: spec/schemas/*.json  ·  Regenerate: pnpm --filter @prm/schema generate
//
// Ahead-of-time compiled Ajv validators. Generated so that validation needs no \`new Function\` at run
// time, which is what lets the browser app ship a Content-Security-Policy without 'unsafe-eval'.
// See scripts/compile-validators.mjs.
// @ts-nocheck
/* eslint-disable */

${preamble.join('\n')}`

// A single missed `require`, or any surviving eval, would throw at import time in the browser — the
// exact failure this script exists to prevent. Fail the build here instead of shipping it.
const leftover = /require\(|new Function|[^.\w]eval\(/.exec(code)
if (leftover) {
  console.error(
    `compile-validators: generated code still contains \`${leftover[0]}\`.\n` +
    "It would fail at run time under a CSP without 'unsafe-eval'. Add it to runtimeImports."
  )
  process.exit(1)
}

fs.mkdirSync(path.dirname(OUT), { recursive: true })
fs.writeFileSync(OUT, banner + code + '\n')

console.log(
  `compiled ${Object.keys(names).length} validators -> src/generated/validators.ts ` +
  `(${(code.length / 1024).toFixed(0)} KiB, no eval)`
)
