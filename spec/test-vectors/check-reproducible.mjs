#!/usr/bin/env node
/**
 * Regenerates every example + vector into a temp directory and asserts the output is
 * byte-identical to what is committed. Catches accidental non-determinism (map ordering,
 * Date.now(), locale-dependent sorting) before it reaches a signature.
 */
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SPEC = path.resolve(HERE, '..')

const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
  const p = path.join(dir, e.name)
  return e.isDirectory() ? walk(p) : p.endsWith('.json') ? [p] : []
})
const snapshot = root => Object.fromEntries(walk(root).map(p =>
  [path.relative(root, p), crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')]))

const targets = [path.join(SPEC, 'examples'), path.join(SPEC, 'test-vectors')]
const before = targets.map(snapshot)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prm-repro-'))
fs.cpSync(path.join(SPEC, '..'), tmp, {
  recursive: true,
  filter: s => !s.includes('node_modules') && !s.includes('/.git/')
})
execFileSync(process.execPath, [path.join(tmp, 'spec/test-vectors/generate.mjs')], { stdio: 'pipe' })
const after = [path.join(tmp, 'spec/examples'), path.join(tmp, 'spec/test-vectors')].map(snapshot)

let drift = 0
for (let i = 0; i < before.length; i++) {
  for (const [file, hash] of Object.entries(before[i])) {
    if (after[i][file] !== hash) {
      console.log(`  \x1b[31m✘\x1b[0m ${file} — regenerated output differs from the committed file`)
      drift++
    }
  }
}
fs.rmSync(tmp, { recursive: true, force: true })

if (drift === 0) {
  const n = before.reduce((a, s) => a + Object.keys(s).length, 0)
  console.log(`\n  \x1b[32m✔\x1b[0m generation is deterministic — ${n} files reproduced byte-for-byte\n`)
} else {
  console.log(`\n  \x1b[31m${drift} file(s) drifted.\x1b[0m Run \`npm run spec:generate\` and commit, or fix the nondeterminism.\n`)
}
process.exit(drift ? 1 : 0)
