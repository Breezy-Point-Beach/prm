import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { cmdVerify, cmdInspect, cmdDigest, cmdVerifyChain, UsageError } from '../src/commands.js'
import { buildProofBundle } from '@prm/notice'

const SPEC = resolve(import.meta.dirname, '../../../spec')
const load = (p: string) => JSON.parse(readFileSync(resolve(SPEC, p), 'utf8'))
const V = load('test-vectors/vectors.json')

let dir: string
const path = (name: string) => join(dir, name)
const write = (name: string, data: unknown) => {
  const p = path(name)
  writeFileSync(p, JSON.stringify(data, null, 2))
  return p
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'prm-cli-'))
  write('v1.json', load('examples/policies/policy-v1.json'))
  write('v2.json', load('examples/policies/policy-v2.json'))
  write('genesis.json', load('examples/key-events/genesis.json'))
  write('kel.json', [load('examples/key-events/genesis.json'), load('examples/key-events/rotation-seq1.json')])
  write('chain.json', [load('examples/policies/policy-v1.json'), load('examples/policies/policy-v2.json')])
  write('evidence.prmproof', buildProofBundle({
    policy: load('examples/policies/policy-v1.json'),
    policyJson: readFileSync(resolve(SPEC, 'examples/policies/policy-v1.json'), 'utf8'),
    keyEventLogJson: readFileSync(resolve(SPEC, 'examples/key-events/genesis.json'), 'utf8'),
    signedTreeHeadJson: readFileSync(resolve(SPEC, 'examples/ledger/signed-tree-head.json'), 'utf8'),
    generatedAt: new Date('2026-11-20T01:00:00Z')
  }))
})

afterAll(() => rmSync(dir, { recursive: true, force: true }))

describe('prm verify', () => {
  it('verifies a policy with its key event log', () => {
    const r = cmdVerify(path('v1.json'), { kel: path('genesis.json'), offline: true })
    expect(r.output).toContain('self-certifies from genesis')
    expect(r.output).toContain('VERIFIED')
    // Exit 1, not 0: currency and revocation are genuinely unknown offline, and the CLI must not
    // pretend otherwise just because the signature checked out.
    expect(r.exitCode).toBe(1)
  })

  it('reports issuer as unconfirmed when no key event log is given', () => {
    const r = cmdVerify(path('v1.json'), {})
    expect(r.output).toContain('no key event log supplied')
    expect(r.exitCode).toBe(1)
  })

  it('detects a key event log and verifies the chain', () => {
    const r = cmdVerify(path('kel.json'), {})
    expect(r.output).toContain('every rotation revealed a pre-committed key')
    expect(r.exitCode).toBe(0)
  })

  it('detects and verifies a .prmproof bundle', () => {
    const r = cmdVerify(path('evidence.prmproof'), {})
    expect(r.output).toContain('manifest')
    expect(r.output).toContain('VERIFIED')
    expect(r.output).toMatch(/Verified: PRM account prm:/)
    expect(r.exitCode).toBe(0)
  })

  it('FAILS a tampered policy with exit code 2', () => {
    const p = load('examples/policies/policy-v1.json')
    p.rules.find((r: { category: string }) => r.category === 'prm:sale').decision = 'allow'
    const r = cmdVerify(write('tampered.json', p), { kel: path('genesis.json') })
    expect(r.output).toContain('FAILED')
    expect(r.exitCode).toBe(2)
  })

  it('emits machine-readable JSON with --json', () => {
    const r = cmdVerify(path('v1.json'), { kel: path('genesis.json'), json: true })
    const parsed = JSON.parse(r.output)
    expect(parsed.integrity).toBe('valid')
    expect(parsed.issuer).toBe('authorized')
    expect(parsed.checked.accountId).toBe(V.accountId.accountId)
  })

  it('exits 3 on a missing file and on malformed JSON', () => {
    expect(() => cmdVerify(path('nope.json'), {})).toThrow(UsageError)
    writeFileSync(path('bad.json'), '{ not json')
    expect(() => cmdVerify(path('bad.json'), {})).toThrow(/not valid JSON/)
  })
})

describe('prm verify-chain', () => {
  it('verifies v1 -> v2', () => {
    const r = cmdVerifyChain(path('chain.json'))
    expect(r.output).toContain('CHAIN VERIFIED')
    expect(r.exitCode).toBe(0)
  })

  it('fails a substituted chain', () => {
    const [a, b] = [load('examples/policies/policy-v1.json'), load('examples/policies/policy-v2.json')]
    b.previousPolicyHash = V.documents['key-events/genesis.json'].digest
    const r = cmdVerifyChain(write('badchain.json', [a, b]))
    expect(r.output).toContain('CHAIN FAILED')
    expect(r.exitCode).toBe(2)
  })
})

describe('prm inspect', () => {
  const out = () => cmdInspect(path('v1.json')).output

  it('separates permitted, conditional, and objected-to', () => {
    const o = out()
    expect(o).toContain('Permitted')
    expect(o).toContain('Initial observation')
    expect(o).toContain('Objected to')
    expect(o).toContain('AI / model training')
  })

  it('shows committed identifiers WITHOUT disclosing their values', () => {
    const o = out()
    expect(o).toContain('values not disclosed')
    expect(o).not.toContain('1HGBH41JXMN109186')
    expect(o).not.toContain('holder@example.org')
  })

  it('includes the issuer prose and the honest legal disclaimer', () => {
    const o = out()
    expect(o).toContain("In the issuer's own words")
    expect(o).toMatch(/does not by itself[\s\S]*establish that every restriction is enforceable/)
  })

  it('rejects a non-policy with exit code 3', () => {
    const r = cmdInspect(path('genesis.json'))
    expect(r.exitCode).toBe(3)
    expect(r.output).toContain('Not a valid PRM policy')
  })
})

describe('prm digest', () => {
  it('prints the canonical digest matching the vectors', () => {
    const r = cmdDigest(path('v1.json'), {})
    expect(r.output).toContain(V.documents['policies/policy-v1.json'].digest)
    expect(r.output).toContain('excluded')
    expect(r.output).toContain('id, proof')
  })

  it('prints the chain id for a v1 policy', () => {
    expect(cmdDigest(path('v1.json'), {}).output).toContain(V.policyChain.chainId)
  })

  it('names logInclusion among the excluded members for a ledger entry', () => {
    const entry = load('examples/ledger/entries.json')[1]
    const r = cmdDigest(write('entry.json', entry), {})
    expect(r.output).toContain('proof, logInclusion')
  })

  it('can print the exact canonical bytes', () => {
    const r = cmdDigest(path('v1.json'), { bytes: true })
    expect(r.output).toContain('canonical bytes')
    expect(r.output).toContain('{"@context":[')
  })
})

describe('the CLI adds no verification logic of its own', () => {
  it('imports verification only from @prm/verify', () => {
    const src = readFileSync(resolve(import.meta.dirname, '../src/commands.ts'), 'utf8')
    // Every verify* symbol used must come from the shared package, so the CLI and the web app can
    // never disagree about whether a document is valid.
    const verifyImport = src.match(/import \{[^}]*\} from '@prm\/verify'/s)
    expect(verifyImport).not.toBeNull()
    expect(src).not.toMatch(/function verify[A-Z]/)
  })

  it('makes no network calls anywhere in its sources', () => {
    for (const f of ['commands.ts', 'cli.ts', 'render.ts', 'index.ts']) {
      const src = readFileSync(resolve(import.meta.dirname, '../src', f), 'utf8')
      expect(src, `${f} must not fetch`).not.toMatch(/\bfetch\s*\(/)
      expect(src, `${f} must not import http`).not.toMatch(/from 'node:https?'/)
    }
  })
})
