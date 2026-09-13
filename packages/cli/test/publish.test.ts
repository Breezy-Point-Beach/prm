import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync, mkdtempSync, existsSync, cpSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

/**
 * The published artifact, enforced.
 *
 * The first publish of @rightsroot/prm-cli shipped a perfect bundle inside a manifest that still
 * declared the workspace packages as `workspace:*` dependencies. The file ran; `npx` could not
 * install it (EUNSUPPORTEDPROTOCOL). Nothing in the test suite noticed, because every test ran the
 * source. This suite runs what would be PUBLISHED: it packs the tarball, installs it into an empty
 * directory with npm — no registry, no network — and verifies a real bundle through the installed
 * binary. If this passes, the instruction printed on rightsroot.com works.
 */
const PKG = resolve(import.meta.dirname, '..')
const manifest = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8')) as {
  name: string; bin: Record<string, string>; files: string[]; dependencies?: Record<string, string>
}

describe('the published manifest', () => {
  it('is @rightsroot/prm-cli with the bundle as its only binary', () => {
    expect(manifest.name).toBe('@rightsroot/prm-cli')
    expect(manifest.bin).toEqual({ prm: 'dist/prm.mjs' })
    expect(manifest.files).toContain('dist/prm.mjs')
  })

  it('declares NO runtime dependencies — everything is inlined in the bundle', () => {
    // A `workspace:*` here would make the package uninstallable; any dependency at all would mean
    // the published tool is not the self-contained file it claims to be.
    expect(manifest.dependencies ?? {}).toEqual({})
  })
})

describe('the packed tarball, installed into an empty directory', () => {
  // Skipped only where the bundle has not been built (a fresh clone running tests before build).
  const bundle = join(PKG, 'dist', 'prm.mjs')
  const canRun = existsSync(bundle)

  it.skipIf(!canRun)('installs with npm and verifies a real .prmproof through the installed binary', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prm-cli-publish-'))
    const tarball = execFileSync('npm', ['pack', '--pack-destination', dir, '--silent'], { cwd: PKG, encoding: 'utf8' }).trim().split('\n').pop() as string
    execFileSync('npm', ['install', '--no-audit', '--no-fund', '--silent', join(dir, tarball)], { cwd: dir, encoding: 'utf8' })
    const installed = join(dir, 'node_modules', '.bin', 'prm')
    expect(existsSync(installed)).toBe(true)

    const example = resolve(PKG, '../../examples/whittier/generated/notice.prmproof')
    cpSync(example, join(dir, 'notice.prmproof'))
    const out = execFileSync(installed, ['verify', 'notice.prmproof', '--no-color'], { cwd: dir, encoding: 'utf8' })
    expect(out).toMatch(/VERIFIED/)
    expect(out).toMatch(/ok manifest/)
  }, 60_000)
})
