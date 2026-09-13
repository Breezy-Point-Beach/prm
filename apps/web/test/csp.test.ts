import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { contentSecurityPolicy } from '../proxy'

/**
 * The Content-Security-Policy, enforced.
 *
 * This file exists because of a real outage with two halves, each of which hid the other:
 *
 *   1. A static `script-src 'self'` blocked Next.js' own inline bootstrap scripts. The page rendered
 *      perfectly and never hydrated, so "Generate my key" — and every other button — did nothing at
 *      all. Nothing failed loudly; the HTML was fine.
 *
 *   2. Fixing (1) with a nonce revealed that Ajv compiles schemas at run time with `new Function`,
 *      which needs 'unsafe-eval'. The page then crashed outright, which looked like a worse bug than
 *      the dead button, and the nonce fix was reverted — restoring (1).
 *
 * The tempting fix for (2) is to add 'unsafe-eval' to the policy. That would be the worst possible
 * outcome here: the master seed is decrypted in this browser, so eval next to an unlocked signing key
 * is precisely the capability this policy exists to deny. The real fix is to compile validators ahead
 * of time (packages/schema/scripts/compile-validators.mjs) so nothing needs eval at all.
 *
 * These tests pin both halves.
 */

const WEB = resolve(import.meta.dirname, '..')
const scriptSrc = (csp: string) =>
  csp.split('; ').find((d) => d.startsWith('script-src ')) ?? ''

describe('the production script-src', () => {
  const prod = contentSecurityPolicy('TESTNONCE')

  it('never permits unsafe-eval', () => {
    // If this fails, something started compiling code in the browser again. Precompile it instead
    // of relaxing this line.
    expect(scriptSrc(prod)).not.toContain("'unsafe-eval'")
  })

  it('never permits unsafe-inline', () => {
    expect(scriptSrc(prod)).not.toContain("'unsafe-inline'")
  })

  it('carries the nonce, so the framework can mark its own inline scripts executable', () => {
    // This is what keeps the app hydrated. Remove it and every button silently stops working.
    expect(scriptSrc(prod)).toContain("'nonce-TESTNONCE'")
  })

  it('allows WebAssembly, which Argon2id needs to unlock the vault', () => {
    // wasm-unsafe-eval permits WebAssembly compilation only — it is not general eval.
    expect(scriptSrc(prod)).toContain("'wasm-unsafe-eval'")
  })

  it('still denies framing, plugins and base-tag hijacking', () => {
    expect(prod).toContain("frame-ancestors 'none'")
    expect(prod).toContain("object-src 'none'")
    expect(prod).toContain("base-uri 'self'")
  })
})

describe('the development script-src', () => {
  it('permits unsafe-eval only in development, for the refresh runtime', () => {
    expect(scriptSrc(contentSecurityPolicy('N', { dev: true }))).toContain("'unsafe-eval'")
    expect(scriptSrc(contentSecurityPolicy('N', { dev: false }))).not.toContain("'unsafe-eval'")
  })
})

describe('the policy is served per request', () => {
  it('is not also pinned as a static header in next.config', () => {
    // A second, static Content-Security-Policy in next.config.ts would carry no nonce and would
    // override this one — which is exactly how the dead button shipped.
    const config = readFileSync(resolve(WEB, 'next.config.ts'), 'utf8')
    expect(config).not.toContain('Content-Security-Policy')
  })

  it('renders at request time, which a nonce requires', () => {
    // A prerendered page would bake in one nonce and serve it to everyone, matching no later
    // response header. `connection()` in the root layout is what opts out of prerendering.
    const layout = readFileSync(resolve(WEB, 'app/layout.tsx'), 'utf8')
    expect(layout).toContain('connection')
  })
})
