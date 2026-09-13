import { NextRequest, NextResponse } from 'next/server'

/**
 * Per-request Content-Security-Policy for the browser application.
 *
 * Next.js emits its bootstrap and RSC payload as INLINE <script> tags. A policy of `script-src 'self'`
 * blocks those, and the failure is silent and specific: the server-rendered HTML still paints, so the
 * page looks completely normal, but React never receives the payload it hydrates against. No event
 * handler is ever attached. Every button on the site becomes decorative.
 *
 * A fresh nonce per request lets Next.js mark its own scripts executable without `unsafe-inline`.
 * Next.js reads the nonce out of the Content-Security-Policy request header set below, and stamps it
 * onto every script tag it emits. `strict-dynamic` then extends that trust to the chunks those
 * scripts load, which is what keeps the policy strict while still allowing the app to boot.
 *
 * A nonce has to differ per request, so pages carrying one cannot be prerendered at build time. The
 * root layout opts into request-time rendering for exactly this reason.
 */

/**
 * The policy itself, as a pure function so its guarantees can be asserted in a test.
 *
 * Signing happens in this browser: the master seed is decrypted here and lives in memory while the
 * user works. An XSS on this origin is therefore an attacker standing next to an unlocked key, which
 * is why `script-src` must never gain `unsafe-inline` or (in production) `unsafe-eval`.
 *
 * `wasm-unsafe-eval` is the exception, and is not a general eval: it permits WebAssembly compilation
 * only. Argon2id, which derives the vault key from the passphrase, needs it.
 */
export function contentSecurityPolicy (nonce: string, { dev = false } = {}): string {
  return [
    "default-src 'self'",
    // 'unsafe-eval' in development only: the dev-mode React refresh runtime needs it. Production
    // must not have it — see test/csp.test.ts. Schema validators are compiled ahead of time
    // (packages/schema/scripts/compile-validators.mjs) precisely so that nothing here needs eval.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${dev ? " 'unsafe-eval'" : ''}`,
    // The current UI uses React style attributes in a few places. Keep styles permissive for now;
    // signing security depends on script-src, not style-src.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; ')
}

export function proxy (request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64')
  const csp = contentSecurityPolicy(nonce, { dev: process.env.NODE_ENV === 'development' })

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-nonce', nonce)
  // Next.js reads the nonce from this request header. Without it, the script tags carry no nonce
  // and the response policy below blocks the very scripts the framework just emitted.
  requestHeaders.set('Content-Security-Policy', csp)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  response.headers.set('Content-Security-Policy', csp)
  return response
}

export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' }
      ]
    }
  ]
}
