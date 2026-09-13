import { NextRequest, NextResponse } from 'next/server'

/**
 * Per-request CSP for the browser application.
 *
 * Next.js App Router emits inline bootstrap/RSC scripts during SSR. A static
 * `script-src 'self'` policy blocks those scripts, leaving the page visible but
 * unhydrated — buttons render but no client event handlers attach. A fresh nonce
 * lets Next.js mark only its own framework/bootstrap scripts as executable without
 * weakening the policy with `unsafe-inline`.
 */
export function proxy (request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64')
  const isDev = process.env.NODE_ENV === 'development'

  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${isDev ? " 'unsafe-eval'" : ''}`,
    // The current UI uses React style attributes in a few places. Keep styles
    // permissive for now; signing security depends on script-src, not style-src.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; ')

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('Content-Security-Policy', csp)

  const response = NextResponse.next({
    request: { headers: requestHeaders }
  })
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
