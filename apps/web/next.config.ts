import type { NextConfig } from 'next'

const config: NextConfig = {
  reactStrictMode: true,
  // Workspace packages ship as ESM TypeScript builds; Next must not try to externalize them.
  transpilePackages: ['@prm/schema', '@prm/crypto', '@prm/vault', '@prm/verify', '@prm/notice'],
  async headers () {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'X-Frame-Options', value: 'DENY' }
        ]
      },
      {
        // Third-party verifiers must be able to fetch the machine-readable policy.
        source: '/u/:handle/policy.json',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Cross-Origin-Resource-Policy', value: 'cross-origin' }
        ]
      }
    ]
  }
}

export default config
