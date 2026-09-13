import type { Metadata } from 'next'
import { connection } from 'next/server'
import './globals.css'
import { Footer } from '../components/Footer'

export const metadata: Metadata = {
  title: 'RightsRoot',
  description:
    'Create, sign, and publish a personal data policy that anyone can verify without trusting us. ' +
    'RightsRoot is the platform; PRM (Personal Rights Management) is the open protocol underneath.',
  robots: { index: false, follow: false }
}

export default async function RootLayout ({ children }: { children: React.ReactNode }) {
  // Nonce-based CSP requires request-time rendering so Next can apply the nonce
  // to its framework/bootstrap scripts. Without this, a statically generated
  // page can render but fail to hydrate under a strict CSP.
  await connection()

  return (
    <html lang="en">
      <body>
        {children}
        <Footer />
      </body>
    </html>
  )
}
