import type { Metadata } from 'next'
import './globals.css'
import { Footer } from '../components/Footer'

export const metadata: Metadata = {
  title: 'RightsRoot',
  description:
    'Create, sign, and publish a personal data policy that anyone can verify without trusting us. ' +
    'RightsRoot is the platform; PRM (Personal Rights Management) is the open protocol underneath.',
  robots: { index: false, follow: false }
}

export default function RootLayout ({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        <Footer />
      </body>
    </html>
  )
}
