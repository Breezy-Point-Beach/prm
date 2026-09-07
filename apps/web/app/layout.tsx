import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'PRM — Personal Rights Management',
  description: 'Create, sign, and publish a personal data policy that anyone can verify without trusting PRM.',
  robots: { index: false, follow: false }
}

export default function RootLayout ({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
