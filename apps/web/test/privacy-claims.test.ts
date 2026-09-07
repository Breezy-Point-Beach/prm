import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'

/**
 * The privacy policy, enforced.
 *
 * Every factual claim on /privacy is asserted here, so the page cannot quietly become false. A
 * privacy product whose privacy policy drifts from its behaviour is worse than one that never made
 * the claim — and the drift is always silent: someone adds an analytics package for a good reason,
 * and nobody rereads the policy.
 *
 * If a test here fails, either the code regressed or the policy needs rewriting. Both are worth
 * stopping for.
 */

const WEB = resolve(import.meta.dirname, '..')
const REPO = resolve(WEB, '../..')

function sourceFiles (dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.next' || entry === 'dist' || entry === '.prm-store') continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) sourceFiles(full, out)
    else if (/\.(ts|tsx)$/.test(entry)) out.push(full)
  }
  return out
}

const appSources = [
  ...sourceFiles(join(WEB, 'app')),
  ...sourceFiles(join(WEB, 'lib')),
  ...sourceFiles(join(WEB, 'components'))
]

const read = (f: string) => readFileSync(f, 'utf8')

/** Strip comments, so documentation placeholders are not mistaken for real resources. */
const code = (f: string) =>
  read(f).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')

describe('"no analytics, no session recording, no third-party resource"', () => {
  const TRACKERS = [
    '@vercel/analytics', '@vercel/speed-insights', 'posthog', 'mixpanel', 'segment',
    'amplitude', '@sentry/', 'logrocket', 'fullstory', 'hotjar', 'datadog', 'heap',
    'plausible', 'fathom', 'google-analytics', 'gtag'
  ]

  it('declares no analytics or telemetry dependency', () => {
    const pkg = JSON.parse(read(join(WEB, 'package.json'))) as {
      dependencies?: Record<string, string>
      devDependencies?: Record<string, string>
    }
    const declared = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })
    for (const tracker of TRACKERS) {
      expect(declared.filter((d) => d.includes(tracker)), `found ${tracker}`).toEqual([])
    }
  })

  it('loads no third-party script or resource in any page', () => {
    for (const file of appSources) {
      const src = code(file)
      // Any absolute URL in real code that is not our own domain would be a third-party resource.
      const urls = src.match(/https?:\/\/[a-zA-Z0-9.-]+/g) ?? []
      for (const url of urls) {
        const host = url.replace(/^https?:\/\//, '')
        const allowed = ['rightsroot.com', 'rightsroot.org', 'github.com', 'www.w3.org', 'localhost']
        if (!allowed.some((a) => host === a || host.endsWith(`.${a}`))) {
          throw new Error(`${file} references a third-party host: ${host}`)
        }
      }
    }
  })

  it('never imports an analytics module', () => {
    for (const file of appSources) {
      for (const tracker of TRACKERS) {
        expect(read(file).includes(`from '${tracker}`), `${file} imports ${tracker}`).toBe(false)
      }
    }
  })
})

describe('"no cookies, for any purpose"', () => {
  it('sets no cookie anywhere', () => {
    for (const file of appSources) {
      const src = read(file)
      expect(src, `${file} sets a cookie`).not.toMatch(/document\.cookie|Set-Cookie|cookies\(\)\.set/)
    }
  })
})

describe('"your key, phrase, passphrase and identifiers never reach us"', () => {
  const serverSources = [
    ...sourceFiles(join(WEB, 'app', 'api')),
    ...sourceFiles(join(WEB, 'lib', 'storage')),
    join(WEB, 'lib', 'publish.ts')
  ]

  it('no server module can even name a secret field', () => {
    // The publish contract accepts exactly two strings. Anything server-side that mentions a seed,
    // a mnemonic or a passphrase is a bug, not a feature.
    const FORBIDDEN = ['masterSeed', 'mnemonic', 'passphrase', 'privateKey', 'bindingSecret', 'backupPhrase']
    for (const file of serverSources) {
      const src = read(file)
      for (const field of FORBIDDEN) {
        expect(src.includes(field), `${file} references ${field}`).toBe(false)
      }
    }
  })

  it('the publish endpoint accepts only the signed bytes and the public key history', () => {
    const src = read(join(WEB, 'lib', 'publish.ts'))
    const contract = /export interface PublishRequest \{([^}]+)\}/.exec(src)?.[1] ?? ''
    const fields = [...contract.matchAll(/^\s*(\w+)[?]?:/gm)].map((m) => m[1])
    expect(fields.sort()).toEqual(['handle', 'keyEventLogJson', 'policyJson'])
  })

  it('notices, delivery and response records are built client-side only', () => {
    // Every one of these can carry a raw identifier. If a server module imports the builders, that
    // material would cross the boundary.
    // lib/client is browser code ('use client'); the boundary being tested is what the SERVER
    // can reach, so exclude it explicitly rather than by accident.
    const serverOnly = [
      ...sourceFiles(join(WEB, 'app', 'api')),
      ...sourceFiles(join(WEB, 'lib')).filter((f) => !f.includes(`${join('lib', 'client')}`))
    ]
    for (const file of serverOnly) {
      const src = read(file)
      expect(src.includes("from '@prm/notice'"), `${file} builds notices server-side`).toBe(false)
      expect(src.includes("from '@prm/vault'"), `${file} touches the vault server-side`).toBe(false)
    }
  })
})

describe('"we store only what you published, and serve it back unchanged"', () => {
  it('the database schema holds no column that could contain a policy or an identifier', () => {
    const schema = read(join(WEB, 'lib', 'storage', 'blob.ts'))
    const table = /create table if not exists published_policies \(([\s\S]+?)\);/.exec(schema)?.[1] ?? ''
    expect(table).not.toBe('')
    const columns = [...table.matchAll(/^\s{2}(\w+)\s+/gm)].map((m) => m[1])
    // Every column is a handle, an identifier of a digest, a location, a length, or a timestamp.
    const allowed = new Set([
      'handle', 'version', 'account_id', 'policy_chain_id', 'policy_digest', 'policy_byte_digest',
      'policy_location', 'policy_byte_length', 'kel_byte_digest', 'kel_location', 'content_type',
      'published_at', 'primary'
    ])
    for (const col of columns) {
      expect(allowed.has(col as string), `unexpected column: ${col}`).toBe(true)
    }
    expect(table).not.toMatch(/jsonb/)
  })
})

describe('the policy pages exist and say what the code does', () => {
  const privacy = read(join(WEB, 'app', 'privacy', 'page.tsx'))
  const terms = read(join(WEB, 'app', 'terms', 'page.tsx'))

  it('privacy discloses the hosting provider sees an IP address', () => {
    // The claim most easily rounded off to "we collect nothing". It would be false.
    expect(privacy).toMatch(/IP address/)
    expect(privacy).toMatch(/Vercel/)
  })

  it('privacy does NOT claim we collect nothing at all', () => {
    expect(privacy.toLowerCase()).not.toMatch(/we collect (nothing|no data) (at all|whatsoever)/)
  })

  it('privacy states the two correlation limits honestly', () => {
    expect(privacy).toMatch(/same published policy to two organizations/)
    expect(privacy).toMatch(/tell someone your handle/)
  })

  it('terms warns about unrecoverable key loss prominently', () => {
    expect(terms).toMatch(/We cannot recover your key/)
    expect(terms).toMatch(/no password\s+reset/i)
  })

  it('terms disclaims creating legal rights, consistently with the notice language', () => {
    expect(terms).toMatch(/does not create legal rights or obligations that do not otherwise exist/)
  })
})
