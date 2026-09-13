import {
  buildTimestampRequest, parseTimestampResponse, timingSafeEqual, tokenToBase64
} from '@prm/crypto'

/**
 * RFC 3161 client — server only. docs/08 §3.
 *
 * Two independent authorities (D25), so one operator's compromise or shutdown does not orphan the
 * archive. Each is asked for a token over the same imprint; each reply is checked to be a GRANTED
 * token for exactly that imprint before it is stored. The authority's certificate chain is fetched
 * and archived beside the token when a source is known (docs/08 §5): a token whose signer
 * certificate has since expired is still verifiable, but only with the chain that was current.
 */
export interface TimestampAuthority {
  /** Short operator label: file stem in bundles, column in the database. */
  tsa: string
  url: string
  /** Where to fetch the operator's CA chain, PEM (TSA_*_CA_URL). Optional; tokens usually embed their signer. */
  caUrl?: string
}

export function configuredAuthorities (env: Record<string, string | undefined> = process.env): TimestampAuthority[] {
  const out: TimestampAuthority[] = []
  for (const [urlKey, caKey] of [['TSA_PRIMARY_URL', 'TSA_PRIMARY_CA_URL'], ['TSA_SECONDARY_URL', 'TSA_SECONDARY_CA_URL']] as const) {
    const url = env[urlKey]?.trim()
    if (!url) continue
    const host = new URL(url).hostname.replace(/^www\./, '')
    const caUrl = env[caKey]?.trim()
    out.push({ tsa: labelFor(host), url, ...(caUrl ? { caUrl } : {}) })
  }
  return out
}

/** "freetsa.org" -> "freetsa"; "timestamp.digicert.com" -> "digicert"; "tsa.example.co.uk" -> "example". */
export function labelFor (host: string): string {
  const parts = host.toLowerCase().split('.').filter(Boolean)
  const generic = new Set(['timestamp', 'tsa', 'ts', 'time', 'rfc3161', 'www', 'api'])
  const secondLevel = new Set(['co', 'com', 'org', 'net', 'ac', 'gov', 'edu'])
  let domain = parts.slice(0, -1)
  if (domain.length >= 2 && secondLevel.has(domain[domain.length - 1] as string)) domain = domain.slice(0, -1)
  const meaningful = domain.filter((p) => !generic.has(p))
  const label = (meaningful[meaningful.length - 1] ?? parts[0] ?? 'tsa').replace(/[^a-z0-9]/g, '')
  return label || 'tsa'
}

export interface AcquiredTimestamp {
  tokenBase64: string
  genTime: string
  serialNumberHex: string
  tsaName?: string
  chainPem?: string
}

export class TimestampAuthorityError extends Error {
  constructor (public readonly tsa: string, message: string) {
    super(`${tsa}: ${message}`)
    this.name = 'TimestampAuthorityError'
  }
}

const chainCache = new Map<string, string>()

/**
 * Ask one authority for a token over `imprint`, and refuse anything that is not a granted token for
 * exactly that imprint. A nonce is sent and must be echoed, so a replayed or misrouted reply cannot
 * be mistaken for a fresh one.
 */
export async function requestTimestamp (
  authority: TimestampAuthority,
  imprint: Uint8Array,
  opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {}
): Promise<AcquiredTimestamp> {
  const fetchImpl = opts.fetchImpl ?? fetch
  const nonce = crypto.getRandomValues(new Uint8Array(8))
  const request = buildTimestampRequest(imprint, { nonce, certReq: true })

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000)
  let bytes: Uint8Array
  try {
    const response = await fetchImpl(authority.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query', Accept: 'application/timestamp-reply' },
      // A fresh copy so the body is exactly the request bytes, with no shared-buffer offset.
      body: request.slice().buffer as ArrayBuffer,
      signal: controller.signal,
      cache: 'no-store'
    })
    if (!response.ok) throw new TimestampAuthorityError(authority.tsa, `HTTP ${response.status}`)
    bytes = new Uint8Array(await response.arrayBuffer())
  } catch (e) {
    if (e instanceof TimestampAuthorityError) throw e
    throw new TimestampAuthorityError(authority.tsa, (e as Error).message)
  } finally {
    clearTimeout(timer)
  }

  const reply = parseTimestampResponse(bytes)
  if (reply.status !== 0 && reply.status !== 1) {
    throw new TimestampAuthorityError(authority.tsa, `status ${reply.statusText}${reply.statusString ? ` — ${reply.statusString}` : ''}`)
  }
  const token = reply.token
  if (!token) throw new TimestampAuthorityError(authority.tsa, 'granted, but no token in the reply')
  if (token.hashedMessage.length !== imprint.length || !timingSafeEqual(token.hashedMessage, imprint)) {
    throw new TimestampAuthorityError(authority.tsa, 'token imprint does not match what was requested')
  }
  const nonceHex = Array.from(nonce, (b) => b.toString(16).padStart(2, '0')).join('').replace(/^0+(?=.)/, '')
  if (token.nonceHex !== undefined && token.nonceHex.replace(/^0+(?=.)/, '') !== nonceHex) {
    throw new TimestampAuthorityError(authority.tsa, 'token nonce does not match the request')
  }

  let chainPem: string | undefined
  if (authority.caUrl) {
    chainPem = chainCache.get(authority.caUrl)
    if (!chainPem) {
      try {
        const r = await fetchImpl(authority.caUrl, { cache: 'no-store' })
        const text = r.ok ? await r.text() : ''
        if (text.includes('-----BEGIN CERTIFICATE-----')) { chainPem = text; chainCache.set(authority.caUrl, text) }
      } catch { /* the token is still evidence without the archived chain; the reader can fetch it */ }
    }
  }

  return {
    tokenBase64: tokenToBase64(bytes),
    genTime: token.genTime,
    serialNumberHex: token.serialNumberHex,
    ...(token.tsaName ? { tsaName: token.tsaName } : {}),
    ...(chainPem ? { chainPem } : {})
  }
}
