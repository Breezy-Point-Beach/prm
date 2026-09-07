import { describe, expect, it } from 'vitest'
import { NormalizationError, normalizeIdentifier } from '../src/normalize.js'

describe('identifier normalization is deterministic', () => {
  it.each([
    ['us-license-plate', 'US-CA-7ABC123', 'US-CA-7ABC123'],
    ['us-license-plate', 'ca 7abc123', 'US-CA-7ABC123'],
    ['us-license-plate', ' CA-7ABC-123 ', 'US-CA-7ABC123'],
    ['us-license-plate', 'us-ca-7abc123', 'US-CA-7ABC123'],
    ['us-license-plate', 'TX ABC123', 'US-TX-ABC123'],
    ['email', 'Holder@Example.ORG', 'holder@example.org'],
    ['email', '  holder@example.org  ', 'holder@example.org'],
    ['phone', '+1 (555) 123-4567', '+15551234567'],
    ['phone', '15551234567', '+15551234567'],
    ['vin', '1hgbh41jxmn109186', '1HGBH41JXMN109186'],
    ['account-id', 'Example.COM:AbC123', 'example.com:AbC123'],
    ['device-id', 'Device-ABC', 'Device-ABC']
  ])('%s: %s -> %s', (ns, input, expected) => {
    expect(normalizeIdentifier(ns, input)).toBe(expected)
  })

  it('every spelling of one plate collapses to a single commitment input', () => {
    const forms = ['US-CA-7ABC123', 'ca 7abc123', 'CA 7ABC 123', 'us-CA-7abc-123']
    const set = new Set(forms.map((f) => normalizeIdentifier('us-license-plate', f)))
    expect(set.size).toBe(1)
  })

  it('does NOT apply provider-specific email canonicalization', () => {
    // Gmail treats these as one mailbox; PRM does not decide that for the user.
    expect(normalizeIdentifier('email', 'a.b+tag@gmail.com')).toBe('a.b+tag@gmail.com')
  })

  it.each([
    ['us-license-plate', 'ZZ-ABC123'],
    ['us-license-plate', 'A'],
    ['email', 'not-an-email'],
    ['email', '@example.com'],
    ['phone', '+1 555'],
    ['vin', 'TOO-SHORT'],
    ['vin', '1HGBH41JXMN10918I'],
    ['account-id', 'no-colon']
  ])('rejects %s: %s', (ns, bad) => {
    expect(() => normalizeIdentifier(ns, bad)).toThrow(NormalizationError)
  })
})
