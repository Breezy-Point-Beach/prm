import { describe, expect, it, beforeEach } from 'vitest'
import type { ArtifactStore, MetadataStore, PolicyRecord, Storage } from './types'
import { DigestMismatchError, ImmutabilityError } from './types'
import { byteDigestOf, utf8, fromUtf8 } from './digest'

/**
 * StorageAdapterContract — the suite EVERY storage adapter must pass.
 *
 * PRM's core property is that what the user signed is exactly what everyone later receives. That
 * property lives or dies in the storage layer, and storage layers get replaced: someone will
 * eventually swap Vercel Blob for S3, or decide Postgres is simpler, and they will not have read the
 * pull request that explains why bytes matter.
 *
 * This contract is the guard rail for that future change. It is deliberately hostile: half the tests
 * simulate a backend that is buggy or malicious rather than merely absent, because a backend that
 * loses data announces itself, while a backend that quietly reserializes JSON does not.
 *
 * Usage, from an adapter's test file:
 *
 *     runStorageContract('BlobStore', () => makeBlobStoreWithFakes())
 */
export interface StorageContractSubject {
  /** A fresh, isolated store. Called before every test. */
  create: () => Storage | Promise<Storage>
  /**
   * A NEW Storage instance over the SAME backing store — a serverless cold start, in other words.
   * Adapters that can express this must, because "does a restart lose data" is the question
   * production storage exists to answer. Omit only where the concept genuinely does not apply.
   */
  reopen?: (storage: Storage) => Storage | Promise<Storage>
}

export function runStorageContract (name: string, subject: StorageContractSubject): void {
  const makeStorage = subject.create
  describe(`${name} satisfies the storage contract`, () => {
    let storage: Storage
    let artifacts: ArtifactStore
    let metadata: MetadataStore

    beforeEach(async () => {
      storage = await makeStorage()
      artifacts = storage.artifacts
      metadata = storage.metadata
    })

    // ---- byte preservation ---------------------------------------------------

    describe('preserves bytes exactly', () => {
      it('returns precisely what was written', async () => {
        const bytes = utf8('{\n  "b": 1,\n  "a": 2\n}\n')
        const digest = byteDigestOf(bytes)
        await artifacts.put('policy', bytes, digest)
        expect(fromUtf8(await artifacts.get(digest))).toBe('{\n  "b": 1,\n  "a": 2\n}\n')
      })

      it('preserves key order that JSON.parse would destroy', async () => {
        // The whole point: an adapter that round-trips through a JSON type would return {"a":2,"b":1}.
        const original = '{"z":1,"a":2,"m":3}'
        const digest = byteDigestOf(original)
        await artifacts.put('policy', utf8(original), digest)
        expect(fromUtf8(await artifacts.get(digest))).toBe(original)
      })

      it('preserves insignificant whitespace', async () => {
        const original = '{\n    "a":   1\n}\n\n'
        const digest = byteDigestOf(original)
        await artifacts.put('policy', utf8(original), digest)
        expect(fromUtf8(await artifacts.get(digest))).toBe(original)
      })

      it('preserves non-ASCII content byte for byte', async () => {
        const original = '{"note":"café — naïve 😀 \\u00e9 vs e\\u0301"}'
        const digest = byteDigestOf(original)
        await artifacts.put('policy', utf8(original), digest)
        expect(fromUtf8(await artifacts.get(digest))).toBe(original)
      })

      it('preserves a large artifact', async () => {
        const original = JSON.stringify({ padding: 'x'.repeat(200_000) })
        const digest = byteDigestOf(original)
        await artifacts.put('policy', utf8(original), digest)
        const back = fromUtf8(await artifacts.get(digest))
        expect(back.length).toBe(original.length)
        expect(byteDigestOf(back)).toBe(digest)
      })
    })

    // ---- content addressing --------------------------------------------------

    describe('is content-addressed', () => {
      it('REJECTS a write whose bytes do not match the declared digest', async () => {
        const bytes = utf8('{"a":1}')
        const wrongDigest = byteDigestOf('{"a":2}')
        await expect(artifacts.put('policy', bytes, wrongDigest)).rejects.toThrow(DigestMismatchError)
      })

      it('rejects a malformed digest rather than storing under a junk key', async () => {
        await expect(artifacts.put('policy', utf8('{}'), 'not-a-digest')).rejects.toThrow()
      })

      it('reports the storage address as the byte digest', async () => {
        const bytes = utf8('{"a":1}')
        const digest = byteDigestOf(bytes)
        const ref = await artifacts.put('policy', bytes, digest)
        expect(ref.byteDigest).toBe(digest)
        expect(ref.byteLength).toBe(bytes.length)
        expect(ref.location).toContain(digest)
      })

      it('gives DIFFERENT addresses to reserializations of the same document', async () => {
        // Same semantic content, different bytes, therefore different artifacts. If an adapter
        // collapsed these it would have reintroduced exactly the substitution PRM guards against.
        const a = '{\n  "a": 1\n}'
        const b = '{"a":1}'
        expect(byteDigestOf(a)).not.toBe(byteDigestOf(b))
        await artifacts.put('policy', utf8(a), byteDigestOf(a))
        await artifacts.put('policy', utf8(b), byteDigestOf(b))
        expect(fromUtf8(await artifacts.get(byteDigestOf(a)))).toBe(a)
        expect(fromUtf8(await artifacts.get(byteDigestOf(b)))).toBe(b)
      })
    })

    // ---- write-once ----------------------------------------------------------

    describe('is write-once', () => {
      it('is idempotent for identical bytes', async () => {
        const bytes = utf8('{"a":1}')
        const digest = byteDigestOf(bytes)
        const first = await artifacts.put('policy', bytes, digest)
        const second = await artifacts.put('policy', bytes, digest)
        expect(second.byteDigest).toBe(first.byteDigest)
        expect(fromUtf8(await artifacts.get(digest))).toBe('{"a":1}')
      })

      it('REFUSES to overwrite an address with different bytes', async () => {
        const bytes = utf8('{"a":1}')
        const digest = byteDigestOf(bytes)
        await artifacts.put('policy', bytes, digest)
        // A caller claiming a digest that does not match its content is either confused or hostile.
        await expect(artifacts.put('policy', utf8('{"a":999}'), digest))
          .rejects.toThrow(DigestMismatchError)
        expect(fromUtf8(await artifacts.get(digest))).toBe('{"a":1}')
      })

      it('keeps every version forever', async () => {
        const versions = ['{"v":1}', '{"v":2}', '{"v":3}']
        for (const v of versions) await artifacts.put('policy', utf8(v), byteDigestOf(v))
        for (const v of versions) {
          expect(fromUtf8(await artifacts.get(byteDigestOf(v)))).toBe(v)
        }
      })
    })

    // ---- reads are verified --------------------------------------------------

    describe('verifies what it reads back', () => {
      it('reports a missing artifact rather than returning nothing silently', async () => {
        await expect(artifacts.get(byteDigestOf('never stored'))).rejects.toThrow()
      })

      it('has() answers without throwing', async () => {
        const bytes = utf8('{"a":1}')
        await artifacts.put('policy', bytes, byteDigestOf(bytes))
        expect(await artifacts.has(byteDigestOf(bytes))).toBe(true)
        expect(await artifacts.has(byteDigestOf('absent'))).toBe(false)
      })
    })

    // ---- metadata ------------------------------------------------------------

    describe('indexes metadata without becoming authoritative', () => {
      const record = (over: Partial<PolicyRecord> = {}): PolicyRecord => ({
        handle: 'user0001',
        accountId: 'prm:aaaaaaaaaaaaaaaaaaaaaaaaaa',
        policyChainId: 'urn:prm:chain:uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        version: 1,
        policyDigest: 'uEiBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        policyByteDigest: byteDigestOf('{"v":1}'),
        policyLocation: 'artifacts/policy/x',
        policyByteLength: 7,
        kelByteDigest: byteDigestOf('[]'),
        kelLocation: 'artifacts/key-event-log/x',
        publishedAt: '2026-09-20T12:00:00Z',
        contentType: 'application/prm-policy+json',
        ...over
      })

      it('stores and returns the current version', async () => {
        await metadata.publish(record())
        const current = await metadata.currentVersion('user0001')
        expect(current?.version).toBe(1)
        expect(current?.policyByteDigest).toBe(byteDigestOf('{"v":1}'))
      })

      it('advances the current version and keeps the old one addressable', async () => {
        await metadata.publish(record({ version: 1 }))
        await metadata.publish(record({ version: 2, policyByteDigest: byteDigestOf('{"v":2}') }))
        expect((await metadata.currentVersion('user0001'))?.version).toBe(2)
        expect((await metadata.version('user0001', 1))?.version).toBe(1)
        expect((await metadata.versions('user0001')).map((v) => v.version)).toEqual([1, 2])
      })

      it('reports the handle owner', async () => {
        await metadata.publish(record())
        expect(await metadata.handleOwner('user0001')).toBe('prm:aaaaaaaaaaaaaaaaaaaaaaaaaa')
        expect(await metadata.handleOwner('nobody')).toBeNull()
      })

      it('returns null and empty rather than throwing for unknown handles', async () => {
        expect(await metadata.currentVersion('nobody')).toBeNull()
        expect(await metadata.version('nobody', 1)).toBeNull()
        expect(await metadata.versions('nobody')).toEqual([])
      })

      it('keeps handles separate', async () => {
        await metadata.publish(record({ handle: 'alice' }))
        await metadata.publish(record({ handle: 'bob', accountId: 'prm:bbbbbbbbbbbbbbbbbbbbbbbbbb' }))
        expect((await metadata.currentVersion('alice'))?.accountId).toBe('prm:aaaaaaaaaaaaaaaaaaaaaaaaaa')
        expect((await metadata.currentVersion('bob'))?.accountId).toBe('prm:bbbbbbbbbbbbbbbbbbbbbbbbbb')
      })
    })

    // ---- durability ----------------------------------------------------------

    describe('is durable across a restart', () => {
      it.skipIf(subject.reopen === undefined)(
        'a new instance over the same backing store still has the artifacts and metadata',
        async () => {
          const bytes = utf8('{"durable":true}')
          const digest = byteDigestOf(bytes)
          await artifacts.put('policy', bytes, digest)
          await metadata.publish({
            handle: 'durable', accountId: 'prm:aaaaaaaaaaaaaaaaaaaaaaaaaa',
            policyChainId: 'urn:prm:chain:uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            version: 1, policyDigest: 'uEiBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
            policyByteDigest: digest, policyLocation: 'artifacts/policy/x', policyByteLength: bytes.length,
            kelByteDigest: byteDigestOf('[]'), kelLocation: 'artifacts/key-event-log/x',
            publishedAt: '2026-09-20T12:00:00Z', contentType: 'application/prm-policy+json'
          })

          // The shape a serverless cold start takes: same data, new process.
          const reopened = await (subject.reopen as NonNullable<typeof subject.reopen>)(storage)
          expect(fromUtf8(await reopened.artifacts.get(digest))).toBe('{"durable":true}')
          expect((await reopened.metadata.currentVersion('durable'))?.version).toBe(1)
        })
    })
  })
}

/**
 * Hostile-backend suite.
 *
 * Run against an adapter wired to a backend that corrupts data. Every mutation must be caught by the
 * adapter's own read verification, so that a compromised or buggy backend cannot serve altered bytes
 * without the application noticing.
 *
 * The tampering happens BELOW the adapter, which is the realistic threat: the object store is the
 * part most likely to be operated by someone else.
 */
export function runHostileBackendContract (
  name: string,
  makeTampering: (mutate: (stored: Uint8Array) => Uint8Array) => Promise<Storage> | Storage
): void {
  describe(`${name} detects a hostile or buggy backend`, () => {
    const original = '{\n  "policy": "original",\n  "rules": [1, 2, 3]\n}\n'
    const digest = byteDigestOf(original)

    async function expectDetected (
      label: string,
      mutate: (stored: Uint8Array) => Uint8Array
    ): Promise<void> {
      const storage = await makeTampering(mutate)
      await storage.artifacts.put('policy', utf8(original), digest)
      await expect(storage.artifacts.get(digest), label).rejects.toThrow(DigestMismatchError)
    }

    it('DETECTS altered whitespace', async () => {
      await expectDetected('whitespace', (b) => utf8(fromUtf8(b).replace(/\n {2}/g, '\n    ')))
    })

    it('DETECTS reordered JSON keys', async () => {
      await expectDetected('reorder', (b) => {
        const parsed = JSON.parse(fromUtf8(b)) as Record<string, unknown>
        return utf8(JSON.stringify(Object.fromEntries(Object.entries(parsed).reverse()), null, 2))
      })
    })

    it('DETECTS a single changed byte', async () => {
      await expectDetected('one byte', (b) => {
        const copy = new Uint8Array(b)
        copy[copy.length - 3] = (copy[copy.length - 3] as number) ^ 0x01
        return copy
      })
    })

    it('DETECTS truncation', async () => {
      await expectDetected('truncation', (b) => b.slice(0, b.length - 5))
    })

    it('DETECTS appended trailing content', async () => {
      await expectDetected('append', (b) => utf8(fromUtf8(b) + '\n'))
    })

    it('DETECTS an artifact belonging to another account', async () => {
      await expectDetected('substitution', () => utf8('{"policy":"someone else entirely"}'))
    })

    it('DETECTS correct semantic content that was reserialized', async () => {
      // The subtle one, and the reason byte digests exist. The document still means the same thing
      // and its PRM signature would still verify — only the bytes changed.
      await expectDetected('reserialization', (b) => utf8(JSON.stringify(JSON.parse(fromUtf8(b)))))
    })

    it('accepts untouched bytes, proving the suite is not simply failing everything', async () => {
      const storage = await makeTampering((b) => b)
      await storage.artifacts.put('policy', utf8(original), digest)
      expect(fromUtf8(await storage.artifacts.get(digest))).toBe(original)
    })
  })
}
