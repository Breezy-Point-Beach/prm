import { describe, it, expect } from 'vitest'
import { planRemoval, applyRemoval, guardLogTables, readEnvFile } from '../scripts/remove-handle.mjs'

/**
 * The handle-removal script (DEPLOYMENT.md, “Removing a handle”). Two properties matter more than the happy path: an
 * object still referenced by another handle survives, and the transparency-log tables are
 * unreachable from the script by construction, not by convention.
 */
type Row = Record<string, unknown>

function row (handle: string, version: number, policy: string, policyBytes: string, kelBytes: string): Row {
  return {
    handle, version, account_id: `prm:${handle}`, policy_chain_id: 'chain',
    policy_digest: policy, policy_byte_digest: policyBytes,
    policy_location: `artifacts/policy/${policyBytes}`, policy_byte_length: 1,
    kel_byte_digest: kelBytes, kel_location: `artifacts/key-event-log/${kelBytes}`,
    content_type: 'application/json', published_at: '2026-09-13T00:00:00Z'
  }
}

/** The statements the script issues, over in-memory tables. Anything else is a failure. */
function fakeStore (seed: { policies: Row[], links: Row[], objects: string[] }) {
  const policies = [...seed.policies]
  const links = [...seed.links]
  const objects = new Set(seed.objects)
  const statements: string[] = []
  const deleted: string[] = []

  const raw = async (text: string, params: unknown[] = []): Promise<Row[]> => {
    statements.push(text)
    const q = text.replace(/\s+/g, ' ').trim()
    if (q.startsWith('select * from published_policies where handle = $1')) {
      return policies.filter((r) => r.handle === params[0]).sort((a, b) => Number(a.version) - Number(b.version))
    }
    if (q.includes('from published_policies where handle <> $1')) {
      const ds = params[1] as string[]
      return policies.filter((r) => r.handle !== params[0] &&
        (ds.includes(r.policy_byte_digest as string) || ds.includes(r.kel_byte_digest as string)))
    }
    if (q.startsWith('select * from published_policy_log where policy_digest = any($1)')) {
      const ds = params[0] as string[]
      return links.filter((r) => ds.includes(r.policy_digest as string))
    }
    if (q.startsWith('delete from published_policy_log where policy_digest = any($1)')) {
      const ds = params[0] as string[]
      for (let i = links.length - 1; i >= 0; i--) if (ds.includes(links[i]!.policy_digest as string)) links.splice(i, 1)
      return []
    }
    if (q.startsWith('delete from published_policies where handle = $1')) {
      for (let i = policies.length - 1; i >= 0; i--) if (policies[i]!.handle === params[0]) policies.splice(i, 1)
      return []
    }
    throw new Error(`unexpected statement: ${q}`)
  }
  const blob = {
    head: async (pathname: string) => {
      if (!objects.has(pathname)) throw new Error('BlobNotFoundError')
      return { url: `https://blob.example/${pathname}` }
    },
    del: async (pathname: string) => { deleted.push(pathname); objects.delete(pathname) }
  }
  return { sql: guardLogTables(raw), blob, policies, links, objects, statements, deleted }
}

const A1 = row('alice', 1, 'pA1', 'bA1', 'kA')
const A2 = row('alice', 2, 'pA2', 'bA2', 'kA')          // v2 reuses the KEL object
const B1 = row('bob', 1, 'pB1', 'bB1', 'kA')            // bob published the same KEL bytes
const ALL_OBJECTS = ['artifacts/policy/bA1', 'artifacts/policy/bA2', 'artifacts/policy/bB1', 'artifacts/key-event-log/kA']

describe('remove-handle', () => {
  it('plans every version, its log links, and one object per digest', async () => {
    const store = fakeStore({
      policies: [A1, A2],
      links: [{ policy_digest: 'pA2', account_id: 'prm:alice', entry_digest: 'e', leaf_index: 7 }],
      objects: ALL_OBJECTS
    })
    const plan = await planRemoval({ sql: store.sql, blob: store.blob, handle: 'alice' })
    expect(plan.rows.map((r: Row) => r.version)).toEqual([1, 2])
    expect(plan.links.map((l: Row) => l.leaf_index)).toEqual([7])
    expect(plan.remove.map((o: { location: string }) => o.location).sort()).toEqual(
      ['artifacts/key-event-log/kA', 'artifacts/policy/bA1', 'artifacts/policy/bA2'])
    expect(plan.keep).toEqual([])
    expect(store.statements.some((s) => s.startsWith('delete'))).toBe(false)
  })

  it('is empty for a handle nobody published', async () => {
    const store = fakeStore({ policies: [A1], links: [], objects: ALL_OBJECTS })
    const plan = await planRemoval({ sql: store.sql, blob: store.blob, handle: 'nobody' })
    expect(plan).toEqual({ handle: 'nobody', rows: [], links: [], remove: [], keep: [] })
  })

  it('keeps an object that another handle still references', async () => {
    const store = fakeStore({ policies: [A1, B1], links: [], objects: ALL_OBJECTS })
    const plan = await planRemoval({ sql: store.sql, blob: store.blob, handle: 'alice' })
    expect(plan.remove.map((o: { location: string }) => o.location)).toEqual(['artifacts/policy/bA1'])
    expect(plan.keep).toEqual([
      { digest: 'kA', location: 'artifacts/key-event-log/kA', exists: true, sharedWith: ['bob v1'] }
    ])
  })

  it('applies rows first, then objects, and leaves the other handle whole', async () => {
    const store = fakeStore({
      policies: [A1, A2, B1],
      links: [{ policy_digest: 'pA1', account_id: 'prm:alice', entry_digest: 'e', leaf_index: 3 }],
      objects: ALL_OBJECTS
    })
    const ctx = { sql: store.sql, blob: store.blob, handle: 'alice' }
    const plan = await planRemoval(ctx)
    const done = await applyRemoval(plan, ctx)

    expect(done).toEqual({ links: 1, rows: 2, objects: 2 })
    expect(store.policies).toEqual([B1])
    expect(store.links).toEqual([])
    expect([...store.objects].sort()).toEqual(['artifacts/key-event-log/kA', 'artifacts/policy/bB1'])

    const firstDelete = store.statements.findIndex((s) => s.startsWith('delete'))
    const lastDelete = store.statements.length - 1
    expect(firstDelete).toBeGreaterThan(0)
    expect(store.statements[lastDelete]).toMatch(/^delete from published_policies/)
    // objects went after the last row deletion, which was the last statement
    expect(store.deleted).toEqual(['artifacts/policy/bA1', 'artifacts/policy/bA2'])
  })

  it('skips objects that are already absent', async () => {
    const store = fakeStore({ policies: [A1], links: [], objects: ['artifacts/policy/bA1'] })
    const ctx = { sql: store.sql, blob: store.blob, handle: 'alice' }
    const plan = await planRemoval(ctx)
    expect(plan.remove.find((o: { digest: string }) => o.digest === 'kA')?.exists).toBe(false)
    const done = await applyRemoval(plan, ctx)
    expect(done.objects).toBe(1)
    expect(store.deleted).toEqual(['artifacts/policy/bA1'])
  })

  it('prefixes every table in a preview namespace', async () => {
    const seen: string[] = []
    const sql = guardLogTables(async (text: string) => { seen.push(text); return [] })
    await planRemoval({ sql, blob: { head: async () => ({}), del: async () => {} }, handle: 'x', tablePrefix: 'preview_' })
    expect(seen).toHaveLength(1)
    expect(seen[0]).toContain('from preview_published_policies')
  })

  it('cannot reach the transparency log, whatever statement is attempted', () => {
    const sql = guardLogTables(async () => [])
    for (const table of ['log_leaves', 'log_tree_heads', 'log_timestamps']) {
      expect(() => sql(`delete from ${table}`, [])).toThrow(/append-only/)
      expect(() => sql(`select * from preview_${table}`, [])).toThrow(/append-only/)
    }
    expect(() => sql('select * from published_policy_log', [])).not.toThrow()
  })

  it('reads the file `vercel env pull` writes without evaluating it', () => {
    const parsed = readEnvFile([
      '# Created by Vercel CLI',
      'DATABASE_URL="postgres://u:p@host/db?sslmode=require"',
      'BLOB_READ_WRITE_TOKEN="vercel_blob_rw_abc"',
      'PLAIN=value',
      'QUOTED="a \\"b\\" c"',
      ''
    ].join('\n'))
    expect(parsed).toEqual({
      DATABASE_URL: 'postgres://u:p@host/db?sslmode=require',
      BLOB_READ_WRITE_TOKEN: 'vercel_blob_rw_abc',
      PLAIN: 'value',
      QUOTED: 'a "b" c'
    })
  })
})
