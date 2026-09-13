import type { SqlQuery } from '../../lib/storage/blob'

/**
 * A stand-in for Neon's HTTP driver: one statement per call, no transactions.
 *
 * It understands only the statements the Postgres adapters issue, matched on shape rather than
 * parsed, and it reproduces the one behaviour that matters for correctness — a primary-key
 * collision on leaf_index raises, so the adapter's retry loop is what makes concurrent appends
 * safe. Relations are keyed by their FULL name, prefix included, so a namespaced store and a plain
 * one over the same fake see disjoint tables — exactly what the real database does.
 */
type Row = Record<string, unknown>
export interface FakePostgres {
  sql: SqlQuery
  tables: Map<string, Row[]>
  statements: string[]
}

export function fakePostgres (): FakePostgres {
  const tables = new Map<string, Row[]>()
  const statements: string[] = []
  const table = (name: string): Row[] => {
    let t = tables.get(name)
    if (!t) { t = []; tables.set(name, t) }
    return t
  }
  const rel = (q: string, verb: RegExp): string => {
    const m = verb.exec(q)
    if (!m?.[1]) throw new Error(`fakePostgres: no relation in: ${q.slice(0, 80)}`)
    return m[1]
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const sql = (async (text: string, values: unknown[] = []): Promise<any[]> => {
    const q = text.replace(/\s+/g, ' ').trim().toLowerCase()
    statements.push(q)
    if (q.startsWith('create table') || q.startsWith('create index')) return []

    if (q.startsWith('insert into')) {
      const name = rel(q, /^insert into (\w+)/)
      const rows = table(name)
      if (name.endsWith('log_leaves')) {
        const [leaf_hash, appended_at] = values as [string, string]
        if (rows.some((r) => r.leaf_hash === leaf_hash)) return []
        const leaf_index = rows.length === 0 ? 0 : Math.max(...rows.map((r) => Number(r.leaf_index))) + 1
        // Simulate the race the real database would expose: yield, then check the key again.
        await new Promise((r) => setTimeout(r, Math.random() * 3))
        if (rows.some((r) => r.leaf_index === leaf_index)) {
          throw new Error(`duplicate key value violates unique constraint "${name}_pkey"`)
        }
        rows.push({ leaf_index, leaf_hash, appended_at })
        return [{ leaf_index }]
      }
      if (name.endsWith('log_tree_heads')) {
        const [tree_size, sth_json, created_at] = values
        if (!rows.some((r) => r.tree_size === tree_size)) rows.push({ tree_size, sth_json, created_at })
        return []
      }
      if (name.endsWith('log_timestamps')) {
        const [tree_size, tsa, token_b64, gen_time, chain_pem, acquired_at] = values
        const row = { tree_size, tsa, token_b64, gen_time, chain_pem, acquired_at }
        const i = rows.findIndex((r) => r.tree_size === tree_size && r.tsa === tsa)
        if (i >= 0) rows[i] = row; else rows.push(row)
        return []
      }
      if (name.endsWith('published_policy_log')) {
        const [policy_digest, account_id, entry_digest, leaf_index, linked_at] = values
        if (!rows.some((r) => r.policy_digest === policy_digest)) rows.push({ policy_digest, account_id, entry_digest, leaf_index, linked_at })
        return []
      }
      if (name.endsWith('published_policies')) {
        const [handle, version, account_id, policy_chain_id, policy_digest, policy_byte_digest, policy_location, policy_byte_length, kel_byte_digest, kel_location, content_type, published_at] = values
        if (!rows.some((r) => r.handle === handle && r.version === version)) {
          rows.push({ handle, version, account_id, policy_chain_id, policy_digest, policy_byte_digest, policy_location, policy_byte_length, kel_byte_digest, kel_location, content_type, published_at })
        }
        return []
      }
      throw new Error(`fakePostgres: unhandled insert: ${q.slice(0, 80)}`)
    }

    if (q.startsWith('select')) {
      const name = rel(q, / from (\w+)/)
      const rows = table(name)
      if (q.includes('count(*)')) return [{ n: rows.length }]
      if (name.endsWith('log_leaves')) {
        if (q.includes('where leaf_hash')) return rows.filter((r) => r.leaf_hash === values[0])
        return [...rows].sort((a, b) => Number(a.leaf_index) - Number(b.leaf_index))
      }
      if (name.endsWith('log_tree_heads')) {
        if (q.includes('where')) return rows.filter((r) => r.tree_size === values[0])
        return [...rows].sort((a, b) => Number(b.tree_size) - Number(a.tree_size)).slice(0, 1)
      }
      if (name.endsWith('log_timestamps')) {
        if (q.includes('where')) return rows.filter((r) => r.tree_size === values[0]).sort((a, b) => String(a.tsa).localeCompare(String(b.tsa)))
        return [...rows].sort((a, b) => String(b.acquired_at).localeCompare(String(a.acquired_at)) || Number(b.tree_size) - Number(a.tree_size)).slice(0, 1)
      }
      if (name.endsWith('published_policy_log')) return rows.filter((r) => r.policy_digest === values[0])
      if (name.endsWith('published_policies')) {
        const byHandle = rows.filter((r) => r.handle === values[0])
        if (q.includes('and version')) return byHandle.filter((r) => r.version === values[1])
        if (q.includes('order by version desc')) return [...byHandle].sort((a, b) => Number(b.version) - Number(a.version)).slice(0, 1)
        if (q.includes('limit 1')) return byHandle.slice(0, 1)
        return [...byHandle].sort((a, b) => Number(a.version) - Number(b.version))
      }
    }
    throw new Error(`fakePostgres: unhandled statement: ${q.slice(0, 80)}`)
  }) as SqlQuery
  return { sql, tables, statements }
}
