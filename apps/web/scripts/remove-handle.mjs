#!/usr/bin/env node
/**
 * Removes a handle from storage: its published_policies rows, its log links, and the artifacts
 * those rows point to — unless another handle still references the same bytes.
 *
 *   node apps/web/scripts/remove-handle.mjs <handle>                      # dry run: print the plan, change nothing
 *   node apps/web/scripts/remove-handle.mjs <handle> --apply              # do it
 *   node apps/web/scripts/remove-handle.mjs <handle> --env-file <path>    # DATABASE_URL and BLOB_READ_WRITE_TOKEN from a `vercel env pull` file
 *   node apps/web/scripts/remove-handle.mjs <handle> --namespace preview_ # a preview namespace (docs/16 §4)
 *
 * What it never touches: log_leaves, log_tree_heads, log_timestamps. The transparency log is
 * append-only (docs/07 §5): a signed tree head already commits to the removed policy's leaf, and a
 * timestamp authority may have attested to that tree head, so removing the leaf would break every
 * later inclusion proof and every token already issued. The handle stops resolving; the leaf stays.
 *
 * Artifacts are content-addressed. Two handles that published byte-identical documents share one
 * object, so an object is deleted only when no remaining row references its digest.
 *
 * Order on --apply: link rows, policy rows, then objects. If object deletion fails part-way the
 * handle is already a 404 and the leftovers are unreachable content-addressed objects; the other
 * order could leave a page that serves an integrity failure.
 *
 * Secrets are read from the environment or the env file and are never printed.
 */
import { readFileSync, realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const LOG_TABLES = ['log_leaves', 'log_tree_heads', 'log_timestamps']

/** Wraps a query function so that no statement can name a log table, whatever the caller does. */
export function guardLogTables (sql) {
  return (text, params) => {
    const hit = LOG_TABLES.find((t) => new RegExp(`${t}\\b`).test(text))
    if (hit) throw new Error(`refusing to touch ${hit}: the transparency log is append-only`)
    return sql(text, params)
  }
}

/**
 * @typedef {object} Context
 * @property {(text: string, params?: unknown[]) => Promise<Record<string, unknown>[]>} sql  the Neon query function
 * @property {{ head: (p: string, o?: object) => Promise<unknown>, del: (p: string, o?: object) => Promise<unknown> }} blob  the Vercel Blob SDK, or a stand-in
 * @property {string} handle
 * @property {string} [tablePrefix]  "preview_" for a preview namespace
 * @property {string} [token]        BLOB_READ_WRITE_TOKEN
 */

/**
 * Everything that would change, computed without changing anything.
 * @param {Context} ctx
 */
export async function planRemoval ({ sql, blob, handle, tablePrefix = '', token }) {
  const t = (name) => tablePrefix + name
  const opts = token ? { token } : {}

  const rows = await sql(
    `select * from ${t('published_policies')} where handle = $1 order by version asc`, [handle])
  if (rows.length === 0) return { handle, rows: [], links: [], remove: [], keep: [] }

  const digests = [...new Set(rows.flatMap((r) => [r.policy_byte_digest, r.kel_byte_digest]))]
  const others = await sql(
    `select handle, version, policy_byte_digest, kel_byte_digest from ${t('published_policies')}
      where handle <> $1 and (policy_byte_digest = any($2) or kel_byte_digest = any($2))`,
    [handle, digests])
  const sharedWith = new Map()
  for (const o of others) {
    for (const d of [o.policy_byte_digest, o.kel_byte_digest]) {
      if (!digests.includes(d)) continue
      if (!sharedWith.has(d)) sharedWith.set(d, [])
      sharedWith.get(d).push(`${o.handle} v${o.version}`)
    }
  }

  const links = await sql(
    `select * from ${t('published_policy_log')} where policy_digest = any($1)`,
    [rows.map((r) => r.policy_digest)])

  // One object per digest, however many versions point at it.
  const locations = new Map()
  for (const r of rows) {
    locations.set(r.policy_byte_digest, r.policy_location)
    locations.set(r.kel_byte_digest, r.kel_location)
  }
  const remove = []
  const keep = []
  for (const [digest, location] of locations) {
    let exists = true
    try { await blob.head(location, opts) } catch { exists = false }
    if (sharedWith.has(digest)) keep.push({ digest, location, exists, sharedWith: sharedWith.get(digest) })
    else remove.push({ digest, location, exists })
  }
  return { handle, rows, links, remove, keep }
}

/**
 * Executes a plan. Returns counts of what was deleted.
 * @param {Awaited<ReturnType<typeof planRemoval>>} plan
 * @param {Context} ctx
 */
export async function applyRemoval (plan, { sql, blob, tablePrefix = '', token }) {
  const t = (name) => tablePrefix + name
  const opts = token ? { token } : {}
  const done = { links: 0, rows: 0, objects: 0 }
  if (plan.links.length > 0) {
    await sql(`delete from ${t('published_policy_log')} where policy_digest = any($1)`,
      [plan.links.map((l) => l.policy_digest)])
    done.links = plan.links.length
  }
  if (plan.rows.length > 0) {
    await sql(`delete from ${t('published_policies')} where handle = $1`, [plan.handle])
    done.rows = plan.rows.length
  }
  for (const o of plan.remove) {
    if (!o.exists) continue
    await blob.del(o.location, opts)
    done.objects += 1
  }
  return done
}

/** KEY="value" lines as `vercel env pull` writes them. */
export function readEnvFile (text) {
  const out = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) continue
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(?:"((?:[^"\\]|\\.)*)"|(.*))$/.exec(line)
    if (m) out[m[1]] = m[2] !== undefined ? m[2].replace(/\\(.)/g, '$1') : m[3]
  }
  return out
}

function parseArgs (argv) {
  const args = { handle: undefined, apply: false, envFile: undefined, namespace: '' }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--apply') args.apply = true
    else if (a === '--env-file') args.envFile = argv[++i]
    else if (a === '--namespace') args.namespace = argv[++i] ?? ''
    else if (a.startsWith('--')) throw new Error(`unknown option ${a}`)
    else if (args.handle === undefined) args.handle = a
    else throw new Error('one handle at a time')
  }
  if (!args.handle) {
    throw new Error('usage: remove-handle.mjs <handle> [--apply] [--env-file <path>] [--namespace <prefix>]')
  }
  return args
}

const short = (s) => `${String(s).slice(0, 14)}…`

async function main () {
  const args = parseArgs(process.argv.slice(2))
  // The file is explicit, so it wins over whatever the shell happens to have exported.
  const env = { ...process.env, ...(args.envFile ? readEnvFile(readFileSync(args.envFile, 'utf8')) : {}) }
  const databaseUrl = env.DATABASE_URL
  const token = env.BLOB_READ_WRITE_TOKEN
  if (!databaseUrl || !token) {
    throw new Error('DATABASE_URL and BLOB_READ_WRITE_TOKEN are required, from the environment or --env-file. Neither is ever printed.')
  }

  const { neon } = await import('@neondatabase/serverless')
  const blob = await import('@vercel/blob')
  const client = neon(databaseUrl)
  const sql = guardLogTables((text, params) => client.query(text, params))
  const ctx = { sql, blob, handle: args.handle, tablePrefix: args.namespace, token }

  const plan = await planRemoval(ctx)
  const where = args.namespace ? `namespace "${args.namespace}"` : 'the production namespace'
  console.log(`\n  ${args.handle} in ${where}`)
  if (plan.rows.length === 0) { console.log('  nothing published under this handle. Nothing to do.\n'); return }

  console.log(`  rows (${plan.rows.length}):`)
  for (const r of plan.rows) {
    console.log(`    v${r.version}  account ${short(r.account_id)}  policy ${short(r.policy_digest)}  published ${String(r.published_at)}`)
  }
  console.log(`  log links (${plan.links.length}):${plan.links.length === 0 ? ' none' : ''}`)
  for (const l of plan.links) console.log(`    ${short(l.policy_digest)} → leaf ${l.leaf_index}  (the leaf itself stays)`)
  console.log(`  objects to delete (${plan.remove.length}):`)
  for (const o of plan.remove) console.log(`    ${o.location}  ${o.exists ? '' : '(already absent)'}`)
  console.log(`  objects kept, still referenced elsewhere (${plan.keep.length}):${plan.keep.length === 0 ? ' none' : ''}`)
  for (const o of plan.keep) console.log(`    ${o.location}  shared with ${o.sharedWith.join(', ')}`)

  if (!args.apply) { console.log('\n  Dry run: nothing was changed. Re-run with --apply to remove.\n'); return }

  const done = await applyRemoval(plan, ctx)
  const left = await sql(
    `select count(*)::int as n from ${args.namespace}published_policies where handle = $1`, [args.handle])
  console.log(`\n  removed: ${done.rows} row(s), ${done.links} link(s), ${done.objects} object(s)`)
  console.log(`  rows remaining for ${args.handle}: ${left[0]?.n ?? '?'}\n`)
}

if (process.argv[1] && pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url) {
  main().catch((e) => { console.error(`  error: ${e.message}`); process.exit(1) })
}
