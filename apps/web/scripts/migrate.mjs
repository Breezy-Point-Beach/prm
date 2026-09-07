#!/usr/bin/env node
/**
 * Applies the database schema.
 *
 *   node apps/web/scripts/migrate.mjs            # uses DATABASE_URL from the environment
 *   node apps/web/scripts/migrate.mjs --check    # report the current schema, change nothing
 *
 * The SQL is READ FROM lib/storage/blob.ts rather than duplicated here, so there is exactly one
 * definition of the schema. A migration script with its own copy of the DDL is a second source of
 * truth, and the two drift the first time someone edits only one of them.
 *
 * Every statement is `if not exists`, so this is safe to re-run.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { neon } from '@neondatabase/serverless'

const HERE = dirname(fileURLToPath(import.meta.url))
const WEB = resolve(HERE, '..')
const REPO = resolve(WEB, '../..')

/** Pull SCHEMA_SQL out of the TypeScript source without importing it. */
function schemaSql () {
  const src = readFileSync(resolve(WEB, 'lib/storage/blob.ts'), 'utf8')
  const match = /export const SCHEMA_SQL = `([\s\S]*?)`/.exec(src)
  if (!match?.[1]) throw new Error('could not find SCHEMA_SQL in lib/storage/blob.ts')
  return match[1]
}

/** DATABASE_URL from the environment, or from .env.local for local runs. */
function databaseUrl () {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL
  for (const candidate of [resolve(REPO, '.env.local'), resolve(WEB, '.env.local')]) {
    try {
      const found = /^DATABASE_URL="?([^"\n]+)"?/m.exec(readFileSync(candidate, 'utf8'))?.[1]
      if (found) return found
    } catch { /* try the next candidate */ }
  }
  throw new Error(
    'DATABASE_URL is not set. Run `vercel env pull` first, or export it. ' +
    'It is never printed by this script.')
}

const check = process.argv.includes('--check')
const sql = neon(databaseUrl())

if (!check) {
  const statements = schemaSql().split(';').map((s) => s.trim()).filter(Boolean)
  for (const statement of statements) {
    await sql.query(statement)
    console.log('  applied:', statement.split('\n')[0].slice(0, 68))
  }
}

const columns = await sql.query(
  `select column_name, data_type, is_nullable
     from information_schema.columns
    where table_name = 'published_policies'
    order by ordinal_position`)

if (columns.length === 0) {
  console.log('\n  published_policies does not exist. Run without --check to create it.')
  process.exit(1)
}

console.log('\n  published_policies')
for (const c of columns) {
  console.log(`    ${c.column_name.padEnd(20)} ${c.data_type}${c.is_nullable === 'NO' ? ' not null' : ''}`)
}

// The invariant from decision D51/D58: no column may hold a policy or a raw identifier.
const forbidden = columns.filter((c) => c.data_type === 'jsonb' || /policy_json|document|content$/.test(c.column_name))
if (forbidden.length > 0) {
  console.error('\n  ERROR: a column could hold a signed artifact. Artifacts belong in blob storage.')
  for (const c of forbidden) console.error(`    ${c.column_name} (${c.data_type})`)
  process.exit(1)
}
console.log('\n  OK: every column is a handle, a digest, a location, a length, or a timestamp.')
