#!/usr/bin/env node
/**
 * Derive the public log key from a LOG_SIGNING_KEY_B64 seed, for NEXT_PUBLIC_LOG_PUBLIC_KEY.
 *
 *   node apps/web/scripts/log-key.mjs                 # generate a new seed and print both
 *   node apps/web/scripts/log-key.mjs <base64 seed>   # print the public key for an existing seed
 *
 * The seed is printed ONLY when this script generated it. Never paste a production seed into a
 * shell history you do not control; prefer `vercel env add LOG_SIGNING_KEY_B64 production` and
 * type it at the prompt.
 */
import { randomBytes } from 'node:crypto'
import { keyPairFromSeed } from '@prm/crypto'

const given = process.argv[2]
const seed = given ? Buffer.from(given, 'base64') : randomBytes(32)
if (seed.length !== 32) {
  console.error('the seed must be 32 bytes, base64')
  process.exit(3)
}
const pair = keyPairFromSeed(new Uint8Array(seed))
if (!given) console.log(`LOG_SIGNING_KEY_B64=${seed.toString('base64')}`)
console.log(`NEXT_PUBLIC_LOG_PUBLIC_KEY=${pair.publicKeyMultibase}`)
