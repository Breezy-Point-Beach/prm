#!/usr/bin/env node
/**
 * Bundle the CLI into ONE self-contained ESM file for publishing.
 *
 * Why a bundle: the CLI depends on the workspace packages (@prm/crypto, @prm/schema, @prm/verify),
 * which are not published — and the `@prm` npm scope belongs to someone else, so a published
 * package that merely listed them as dependencies would resolve to a stranger's code. Inlining
 * everything means the published artifact has no dependencies at all: what runs is what shipped.
 *
 * ESM rather than CJS because cli.ts decides whether it is the entry point with `import.meta.url`.
 * The banner provides `require` for the CommonJS dependencies esbuild inlines (ajv-formats, ajv's
 * runtime helpers), which otherwise become "Dynamic require is not supported" at run time.
 */
import { build } from 'esbuild'
import { chmodSync } from 'node:fs'

await build({
  entryPoints: ['src/cli.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  outfile: 'dist/prm.mjs',
  banner: {
    // esbuild keeps the entry file's own "#!/usr/bin/env node" as line 1; the banner follows it.
    js: 'import { createRequire } from "node:module";\nconst require = createRequire(import.meta.url);'
  },
  logLevel: 'warning'
})
chmodSync('dist/prm.mjs', 0o755)
