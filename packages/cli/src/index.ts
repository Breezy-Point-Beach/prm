/**
 * @prm/cli — programmatic access to the same commands the `prm` binary runs.
 *
 * All verification comes from @prm/verify. This package adds argument parsing and rendering only.
 */
export * from './commands.js'
export * from './render.js'
export { main } from './cli.js'
