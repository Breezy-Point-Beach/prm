/**
 * @prm/crypto — the cryptographic core.
 *
 * Every function here is pure and makes no network calls, so the whole package runs unchanged in a
 * browser, in Node, and in the CLI. That is a requirement, not a convenience: signing must happen on
 * the user's device, and verification must work with PRM unreachable.
 *
 * Primitives come from @noble/*, pinned to exact versions. Nothing cryptographic is hand-rolled here
 * beyond composition of those primitives.
 */
export * from './jcs.js'
export * from './encoding.js'
export * from './digest.js'
export * from './sign.js'
export * from './keys.js'
export * from './account.js'
export * from './merkle.js'
