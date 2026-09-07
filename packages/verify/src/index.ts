/**
 * @prm/verify — independent verification of PRM artifacts.
 *
 * THE DEFINING PROPERTY OF THIS PACKAGE: it never contacts PRM, or anything else.
 *
 * There is no HTTP client, no fetch, no filesystem access, and no PRM API dependency anywhere in it.
 * Every input a verification needs is passed in by the caller. This is what makes the project's
 * central claim technically true rather than rhetorical — a recipient can verify a policy with
 * prm.app deleted, its domain expired, and its operator hostile.
 *
 * A CI job asserts this package's dependency graph stays clean. If you find yourself wanting to add
 * a network call here, add it to the caller instead.
 */
export * from './types.js'
export * from './kel.js'
export * from './policy.js'
export * from './ledger.js'
export * from './authorization.js'
export * from './bundle.js'
