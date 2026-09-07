/**
 * @prm/vault — client-side key custody.
 *
 * Runs on the user's device. There is no network client here, and there must never be one: this is
 * the package that holds the master seed, and the project's central claim is that no server can act
 * for the user.
 *
 * PRM cannot recover an account. There is no escrow, no support reset, and no server-held share. The
 * only recovery path is the pre-committed recovery key, which the user holds. That is a deliberate
 * trade: accidental loss is the most likely failure in this whole system, and it is preferred to a
 * provider that could impersonate its users.
 */
export * from './mnemonic.js'
export * from './vault.js'
export * from './account.js'
export * from './webauthn.js'
