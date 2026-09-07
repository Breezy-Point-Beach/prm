/**
 * @prm/notice — recipient-specific notices, delivery and response records, portable proof bundles,
 * and PDF rendering.
 *
 * Everything here runs on the user's device. A notice may carry a private matching identifier, and a
 * notice a server could author is a notice the user did not send.
 */
export * from './records.js'
export * from './bundle.js'
export * from './pdf.js'
