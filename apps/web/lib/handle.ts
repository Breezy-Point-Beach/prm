/**
 * Handle rules, with no imports.
 *
 * Shared by the server (publish refuses invalid or reserved handles) and the browser (the restore
 * screen checks before it fetches). Kept free of any storage import so a client page can use it
 * without dragging the filesystem adapter into the bundle.
 */
export const HANDLE_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$/

const RESERVED_HANDLES = new Set([
  'api', 'app', 'admin', 'status', 'log', 'well-known', 'u', 'p', 'create', 'author', 'publish',
  'about', 'docs', 'verify', 'help', 'settings', 'login', 'signup', 'prm', 'share', 'v',
  'restore', 'recover', 'notice', 'privacy', 'terms'
])

export function isValidHandle (handle: string): boolean {
  return HANDLE_PATTERN.test(handle) && !RESERVED_HANDLES.has(handle)
}
