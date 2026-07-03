// CSRF double-submit helpers (CONTRACT.md §3, D-05/D-28).
//
// The AXIAM server's CSRF middleware validates X-CSRF-Token against the
// axiam_csrf cookie value directly (cookie double-submit). The regex is
// deliberately hardcoded (not built dynamically from a configurable cookie
// name) to avoid ReDoS/CWE-1333 — mirrors frontend/src/lib/api.ts exactly.

export const CSRF_COOKIE_NAME = 'axiam_csrf';
export const CSRF_HEADER = 'X-CSRF-Token';
export const CSRF_METHODS: ReadonlySet<string> = new Set(['post', 'put', 'patch', 'delete']);

const CSRF_COOKIE_REGEX = /(?:^|;\s*)axiam_csrf=([^;]*)/;

/** Extract the axiam_csrf cookie value from a `document.cookie`-shaped string, or null if absent. */
export function readCsrfCookie(cookieString: string): string | null {
  const match = CSRF_COOKIE_REGEX.exec(cookieString);
  if (!match) {
    return null;
  }
  return decodeURIComponent(match[1]);
}

/**
 * Returns the CSRF header value for a state-changing HTTP method
 * (post/put/patch/delete, case-insensitive), or undefined for safe methods
 * (get/head/options) or when no CSRF cookie is present yet.
 */
export function csrfHeaderForMethod(method: string, cookieString: string): string | undefined {
  if (!CSRF_METHODS.has(method.toLowerCase())) {
    return undefined;
  }
  const token = readCsrfCookie(cookieString);
  return token ?? undefined;
}
