// tough-cookie jar + axios wiring (CONTRACT.md §4, D-09).
//
// AXIAM delivers access/refresh tokens exclusively via httpOnly Set-Cookie
// (RESEARCH.md Area 3 — login/refresh response bodies carry NO token
// fields). A Node persona therefore needs an explicit, per-client-instance
// cookie jar so httpOnly cookies persist across requests, and the only way
// to obtain the token values is to read them back out of that jar by name.
//
// Cookie names/paths mirror the server's CSRF/cookie middleware exactly
// (crates/axiam-api-rest/src/middleware/csrf.rs) and the already-shipped
// Rust SDK (sdks/rust/src/token/manager.rs).

import { CookieJar } from 'tough-cookie';
import { wrapper } from 'axios-cookiejar-support';
import type { AxiosInstance } from 'axios';

/** The `axiam_access` cookie name (httpOnly, path `/`). */
export const ACCESS_COOKIE = 'axiam_access';
/** The `axiam_refresh` cookie name (httpOnly, path-scoped to `/api/v1/auth/refresh`). */
export const REFRESH_COOKIE = 'axiam_refresh';
/** The `axiam_csrf` cookie name (JS-readable, path `/`). */
export const CSRF_COOKIE = 'axiam_csrf';

/** Construct a fresh, per-client-instance cookie jar (§4 — never process-global). */
export function createJar(): CookieJar {
  return new CookieJar();
}

/**
 * Wrap an axios instance with `axios-cookiejar-support` so the jar persists
 * `Set-Cookie` responses across requests and replays them on subsequent
 * requests to the same origin/path (§4). Mutates and returns the same
 * instance (matches `axios-cookiejar-support`'s documented in-place wrap).
 */
export function wrapAxios(instance: AxiosInstance, jar: CookieJar): AxiosInstance {
  const wrapped = wrapper(instance);
  wrapped.defaults.jar = jar;
  return wrapped;
}

/**
 * Read a single cookie's value out of the jar by name, for the given URL.
 * This is the ONLY token-source path (RESEARCH.md Area 3 — no JSON-body
 * fallback exists on the wire).
 */
export async function extractCookieValue(
  jar: CookieJar,
  url: string,
  name: string,
): Promise<string | undefined> {
  const cookies = await jar.getCookies(url);
  return cookies.find((c) => c.key === name)?.value;
}
