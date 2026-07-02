// Internal Cookie header parser + token extractor (D-27, CONTRACT.md §10).
//
// No `cookie-parser`/`@fastify/cookie` peer dependency — a small
// RFC6265-lenient splitter shared by both Express and Fastify middleware,
// mirroring the Rust extractor's cookie-then-Bearer fallback order
// (sdks/rust/src/middleware/actix.rs:129-149).

/**
 * Parse a raw `Cookie` request header into a name -> value map.
 * Lenient: splits on `;`, trims whitespace, splits each pair on the first
 * `=` only (cookie values may themselves contain `=`, e.g. base64/JWT).
 */
export function parseCookieHeader(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!header) {
    return cookies;
  }
  for (const pair of header.split(';')) {
    const trimmed = pair.trim();
    if (!trimmed) {
      continue;
    }
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) {
      continue;
    }
    const name = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();
    if (name) {
      cookies[name] = value;
    }
  }
  return cookies;
}

export const ACCESS_COOKIE_NAME = 'axiam_access';

/**
 * Extract the bearer token: `axiam_access` cookie first, falling back to
 * `Authorization: Bearer <token>` (case-insensitive scheme), else
 * `undefined` — mirrors the Rust extractor's cookie-then-Bearer order.
 */
export function extractToken(
  cookieHeader: string | undefined,
  authHeader: string | undefined,
): string | undefined {
  const cookies = parseCookieHeader(cookieHeader);
  const cookieToken = cookies[ACCESS_COOKIE_NAME];
  if (cookieToken) {
    return cookieToken;
  }

  if (!authHeader) {
    return undefined;
  }

  const trimmed = authHeader.trim();
  const spaceIndex = trimmed.indexOf(' ');
  if (spaceIndex === -1) {
    return undefined;
  }
  const scheme = trimmed.slice(0, spaceIndex);
  const credentials = trimmed.slice(spaceIndex + 1).trim();
  if (scheme.toLowerCase() !== 'bearer' || !credentials) {
    return undefined;
  }
  return credentials;
}
