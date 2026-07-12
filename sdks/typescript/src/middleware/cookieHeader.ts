// Internal Cookie header parser + token extractor (D-27, CONTRACT.md §10).
//
// No `cookie-parser`/`@fastify/cookie` peer dependency — a small
// RFC6265-lenient splitter shared by both Express and Fastify middleware,
// mirroring the Rust extractor's cookie-then-Bearer fallback order
// (sdks/rust/src/middleware/actix.rs:129-149).

import { timingSafeEqual } from 'node:crypto';

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
 * Where an extracted bearer credential came from. Load-bearing for the CSRF
 * gate below (CONTRACT.md §3): a token sourced from the `axiam_access`
 * cookie is attached to a request automatically by the browser (including
 * cross-site ones, in a same-site deployment), so it is NOT CSRF-immune the
 * way an `Authorization: Bearer` header is — a cross-site attacker cannot
 * set arbitrary request headers, but the browser will still send cookies.
 */
export type CredentialSource = 'cookie' | 'header';

export interface ExtractedCredential {
  token: string;
  source: CredentialSource;
}

/**
 * Extract the bearer credential and its source: `axiam_access` cookie
 * first, falling back to `Authorization: Bearer <token>` (case-insensitive
 * scheme), else `undefined` — mirrors the Rust extractor's
 * cookie-then-Bearer order.
 */
export function extractCredential(
  cookieHeader: string | undefined,
  authHeader: string | undefined,
): ExtractedCredential | undefined {
  const cookies = parseCookieHeader(cookieHeader);
  const cookieToken = cookies[ACCESS_COOKIE_NAME];
  if (cookieToken) {
    return { token: cookieToken, source: 'cookie' };
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
  return { token: credentials, source: 'header' };
}

/**
 * Extract just the bearer token, discarding its source. Retained for
 * backward compatibility with existing (non-CSRF-aware) callers/exports;
 * new code that needs to gate on credential source should call
 * {@link extractCredential} directly.
 */
export function extractToken(
  cookieHeader: string | undefined,
  authHeader: string | undefined,
): string | undefined {
  return extractCredential(cookieHeader, authHeader)?.token;
}

export const CSRF_COOKIE_NAME = 'axiam_csrf';
export const CSRF_HEADER_NAME = 'x-csrf-token';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Whether `method` is a "safe" (non-state-changing) HTTP method per
 * CONTRACT.md §3 (state-changing = POST/PUT/PATCH/DELETE). An
 * undefined/empty method is treated as safe: real Express/Fastify
 * requests always populate `req.method`, so this only affects
 * hand-constructed callers that omit it, and defaulting to "no CSRF
 * required" never weakens the check for a real HTTP request.
 */
export function isSafeMethod(method: string | undefined): boolean {
  if (!method) {
    return true;
  }
  return SAFE_METHODS.has(method.toUpperCase());
}

/**
 * Cookie double-submit check (CONTRACT.md §3): `csrfHeaderValue` (the
 * `X-CSRF-Token` request header) must be present and equal, in constant
 * time, to the `axiam_csrf` cookie value.
 *
 * Rationale: cookie-sourced requests aren't CSRF-immune, and in any
 * same-site deployment where `axiam_access` reaches the app, the
 * non-`httpOnly` `axiam_csrf` cookie does too (§3) — this mirrors, locally,
 * the same double-submit check the AXIAM server performs on its own
 * endpoints.
 *
 * Never throws: a missing header/cookie or a length mismatch both return
 * `false` (mirrors amqp/hmac.ts's `verifyPayload` idiom — `timingSafeEqual`
 * throws on unequal-length buffers, so length is checked first).
 */
export function isCsrfValid(
  cookieHeader: string | undefined,
  csrfHeaderValue: string | undefined,
): boolean {
  if (!csrfHeaderValue) {
    return false;
  }
  const cookies = parseCookieHeader(cookieHeader);
  const csrfCookie = cookies[CSRF_COOKIE_NAME];
  if (!csrfCookie) {
    return false;
  }
  const received = Buffer.from(csrfHeaderValue, 'utf8');
  const expected = Buffer.from(csrfCookie, 'utf8');
  if (received.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(received, expected);
}
