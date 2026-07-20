// Setup helpers shared by scenarios that need a pre-existing token (introspect,
// refresh, userinfo, authz). Run once in k6 setup() and shared with all VUs.
import http from 'k6/http';
import encoding from 'k6/encoding';
import { adapter } from './targets.js';

// Obtain an access (+ refresh) token once, for scenarios that operate on a token.
// Tries client_credentials first (works for every target); falls back to login.
export function mintToken() {
  const a = adapter();
  for (const builder of [a.clientCredentials, a.login]) {
    const built = builder();
    const res = http.request(built.method, built.url, built.body || null, built.params || {});
    if (res.status === (built.expect || 200)) {
      let body;
      try { body = res.json(); } catch (_e) { continue; }
      const access = body.access_token || body.token;
      if (access) {
        return { access_token: access, refresh_token: body.refresh_token };
      }
    }
  }
  throw new Error('auth.mintToken: could not obtain a token for setup (check seeding + profile)');
}

// Shared cookie-jar extraction for `login()` responses. Two AXIAM specifics
// drive this:
//   1. `/api/v1/auth/login` delivers tokens ONLY via Set-Cookie (axiam_access,
//      axiam_csrf, axiam_refresh) — the JSON body carries no token — so we read
//      them back out of k6's cookie jar (HttpOnly is irrelevant to the jar).
//   2. The authz endpoints derive the authoritative subject/tenant from the
//      verified JWT; the gRPC handler additionally cross-validates the request
//      body identity against those claims and rejects on mismatch (SEC-003 /
//      T-27-12). A client-credentials service-account subject would neither match
//      the seeded grant nor the required subject_id, so authz scenarios log in as
//      the user.
// Falls back to a body token for targets/profiles that return one there instead
// of (or in addition to) cookies (e.g. Keycloak's ROPC "login").
// Used by both `loginSession()` (authz scenarios) and `mintUserToken()`
// (token-holding scenarios like userinfo) so the cookie-reading logic lives in
// exactly one place.
export function readAccessFromLogin(built, res, jar) {
  const cookies = jar.cookiesForURL(built.url);
  let body = null;
  try { body = res.json(); } catch (_e) { /* cookie-only response, no JSON body */ }
  const access = (cookies.axiam_access && cookies.axiam_access[0]) || (body && (body.access_token || body.token));
  const refresh = (cookies.axiam_refresh && cookies.axiam_refresh[0]) || (body && body.refresh_token);
  const csrf = cookies.axiam_csrf && cookies.axiam_csrf[0];
  return { access_token: access, refresh_token: refresh, csrf_token: csrf };
}

// Log in as the seeded *user* (never client_credentials) and return the session
// credentials the authz scenarios need. The access token doubles as the gRPC
// bearer metadata; the CSRF token is required as an X-CSRF-Token header
// (double-submit) on non-GET REST calls under /api/v1.
export function loginSession() {
  const jar = http.cookieJar();
  const built = adapter().login();
  const res = http.request(built.method, built.url, built.body || null, built.params || {});
  if (res.status !== (built.expect || 200)) {
    throw new Error(`auth.loginSession: login failed (status ${res.status}) — check seeding + profile`);
  }
  const { access_token, csrf_token } = readAccessFromLogin(built, res, jar);
  if (!access_token) throw new Error('auth.loginSession: no axiam_access cookie (or body token) in login response');
  return { access_token, csrf_token };
}

// Obtain a token that represents the seeded *user* (not a service account),
// for scenarios that need a genuine OIDC subject (e.g. userinfo). Tries the
// target's `login()` op first; falls back to `clientCredentials()` only if
// login isn't available/successful (e.g. a target with ROPC disabled) or
// returns no usable token. `is_user_token` tells the caller (and the report,
// via `bench_fallback`) whether the fallback was used, so a client-credentials
// subject reading /userinfo isn't silently mistaken for the real op.
export function mintUserToken() {
  const a = adapter();
  const jar = http.cookieJar();
  const built = a.login();
  // Some adapters' login() IS client_credentials in disguise, tagged
  // `fallback: true` (see zitadel in targets.js) — skip straight to the
  // explicit client_credentials branch below rather than "succeeding" here
  // and mislabelling it is_user_token: true.
  if (!built.fallback) {
    const res = http.request(built.method, built.url, built.body || null, built.params || {});
    if (res.status === (built.expect || 200)) {
      const { access_token, refresh_token } = readAccessFromLogin(built, res, jar);
      if (access_token) {
        return { access_token, refresh_token, is_user_token: true };
      }
    }
  }
  // Fall back to client_credentials (e.g. a target whose login() already IS
  // client_credentials — see zitadel in targets.js — or a login that failed).
  const cc = a.clientCredentials();
  const ccRes = http.request(cc.method, cc.url, cc.body || null, cc.params || {});
  if (ccRes.status !== (cc.expect || 200)) {
    throw new Error(`auth.mintUserToken: could not obtain a token for setup (status ${ccRes.status})`);
  }
  let body;
  try { body = ccRes.json(); } catch (_e) { body = {}; }
  const access = body.access_token || body.token;
  if (!access) throw new Error('auth.mintUserToken: client_credentials fallback returned no token');
  return { access_token: access, refresh_token: body.refresh_token, is_user_token: false };
}

// Decode the (unverified) claims from a JWT payload segment. Used only to read
// `sub`/`tenant_id` so an authz request body can be made to match the token —
// the gRPC handler rejects any body identity that differs from the verified
// claims, so the scenario echoes the token's own subject/tenant. This is NOT a
// signature check; the server still verifies the token.
export function jwtClaims(token) {
  const parts = String(token).split('.');
  if (parts.length < 2) return {};
  try {
    return JSON.parse(encoding.b64decode(parts[1], 'rawurl', 's'));
  } catch (_e) {
    return {};
  }
}
