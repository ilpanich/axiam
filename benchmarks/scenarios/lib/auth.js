// Setup helpers shared by scenarios that need a pre-existing token (introspect,
// refresh, userinfo, authz). Run once in k6 setup() and shared with all VUs.
import http from 'k6/http';
import encoding from 'k6/encoding';
import { adapter } from './targets.js';
import { cfg, baseUrl } from './config.js';

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
//
// G4: `axiam_refresh` is Path-scoped to `/api/v1/auth/refresh`
// (crates/axiam-api-rest/src/middleware/csrf.rs `refresh_cookie()`,
// `.path("/api/v1/auth/refresh")`) — unlike `axiam_access`/`axiam_csrf`, which
// are Path=`/` (same file, `access_cookie()`/`csrf_cookie()`). A jar read
// scoped to the *login* URL (`/api/v1/auth/login`) therefore never returns it
// (RFC 6265 path-matching: "/api/v1/auth/refresh" is not a prefix of
// "/api/v1/auth/login") — this was the entire root cause of the AXIAM
// `token_refresh` cell measuring 100% `bench_fallback`: `refresh_token` came
// back `undefined` on every call, so callers always fell through to the
// client_credentials fallback branch. Fix: also probe the jar against the
// refresh endpoint's own path so the narrowly-scoped cookie is found. This is
// a pure jar read (no extra HTTP request) and is a harmless no-op for targets
// that never set an `axiam_refresh`-named cookie (Keycloak/Zitadel deliver
// their refresh token in the JSON body instead, via the fallback below).
export function readAccessFromLogin(built, res, jar) {
  const cookies = jar.cookiesForURL(built.url);
  let body = null;
  try { body = res.json(); } catch (_e) { /* cookie-only response, no JSON body */ }
  const access = (cookies.axiam_access && cookies.axiam_access[0]) || (body && (body.access_token || body.token));
  const originMatch = /^(https?:\/\/[^/]+)/.exec(built.url);
  const origin = originMatch ? originMatch[1] : '';
  const refreshScopeCookies = origin ? jar.cookiesForURL(`${origin}/api/v1/auth/refresh`) : {};
  const refresh =
    (cookies.axiam_refresh && cookies.axiam_refresh[0]) ||
    (refreshScopeCookies.axiam_refresh && refreshScopeCookies.axiam_refresh[0]) ||
    (body && body.refresh_token);
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
      const { access_token, refresh_token, csrf_token } = readAccessFromLogin(built, res, jar);
      if (access_token) {
        return { access_token, refresh_token, csrf_token, is_user_token: true };
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
  return { access_token: access, refresh_token: body.refresh_token, csrf_token: undefined, is_user_token: false };
}

// G4: AXIAM's user-login-issued refresh token is redeemed at the *session*
// refresh endpoint `POST /api/v1/auth/refresh` — NOT the generic OAuth2
// `POST /oauth2/token?grant_type=refresh_token` grant that `targets.js`'s
// `axiam.refresh()` builder sends every refresh request to today. These are
// two different token stores server-side:
//   - `/api/v1/auth/login` mints its refresh token via axiam-auth's
//     SessionRepository (crates/axiam-auth/src/service.rs, `login()` ~L604-634).
//   - `/oauth2/token`'s `refresh_token` grant looks the presented token up in
//     axiam-oauth2's RefreshTokenRepository instead
//     (crates/axiam-oauth2/src/token.rs `handle_refresh_token`, ~L502-514) and
//     returns `invalid_grant` ("refresh token is invalid, expired, or
//     revoked") for anything not issued by an OAuth2-flow grant — a
//     session-login refresh token is never in that table, so this call
//     always 401s once the cookie-extraction bug above is fixed.
// The correct redemption target, `/api/v1/auth/refresh`
// (crates/axiam-api-rest/src/handlers/auth.rs `refresh()`, ~L421-480),
// requires:
//   - the `axiam_refresh` cookie (read from the httpOnly cookie, L429-434 —
//     there is no body/header alternative),
//   - the CSRF double-submit header `X-CSRF-Token` matching the `axiam_csrf`
//     cookie (this path is NOT in `CSRF_EXEMPT_SUFFIXES`, middleware/csrf.rs),
//   - a JSON body `{ tenant_id, org_id? }` (`RefreshRequest`, handlers/auth.rs)
//     — `org_id` is `Option<Uuid>` with `#[serde(default)]` and is never
//     trusted (the handler re-derives it from the tenant record, NEW-1), so
//     the correct thing to send is *nothing at all*.
//
//     N4: this used to interpolate `cfg.orgId` unconditionally. `BENCH_ORG_ID`
//     is empty whenever `seed.sh` re-seeds onto a volume that is already
//     bootstrapped (bootstrap answers 409 and the recovery probe could not
//     fill it — fixed separately in seed.sh), so the body went out as
//     `{"tenant_id":"...","org_id":""}`. `""` is not `null`: serde hands it to
//     `Uuid`'s deserializer, which rejects it, so actix answered **400 before
//     the handler ever ran** — every refresh failed in ~1 ms with a healthy
//     server and a valid token, and the whole cell read as
//     "the k6 client could not reach the target". Guard the field exactly the
//     way every other org-scoped body in this harness already does
//     (`targets.js`, `nested.js`, `authz_check_rest.js`,
//     `uma_ticket_grant.js`: `if (cfg.orgId) body.org_id = cfg.orgId`).
// The response rotates all three cookies (new access/refresh/csrf) but its
// JSON body carries only `{ expires_in }` — no tokens — so the new
// refresh/csrf values must be read back out of the jar (see
// `readAxiamRefreshCookies` below), not out of `doOp()`'s return value.
//
// This belongs in targets.js's `axiam.refresh()` long-term so every target
// goes through the same `a.refresh()` call shape; implemented here because
// targets.js is out of scope for this change (see
// claude_dev/refresh-harness-diagnosis.md for the exact diff to make there).
export function axiamRefreshOp(refreshToken, csrfToken) {
  const body = { tenant_id: cfg.tenantId };
  if (cfg.orgId) body.org_id = cfg.orgId;
  return {
    method: 'POST',
    url: `${baseUrl()}/api/v1/auth/refresh`,
    body: JSON.stringify(body),
    params: {
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' },
      cookies: { axiam_refresh: refreshToken, axiam_csrf: csrfToken || '' },
    },
    expect: 200,
  };
}

// Read the rotated `axiam_refresh`/`axiam_csrf` cookies out of the jar after
// an `axiamRefreshOp` redemption. k6 stores a response's Set-Cookie headers
// into the VU's jar automatically regardless of how the request's own
// cookies were supplied, so this works whether or not the prior request also
// happened to hit the jar. Scoped to the refresh endpoint's own path/origin
// for the same Path-scoping reason documented on `readAccessFromLogin` above.
export function readAxiamRefreshCookies(jar) {
  const cookies = jar.cookiesForURL(`${baseUrl()}/api/v1/auth/refresh`);
  return {
    refresh_token: cookies.axiam_refresh && cookies.axiam_refresh[0],
    csrf_token: cookies.axiam_csrf && cookies.axiam_csrf[0],
  };
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
