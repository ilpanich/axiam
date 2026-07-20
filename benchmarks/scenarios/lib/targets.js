// Per-target adapter layer.
//
// This is the ONLY place where vendor differences live. Every scenario asks this
// module for the endpoint + request encoding of a *logical* operation; the body of
// each scenario is identical across targets. That is what keeps the comparison
// apples-to-apples (see docs/methodology.md §1).
//
// Each adapter exposes the same set of operation builders, returning:
//   { method, url, body, params }  ready to hand to http.request().
import { cfg, baseUrl } from './config.js';

function formBody(obj) {
  return Object.keys(obj)
    .filter((k) => obj[k] !== undefined && obj[k] !== '')
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}
const FORM = { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };
const JSONH = { headers: { 'Content-Type': 'application/json' } };

// --- AXIAM ----------------------------------------------------------------
// REST under /api/v1; OAuth2/OIDC under /oauth2 and /.well-known. Tenant context
// is carried in the request body / query (?tenant_id=) per the REST handlers.
const axiam = {
  // Resource-owner login (AXIAM's first-party session/login endpoint).
  // Login requires BOTH org and tenant context (a tenant slug is only unique
  // within an org). Prefer the seeded UUIDs, falling back to slugs, and omit
  // any empty selector so the server doesn't reject a blank id.
  login() {
    const body = { username_or_email: cfg.username, password: cfg.password };
    if (cfg.orgId) body.org_id = cfg.orgId;
    else if (cfg.orgSlug) body.org_slug = cfg.orgSlug;
    if (cfg.tenantId) body.tenant_id = cfg.tenantId;
    else if (cfg.tenantSlug) body.tenant_slug = cfg.tenantSlug;
    return {
      method: 'POST',
      url: `${baseUrl()}/api/v1/auth/login`,
      body: JSON.stringify(body),
      params: JSONH,
      expect: 200,
    };
  },
  clientCredentials() {
    return {
      method: 'POST',
      url: `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
      body: formBody({
        grant_type: 'client_credentials',
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        scope: 'openid',
      }),
      params: FORM,
      expect: 200,
    };
  },
  introspect(token) {
    return {
      method: 'POST',
      url: `${baseUrl()}/oauth2/introspect?tenant_id=${cfg.tenantId}`,
      body: formBody({
        token,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
      }),
      params: FORM,
      expect: 200,
    };
  },
  refresh(refreshToken) {
    return {
      method: 'POST',
      url: `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
      body: formBody({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
      }),
      params: FORM,
      expect: 200,
    };
  },
  jwks() {
    return { method: 'GET', url: `${baseUrl()}/oauth2/jwks?tenant_id=${cfg.tenantId}`, expect: 200 };
  },
  userinfo(accessToken) {
    return {
      method: 'GET',
      url: `${baseUrl()}/oauth2/userinfo`,
      params: { headers: { Authorization: `Bearer ${accessToken}` } },
      expect: 200,
    };
  },
};

// --- Keycloak -------------------------------------------------------------
// Standard realm endpoints under /realms/<realm>/protocol/openid-connect/*.
function kcBase() {
  return `${baseUrl()}/realms/${cfg.realm}/protocol/openid-connect`;
}
const keycloak = {
  login() {
    // Keycloak's comparable "login → token" is the ROPC (password) grant.
    return {
      method: 'POST',
      url: `${kcBase()}/token`,
      body: formBody({
        grant_type: 'password',
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        username: cfg.username,
        password: cfg.password,
        scope: 'openid',
      }),
      params: FORM,
      expect: 200,
    };
  },
  clientCredentials() {
    return {
      method: 'POST',
      url: `${kcBase()}/token`,
      body: formBody({
        grant_type: 'client_credentials',
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        // Without an explicit scope Keycloak still issues a token, but it is
        // not OIDC-capable (no 'openid' in the granted scope), so /userinfo
        // rejects it. Request it explicitly, matching the login() ROPC grant.
        scope: 'openid',
      }),
      params: FORM,
      expect: 200,
    };
  },
  introspect(token) {
    return {
      method: 'POST',
      url: `${kcBase()}/token/introspect`,
      body: formBody({ token, client_id: cfg.clientId, client_secret: cfg.clientSecret }),
      params: FORM,
      expect: 200,
    };
  },
  refresh(refreshToken) {
    return {
      method: 'POST',
      url: `${kcBase()}/token`,
      body: formBody({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
      }),
      params: FORM,
      expect: 200,
    };
  },
  jwks() {
    return { method: 'GET', url: `${kcBase()}/certs`, expect: 200 };
  },
  userinfo(accessToken) {
    return {
      method: 'GET',
      url: `${kcBase()}/userinfo`,
      params: { headers: { Authorization: `Bearer ${accessToken}` } },
      expect: 200,
    };
  },
};

// --- Zitadel --------------------------------------------------------------
// OIDC endpoints at well-known paths; ROPC is generally disabled, so `login`
// used to fall back to client_credentials for the comparative token-issuance
// number. D5 replaces that with a real password check via Zitadel's session
// API v2 (`POST /v2/sessions`, `checks.password`) so oauth2_password_login
// measures an actual Argon2/bcrypt-class password verification on Zitadel,
// same as axiam/keycloak.
const zitadel = {
  // Real password verification via the session API v2: create a session with
  // a `password` check factor over the seeded human bench user. This is NOT
  // client_credentials — it drives Zitadel's actual password-hash comparison
  // — so the built request is tagged `fallback: true` ONLY in the degraded
  // path below (no seeded human user / session credential available); the
  // normal-path request is untagged, so doOp()/report.py stop flagging this
  // cell as a fallback op (D5 acceptance criterion).
  //
  // Session-create is an admin/management-style call (not a user-facing OIDC
  // endpoint), so it needs its own bearer credential — seed.sh mints/derives
  // one (the Zitadel instance PAT — see seed_zitadel()) and exports it as
  // BENCH_ZITADEL_SESSION_PAT, alongside the seeded human user's id as
  // BENCH_ZITADEL_USER_ID. Read directly via `__ENV` (a k6 global available
  // to every module, same mechanism config.js's str()/num() use) rather than
  // adding fields to `cfg` — config.js is out of scope for this change.
  //
  // IMPORTANT interaction with auth.js `mintUserToken()` (used by the
  // userinfo scenario): a session-create response returns a `sessionToken`,
  // NOT an OIDC access token — it is useless as a `/userinfo` bearer.
  // `mintUserToken()` only accepts login()'s response as a real user token
  // when `readAccessFromLogin()` finds an `access_token`/`token` JSON field
  // or an `axiam_access` cookie (see auth.js). The v2 CreateSession body has
  // neither (its field is literally named `sessionToken`, which does not
  // match `access_token`/`token`), so `mintUserToken()` naturally falls
  // through to its own `clientCredentials()` fallback for userinfo — exactly
  // the previous behavior — WITHOUT needing this function to tag its result
  // `fallback: true`. That tag is reserved for the "session API unavailable"
  // guard below, per the D5 spec. No change to auth.js was required or made;
  // this is a deliberate design choice, not an oversight.
  login() {
    const userId = __ENV.BENCH_ZITADEL_USER_ID;
    const sessionPat = __ENV.BENCH_ZITADEL_SESSION_PAT;
    if (!userId || !sessionPat) {
      // No seeded human user / session-creation credential (e.g. manual
      // client-only seeding via BENCH_CLIENT_ID/SECRET, or the
      // BENCH_ZITADEL_ALLOW_UNSEEDED jwks-only mode — see seed.sh) — the
      // session API can't be exercised, so fall back to the old comparative
      // token-issuance number and tag it accordingly (A3 fallback).
      return Object.assign({}, zitadel.clientCredentials(), { fallback: true });
    }
    return {
      method: 'POST',
      url: `${baseUrl()}/v2/sessions`,
      body: JSON.stringify({
        checks: {
          user: { userId },
          password: { password: cfg.password },
        },
      }),
      params: {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionPat}`,
        },
      },
      // Zitadel's v2 resource-creation endpoints return 201 in the docs/
      // examples this was modeled on; unconfirmed against a live instance
      // (no Zitadel available in this sandbox — see D5 report). If a live
      // run shows 200 instead, this is the only line to change.
      expect: 201,
    };
  },
  clientCredentials() {
    // Add the bench project's reserved audience scope so the issued token is
    // introspectable by the resource server: Zitadel only marks a token `active`
    // to an API app whose project is in the token's aud. Falls back to plain
    // openid when no project was seeded (e.g. manual/jwks-only setups).
    const scope = cfg.projectId
      ? `openid urn:zitadel:iam:org:project:id:${cfg.projectId}:aud`
      : 'openid';
    return {
      method: 'POST',
      url: `${baseUrl()}/oauth/v2/token`,
      body: formBody({
        grant_type: 'client_credentials',
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        scope,
      }),
      params: FORM,
      expect: 200,
    };
  },
  introspect(token) {
    // Zitadel requires the *resource server* (an API application), not the
    // machine user, to introspect. Use the dedicated introspection client when
    // seeded; fall back to the machine-user creds otherwise.
    const clientId = cfg.introspectClientId || cfg.clientId;
    const clientSecret = cfg.introspectClientSecret || cfg.clientSecret;
    return {
      method: 'POST',
      url: `${baseUrl()}/oauth/v2/introspect`,
      body: formBody({ token, client_id: clientId, client_secret: clientSecret }),
      params: FORM,
      expect: 200,
    };
  },
  refresh(refreshToken) {
    return {
      method: 'POST',
      url: `${baseUrl()}/oauth/v2/token`,
      body: formBody({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
      }),
      params: FORM,
      expect: 200,
    };
  },
  jwks() {
    return { method: 'GET', url: `${baseUrl()}/oauth/v2/keys`, expect: 200 };
  },
  userinfo(accessToken) {
    return {
      method: 'GET',
      url: `${baseUrl()}/oidc/v1/userinfo`,
      params: { headers: { Authorization: `Bearer ${accessToken}` } },
      expect: 200,
    };
  },
};

const ADAPTERS = { axiam, keycloak, zitadel };

export function adapter() {
  const a = ADAPTERS[cfg.target];
  if (!a) throw new Error(`no adapter for target '${cfg.target}' (have: ${Object.keys(ADAPTERS).join(', ')})`);
  return a;
}
