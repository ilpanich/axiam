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
  login() {
    return {
      method: 'POST',
      url: `${baseUrl()}/api/v1/auth/login`,
      body: JSON.stringify({
        tenant_id: cfg.tenantId,
        username_or_email: cfg.username,
        password: cfg.password,
      }),
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
// falls back to client_credentials for the comparative token-issuance number.
const zitadel = {
  login() {
    return zitadel.clientCredentials();
  },
  clientCredentials() {
    return {
      method: 'POST',
      url: `${baseUrl()}/oauth/v2/token`,
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
      url: `${baseUrl()}/oauth/v2/introspect`,
      body: formBody({ token, client_id: cfg.clientId, client_secret: cfg.clientSecret }),
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
