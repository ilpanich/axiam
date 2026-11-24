// Scenario: the OAuth2 refresh-token grant, like for like — every target
// answers the SAME request, `POST <token endpoint>` with
// `grant_type=refresh_token` and the confidential bench client's credentials,
// and every target rotates (or reuses) the refresh token it returns.
//
// # Why this exists
//
// `token_refresh.js` is a `protocol-variant` cell: it obtains each target's
// refresh token from a password login, and AXIAM's token endpoint has no
// password (ROPC) grant — `TokenService::exchange` accepts
// `authorization_code`, `client_credentials` and `refresh_token` only — so on
// AXIAM that cell measures the SESSION refresh (`POST /api/v1/auth/refresh`,
// cookie + CSRF double-submit) while Keycloak's measures the OAuth2 grant.
// AXIAM does support the OAuth2 refresh-token grant; it just issues the first
// refresh token from the authorization-code flow, which `token_refresh.js`
// never drove (claude_dev/refresh-harness-diagnosis.md §6, option 2).
//
// This cell drives it. Only how the FIRST refresh token is obtained differs
// per target, and that happens before measurement:
//
//   * AXIAM — setup() runs the authorization-code flow with PKCE (S256) for
//     every VU: an unmeasured `GET /oauth2/authorize` authenticated with the
//     bench user's bearer token (as `oauth2_authorize.js` and
//     `oauth2_code_pkce.js` do), answered 302 with a code, redeemed at
//     `POST /oauth2/token` (`grant_type=authorization_code`, the bench
//     client's secret, the PKCE verifier). The seeded `bench-client` is
//     confidential, registered for `authorization_code` and `refresh_token`
//     with the redirect URI `http://localhost/cb`, and is admin-created, so
//     the external-consent gate does not stop it.
//   * Keycloak — the ROPC grant, per VU, through `mintUserToken()`, exactly as
//     `token_refresh.js` does.
//   * Zitadel, authentik — no refresh token is obtainable non-interactively
//     (see `token_refresh.js`); the VU measures a client_credentials re-mint
//     instead and counts it as a fallback, so the cell reads `fallback-op` and
//     stays out of head-to-head tables.
//
// # What is measured
//
// ONE request per iteration: the refresh grant. A successful answer carries a
// new refresh token (single-use rotation on AXIAM and Keycloak), which the VU
// chains into its next iteration. A failed rotation is counted by `doOp` and
// the VU keeps the token it holds: it never re-runs the authorization flow in
// the measured loop, for the reason `token_refresh.js` gives about re-login —
// a refresh cell that silently turns into an authorization cell measures the
// wrong endpoint.
//
// On AXIAM the grant is `token.rs::handle_refresh_token`: client lookup and
// secret check, tenant liveness, the refresh row by hash, the account check,
// the session evidence the row is bound to, rotation (the old row consumed,
// a new one created) and an Ed25519 access token.
//
// # Rate limits
//
// The AXIAM pre-mint makes one authorize call and one token-endpoint call
// (the redemption) per VU, plus one probe refresh. Under the neutralized
// benchmark limits that is immaterial; under `rl=prod` the token bucket
// (120/min) would throttle a 50-VU pre-mint, and setup() refuses to start
// with a partial pool rather than measure throttling — run this cell with the
// neutralized posture.
import http from 'k6/http';
import { fail, sleep } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp, m } from './lib/metrics.js';
import { loginSession, mintUserToken } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      refreshGrant: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    setupTimeout: `${Number(__ENV.BENCH_MAX_SETUP_SECS || 300) + 60}s`,
  },
  tlsOptions(),
);

// The redirect URI `runner/seed.sh` registers on the confidential
// `bench-client`. A confidential web client's URI is compared exactly, so it
// is presented byte for byte, and nothing listens on it: the authorization
// leg stops at the 302 (`redirects: 0`).
const REDIRECT_URI = 'http://localhost/cb';
const SCOPE = 'openid';

function formBody(obj) {
  return Object.keys(obj)
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}

function snippet(res) {
  return String(res && res.body ? res.body : '').slice(0, 300);
}

function pkcePair() {
  const verifier = encoding.b64encode(crypto.randomBytes(32), 'rawurl');
  return { verifier, challenge: crypto.sha256(verifier, 'base64rawurl') };
}

// One AXIAM authorization-code round trip, unmeasured. Returns the token
// response JSON, or throws naming the step that failed.
function axiamCodeFlow(accessToken) {
  const pair = pkcePair();
  const query = [
    'response_type=code',
    `client_id=${encodeURIComponent(cfg.clientId)}`,
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
    `scope=${encodeURIComponent(SCOPE)}`,
    'state=bench',
    `code_challenge=${pair.challenge}`,
    'code_challenge_method=S256',
  ].join('&');
  const auth = http.get(`${baseUrl()}/oauth2/authorize?${query}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    redirects: 0,
    tags: { leg: 'authorize_unmeasured' },
  });
  const location = auth.headers.Location || auth.headers.location || '';
  const match = auth.status === 302 ? /[?&]code=([^&]+)/.exec(location) : null;
  if (!match) {
    throw new Error(
      `authorize did not redirect with a code (HTTP ${auth.status}, Location=${location || '<none>'}): ${snippet(auth)}`,
    );
  }
  const tok = http.post(
    `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    formBody({
      grant_type: 'authorization_code',
      code: decodeURIComponent(match[1]),
      redirect_uri: REDIRECT_URI,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code_verifier: pair.verifier,
    }),
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      tags: { leg: 'redeem_unmeasured' },
    },
  );
  if (tok.status !== 200) {
    throw new Error(`code redemption answered HTTP ${tok.status}: ${snippet(tok)}`);
  }
  const body = tok.json();
  if (!body || !body.refresh_token) {
    throw new Error(
      'code redemption returned no refresh_token — is bench-client still registered for the ' +
        'refresh_token grant? Re-run `just target=axiam bench-seed`.',
    );
  }
  return body;
}

export function setup() {
  requireSeed();
  if (cfg.target !== 'axiam') return { tokens: [] };
  if (!cfg.clientSecret) {
    fail('BENCH_CLIENT_SECRET is empty — the confidential bench client was not seeded.');
  }

  const session = loginSession();
  const tokens = [];
  for (let i = 0; i < cfg.vus; i++) {
    tokens.push(axiamCodeFlow(session.access_token).refresh_token);
  }

  // One measured-shape refresh before the run, so a defect in the grant
  // itself stops the cell here instead of producing a cell of 400s. It
  // rotates the probe token, so the rotated one replaces it in the pool.
  const probe = http.request(
    'POST',
    `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    formBody({
      grant_type: 'refresh_token',
      refresh_token: tokens[0],
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );
  if (probe.status !== 200 || !probe.json('refresh_token')) {
    fail(`refresh-grant probe answered HTTP ${probe.status}: ${snippet(probe)}`);
  }
  tokens[0] = probe.json('refresh_token');
  return { tokens };
}

let vuRefresh = null;

export default function (data) {
  const a = adapter();

  if (!vuRefresh && cfg.target === 'axiam') {
    vuRefresh = data.tokens[(__VU - 1) % data.tokens.length] || null;
    if (!vuRefresh) {
      m.failed.add(1);
      m.errorRate.add(true);
      sleep(1);
      return;
    }
  }

  if (!vuRefresh) {
    let tok;
    try {
      tok = mintUserToken();
    } catch (_e) {
      m.failed.add(1);
      m.errorRate.add(true);
      sleep(1);
      return;
    }
    vuRefresh = tok.refresh_token;
    if (!vuRefresh) {
      // No refresh token obtainable on this target (Zitadel, authentik — see
      // the header): measure the closest issuance op and label it.
      m.fallback.add(1);
      doOp(a.clientCredentials());
      return;
    }
  }

  const body = doOp(a.refresh(vuRefresh));
  if (body && body.refresh_token) {
    vuRefresh = body.refresh_token;
  } else if (body === null && cfg.target !== 'axiam') {
    // As token_refresh.js: a competitor VU re-mints next iteration. An AXIAM
    // VU keeps its token and backs off — re-running the authorization flow in
    // the measured loop would turn this into an authorization cell.
    vuRefresh = null;
  } else if (body === null) {
    sleep(1);
  }
}
