// Scenario: the OpenID Connect authorization endpoint — `GET /oauth2/authorize`
// issuing an authorization code to an already-authenticated principal.
//
// Why this exists. The authorization-code flow is the flow every OpenID
// Connect deployment actually runs, and until now the harness measured every
// OAuth2 endpoint around it — `/oauth2/token`, `/introspect`, `/revoke`,
// `/jwks`, `/userinfo`, the device pair, token exchange, UMA — and not the one
// that starts it. The gap was tolerable while `/oauth2/authorize` served only
// first-party applications on AXIAM's own origin. It stopped being tolerable
// with the Basic OP waves (W1–W7, 2026-09-07…10), which turned this endpoint
// into the largest single body of new server work in the release: the
// authn-request parameter gates, the honour lane, the browser login hop and
// its OP session cookie, the cosmetic parameters, and the sensitive-scope
// consent gate all execute here, on the hot path, for every authorization.
//
// AXIAM-ONLY. Keycloak and Zitadel both expose an authorization endpoint, but
// neither will issue a code to a bearer-authenticated API caller: both require
// an interactive HTML login form whose hidden-field ceremony is
// vendor-specific, which is precisely the coupling `README.md`'s "Why a custom
// framework?" section refuses. A cross-vendor authorization-code cell would be
// measuring three different login pages, so this is never published
// head-to-head.
//
// # What is measured, and what is deliberately not
//
// ONE measured call per iteration: the authorization request itself. The code
// it mints is NOT redeemed. That is the same shape `device_authorization.js`
// already runs — flood the endpoint that mints a short-lived grant, let the
// grant expire — and it is chosen for the same two reasons:
//
//   1. Redeeming would put a second, differently-shaped request
//      (`POST /oauth2/token`) inside one iteration, so the cell's throughput
//      figure would describe neither endpoint.
//   2. The `authorization_code` **redemption** deserves its own cell rather
//      than a half of this one. It is a named follow-up in
//      `VERIFICATION-2026-09-11.md`, not an oversight.
//
// An unredeemed code is a row with a short TTL, cleaned up by the server's own
// expiry sweep (`crates/axiam-server/src/cleanup.rs`) exactly as an abandoned
// sign-in leaves one in production.
//
// # No PKCE, and why that is the honest default here
//
// `crates/axiam-oauth2/src/authorize.rs` requires `code_challenge` for PUBLIC
// clients only; the seeded bench client is confidential (it holds a secret),
// so a code request without PKCE is the ordinary, conforming shape for it.
// Sending one anyway would measure a `code_challenge` the server only stores
// at this endpoint — it is verified at redemption, which this cell does not
// do — so it would add k6-side SHA-256 work to the load generator and change
// nothing on the server. A PKCE-verifying cell belongs with the redemption
// cell, where the verification actually happens.
//
// # Authentication: a bearer token, not the browser login hop
//
// `authorize()` resolves its principal through `MaybeAuthenticatedUser`, which
// accepts the `axiam_access` bearer token `loginSession()` already mints. That
// is the first-party path, it predates W3, and it is what a k6 VU can drive
// without a browser.
//
// The W3 browser login hop — anonymous request, `302` to `/login`, sign in,
// come back with an `axiam_op_session` cookie — is NOT measured here, and
// cannot be with this seed: the hop only answers a client registered
// `browser_sso: true`, and `runner/seed.sh` registers the bench client with
// the default `false`. It is also an inherently multi-hop, cookie-bound
// ceremony whose cost is dominated by the `/login` page and the password hash,
// both of which `oauth2_password_login.js` already measures on their own. See
// `docs/admin/browser-login-hop.md` for what the hop adds.
//
// ============================================================================
// RUN HISTORY: first executed 2026-09-11 and PASSED on that first run
// (ok=636, p95=21ms), which is what removed it from PENDING_SCENARIOS. The
// three design choices argued below — no code redemption, no PKCE, bearer
// authentication rather than the W3 browser hop — were all confirmed by that
// run and are unchanged.
// ============================================================================
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { loginSession } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      oauth2Authorize: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// The redirect URI `runner/seed.sh` registers on the bench client. RFC 6749
// §3.1.2.3 matching is EXACT — not a prefix — so this string and the seed's
// must stay byte-identical, and a mismatch answers `invalid_request` directly
// rather than by redirect (there is no registered URI to redirect to).
const REDIRECT_URI = 'http://localhost/cb';

// `openid` is one of the two scopes the seed registers (the other,
// `uma_protection`, belongs to the UMA cells). Deliberately NOT `address` or
// `phone`: those are W7's sensitive scopes, and requesting one sends this
// request down the consent gate instead of the code branch — a different
// measurement, gated on a per-tenant switch that is off by default.
const SCOPE = 'openid';

export function setup() {
  requireSeed();
  // A USER session, not client_credentials: `/oauth2/authorize` issues a code
  // on behalf of a subject, and a service-account principal is not the
  // comparable operation. `loginSession()` throws on failure rather than
  // silently degrading, so an under-seeded stack fails here with a message
  // naming the cause instead of producing a cell of 401s.
  const session = loginSession();
  return { access_token: session.access_token };
}

export default function (data) {
  // `state` is opaque to the server and echoed verbatim; a constant keeps the
  // load generator's per-iteration work at zero without changing the server's.
  const query = [
    'response_type=code',
    `client_id=${encodeURIComponent(cfg.clientId)}`,
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
    `scope=${encodeURIComponent(SCOPE)}`,
    'state=bench',
  ].join('&');

  doOp({
    method: 'GET',
    url: `${baseUrl()}/oauth2/authorize?${query}`,
    params: {
      headers: { Authorization: `Bearer ${data.access_token}` },
      // The measured op ENDS at the 302. Following it would send k6 to
      // http://localhost/cb — an address nothing in the bench stack serves —
      // and record that connection failure as this endpoint's latency.
      redirects: 0,
    },
    // RFC 6749 §4.1.2 delivers the code by redirect: `HttpResponse::Found()`
    // with a `Location` carrying `code`, `state` and `iss`. A 200 here would
    // mean a refusal rendered as a page (the W3 prose answer), and a 401 that
    // the bearer token was not accepted — both are failures for this cell, and
    // `expect` makes them count as such rather than pass as "a response".
    expect: 302,
  });
}
