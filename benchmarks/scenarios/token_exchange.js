// Scenario: RFC 8693 token exchange (B3) — the `token_exchange` limiter
// family, and (R7) the `token-exchange` bench cell.
//
// Why this exists:
//   - R5.2 / A1 §5: `RateLimitConfig::token_exchange_per_min` (default
//     120/min, keyed by authenticated client — see the comment on
//     `handle_token_exchange` in `crates/axiam-api-rest/src/handlers/oauth2.rs`)
//     had no k6 scenario, so `rl_prod_check.py` could not check it.
//   - R7 / E4 (`claude_dev/new-feature-bench-cells.md` "Cells waiting on
//     their features"): the token-exchange cell was blocked on the feature
//     shipping. It has since shipped (SEC-088, `token_exchange.rs:623-641`),
//     so this file also doubles as the `token-exchange` labeled bench cell —
//     the same file serves both purposes under different `rl=` postures,
//     exactly like `oauth2_client_credentials.js` already does for the
//     `token` family.
//
// AXIAM-ONLY: RFC 8693 token exchange has no equivalent grant on
// Keycloak/Zitadel in this harness's target set. Never published head-to-head.
//
// One exchange per request, per the plan's own framing ("measuring the
// scope-narrowing and audience-restriction work on the hot path"): the
// subject token is minted once in setup() (a real user session, so the
// exchange evaluates a genuine subject rather than a service-account
// identity with no scopes to narrow) and redeemed repeatedly. Unlike RFC 7009
// revocation, RFC 8693 exchange is NOT idempotent-by-spec, but the AXIAM
// implementation places no single-use constraint on the *subject* token —
// only the minted exchange token is one-shot-scoped by its own short
// lifetime — so re-presenting the same subject_token every iteration is a
// legitimate, repeatable exchange rather than a replay of a consumed
// credential. `scope`/`audience` are both omitted, which per the field docs
// on `TokenExchangeRequest` resolves to "the subject's own scopes" and the
// default (same-domain) audience — the minimal, always-valid exchange shape.
//
// # Known blocker (discovered while authoring this scenario, not fixed here)
//
// `handle_token_exchange` requires the authenticated client to carry
// `urn:ietf:params:oauth:grant-type:token-exchange` in its `grant_types`
// (`crates/axiam-oauth2/src/token_exchange.rs` `exchange()`, the
// `UnauthorizedClient` check). The admin client-creation endpoint's
// allow-list (`KNOWN_GRANT_TYPES` in
// `crates/axiam-api-rest/src/handlers/oauth2_clients.rs`) is
// `["authorization_code", "client_credentials", "refresh_token"]` — it does
// NOT include the token-exchange URN, so `runner/seed.sh`'s REST-only
// provisioning cannot mark the seeded bench client eligible for this grant.
// Until `KNOWN_GRANT_TYPES` is widened (out of scope for this file — this is
// a benchmarks-only change), `setup()` below will complete, but every
// exchange call will answer `400 unauthorized_client` and `bench_error_rate`
// will read 100%. That is the EXPECTED, honest failure shape for this known
// gap — not a bug in this scenario — and this scenario is exactly what will
// go green the moment that gap is closed, with no further changes needed
// here.
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { loginSession } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      tokenExchange: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

function formBody(obj) {
  return Object.keys(obj)
    .filter((k) => obj[k] !== undefined && obj[k] !== '')
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}

const SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

export function setup() {
  requireSeed();
  const session = loginSession();
  return { subject_token: session.access_token };
}

export default function (data) {
  doOp({
    method: 'POST',
    url: `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    body: formBody({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: data.subject_token,
      subject_token_type: SUBJECT_TOKEN_TYPE,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
    }),
    params: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    expect: 200,
  });
}
