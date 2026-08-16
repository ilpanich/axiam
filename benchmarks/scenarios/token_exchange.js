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
// subject token is minted once in setup() and redeemed repeatedly. (It used to
// say "a real user session, so the exchange evaluates a genuine subject rather
// than a service-account identity with no scopes to narrow". That is backwards
// on AXIAM — the session token is the one with no scopes — see the note above
// setup().) Unlike RFC 7009
// revocation, RFC 8693 exchange is NOT idempotent-by-spec, but the AXIAM
// implementation places no single-use constraint on the *subject* token —
// only the minted exchange token is one-shot-scoped by its own short
// lifetime — so re-presenting the same subject_token every iteration is a
// legitimate, repeatable exchange rather than a replay of a consumed
// credential. `scope`/`audience` are both omitted, which per the field docs
// on `TokenExchangeRequest` resolves to "the subject's own scopes" and the
// default (same-domain) audience — the minimal, always-valid exchange shape.
//
// # Former blocker — CLOSED. This cell is expected GREEN.
//
// `handle_token_exchange` requires the authenticated client to carry
// `urn:ietf:params:oauth:grant-type:token-exchange` in its `grant_types`
// (`crates/axiam-oauth2/src/token_exchange.rs` `exchange()`, the
// `UnauthorizedClient` check). This scenario was authored when the admin
// client-creation allow-list (`KNOWN_GRANT_TYPES` in
// `crates/axiam-api-rest/src/handlers/oauth2_clients.rs`) was exactly
// `["authorization_code", "client_credentials", "refresh_token"]`, so
// `runner/seed.sh`'s REST-only provisioning could not mark the bench client
// eligible and every exchange answered `400 unauthorized_client` — documented
// here as the expected shape until the gap closed.
//
// It has since closed on both sides: `KNOWN_GRANT_TYPES` now also carries
// `DEVICE_CODE_GRANT_TYPE`, the `"device_code"` alias and
// `TOKEN_EXCHANGE_GRANT_TYPE`, and `runner/seed.sh` registers the bench client
// with the token-exchange URN. A 100% `unauthorized_client` rate is therefore
// no longer "expected and honest" — it now means the seed did not run, ran
// against a pre-existing client from an older seed, or was rolled back. The
// alpha25 dry run found this note still claiming the old status, which cost a
// pass of diagnosis on a cell that was simply under-seeded.
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { mintToken } from './lib/auth.js';

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
const ACTOR_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

// DELEGATION, not impersonation — and that is forced, not a preference.
//
// `exchange()` (crates/axiam-oauth2/src/token_exchange.rs) branches on
// `actor_token`: absent means impersonation, which is refused unless the client
// carries the `urn:axiam:params:oauth:grant-type:may-impersonate` marker —
//   400 {"error":"unauthorized_client","error_description":
//        "impersonation requires the may_impersonate grant;
//         supply an actor_token to delegate instead"}
// — and that marker is DELIBERATELY absent from `KNOWN_GRANT_TYPES`, pinned by
// `oauth2_client_test.rs::update_oauth2_client_rejects_the_may_impersonate_marker`
// ("whether an admin-API caller may confer impersonation is an open security
// decision"). `runner/seed.sh` provisions over REST, so it CANNOT confer it; an
// impersonation-shaped cell is unreachable by design, not under-seeded.
//
// Delegation costs the measurement nothing. The branch above only decides
// `ExchangeKind` and the actor claim; the scope-narrowing (`narrow_scopes`) and
// audience-restriction work this cell exists to measure run identically on both
// paths. The actor is a client_credentials token — the service acting on the
// user's behalf, which is the shape a real mesh delegation takes anyway.
// # Subject identity: a service token, not a user session — and why
//
// The header above (and the original setup()) used `loginSession()`, on the
// stated reasoning that "a real user session ... evaluates a genuine subject
// rather than a service-account identity with no scopes to narrow". The
// premise is inverted on AXIAM, which is why this cell could never pass:
//
//   - `/api/v1/auth/login` mints a SESSION token with NO `scope` claim at all
//     (verified by decoding it). `narrow_scopes` refuses any scope the subject
//     token does not hold, and then refuses an empty result outright —
//       400 {"error":"invalid_scope",
//            "error_description":"the exchange would grant no scopes at all"}
//     — so a cookie-session subject can never produce a successful exchange,
//     whatever `scope` the request asks for.
//   - There is no other way to obtain a scoped USER token here: AXIAM's token
//     endpoint answers `unsupported_grant_type` to `grant_type=password`, so
//     there is no ROPC path, and the authorization-code flow needs an
//     interactive consent leg that does not belong in a k6 setup().
//
// So the service-account token is the identity that HAS scopes to narrow, and
// this cell exchanges one. That is a real RFC 8693 delegation — the shape a
// mesh service actually uses — and it drives `narrow_scopes` and the audience
// restriction, which is what the cell exists to measure. What it does NOT
// measure is a human subject; if a scoped user token ever becomes reachable
// (ROPC, or a seed-provisionable auth-code fixture), switch `subject_token`
// back and this comment is the reason it changed.
export function setup() {
  requireSeed();
  // Two independent mints rather than one token reused as both: `exchange()`
  // decodes them separately and the tenant must match, which mintToken()'s
  // client_credentials arm satisfies (it is scoped to cfg.tenantId).
  const subject = mintToken();
  const actor = mintToken();
  return { subject_token: subject.access_token, actor_token: actor.access_token };
}

export default function (data) {
  doOp({
    method: 'POST',
    url: `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    body: formBody({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: data.subject_token,
      subject_token_type: SUBJECT_TOKEN_TYPE,
      // Both are required together: `exchange()` rejects an actor_token whose
      // actor_token_type is missing or not an access token.
      actor_token: data.actor_token,
      actor_token_type: ACTOR_TOKEN_TYPE,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
    }),
    params: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    expect: 200,
  });
}
