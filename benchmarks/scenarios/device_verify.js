// Scenario: RFC 8628 device verification lookup — the `device_verify`
// limiter family.
//
// Why this exists (R5.2 / A1 §5): B2's human-facing half
// (`GET /api/v1/device/verify`) shares `RateLimitConfig::device_verify_per_min`
// with `POST /api/v1/device/decide`, and per `handlers/device.rs`'s own
// header comment that bucket is deliberately sized against OWASP's
// brute-force arithmetic — a limiter guarding a short, human-typable code
// space is exactly the kind of thing that needs to be driven, not assumed.
// No scenario existed, so `rl_prod_check.py` could not check it.
//
// AXIAM-ONLY: this endpoint is the second half of AXIAM's device-flow
// verification screen; no competitor in this harness's target set exposes an
// equivalent lookup. Never published as a head-to-head number.
//
// Deliberately queries a code that does not exist. `verify()`
// (`crates/axiam-api-rest/src/handlers/device.rs`) answers `found: false`
// with HTTP 200 for an unknown, expired, or already-decided code alike — by
// design, so a guessing attacker cannot use the response shape as an oracle.
// That means a bogus code is a legitimate, side-effect-free 200 flood: it
// exercises the exact lookup path a real (and a guessing) caller drives,
// without needing a live pending device grant seeded first.
import { baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { loginSession } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      deviceVerify: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// Deliberately never a real user_code: 8 characters, uppercase, matching the
// shape `generate_user_code()` produces (`crates/axiam-oauth2/src/device.rs`)
// but never minted, so every call resolves to the `found: false` branch —
// the same "always 200" property oauth2_revoke.js relies on for its flood.
const BOGUS_USER_CODE = 'ZZZZ9999';

export function setup() {
  requireSeed();
  // GET is not CSRF-protected (only non-GET /api/v1 mutations are), so only
  // the bearer token from a user session is needed — no csrf_token required.
  const session = loginSession();
  return { access_token: session.access_token };
}

export default function (data) {
  doOp({
    method: 'GET',
    url: `${baseUrl()}/api/v1/device/verify?user_code=${BOGUS_USER_CODE}`,
    params: { headers: { Authorization: `Bearer ${data.access_token}` } },
    expect: 200,
  });
}
