// Scenario: RFC 8628 device authorization request — the `device_authorization`
// limiter family.
//
// Why this exists (R5.2 / A1 §5): B2's device flow landed with its own bucket
// (`RateLimitConfig::device_authorization_per_min`, server.rs's
// `/oauth2/device_authorization` resource) but no k6 scenario ever drove it,
// so `rl_prod_check.py` reported it as "no scenario — not checked" and the
// §7 verdict table had a hole where this family should be. A limiter nobody
// drives is a limiter nobody has verified.
//
// AXIAM-ONLY: RFC 8628 device authorization has no equivalent endpoint on
// Keycloak/Zitadel in this harness's target set, so — like oauth2_revoke.js
// and the gRPC-family scenarios — this is a limiter scenario first and is
// never published as a head-to-head throughput number.
//
// Deliberately unauthenticated and stateless per call: RFC 8628 §3.1 requires
// no client secret (this is the public-client half of the flow — "a
// television cannot keep a secret"), and every well-formed request allocates
// a *new* pending device grant and returns 200, so a single scenario body can
// flood the endpoint indefinitely without any setup()-minted credential.
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';

export const options = Object.assign(
  {
    scenarios: {
      deviceAuthorization: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
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

export function setup() {
  requireSeed();
  return {};
}

export default function () {
  doOp({
    method: 'POST',
    url: `${baseUrl()}/oauth2/device_authorization?tenant_id=${cfg.tenantId}`,
    body: formBody({ client_id: cfg.clientId, scope: 'openid' }),
    params: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    expect: 200,
  });
}
