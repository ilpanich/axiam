// Scenario: single authorization decision over REST (POST /api/v1/authz/check).
//
// AXIAM-ONLY: no competitor exposes an equivalent REST authorization-decision
// endpoint, so like the gRPC authz scenarios this is reported separately, never
// as a head-to-head number. It exists because SDK check_access()/batch_check()
// are REST calls in every SDK — this scenario is the wire baseline the SDK
// harness's overhead delta is measured against (sdk/collect.py, HARNESS-SPEC.md).
//
// Identity comes from the verified JWT (a self-check needs no subject_id); the
// resource_id must be the seeded resource UUID and a seeded role grant makes the
// decision allowed=true. A non-GET call under /api/v1 requires the CSRF
// double-submit (axiam_csrf cookie + X-CSRF-Token header), both taken from login.
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { loginSession } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      authzCheckRest: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

const RESOURCE = __ENV.BENCH_RESOURCE_ID || 'bench-resource';

export function setup() {
  requireSeed();
  return loginSession();
}

export default function (data) {
  doOp({
    method: 'POST',
    url: `${baseUrl()}/api/v1/authz/check`,
    body: JSON.stringify({ action: 'read', resource_id: RESOURCE }),
    params: {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${data.access_token}`,
        'X-CSRF-Token': data.csrf_token,
      },
      cookies: { axiam_csrf: data.csrf_token },
    },
    expect: 200,
  });
}
