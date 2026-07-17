// Scenario: batch authorization decision over REST (POST /api/v1/authz/check/batch).
//
// AXIAM-ONLY (see authz_check_rest.js). This is the wire baseline for the SDK
// harness's batch_check() overhead delta. Results are returned in input order.
//
// Every check reuses the SAME seeded resource UUID: the server rejects non-UUID
// resource_ids, and a self-check derives the subject from the JWT, so no
// per-index resource suffixing. CSRF double-submit is required as for the single
// check.
import { baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { doOp } from './lib/metrics.js';
import { loginSession } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      authzBatchRest: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

const RESOURCE = __ENV.BENCH_RESOURCE_ID || 'bench-resource';
const BATCH_SIZE = Number(__ENV.BENCH_BATCH_SIZE || 5);

function batchBody() {
  const checks = [];
  for (let i = 0; i < BATCH_SIZE; i++) {
    checks.push({ action: 'read', resource_id: RESOURCE });
  }
  return JSON.stringify({ checks });
}

export function setup() {
  requireSeed();
  return loginSession();
}

export default function (data) {
  doOp({
    method: 'POST',
    url: `${baseUrl()}/api/v1/authz/check/batch`,
    body: batchBody(),
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
