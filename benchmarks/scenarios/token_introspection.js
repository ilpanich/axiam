// Scenario: token introspection (RFC 7662) — the per-request validation hot path
// for resource servers that do not verify JWTs locally.
import { loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';
import { mintToken } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      introspect: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

export function setup() {
  requireSeed();
  return mintToken(); // { access_token, refresh_token } shared with all VUs
}

export default function (data) {
  doOp(adapter().introspect(data.access_token));
}
