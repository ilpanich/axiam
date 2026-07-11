// Scenario: JWKS fetch (RFC 7517). Cheap, cache-friendly endpoint — a useful
// floor on raw HTTP-serving efficiency with no crypto/DB work per request.
import { loadStages, thresholds, tlsOptions } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';

export const options = Object.assign(
  {
    scenarios: {
      jwks: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

export default function () {
  doOp(adapter().jwks());
}
