// Scenario: OIDC /userinfo — authenticated read of the identity claims. Exercises
// bearer-token verification + a profile read on every request.
import { loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';
import { mintToken } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      userinfo: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

export function setup() {
  requireSeed();
  return mintToken();
}

export default function (data) {
  doOp(adapter().userinfo(data.access_token));
}
