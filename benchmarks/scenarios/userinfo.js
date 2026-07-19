// Scenario: OIDC /userinfo — authenticated read of the identity claims. Exercises
// bearer-token verification + a profile read on every request.
import { loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp, m } from './lib/metrics.js';
import { mintUserToken } from './lib/auth.js';

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
  // userinfo returns identity claims for the bearer's *subject* — a
  // client_credentials service-account token is not the comparable op, so
  // mint a real user token (via login()) and only fall back if that fails.
  // k6 allows metric emission in setup(), so a fallback is recorded once here
  // (not per-iteration) and shows up as bench_fallback in the summary.
  const tok = mintUserToken();
  if (!tok.is_user_token) m.fallback.add(1);
  return tok;
}

export default function (data) {
  doOp(adapter().userinfo(data.access_token));
}
