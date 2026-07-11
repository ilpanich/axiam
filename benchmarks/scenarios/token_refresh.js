// Scenario: refresh-token grant. AXIAM rotates refresh tokens single-use, so each
// VU mints its own token in setup-per-VU style and chains rotations. For targets
// without rotation the same refresh token is reusable; both are handled.
import { loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';
import { mintToken } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      refresh: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// Per-VU refresh token, so single-use rotation does not invalidate other VUs.
let vuRefresh = null;

export function setup() {
  requireSeed();
}

export default function () {
  const a = adapter();
  if (!vuRefresh) {
    const tok = mintToken();
    vuRefresh = tok.refresh_token;
    if (!vuRefresh) {
      // Target issued no refresh token (e.g. pure client_credentials) — nothing to
      // measure; mint again as the closest comparable token-issuance op.
      doOp(a.clientCredentials());
      return;
    }
  }
  const body = doOp(a.refresh(vuRefresh));
  // Follow rotation: adopt the new refresh token if one was returned.
  if (body && body.refresh_token) vuRefresh = body.refresh_token;
  else if (body && !body.refresh_token) vuRefresh = vuRefresh; // reusable token
  else vuRefresh = null; // failed → re-mint next iteration
}
