// Scenario: OAuth2 token revocation (RFC 7009) — the `revoke_per_min` limiter
// family.
//
// Why this exists (run-5 J1c): `revoke` is one of the eight rate-limit
// families the shipped posture configures, and it was the only REST one with
// no k6 scenario at all, so `rl_prod_check.py` reported it as
// "no scenario — not checked" and the run-5 §7 verdict table had a hole in it.
// A limiter nobody drives is a limiter nobody has verified.
//
// This is a *limiter* scenario first and a throughput scenario second: the
// point is to flood a single source IP well past `revoke_per_min` (shipped
// default 60/min) and let the harness compare admitted-vs-configured. Its
// throughput number is therefore not comparable to the unthrottled scenarios
// and is never published as one.
//
// RFC 7009 §2.2: the revocation endpoint returns 200 for an already-revoked
// or unknown token, so every iteration legitimately expects 200 — including
// the ones re-revoking a token a previous iteration already killed. That is
// what makes a single minted token enough to sustain the flood.
import { loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';
import { mintToken } from './lib/auth.js';

export const options = Object.assign(
  {
    scenarios: {
      revoke: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
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
  doOp(adapter().revoke(data.access_token));
}
