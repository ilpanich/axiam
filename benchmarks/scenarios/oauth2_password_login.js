// Scenario: resource-owner login → token/session.
// The most security-sensitive hot path (involves Argon2id verification on AXIAM).
//
// Every target's login() verifies the seeded user's real password, but not with
// one wire shape: AXIAM, Keycloak and Zitadel answer in one request, authentik's
// is a three-call flow-executor conversation that doOp() runs as a single
// operation (targets.js `authentik.login()`, metrics.js `doSteps()`).
import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';

export const options = Object.assign(
  {
    scenarios: {
      login: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

export function setup() {
  requireSeed();
}

export default function () {
  doOp(adapter().login());
}
