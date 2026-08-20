// Scenario: OPAQUE register/start — the OPRF evaluation, on its own.
//
// ## Why this has its own scenario
//
// `POST /api/v1/auth/opaque/register/start` is **unauthenticated by
// necessity**: it is called while creating a user who does not exist yet, so
// there is nobody to authenticate as. That is safe — the server mints the
// credential identifier itself, so an anonymous caller obtains OPRF evaluations
// under identifiers they neither chose nor can predict — but it does mean this
// is the OPAQUE endpoint an attacker can reach most cheaply, and therefore the
// one whose per-request cost an operator most needs when sizing a rate-limit
// budget.
//
// SRP had no equivalent: a verifier was computed entirely client-side from a
// self-chosen salt, so enrolment cost the server nothing until the finished
// verifier arrived on an authenticated endpoint. This scenario exists because
// that changed.
//
// ## What it measures
//
// One OPRF evaluation (a single ristretto255 scalar multiplication), the
// tenant's key material being decrypted and parsed, and an AES-256-GCM seal of
// the exchange state. It does not measure the client's blinding or its
// key-stretching, both of which are paid on the client.
//
// The `registration_request` is a fixed, valid constant — see `lib/targets.js`
// for why generating a fresh one per iteration would measure k6 rather than
// AXIAM.

import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';

export const options = Object.assign(
  {
    scenarios: {
      opaque_register_start: {
        executor: 'ramping-vus',
        startVUs: 0,
        stages: loadStages(),
        gracefulRampDown: '5s',
      },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

export function setup() {
  requireSeed();
  if (!adapter().opaqueRegisterStart) {
    throw new Error(
      `target "${cfg.target}" has no OPAQUE endpoint; this scenario is AXIAM-only`,
    );
  }
}

export default function () {
  doOp(adapter().opaqueRegisterStart());
}
