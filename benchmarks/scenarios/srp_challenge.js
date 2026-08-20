// Scenario: SRP-6a challenge — the server-side cost of the PAKE handshake.
//
// ## What this measures, and what it deliberately does not
//
// `POST /api/v1/auth/srp/challenge` is where the server's SRP work lives: two
// modular exponentiations in the tenant's RFC 5054 group (`g^b` and `v^u`),
// plus hashing and an AES-256-GCM seal. That is a real, load-bearing cost that
// scales with the group size, and it is what this scenario isolates.
//
// It does **not** measure a full SRP login, and the numbers must not be
// presented as one. A complete exchange also costs:
//
//   * the client-side KDF (Argon2id at m=19456 KiB by default) — which is paid
//     on the *client*, not the server, and is by design expensive;
//   * one client-side modular exponentiation;
//   * `/auth/srp/verify`, which is cheap server-side: an AEAD open, a
//     constant-time 32-byte compare, and the same session issuance every login
//     path pays.
//
// Putting the client half inside a k6 VU would measure k6's CPU rather than
// AXIAM's, and would depress throughput by an amount that says nothing about
// the server. So the client half is excluded, and `A` is a fixed constant: the
// server performs identical work whichever `A` it receives, provided it is not
// congruent to zero (which the handler rejects outright).
//
// ## Comparing against `oauth2_password_login`
//
// The honest comparison for "what did SRP cost us server-side" is
// `srp_challenge` + `srp_verify` against `oauth2_password_login`, whose cost is
// dominated by one Argon2id verification. Expect SRP's server cost to be
// *lower* per request at the default parameters — the memory-hard work moved to
// the client — and the group size, not the KDF, to be the knob that moves it.
//
// Requires the target tenant to have `srp_mode` set to `optional` or
// `required`; against a tenant with SRP disabled every request is a 404 and the
// scenario reports that rather than silently measuring error latency.

import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';

export const options = Object.assign(
  {
    scenarios: {
      srp_challenge: {
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
  if (!adapter().srpChallenge) {
    throw new Error(
      `target "${cfg.target}" has no SRP endpoint; this scenario is AXIAM-only`,
    );
  }
}

export default function () {
  doOp(adapter().srpChallenge());
}
