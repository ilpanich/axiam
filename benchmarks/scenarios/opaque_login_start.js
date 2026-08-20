// Scenario: OPAQUE login/start — the server-side cost of the PAKE handshake.
//
// ## What this measures, and what it deliberately does not
//
// `POST /api/v1/auth/opaque/login/start` is where the server's OPAQUE work
// lives: one OPRF evaluation over the client's blinded password, the envelope
// masking, the server's ephemeral share and the 3DH inputs for `KE2`, plus an
// AES-256-GCM seal of the exchange state. That is a real, load-bearing cost and
// it is what this scenario isolates.
//
// It does **not** measure a full OPAQUE login, and the numbers must not be
// presented as one. A complete exchange also costs:
//
//   * the client-side key-stretching function (Argon2id at m=19456 KiB by
//     default) — paid on the *client*, not the server, and by design expensive;
//   * the client's own elliptic-curve work in `KE1` and `KE3`;
//   * `/auth/opaque/login/finish`, which is cheap server-side: an AEAD open, a
//     constant-time MAC verification, and the same session issuance every login
//     path pays.
//
// Putting the client half inside a k6 VU would measure k6's CPU rather than
// AXIAM's. So `KE1` is a fixed, valid constant — see `lib/targets.js`. The
// server performs identical work for any well-formed `KE1`, which is also why
// this scenario cannot distinguish a real account from an unknown one: the
// decoy path is designed to cost the same, and if this benchmark ever showed a
// difference between the two that would itself be the bug.
//
// ## Comparing against SRP, and against password login
//
// AXIAM previously shipped SRP-6a, whose `srp_challenge` scenario this replaces.
// The two are not comparable per-request and should not be charted together:
// SRP's server cost was two modular exponentiations in a 2048–4096-bit group
// and scaled with the group size, while OPAQUE's is a handful of ristretto255
// scalar multiplications and does not. Expect OPAQUE to be substantially
// cheaper server-side; that is a property of elliptic curves over finite-field
// groups, not evidence about the protocols' security.
//
// The comparison that is meaningful is `opaque_login_start` +
// `opaque_login_finish` against `oauth2_password_login`, whose cost is dominated
// by one Argon2id verification. Expect OPAQUE's server cost to be *lower* — the
// memory-hard work moved to the client — which is the trade the whole design
// makes.
//
// Requires the target tenant to have `opaque_mode` set to `optional` or
// `required`; against a tenant with OPAQUE disabled every request is a 404 and
// the scenario reports that rather than silently measuring error latency.

import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';

export const options = Object.assign(
  {
    scenarios: {
      opaque_login_start: {
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
  if (!adapter().opaqueLoginStart) {
    throw new Error(
      `target "${cfg.target}" has no OPAQUE endpoint; this scenario is AXIAM-only`,
    );
  }
}

export default function () {
  doOp(adapter().opaqueLoginStart());
}
