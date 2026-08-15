// Scenario: `oauth2_client_credentials` labeled cell with a no-op
// `token.pre_issue` reactor registered (X1 / R2.4) — "the cost of hooking
// token issuance". AXIAM-only: no other bench target has reactors.
//
// ============================================================================
// STATUS: PENDING — two things, in order, must land before this cell can
// run for real. This file is EXCLUDED from `scenario=all` auto-discovery by
// `runner/run-benchmark.sh`'s `PENDING_SCENARIOS` list until then — same
// mechanism `scim_provisioning.js` uses, see that file's header for the
// exact opt-back-in path (`BENCH_ENABLE_PENDING_SCENARIOS=1` or an explicit
// `scenario=oauth2_client_credentials_reactor_hook.js`).
//
// 1. **No admin-session helper for k6 scenarios.** Registering a reactor
//    (`POST /api/v1/reactors`) requires the `reactors:create` permission,
//    which the seeded bench USER (`loginSession()` / `cfg.username` —
//    `benchmarks/runner/seed.sh`'s "bench-reader" role) deliberately does
//    NOT hold — it is granted exactly one `read` permission, on purpose, so
//    every other scenario that reuses it stays a proof of the operation
//    under test rather than of an over-privileged bench identity. The
//    principal that DOES hold `reactors:create` is the bootstrap admin
//    `seed.sh` creates for itself (`admin@bench.dev` by default), and its
//    session lives only in that shell script's cookie jar — `lib/auth.js`
//    exposes no equivalent for k6. Closing this gap means either a new
//    `lib/auth.js` helper that logs in as the bootstrap admin (mirroring
//    `seed.sh`'s own `/api/v1/auth/login` call, with the admin
//    username/password threaded through as `BENCH_ADMIN_*` env vars the way
//    `seed.sh` already reads them) or `seed.sh` itself minting and exporting
//    an admin bearer token this scenario's `setup()` can read.
//
// 2. **The registration this cell needs doesn't yet produce the round trip
//    the plan describes.** The plan's one-line description ("+1 AMQP RTT ≈
//    1-3 ms p50") assumes a real reactor process is answering the queue.
//    As of R2.4, `axiam-server` composes `axiam_amqp::UnavailableReactorTransport`
//    (the lapin `ReactorTransport` is not merged — `dispatcher.rs`'s doc
//    comment on that type, and `sdks/CONTRACT.md` §22.1's scope note, are
//    both explicit about this). Every dispatch to a registered reactor
//    therefore resolves as a `Transport` failure SYNCHRONOUSLY — no socket,
//    no broker round trip — and `token.pre_issue`'s default `fail_open`
//    policy turns that into an immediate `Allow`. Running this cell today
//    would measure "routing-table lookup + failure-policy resolution for an
//    unreachable reactor," which is a real number but not the one the cell
//    is named for. Getting the genuine "+1 AMQP RTT" number needs either
//    R2.5 (a real `reactor_serve` process backing the registration) or a
//    hand-rolled no-op consumer standing in for one — either way, something
//    that actually answers the queue.
//
// Once both are closed, the shape below needs no further changes: create
// the reactor once in `setup()` (mode `intercept`, the registry's default
// `fail_open` policy — deliberately NOT overridden, since a `token.pre_issue`
// hook is enrichment, not a security veto, and the whole point of the cell
// is the cost of a hook that behaves), then drive the same
// `clientCredentials()` op `oauth2_client_credentials.js` already benches,
// against the SAME tenant, so the p50 delta between the two cells' results
// IS the number the plan asks for — no separate baseline to keep in sync.
// ============================================================================
import { cfg, baseUrl, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { adapter } from './lib/targets.js';
import { doOp } from './lib/metrics.js';
import http from 'k6/http';

export const options = Object.assign(
  {
    scenarios: {
      ccReactorHook: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

const JSONH = { headers: { 'Content-Type': 'application/json' } };

// See STATUS §1 above: this env var does not exist anywhere else in the
// harness yet — it is the shape the closing PR should add, not a knob
// `seed.sh` already sets.
function adminAccessToken() {
  const token = __ENV.BENCH_ADMIN_ACCESS_TOKEN;
  if (!token) {
    throw new Error(
      'oauth2_client_credentials_reactor_hook: BENCH_ADMIN_ACCESS_TOKEN is not set — this ' +
        "scenario needs a session holding 'reactors:create', which the seeded bench user does " +
        "not have. See this file's header (STATUS §1) for what closes the gap.",
    );
  }
  return token;
}

// Idempotent: a re-run against an already-hooked tenant must not fail or
// double-register. The no-op reactor is named deterministically so a second
// setup() call can find and reuse it rather than accumulating registrations.
const REACTOR_NAME = 'bench-noop-token-pre-issue';

function findExistingReactor(adminToken) {
  const res = http.get(`${baseUrl()}/api/v1/reactors?limit=100`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  if (res.status !== 200) return null;
  const items = res.json().items || res.json();
  return (Array.isArray(items) ? items : []).find((r) => r.name === REACTOR_NAME) || null;
}

export function setup() {
  requireSeed();
  const adminToken = adminAccessToken();

  if (findExistingReactor(adminToken)) {
    return; // already hooked by a prior run against this tenant.
  }

  const res = http.post(
    `${baseUrl()}/api/v1/reactors`,
    JSON.stringify({
      name: REACTOR_NAME,
      description: 'Bench-only no-op enrichment hook (R2.4 hook-cost cell).',
      events: ['token.pre_issue'],
      mode: 'intercept',
      // Deliberately omitted: the registry default (fail_open) is exactly
      // what the cell wants to measure, not a stricter override.
    }),
    { ...JSONH, headers: { ...JSONH.headers, Authorization: `Bearer ${adminToken}` } },
  );
  if (res.status !== 201) {
    throw new Error(
      `oauth2_client_credentials_reactor_hook: could not register the bench reactor ` +
        `(status ${res.status}): ${String(res.body).slice(0, 200)}`,
    );
  }
}

export default function () {
  // Identical to oauth2_client_credentials.js's op — the delta between the
  // two cells' recorded p50/p95 IS "the cost of hooking token issuance".
  doOp(adapter().clientCredentials());
}
