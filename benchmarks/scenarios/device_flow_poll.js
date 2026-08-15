// Bench cell: `device-flow-poll` (R7 / E4) — the RFC 8628 polling loop.
//
// Why this exists: `claude_dev/new-feature-bench-cells.md` listed this cell
// as blocked ("the grant's core, storage and state machine landed, but no
// REST handlers are mounted yet"). B2's REST handlers are mounted now
// (`POST /oauth2/device_authorization`, the `device_code` grant arm of
// `POST /oauth2/token` — both in `crates/axiam-api-rest/src/server.rs`), so
// this is the missing scenario the cell was waiting on.
//
// # A deliberately different load shape
//
// Every other scenario in this directory is a closed-loop throughput flood:
// as many requests as the VU count and duration allow, via `loadStages()`.
// That shape is wrong for what this cell needs to show. RFC 8628 polling is
// an INPUT-CONSTRAINED DEVICE repeatedly asking "is the user done yet?" at a
// server-dictated cadence (`interval`, `slow_down` on violation) — many
// devices each making one request every few seconds, not one VU hammering as
// fast as it can. So this scenario uses `constant-vus` (each VU is one
// simulated device, live for the whole run, no ramp) and paces its own
// requests with `sleep(interval)` rather than relying on `loadStages()`.
// `BENCH_VUS` here means "how many devices are polling concurrently", not
// "how much load to throw".
//
// # What "success" looks like
//
// A device is never approved during this run (nobody drives the `/device`
// approval UI), so the steady-state, expected answer to every poll is RFC
// 8628's `authorization_pending` — a 400 with `error: "authorization_pending"`
// (`crates/axiam-oauth2/src/error.rs`, `build_oauth2_error_response`'s
// default-to-400 arm). That is the SAME "the expected business outcome is a
// non-2xx the limiter still admits" shape `grpc_infra.js` and
// `grpc_admin_validate.js` already use — `doOp()`'s `expect: 400` treats it
// as the pass case, and `bench_op_latency_ms` measures the cost of a poll
// that finds nothing yet, which is the overwhelmingly common case in a real
// deployment (most polls occur before a human has acted). `slow_down` (also
// 400) is honored by widening this device's own poll interval, per RFC 8628
// §3.5 — a device that ignored it would be measuring its own protocol
// violation, not the endpoint.
//
// # Why this does not double as an `rl_prod_check.py` row
//
// Device polling hits `/oauth2/token`, which shares `token_per_min` with
// every other grant on that endpoint — the plan's own framing ("do not let
// the generic token bucket absorb polling floods") is exactly the risk this
// cell is meant to surface, by measuring what happens when many devices'
// honestly-paced polling adds up against that SHARED bucket, not by adding a
// new bucket. `token_per_min` already has its scenario
// (`oauth2_client_credentials.js`) and its `rl_prod_check.py` row; this cell
// is a second, differently-shaped way of loading the same family, published
// as its own labeled cell per `new-feature-bench-cells.md`'s convention, not
// folded into the limiter table.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { cfg, baseUrl, tlsOptions, requireSeed } from './lib/config.js';
import { m, protoCode } from './lib/metrics.js';

// k6 `options` values (BENCH_WARMUP/DURATION/COOLDOWN) are duration strings
// ("30s"); this scenario needs their sum as a single duration for
// constant-vus rather than three staged targets. Only "<n>s" is parsed
// (matching every profile shipped in benchmarks/profiles/) — anything else
// falls back to a safe default rather than silently producing "NaNs".
function secondsOf(durationStr) {
  const match = /^(\d+)s$/.exec(String(durationStr));
  return match ? Number(match[1]) : 30;
}

const TOTAL_SECONDS = secondsOf(cfg.warmup) + secondsOf(cfg.duration) + secondsOf(cfg.cooldown);

export const options = Object.assign(
  {
    scenarios: {
      deviceFlowPoll: {
        executor: 'constant-vus',
        vus: cfg.vus,
        duration: `${TOTAL_SECONDS}s`,
      },
    },
    // authorization_pending/slow_down are expected 400s (see file header),
    // so the shape mirrors thresholds('bench_op_latency_ms') rather than
    // reusing it verbatim — this scenario's checks assert "the limiter
    // admitted it", not "the grant succeeded".
    thresholds: {
      bench_op_latency_ms: [`p(95)<${cfg.maxP95}`],
      checks: [`rate>${1 - cfg.maxErrorRate}`],
    },
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

function formBody(obj) {
  return Object.keys(obj)
    .filter((k) => obj[k] !== undefined && obj[k] !== '')
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}

const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

export function setup() {
  requireSeed();
  return {};
}

// Per-VU device state, module scope (per-VU in k6, persists across a VU's
// iterations — see authz_check_rest.js's `rngState` for the same idiom).
// Obtained lazily on iteration 1 rather than in setup(), because setup() runs
// ONCE globally and every simulated device needs its own device_code.
let device = null;

function obtainDeviceCode() {
  const res = http.post(
    `${baseUrl()}/oauth2/device_authorization?tenant_id=${cfg.tenantId}`,
    formBody({ client_id: cfg.clientId, scope: 'openid' }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );
  if (res.status !== 200) {
    throw new Error(
      `device_flow_poll: device_authorization failed (status ${res.status}): ${String(res.body).slice(0, 200)}`,
    );
  }
  const body = res.json();
  if (!body.device_code) throw new Error('device_flow_poll: device_authorization returned no device_code');
  return { device_code: body.device_code, interval: body.interval || 5 };
}

export default function () {
  if (!device) {
    device = obtainDeviceCode();
  }

  const start = Date.now();
  const res = http.post(
    `${baseUrl()}/oauth2/token?tenant_id=${cfg.tenantId}`,
    formBody({
      grant_type: DEVICE_CODE_GRANT_TYPE,
      device_code: device.device_code,
      client_id: cfg.clientId,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );

  if (res.proto) m.httpProto.add(protoCode(res.proto));

  // 400 is the admitted, steady-state answer (authorization_pending /
  // slow_down); 200 would mean an out-of-band approval happened (harmless,
  // still counted as admitted); anything else is a real failure.
  const admitted = check(res, {
    'admitted by the limiter (pending, slow_down, or approved)': (r) => r.status === 400 || r.status === 200,
  });
  m.latency.add(Date.now() - start);
  m.errorRate.add(!admitted);
  if (admitted) {
    m.ok.add(1);
  } else {
    m.failed.add(1);
    if (res.status === 429) m.throttled.add(1);
  }

  // RFC 8628 §3.5: honor `slow_down` by widening this device's own interval;
  // a device that ignored it would be measuring a self-inflicted violation,
  // not the endpoint's steady-state cost.
  let error = null;
  try {
    error = res.json().error;
  } catch (_e) {
    /* non-JSON body — leave error null, sleep at the current interval */
  }
  if (error === 'slow_down') device.interval += 5;

  sleep(device.interval);
}
