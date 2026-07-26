// Shared custom metrics + a uniform request helper so every scenario reports the
// same metric names. The report aggregator keys off these names.
import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

export const m = {
  ok: new Counter('bench_ok'),               // successful logical operations
  failed: new Counter('bench_failed'),       // failed logical operations
  errorRate: new Rate('bench_error_rate'),   // fraction failed (validity gate)
  latency: new Trend('bench_op_latency_ms', true), // end-to-end op latency
  // Count of iterations that measured a fallback operation instead of the
  // labelled logical op (e.g. Zitadel's login() falling back to
  // client_credentials, or a userinfo setup() that couldn't mint a real user
  // token). report.py annotates any cell with bench_fallback > 0 as
  // comparability: fallback-op and excludes it from head-to-head tables.
  fallback: new Counter('bench_fallback'),
  // D11: gRPC status code of each invoke(), so a 100%-non-OK scenario is
  // diagnosable from the summary alone (e.g. 7=PermissionDenied,
  // 16=Unauthenticated) instead of just showing up as failed checks with no
  // hint why. A Trend (not a Counter) so the summary's percentile/avg stats
  // surface which code dominates. Recorded by the gRPC scenarios only.
  grpcStatus: new Trend('bench_grpc_status'),
  // G9/item-3: rate-limit rejections counted DISTINCTLY from other failures
  // (REST 429 / gRPC RESOURCE_EXHAUSTED=8 — the status both
  // crates/axiam-api-rest's shared+in-memory limiters and
  // crates/axiam-api-grpc's GrpcSharedRateLimitLayer/GovernorLayer return,
  // see crates/axiam-api-grpc/src/middleware/rate_limit.rs
  // too_many_requests_response()). This is additive: a throttled op is still
  // counted in bench_failed / bench_error_rate exactly as before (it is not a
  // success), so nothing downstream that reads those two metrics changes
  // behavior. What this adds is the ability to tell, from the summary alone,
  // whether a near-100%-error cell is "almost entirely expected control-plane
  // rejections" (bench_failed ≈ bench_throttled) or "something else is also
  // broken" (bench_failed >> bench_throttled) — the run-3 "13.6/s bench_ok at
  // bench_error_rate=1.00" cells were not a bug in bench_ok's accounting
  // (doOp() below already only ever increments bench_ok on a true logical
  // pass — see the report for the full trace); they were a handful of
  // legitimate successes admitted by the rate limiter, plus a k6 closed-loop
  // VU loop retrying near-instantly on every 429 with no backoff, producing
  // an iteration count so large that bench_error_rate rounds to "1.00" at 2
  // decimal places while bench_ok's count-over-full-test-duration rate still
  // reads as a nonzero, seemingly-contradictory "ops/s". bench_throttled
  // makes that story legible without changing either existing metric.
  throttled: new Counter('bench_throttled'),
};

// Execute one built request (from targets.js) and record uniform metrics.
// Returns the parsed JSON body on success, or null on failure.
export function doOp(built, params) {
  const reqParams = Object.assign({}, built.params || {}, params || {});
  const res = http.request(built.method, built.url, built.body || null, reqParams);

  if (built.fallback) m.fallback.add(1);

  const expected = built.expect || 200;
  const passed = check(res, {
    [`status is ${expected}`]: (r) => r.status === expected,
  });

  m.latency.add(res.timings.duration);
  m.errorRate.add(!passed);
  if (passed) {
    m.ok.add(1);
  } else {
    m.failed.add(1);
    // G9/item-3: classify rate-limit rejections distinctly (see m.throttled
    // above). res.status === 429 can only be true here because `passed` is
    // already false, i.e. `expected` (200/201) didn't match — so a scenario
    // whose `built.expect` was itself 429 could never reach this branch as a
    // "throttled" success; no scenario in this repo sets expect: 429 (grep
    // confirms every adapter/scenario expects 200/201), so a 429 can only
    // ever land in the failed/throttled branch, never in bench_ok.
    if (res.status === 429) m.throttled.add(1);
  }

  if (!passed) return null;
  try {
    return res.json();
  } catch (_e) {
    return {}; // non-JSON 2xx (e.g. JWKS variants) still counts as success
  }
}

// Shared record-and-classify helper for scenarios that cannot use doOp()
// because their transport isn't k6/http (currently: the gRPC scenarios —
// authz_check_grpc.js, authz_batch_grpc.js, userinfo_grpc.js,
// zitadel_userinfo_grpc.js — whose k6/net/grpc `invoke()` response shape and
// timing model differ from http.request()'s, so they hand-roll their own
// ok/failed/latency/status recording instead). This centralizes the SAME
// classify-and-count semantics doOp() uses above (including the
// bench_throttled split) so those scenarios can adopt it with a one-line
// change at their call site instead of re-diverging their own copy again.
// NOT wired into any scenario by this change — see G9
// (claude_dev/grpc-vs-rest-authz-analysis.md) for the exact remaining
// call-site edit each of those (unowned) files needs.
//
// `res` is the raw k6 grpc.Client.invoke() response, `latencyMs` the
// caller-measured duration, `ok` the caller's `grpc status OK` check result.
export function recordGrpcResult(res, latencyMs, ok) {
  // Number() is required: k6 hands res.status to JS as a wrapped Go value
  // (typeof === "object"), so `res.status === 8` below would silently never
  // match without this coercion (same pitfall the D11 grpcStatus comments in
  // the gRPC scenarios already document for the OK-code case).
  const statusCode = res && res.status != null ? Number(res.status) : -1;
  m.grpcStatus.add(statusCode);
  m.latency.add(latencyMs);
  m.errorRate.add(!ok);
  if (ok) {
    m.ok.add(1);
  } else {
    m.failed.add(1);
    // grpc RESOURCE_EXHAUSTED=8 — the status too_many_requests_response()
    // (crates/axiam-api-grpc/src/middleware/rate_limit.rs) and the in-memory
    // GovernorLayer's GovernorError::TooManyRequests both return.
    if (statusCode === 8) m.throttled.add(1);
  }
}
