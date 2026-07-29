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
  // H6: the negotiated wire protocol of every measured response, so a TLS
  // h1-vs-h2 cell can be read as evidence instead of assumed. G8's summary
  // tried to recover this from k6's `http_version` tag on http_req_duration,
  // but k6 only emits that tag into the *summary* metric key when the metric
  // is explicitly tagged in options — it is not by default — so the column
  // read "?" for every cell and the whole conviction rested on which conf
  // file we believed nginx had loaded.
  //
  // Encoding (a Trend, not a Counter, so min/max/avg expose a MIXED cell —
  // exactly the failure mode that silently voids an h1 control):
  //     10 = HTTP/1.0   11 = HTTP/1.1   20 = HTTP/2.0   30 = HTTP/3
  //      0 = k6 reported no/unrecognized proto (never seen in practice; kept
  //          so an unknown string is loud rather than silently absent)
  // report.py decodes min/max back to a label and prints "mixed(1.1,2.0)"
  // when they disagree. gRPC scenarios record 20 via recordGrpcResult():
  // gRPC is HTTP/2 by definition, which makes the column total rather than
  // REST-only.
  httpProto: new Trend('bench_http_proto'),
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

// H6: map k6's res.proto string ("HTTP/1.1", "HTTP/2.0", …) to the numeric
// encoding documented on m.httpProto above. Exported for unit-testability and
// for any scenario that needs to record a response outside doOp().
export function protoCode(proto) {
  switch (proto) {
    case 'HTTP/1.0': return 10;
    case 'HTTP/1.1': return 11;
    case 'HTTP/2.0': return 20;
    // k6 (Go net/http) reports h2 as "HTTP/2.0"; accept the short form too in
    // case a future k6 changes it, rather than silently reporting 0.
    case 'HTTP/2': return 20;
    case 'HTTP/3.0':
    case 'HTTP/3': return 30;
    default: return 0;
  }
}

// Execute one built request (from targets.js) and record uniform metrics.
// Returns the parsed JSON body on success, or null on failure.
export function doOp(built, params) {
  const reqParams = Object.assign({}, built.params || {}, params || {});
  const res = http.request(built.method, built.url, built.body || null, reqParams);

  if (built.fallback) m.fallback.add(1);

  // H6: record the negotiated protocol for EVERY response, pass or fail — a
  // failing p2-h1 cell's protocol is exactly the datum that says whether the
  // edge was really speaking http/1.1 while it failed. Only skip the sample
  // when k6 reports no proto at all (transport-level error: connection
  // refused/reset, so no protocol was ever negotiated); a *present but
  // unrecognized* string still records as 0 so it shows up loudly rather than
  // vanishing.
  if (res.proto) m.httpProto.add(protoCode(res.proto));

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
  // H6: gRPC is HTTP/2 by definition (RFC-level requirement of the gRPC wire
  // protocol), and k6/net/grpc exposes no proto field, so record it as such
  // rather than leaving the column empty for gRPC cells.
  m.httpProto.add(20);
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
