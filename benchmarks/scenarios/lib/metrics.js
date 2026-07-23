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
  }

  if (!passed) return null;
  try {
    return res.json();
  } catch (_e) {
    return {}; // non-JSON 2xx (e.g. JWKS variants) still counts as success
  }
}
