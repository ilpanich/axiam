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
};

// Execute one built request (from targets.js) and record uniform metrics.
// Returns the parsed JSON body on success, or null on failure.
export function doOp(built, params) {
  const reqParams = Object.assign({}, built.params || {}, params || {});
  const res = http.request(built.method, built.url, built.body || null, reqParams);

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
