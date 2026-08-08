// Scenario: gRPC infrastructure family (`grpc_infra`) — reflection + health.
//
// Why this exists (run-5 J1c): `grpc_infra` is the eighth and last limiter
// family, and it had no scenario, so the run-5 §7 verdict table could not
// speak to it. It is also the family most likely to be assumed harmless: it
// carries the fixed `INFRA_PER_SEC` ceiling precisely because reflection is a
// cheap-to-call, expensive-to-serve, unauthenticated-adjacent surface.
//
// # What this measures, and why UNIMPLEMENTED is the success case
//
// AXIAM does not mount `grpc.health.v1.Health` or the reflection service, so
// a call to either returns UNIMPLEMENTED. That does not make the family
// unmeasurable — the opposite. Both rate-limit layers are `tower` layers on
// the tonic listener, so they classify by request path and decide **before**
// tonic routes anything. The observable contract is therefore:
//
//   - under the ceiling → UNIMPLEMENTED (the limiter admitted it; tonic had
//     nothing to route it to),
//   - over the ceiling  → RESOURCE_EXHAUSTED (the limiter rejected it).
//
// So this scenario asserts UNIMPLEMENTED as its "admitted" outcome and lets
// `bench_throttled` count the rejections, which is exactly the signal
// `rl_prod_check.py` needs. If AXIAM ever does mount health/reflection, the
// only change required here is widening the admitted-status check to also
// accept OK — the limiter arithmetic is unaffected.
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, grpcConnectParams, requireSeed } from './lib/config.js';
import { recordGrpcResult } from './lib/metrics.js';

const client = new grpc.Client();
// Vendored under benchmarks/ rather than the shipped proto/ tree — see the
// header comment in that file for why.
client.load(
  [__ENV.BENCH_INFRA_PROTO_ROOT || './proto/grpc-health'],
  'grpc/health/v1/health.proto',
);

export const options = Object.assign(
  {
    scenarios: {
      infra: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

export function setup() {
  requireSeed();
  return {};
}

export default function () {
  if (__ITER === 0) {
    client.connect(cfg.grpcAddr, grpcConnectParams());
  }
  const start = Date.now();
  // No `authorization` metadata on purpose: the infra family is reachable
  // without a bearer token (that is why it has its own ceiling), and adding
  // one would measure a different surface.
  const res = client.invoke('grpc.health.v1.Health/Check', { service: '' });
  const ok = check(res, {
    'admitted by the limiter': (r) =>
      r && (r.status === grpc.StatusOK || r.status === grpc.StatusUnimplemented),
  });
  recordGrpcResult(res, Date.now() - start, ok);
}
