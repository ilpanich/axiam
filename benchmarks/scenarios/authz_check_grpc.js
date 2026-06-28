// Scenario: low-latency authorization decision over gRPC (AuthorizationService.CheckAccess).
//
// NON-COMPARATIVE: most competitors do not expose an equivalent low-latency gRPC
// authz decision endpoint. This measures an AXIAM capability (service-mesh authz)
// in isolation and is reported separately, never as a head-to-head number.
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds } from './lib/config.js';
import { m } from './lib/metrics.js';

const client = new grpc.Client();
// Proto is loaded relative to the repo root; run k6 from benchmarks/ or pass
// --include-system-env-vars with BENCH_PROTO_ROOT.
client.load([__ENV.BENCH_PROTO_ROOT || '../proto'], 'axiam/v1/authorization.proto');

export const options = {
  scenarios: {
    authz: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
  },
  thresholds: thresholds('bench_op_latency_ms'),
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// A seeded subject/resource pair is required for a meaningful (allowed=true) check.
const SUBJECT = __ENV.BENCH_SUBJECT_ID || cfg.username;
const RESOURCE = __ENV.BENCH_RESOURCE_ID || 'bench-resource';

export default function () {
  if (__ITER === 0) {
    client.connect(cfg.grpcAddr, { plaintext: cfg.scheme === 'http' });
  }
  const start = Date.now();
  const res = client.invoke('axiam.v1.AuthorizationService/CheckAccess', {
    tenant_id: cfg.tenantId,
    subject_id: SUBJECT,
    action: 'read',
    resource_id: RESOURCE,
  });
  const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
  m.latency.add(Date.now() - start);
  m.errorRate.add(!ok);
  if (ok) m.ok.add(1); else m.failed.add(1);
}
