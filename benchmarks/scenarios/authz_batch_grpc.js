// Scenario: batch authorization decision over gRPC (AuthorizationService.BatchCheckAccess).
//
// NON-COMPARATIVE: most competitors do not expose an equivalent low-latency gRPC
// batch authz decision endpoint. This measures an AXIAM capability (service-mesh
// batch authz) in isolation and is reported separately, never as a head-to-head number.
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { m } from './lib/metrics.js';
import { loginSession, jwtClaims } from './lib/auth.js';

const client = new grpc.Client();
// Proto is loaded relative to the repo root; run k6 from benchmarks/ or pass
// --include-system-env-vars with BENCH_PROTO_ROOT.
client.load([__ENV.BENCH_PROTO_ROOT || '../proto'], 'axiam/v1/authorization.proto');

// tlsOptions() supplies insecureSkipTLSVerify (private-CA edge) + tlsAuth (mTLS);
// merged in so the setup() HTTPS login — and the gRPC TLS dial — honor the profile.
export const options = Object.assign(
  {
    scenarios: {
      authzBatch: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

const RESOURCE = __ENV.BENCH_RESOURCE_ID || 'bench-resource';
const BATCH_SIZE = Number(__ENV.BENCH_BATCH_SIZE || 5);

// Every request in the batch must carry the SAME (real, UUID) resource_id: the
// server rejects non-UUID resource_ids, and the batch handler cross-validates
// each entry's tenant_id/subject_id against the token claims (T-27-12) — a single
// mismatch rejects the whole batch. So we reuse the seeded RESOURCE and the
// token's own subject/tenant for every entry (no per-index resource suffixing).
function batchRequest(data) {
  const requests = [];
  for (let i = 0; i < BATCH_SIZE; i++) {
    requests.push({
      tenant_id: data.tenant_id,
      subject_id: data.subject_id,
      action: 'read',
      resource_id: RESOURCE,
    });
  }
  return { requests };
}

export function setup() {
  requireSeed();
  const s = loginSession();
  const claims = jwtClaims(s.access_token);
  return {
    access_token: s.access_token,
    subject_id: claims.sub || __ENV.BENCH_SUBJECT_ID || cfg.username,
    tenant_id: claims.tenant_id || cfg.tenantId,
  };
}

export default function (data) {
  if (__ITER === 0) {
    client.connect(cfg.grpcAddr, { plaintext: cfg.grpcPlaintext });
  }
  const start = Date.now();
  const res = client.invoke(
    'axiam.v1.AuthorizationService/BatchCheckAccess',
    batchRequest(data),
    { metadata: { authorization: `Bearer ${data.access_token}` } },
  );
  const ok = check(res, {
    'grpc status OK': (r) => r && r.status === grpc.StatusOK,
    'results length matches batch size': (r) =>
      r && r.message && Array.isArray(r.message.results) && r.message.results.length === BATCH_SIZE,
  });
  m.latency.add(Date.now() - start);
  m.errorRate.add(!ok);
  if (ok) m.ok.add(1); else m.failed.add(1);
}
