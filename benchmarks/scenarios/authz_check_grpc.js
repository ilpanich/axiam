// Scenario: low-latency authorization decision over gRPC (AuthorizationService.CheckAccess).
//
// NON-COMPARATIVE: most competitors do not expose an equivalent low-latency gRPC
// authz decision endpoint. This measures an AXIAM capability (service-mesh authz)
// in isolation and is reported separately, never as a head-to-head number.
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, grpcConnectParams, requireSeed } from './lib/config.js';
import { m } from './lib/metrics.js';
import { loginSession, jwtClaims } from './lib/auth.js';

const client = new grpc.Client();
// Proto is loaded relative to the repo root; run k6 from benchmarks/ or pass
// --include-system-env-vars with BENCH_PROTO_ROOT.
client.load([__ENV.BENCH_PROTO_ROOT || '../proto'], 'axiam/v1/authorization.proto');

// tlsOptions() supplies insecureSkipTLSVerify (private-CA edge) + tlsAuth (mTLS)
// for the setup() HTTPS login. The gRPC dial itself is separately TLS-gated via
// grpcConnectParams() (D2) — see cfg.grpcPlaintext in lib/config.js.
export const options = Object.assign(
  {
    scenarios: {
      authz: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

const RESOURCE = __ENV.BENCH_RESOURCE_ID || 'bench-resource';

// The gRPC AuthorizationService is behind AuthInterceptor and derives identity
// from the verified JWT, then cross-validates the request's tenant_id/subject_id
// against the token claims (SEC-003 / T-27-12) — a mismatch is permission_denied.
// So we log in as the seeded user once and echo the token's own sub/tenant in the
// request body. A seeded role grant (action "read" on RESOURCE) is what makes the
// decision allowed=true; without it the call still succeeds (gRPC OK) but denies.
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
    client.connect(cfg.grpcAddr, grpcConnectParams());
  }
  const start = Date.now();
  const res = client.invoke(
    'axiam.v1.AuthorizationService/CheckAccess',
    {
      tenant_id: data.tenant_id,
      subject_id: data.subject_id,
      action: 'read',
      resource_id: RESOURCE,
    },
    { metadata: { authorization: `Bearer ${data.access_token}` } },
  );
  const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
  m.latency.add(Date.now() - start);
  m.errorRate.add(!ok);
  if (ok) m.ok.add(1); else m.failed.add(1);
}
