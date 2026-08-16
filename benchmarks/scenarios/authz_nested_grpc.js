// Scenario: authorize a resource nested N levels deep, over gRPC
// (axiam.v1.AuthorizationService/CheckAccess).
//
// N1. The gRPC half of the depth sweep, and the transport pair of
// authz_nested_rest.js: the SAME resource chain, the SAME grant, the SAME
// leaf — only the wire differs. That is what makes the two cells a genuine
// within-vendor protocol-efficiency comparison at each rung of the ladder
// (docs/methodology.md §5), and it is why the chain is provisioned by the
// shared `provisionAxiamChain()` in lib/nested.js rather than re-created here.
//
// AXIAM-ONLY, and unavoidably so. Keycloak exposes no gRPC surface at all, and
// Zitadel's gRPC APIs are management/auth APIs with no per-resource
// authorization decision RPC among them — the same capability gap the REST
// scenario's Zitadel arm documents, one transport further along. Registered in
// AXIAM_ONLY_SCENARIOS (runner/run-benchmark.sh) accordingly; it is never
// published head-to-head.
//
// The gRPC AuthorizationService sits behind AuthInterceptor and cross-validates
// the request's tenant_id/subject_id against the verified token claims
// (SEC-003 / T-27-12) — a mismatch is permission_denied, not a decision. So the
// scenario logs in as the seeded user and echoes that token's own sub/tenant,
// exactly as authz_check_grpc.js does.
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, grpcConnectParams, requireSeed } from './lib/config.js';
import { recordGrpcResult } from './lib/metrics.js';
import { loginSession, jwtClaims } from './lib/auth.js';
import { provisionAxiamChain, nestedDepth } from './lib/nested.js';

const client = new grpc.Client();
// Proto is loaded relative to the repo root; run-benchmark.sh runs k6 from
// benchmarks/scenarios with BENCH_PROTO_ROOT pointed at ../proto.
client.load([__ENV.BENCH_PROTO_ROOT || '../proto'], 'axiam/v1/authorization.proto');

export const options = Object.assign(
  {
    scenarios: {
      authzNestedGrpc: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    setupTimeout: cfg.setupTimeout,
  },
  tlsOptions(),
);

export function setup() {
  requireSeed();
  if (cfg.target !== 'axiam') {
    // Defence in depth behind run-benchmark.sh's AXIAM_ONLY filter: a manual
    // `k6 run` against another target would otherwise dial AXIAM's proto at a
    // server that has never heard of it and report the resulting UNIMPLEMENTED
    // flood as a measurement.
    throw new Error(
      `authz_nested_grpc: target is '${cfg.target}' — this scenario is AXIAM-only (no competitor in this ` +
        "harness's target set exposes a gRPC authorization-decision RPC). See the header.",
    );
  }
  const depth = nestedDepth();
  const chain = provisionAxiamChain(depth);
  const leaf = chain[chain.length - 1];
  const s = loginSession();
  const claims = jwtClaims(s.access_token);
  const data = {
    depth,
    leaf_id: leaf,
    access_token: s.access_token,
    subject_id: claims.sub || __ENV.BENCH_SUBJECT_ID || cfg.username,
    tenant_id: claims.tenant_id || cfg.tenantId,
  };

  // Fail-closed probe, over the transport this cell actually measures. The
  // REST arm's probe would not catch a gRPC-side identity mismatch, and a
  // permission_denied flood is indistinguishable from a slow deny once it is
  // averaged into a trend.
  client.connect(cfg.grpcAddr, grpcConnectParams());
  const probe = client.invoke(
    'axiam.v1.AuthorizationService/CheckAccess',
    { tenant_id: data.tenant_id, subject_id: data.subject_id, action: 'read', resource_id: leaf },
    { metadata: { authorization: `Bearer ${s.access_token}` } },
  );
  const probeStatus = probe && probe.status != null ? Number(probe.status) : -1;
  if (probeStatus !== grpc.StatusOK) {
    client.close();
    throw new Error(
      `authz_nested_grpc: depth-${depth} probe returned gRPC status ${probeStatus}, not OK — ` +
        'the cell would measure a transport/auth rejection instead of a decision.',
    );
  }
  if (!probe.message || probe.message.allowed !== true) {
    client.close();
    throw new Error(
      `authz_nested_grpc: the depth-${depth} leaf evaluated to DENY (reason: ${probe.message && probe.message.reason}). ` +
        'The seeded grant on bench-resource did not cascade down the chain, so this cell would measure the ' +
        'SHORT deny path instead of an ancestor walk.',
    );
  }
  client.close();
  console.log(`authz_nested_grpc: depth=${depth} probe = ALLOW, leaf=${leaf}`);
  return data;
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
      resource_id: data.leaf_id,
    },
    { metadata: { authorization: `Bearer ${data.access_token}` } },
  );
  const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
  // G9: one shared classifier for every gRPC scenario — records the raw status
  // code (D11) and splits RESOURCE_EXHAUSTED out into bench_throttled so a
  // rate-limited cell stays legible. See lib/metrics.js.
  recordGrpcResult(res, Date.now() - start, ok);
}
