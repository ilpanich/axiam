// Scenario: gRPC UserService/ValidateCredentials — the `grpc_admin` limiter
// family (SEC-079).
//
// Why this exists (run-5 J1c): `grpc_admin` had no scenario, so
// `rl_prod_check.py` could not check the one gRPC ceiling that is an absolute
// constant rather than a multiple of the authz base. That ceiling exists
// because this RPC performs an **Argon2id verification** — it is a CPU guard,
// and an unchecked CPU guard is the one you find out about in production.
//
// Deliberately *invalid* credentials: a wrong password still costs the full
// Argon2id verification (the handler must not short-circuit — that would be a
// timing oracle), so this drives the exact cost the ceiling is sized for
// without minting sessions as a side effect. `valid: false` is the expected
// business outcome; the gRPC status is still OK, and OK-vs-RESOURCE_EXHAUSTED
// is what the limiter check reads.
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, grpcConnectParams, requireSeed } from './lib/config.js';
import { recordGrpcResult } from './lib/metrics.js';
import { loginSession, jwtClaims } from './lib/auth.js';

const client = new grpc.Client();
client.load([__ENV.BENCH_PROTO_ROOT || '../proto'], 'axiam/v1/user.proto');

export const options = Object.assign(
  {
    scenarios: {
      admin: { executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s' },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// Never a real password: this must not accidentally authenticate, and it must
// not be mistakable for a credential if it leaks into a log or a results tree.
const WRONG_PASSWORD = 'bench-invalid-password-do-not-use';

export function setup() {
  requireSeed();
  const s = loginSession();
  const claims = jwtClaims(s.access_token);
  return {
    access_token: s.access_token,
    tenant_id: claims.tenant_id || cfg.tenantId,
  };
}

export default function (data) {
  if (__ITER === 0) {
    client.connect(cfg.grpcAddr, grpcConnectParams());
  }
  const start = Date.now();
  const res = client.invoke(
    'axiam.v1.UserService/ValidateCredentials',
    {
      tenant_id: data.tenant_id,
      username_or_email: cfg.username,
      password: WRONG_PASSWORD,
    },
    { metadata: { authorization: `Bearer ${data.access_token}` } },
  );
  const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
  recordGrpcResult(res, Date.now() - start, ok);
}
