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
//
// # REQUIRES a neutralized account lockout — do not run this cell without it
//
// "No session side effects" is true; "no side effects" is not. Every iteration
// here is a failed credential check against the seeded user, and D-06 accrual
// (crates/axiam-auth/src/lockout.rs) is shared by the REST and gRPC paths, so
// at the shipped threshold (5 attempts / 900s, backoff x2, cap 3600s) this
// scenario LOCKS THE BENCHMARK'S ONLY USER about five iterations in. Two
// consequences, both found by the alpha25 dry run:
//
//   - Every later login-based cell fails 401 for up to an hour, and a re-seed
//     does not clear it (create_or_find finds the locked user untouched). In
//     that run it took out oauth2_password_login, token_exchange,
//     token_refresh, uma_ticket_grant, userinfo and userinfo_grpc.
//   - This scenario stops measuring what it is for. `validate_credentials`
//     returns `invalid` BEFORE `verify_password` once `locked_until > now`
//     (crates/axiam-api-grpc/src/services/user.rs), so post-lock iterations
//     skip Argon2id, still answer gRPC OK, and still count as `bench_ok`. The
//     cell reported p95 2ms where a genuine Argon2id verify costs ~34ms — a
//     green cell measuring the lockout short-circuit.
//
// `targets/axiam/docker-compose.yml` therefore pins
// AXIAM__AUTH__MAX_FAILED_LOGIN_ATTEMPTS high for the bench posture. If you
// ever see this cell report a single-digit-millisecond p95, suspect that the
// neutralization is not in effect rather than that AXIAM got fast.
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
