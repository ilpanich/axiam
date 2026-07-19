// Scenario: gRPC identity read — zitadel.auth.v1.AuthService/GetMyUser.
//
// This is Zitadel's gRPC counterpart to its own REST `/oidc/v1/userinfo`
// (scenarios/userinfo.js): same logical operation (return the authenticated
// user's identity from a bearer token), two wire protocols, same vendor. It
// is a PROTOCOL-EFFICIENCY pairing (REST vs gRPC within Zitadel), NOT a
// cross-vendor head-to-head — AXIAM and Keycloak expose no equivalent gRPC
// identity RPC, so this scenario is Zitadel-only (see
// runner/run-benchmark.sh's ZITADEL_ONLY_SCENARIOS) and report.py never
// places it in a cross-vendor winner table (docs/methodology.md §3,
// runner/report.py's NON_COMPARATIVE_SCENARIOS). Mirrors the structure of
// scenarios/authz_check_grpc.js.
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, requireSeed } from './lib/config.js';
import { m } from './lib/metrics.js';
import { mintUserToken } from './lib/auth.js';

const client = new grpc.Client();
// Vendored, hand-trimmed proto (scenarios/proto/zitadel/README.md documents
// exactly what was kept/cut and why) — only AuthService/GetMyUser and the
// message shapes it needs. Import root defaults to this repo's
// scenarios/proto/zitadel (k6 is run with cwd=benchmarks/scenarios, see
// runner/run-benchmark.sh); override with BENCH_ZITADEL_PROTO_ROOT if
// invoking k6 from elsewhere.
client.load([__ENV.BENCH_ZITADEL_PROTO_ROOT || 'proto/zitadel'], 'zitadel/auth.proto');

// tlsOptions() supplies insecureSkipTLSVerify (private-CA edge) + tlsAuth
// (mTLS) for the setup() HTTPS token mint. Unlike AXIAM (whose gRPC service
// runs on a dedicated always-plaintext :50051 port, independent of the REST
// edge's TLS profile — see config.js's grpcPlaintext comment), Zitadel
// serves gRPC and REST multiplexed on the SAME port, so the gRPC dial's
// TLS-ness must follow the security profile's scheme, not a fixed flag —
// see connectParams() below.
export const options = Object.assign(
  {
    scenarios: {
      zitadel_userinfo_grpc: {
        executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s',
      },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// GetMyUser resolves identity purely from the bearer token — same rule as
// userinfo.js: a client_credentials service-account token is not the
// comparable op, so mint a real user token and record the fallback (once,
// in setup()) if that wasn't possible.
export function setup() {
  requireSeed();
  const tok = mintUserToken();
  if (!tok.is_user_token) m.fallback.add(1);
  return tok;
}

// Zitadel multiplexes gRPC and REST on cfg.port (no separate gRPC port like
// AXIAM's :50051), so dial the same host:port the REST scenarios use, and
// derive plaintext/TLS from the active security profile's scheme.
function grpcTarget() {
  return `${cfg.host}:${cfg.port}`;
}

function connectParams() {
  const plaintext = cfg.scheme !== 'https';
  const params = { plaintext };
  if (!plaintext) {
    // k6 has no "trust this CA" option (see config.js's tlsOptions() note);
    // the bench TLS edge uses a throwaway private-CA cert, so verification
    // must be skipped unless BENCH_VERIFY_TLS points at a publicly-trusted
    // cert.
    params.tls = cfg.verifyTls ? {} : { insecureSkipVerify: true };
  }
  return params;
}

export default function (data) {
  if (__ITER === 0) {
    client.connect(grpcTarget(), connectParams());
  }
  const start = Date.now();
  const res = client.invoke(
    'zitadel.auth.v1.AuthService/GetMyUser',
    {},
    { metadata: { authorization: `Bearer ${data.access_token}` } },
  );
  const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
  m.latency.add(Date.now() - start);
  m.errorRate.add(!ok);
  if (ok) m.ok.add(1); else m.failed.add(1);
}
