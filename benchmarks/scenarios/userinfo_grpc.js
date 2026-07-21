// Scenario: gRPC identity read — axiam.v1.UserInfoService/GetUserInfo.
//
// AXIAM's gRPC counterpart to its own REST `/oauth2/userinfo`
// (scenarios/userinfo.js): same logical operation (return the authenticated
// user's identity from a bearer token), two wire protocols. This is the AXIAM
// side of the PROTOCOL-EFFICIENCY pairing with scenarios/zitadel_userinfo_grpc.js
// (REST vs gRPC within one vendor). Keycloak exposes no equivalent gRPC identity
// RPC, so the cross-vendor gRPC-userinfo comparison is AXIAM-vs-Zitadel only
// (see runner/report.py and docs/methodology.md §3). Mirrors the structure of
// scenarios/authz_check_grpc.js (AXIAM gRPC dialing) and the setup() of
// scenarios/zitadel_userinfo_grpc.js (real user-token minting).
import grpc from 'k6/net/grpc';
import { check } from 'k6';
import { cfg, loadStages, thresholds, tlsOptions, grpcConnectParams, requireSeed } from './lib/config.js';
import { m } from './lib/metrics.js';
import { mintUserToken } from './lib/auth.js';

const client = new grpc.Client();
// Proto is loaded from the repo's own proto/ tree (same convention as
// authz_check_grpc.js). Run k6 from benchmarks/ or set BENCH_PROTO_ROOT.
client.load([__ENV.BENCH_PROTO_ROOT || '../proto'], 'axiam/v1/userinfo.proto');

// tlsOptions() supplies insecureSkipTLSVerify (private-CA edge) + tlsAuth (mTLS)
// for the setup() HTTPS token mint. The gRPC dial itself is separately TLS-gated
// via grpcConnectParams() (D2) — AXIAM's gRPC service runs on a dedicated port
// (cfg.grpcAddr, default :50051) independent of the REST edge's TLS profile.
export const options = Object.assign(
  {
    scenarios: {
      userinfo_grpc: {
        executor: 'ramping-vus', startVUs: 0, stages: loadStages(), gracefulRampDown: '5s',
      },
    },
    thresholds: thresholds('bench_op_latency_ms'),
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  },
  tlsOptions(),
);

// GetUserInfo resolves identity purely from the bearer token — same rule as
// userinfo.js / zitadel_userinfo_grpc.js: a client_credentials service-account
// token is not the comparable op, so mint a real user token and record the
// fallback (once, in setup()) if that wasn't possible.
export function setup() {
  requireSeed();
  const tok = mintUserToken();
  if (!tok.is_user_token) m.fallback.add(1);
  return tok;
}

export default function (data) {
  if (__ITER === 0) {
    client.connect(cfg.grpcAddr, grpcConnectParams());
  }
  const start = Date.now();
  // Empty request — identity comes entirely from the authorization metadata.
  const res = client.invoke(
    'axiam.v1.UserInfoService/GetUserInfo',
    {},
    { metadata: { authorization: `Bearer ${data.access_token}` } },
  );
  const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
  // D11: record the raw gRPC status code (e.g. 16=Unauthenticated) so a
  // 100%-non-OK run is diagnosable from the summary alone (mirrors
  // zitadel_userinfo_grpc.js / authz_check_grpc.js).
  m.grpcStatus.add(res && res.status != null ? res.status : -1);
  m.latency.add(Date.now() - start);
  m.errorRate.add(!ok);
  if (ok) m.ok.add(1); else m.failed.add(1);
}
