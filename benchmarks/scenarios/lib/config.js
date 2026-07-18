// Shared k6 configuration: load model, thresholds, and environment wiring.
//
// All knobs are environment-overridable so the orchestrator (runner/run-benchmark.sh)
// can drive the same scenario at different intensities without editing scripts.
import { fail } from 'k6';

function num(name, dflt) {
  const v = __ENV[name];
  return v === undefined || v === '' ? dflt : Number(v);
}
function str(name, dflt) {
  const v = __ENV[name];
  return v === undefined || v === '' ? dflt : v;
}

export const cfg = {
  // --- target wiring (set by run-benchmark.sh from the target + profile) ---
  target: str('BENCH_TARGET', 'axiam'),
  profile: str('BENCH_PROFILE', 'p0-plaintext'),
  scheme: str('BENCH_SCHEME', 'http'),
  host: str('BENCH_HOST', 'localhost'),
  port: num('BENCH_PORT', 8090),
  grpcAddr: str('BENCH_GRPC_ADDR', 'localhost:50051'),

  // --- tenancy / credentials provisioned by runner/seed.sh ---
  orgId: str('BENCH_ORG_ID', ''),
  orgSlug: str('BENCH_ORG_SLUG', ''),
  tenantId: str('BENCH_TENANT_ID', ''),
  tenantSlug: str('BENCH_TENANT_SLUG', 'default'),
  realm: str('BENCH_REALM', 'bench'), // keycloak/zitadel realm name
  username: str('BENCH_USERNAME', 'benchuser'),
  password: str('BENCH_PASSWORD', 'Bench@User123!'),
  clientId: str('BENCH_CLIENT_ID', 'bench-client'),
  clientSecret: str('BENCH_CLIENT_SECRET', 'bench-secret'),

  // --- TLS (from the security profile) ---
  verifyTls: str('BENCH_VERIFY_TLS', 'true') === 'true',
  caCert: str('BENCH_CA_CERT', ''),
  clientCert: str('BENCH_CLIENT_CERT', ''),
  clientKey: str('BENCH_CLIENT_KEY', ''),

  // --- load model ---
  vus: num('BENCH_VUS', 50),
  warmup: str('BENCH_WARMUP', '30s'),
  duration: str('BENCH_DURATION', '120s'),
  cooldown: str('BENCH_COOLDOWN', '10s'),

  // --- validity gates ---
  maxErrorRate: num('BENCH_MAX_ERROR', 0.01),
  maxP95: num('BENCH_MAX_P95_MS', 2000),
};

export function baseUrl() {
  return `${cfg.scheme}://${cfg.host}:${cfg.port}`;
}

// k6 `options.tlsAuth` / `insecureSkipTLSVerify` derived from the profile.
export function tlsOptions() {
  const o = {};
  if (!cfg.verifyTls) o.insecureSkipTLSVerify = true;
  if (cfg.clientCert && cfg.clientKey) {
    o.tlsAuth = [{
      cert: open(cfg.clientCert),
      key: open(cfg.clientKey),
    }];
  }
  return o;
}

// Standard three-stage closed-loop model: warm-up (uncounted) → measure → cooldown.
// k6 cannot literally exclude warm-up from a single metric, so the orchestrator
// time-slices the resource samples and we tag iterations with stage via groups;
// the report trims the warm-up window. Stages here shape the VU ramp.
export function loadStages() {
  return [
    { duration: cfg.warmup, target: cfg.vus },     // ramp to load (warm-up)
    { duration: cfg.duration, target: cfg.vus },   // hold (measured)
    { duration: cfg.cooldown, target: 0 },         // drain (cooldown)
  ];
}

export function thresholds(durationMetric) {
  const t = {};
  t[durationMetric] = [`p(95)<${cfg.maxP95}`];
  t['checks'] = [`rate>${1 - cfg.maxErrorRate}`];
  return t;
}

export function requireSeed() {
  if (cfg.target === 'axiam' && !cfg.tenantId) {
    fail('BENCH_TENANT_ID is required for the axiam target — run runner/seed.sh first');
  }
}
