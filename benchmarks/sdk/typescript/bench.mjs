// AXIAM TypeScript SDK benchmark (reference scaffold).
//
// The timing harness below is complete; only the SDK calls are TODO, because the
// TypeScript SDK is still under development (feature/phase-17, T17.2). When it
// lands: `npm i @axiam/sdk`, import it, implement the four `ops` calls, and flip
// STATUS to "ok". The stdout JSON contract (axiam.sdk-bench/v1) must stay intact.
//
// Run: node bench.mjs   (or: just sdk-bench sdk=typescript)

const env = (k, d) => process.env[k] ?? d;
const ITER = Number(env("SDK_BENCH_ITERATIONS", "2000"));
const WARMUP = Number(env("SDK_BENCH_WARMUP", "200"));
const CONC = Number(env("SDK_BENCH_CONCURRENCY", "16"));

const cfg = {
  scheme: env("BENCH_SCHEME", "http"),
  host: env("BENCH_HOST", "localhost"),
  port: env("BENCH_PORT", "8090"),
  tenantId: env("BENCH_TENANT_ID", ""),
  clientId: env("BENCH_CLIENT_ID", "bench-client"),
  clientSecret: env("BENCH_CLIENT_SECRET", ""),
};

function pct(arr, p) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const k = (s.length - 1) * (p / 100);
  const lo = Math.floor(k), hi = Math.min(lo + 1, s.length - 1);
  return s[lo] + (s[hi] - s[lo]) * (k - lo);
}

// ---------------------------------------------------------------------------
// TODO(feature/phase-17 T17.2): construct the SDK client and implement each op.
//
//   import { AxiamClient } from "@axiam/sdk";
//   const client = new AxiamClient({
//     baseUrl: `${cfg.scheme}://${cfg.host}:${cfg.port}`,
//     tenantId: cfg.tenantId,
//     clientId: cfg.clientId, clientSecret: cfg.clientSecret,
//   });
//   const OPS = {
//     client_credentials: () => client.auth.clientCredentials({ scope: "openid" }),
//     introspect:        (t) => client.tokens.introspect(t),
//     userinfo:          (t) => client.oidc.userinfo(t),
//     authz_check:        () => client.authz.check({ action: "read", resourceId: "bench" }),
//   };
const SDK_WIRED = false;
let OPS = null;
// ---------------------------------------------------------------------------

async function timeOp(fn) {
  const lat = [];
  let errors = 0;
  // warm-up (uncounted)
  for (let i = 0; i < WARMUP; i++) { try { await fn(); } catch { errors++; } }
  // measured, bounded concurrency
  const start = performance.now();
  let i = 0;
  async function worker() {
    while (i < ITER) {
      i++;
      const t0 = performance.now();
      try { await fn(); lat.push(performance.now() - t0); }
      catch { errors++; }
    }
  }
  await Promise.all(Array.from({ length: CONC }, worker));
  const secs = (performance.now() - start) / 1000;
  return {
    p50_ms: pct(lat, 50), p95_ms: pct(lat, 95), p99_ms: pct(lat, 99),
    throughput_rps: lat.length / secs, errors,
  };
}

async function main() {
  const ops = {};
  let status = "ok", notes = "";
  if (!SDK_WIRED || !OPS) {
    status = "pending";
    notes = "SDK not yet wired — implement OPS in sdk/typescript/bench.mjs (T17.2).";
    for (const k of ["client_credentials", "introspect", "userinfo", "authz_check"])
      ops[k] = { p50_ms: 0, p95_ms: 0, p99_ms: 0, throughput_rps: 0, errors: 0 };
  } else {
    let token = null;
    for (const [k, fn] of Object.entries(OPS)) {
      ops[k] = await timeOp(async () => {
        const r = await fn(token);
        if (k === "client_credentials" && r?.access_token) token = r.access_token;
        return r;
      });
    }
  }
  console.log(JSON.stringify({
    schema: "axiam.sdk-bench/v1", sdk: "typescript",
    sdk_version: "unreleased", language_runtime: `node ${process.version}`,
    target: env("BENCH_TARGET", "axiam"), profile: env("BENCH_PROFILE", "p0-plaintext"),
    status, iterations: status === "ok" ? ITER : 0, concurrency: status === "ok" ? CONC : 0,
    ops, client_cpu_ms_total: 0, client_rss_mib_peak: 0, notes,
  }, null, 2));
}
main();
