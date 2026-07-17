// AXIAM TypeScript SDK benchmark (reference harness, wired to axiam-sdk).
//
// Times the Node persona's AxiamClient (axiam-sdk/node — createNodeClient)
// canonical CONTRACT.md §1 operations: login, refresh, checkAccess,
// batchCheck. oauth2_token/introspect/userinfo are protocol-level ops with
// no SDK wrapper (see ../HARNESS-SPEC.md) and are not measured here. The
// browser SharedSession can't persist httpOnly cookies under Node, so this
// harness uses the Node client (tough-cookie jar), not `axiam-sdk`/`/rest`.
// The stdout JSON contract (axiam.sdk-bench/v1) must stay intact.
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
  tenantSlug: env("BENCH_TENANT_SLUG", "default"),
  username: env("BENCH_USERNAME", "benchuser"),
  password: env("BENCH_PASSWORD", "Bench@User123!"),
  action: env("BENCH_ACTION", "read"),
  resourceId: env("BENCH_RESOURCE_ID", "bench-resource"),
};

const OP_KEYS = ["login", "refresh", "check_access", "batch_check"];

function pct(arr, p) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const k = (s.length - 1) * (p / 100);
  const lo = Math.floor(k), hi = Math.min(lo + 1, s.length - 1);
  return s[lo] + (s[hi] - s[lo]) * (k - lo);
}

function zeroOps() {
  const ops = {};
  for (const k of OP_KEYS) ops[k] = { p50_ms: 0, p95_ms: 0, p99_ms: 0, throughput_rps: 0, errors: 0 };
  return ops;
}

function emit(status, ops, iterations, concurrency, notes) {
  console.log(JSON.stringify({
    schema: "axiam.sdk-bench/v1", sdk: "typescript",
    sdk_version: "1.0.0-alpha2", language_runtime: `node ${process.version}`,
    target: env("BENCH_TARGET", "axiam"), profile: env("BENCH_PROFILE", "p0-plaintext"),
    status, iterations, concurrency,
    ops, client_cpu_ms_total: 0, client_rss_mib_peak: 0, notes,
  }, null, 2));
}

/**
 * Build one logged-in Node AxiamClient and return {opKey: async fn}.
 *
 * `login` builds and discards its own short-lived client per call (a fresh,
 * unauthenticated session per iteration mirrors what the op measures);
 * `refresh`/`checkAccess`/`batchCheck` share one already-authenticated
 * client — refresh is routed through the SDK's single-flight guard, so
 * concurrent callers are safe.
 */
async function buildOps() {
  const { createNodeClient } = await import("axiam-sdk/node");
  const baseUrl = `${cfg.scheme}://${cfg.host}:${cfg.port}`;

  const client = createNodeClient({ baseUrl, tenantSlug: cfg.tenantSlug });
  await client.login(cfg.username, cfg.password);

  // Every check reuses the one seeded resource UUID: the server rejects
  // non-UUID resource_ids, so the old `${resource}-${i}` suffixing would 400.
  const checks = [0, 1, 2].map(() => ({
    action: cfg.action,
    resourceId: cfg.resourceId,
  }));

  // Fail fast if the grant is missing — otherwise we'd silently benchmark the
  // deny fast-path instead of a real allow decision.
  const warm = await client.checkAccess({ action: cfg.action, resourceId: cfg.resourceId });
  if (!warm || !warm.allowed) {
    throw new Error(
      `warm-up checkAccess denied for action=${cfg.action} resourceId=${cfg.resourceId}`
      + ` — seed the resource/role/grant (see runner/seed.sh)`);
  }

  return {
    login: async () => {
      const fresh = createNodeClient({ baseUrl, tenantSlug: cfg.tenantSlug });
      await fresh.login(cfg.username, cfg.password);
    },
    refresh: () => client.refresh(),
    check_access: () => client.checkAccess({ action: cfg.action, resourceId: cfg.resourceId }),
    batch_check: () => client.batchCheck(checks),
  };
}

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
  let opsFns;
  try {
    opsFns = await buildOps();
  } catch (err) {
    // Covers both "axiam-sdk not installed" (ERR_MODULE_NOT_FOUND) and
    // "server unreachable" (ECONNREFUSED/timeout) — either way there is
    // nothing to time, so report gracefully instead of crashing.
    const notes = err && err.code === "ERR_MODULE_NOT_FOUND"
      ? `axiam-sdk not installed — npm i axiam-sdk (${err.message}).`
      : `server unreachable or setup failed: ${err && err.message ? err.message : err}`;
    const status = err && err.code === "ERR_MODULE_NOT_FOUND" ? "pending" : "error";
    emit(status, zeroOps(), 0, 0, notes);
    return;
  }

  const ops = {};
  for (const k of OP_KEYS) ops[k] = await timeOp(opsFns[k]);
  emit("ok", ops, ITER, CONC, "");
}

main();
