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
// Run: node bench.mjs   (or: just sdk=typescript sdk-bench)

import { readFileSync } from "node:fs";

const env = (k, d) => process.env[k] ?? d;
const ITER = Number(env("SDK_BENCH_ITERATIONS", "2000"));
const WARMUP = Number(env("SDK_BENCH_WARMUP", "200"));
const CONC = Number(env("SDK_BENCH_CONCURRENCY", "16"));

// H8 fix: HARNESS-SPEC.md documents BENCH_CA_CERT (a PEM file path) as an
// input every SDK bench should honor under the TLS profiles (p2), but this
// bench never read it — every p2 run failed at the first HTTPS call against
// the profile's throwaway CA. AxiamClientOptions.customCa wants inline PEM
// *content*, not a path, so read the file here.
const caCertPath = env("BENCH_CA_CERT", "");
const customCa = caCertPath ? readFileSync(caCertPath, "utf8") : undefined;

// p3-mtls client identity (CONTRACT.md §6.1). HARNESS-SPEC.md documents
// BENCH_CLIENT_CERT/BENCH_CLIENT_KEY as file PATHS (the same pair k6 hands to
// `tlsAuth` and seed.sh to `curl --cert`); AxiamClientOptions.clientCert/
// clientKey want PEM *strings*, so read them here — same shape as customCa
// above. Both `undefined` when unset, which leaves the SDK's default
// bearer-cookie behavior untouched (§6.1 rule 5: mTLS is opt-in), so p0/p1/p2
// runs are unaffected. Node-only, which is exactly this bench's persona.
//
// Called lazily from buildOps() (inside main()'s try), NOT at module scope: a
// bad/unreadable path must surface as this harness' contractual
// status:"error" record with the reason in `notes` (HARNESS-SPEC.md), not as
// an uncaught throw that emits no record at all.
let clientIdentity;
function readClientIdentity() {
  if (clientIdentity) return clientIdentity;
  const certPath = env("BENCH_CLIENT_CERT", "");
  const keyPath = env("BENCH_CLIENT_KEY", "");
  if (!certPath !== !keyPath) {
    // The SDK validates this too (§6.1 rule 1), but failing here names the
    // env var the operator actually got wrong.
    throw new Error(
      `BENCH_CLIENT_CERT and BENCH_CLIENT_KEY must be set together `
      + `(cert=${JSON.stringify(certPath)}, key=${JSON.stringify(keyPath)}) `
      + `— mTLS needs both (CONTRACT.md §6.1 rule 1)`);
  }
  clientIdentity = {
    clientCert: certPath ? readFileSync(certPath, "utf8") : undefined,
    clientKey: keyPath ? readFileSync(keyPath, "utf8") : undefined,
  };
  return clientIdentity;
}

const cfg = {
  scheme: env("BENCH_SCHEME", "http"),
  host: env("BENCH_HOST", "localhost"),
  port: env("BENCH_PORT", "8090"),
  tenantSlug: env("BENCH_TENANT_SLUG", "default"),
  orgSlug: env("BENCH_ORG_SLUG", "bench-org"),
  username: env("BENCH_USERNAME", "benchuser"),
  password: env("BENCH_PASSWORD", "Bench@User123!"),
  action: env("BENCH_ACTION", "read"),
  resourceId: env("BENCH_RESOURCE_ID", "bench-resource"),
  customCa,
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

  // One construction site for the TLS wiring (custom CA + §6.1 client
  // identity) so it cannot drift between the shared client and the fresh one
  // the `login` op builds per iteration — under p3-mtls a client built
  // without the identity fails the handshake, which would have surfaced as
  // `login` errors only.
  const { clientCert, clientKey } = readClientIdentity();
  const newClient = () => createNodeClient({
    baseUrl,
    tenantSlug: cfg.tenantSlug,
    orgSlug: cfg.orgSlug,
    customCa: cfg.customCa,
    clientCert,
    clientKey,
  });

  const client = newClient();
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
      const fresh = newClient();
      await fresh.login(cfg.username, cfg.password);
    },
    refresh: () => client.refresh(),
    check_access: () => client.checkAccess({ action: cfg.action, resourceId: cfg.resourceId }),
    batch_check: () => client.batchCheck(checks),
  };
}

// HARNESS-SPEC.md requires `refresh` to be measured at concurrency 1: every
// SDK guards refresh() with a single-flight lock, but the underlying
// refresh_token is single-use/rotating (opaque, server-stored, rotated on
// every use per CLAUDE.md) — genuinely concurrent callers race on which
// wire call wins, and the loser reusing an already-rotated token can trip
// reuse-detection and revoke the whole session, cascading into 100% errors
// on every op measured after refresh in the same run (H8 fix — this used to
// pass CONC unconditionally for every op, including refresh).
async function timeOp(fn, conc = CONC) {
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
  await Promise.all(Array.from({ length: conc }, worker));
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
  for (const k of OP_KEYS) ops[k] = await timeOp(opsFns[k], k === "refresh" ? 1 : CONC);
  emit("ok", ops, ITER, CONC, "");
}

main();
