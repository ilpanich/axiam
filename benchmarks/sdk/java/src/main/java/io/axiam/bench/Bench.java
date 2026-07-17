// AXIAM Java SDK benchmark (wired to io.github.ilpanich:axiam-sdk).
//
// Times io.axiam.sdk.AxiamClient's canonical CONTRACT.md §1 operations:
// login, refresh, checkAccess, batchCheck (emitted under the snake_case op
// keys login / refresh / check_access / batch_check). oauth2_token /
// introspect / userinfo are protocol-level ops with no SDK wrapper (see
// ../HARNESS-SPEC.md) and are not measured here.
//
// This mirrors the reference harnesses ../python/bench.py and
// ../typescript/bench.mjs: warm-up + measured loop, the same percentile math,
// and the stdout JSON contract (axiam.sdk-bench/v1), which must stay intact.
// No JSON library is used — the record is assembled by hand so the contract
// keys are exact.
//
// Run: mvn -q exec:java   (or: just sdk-bench sdk=java)
package io.axiam.bench;

import io.axiam.sdk.AxiamClient;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public final class Bench {

    private static final int ITER = envInt("SDK_BENCH_ITERATIONS", 2000);
    private static final int WARMUP = envInt("SDK_BENCH_WARMUP", 200);
    private static final int CONC = envInt("SDK_BENCH_CONCURRENCY", 16);

    private static final String SCHEME = env("BENCH_SCHEME", "http");
    private static final String HOST = env("BENCH_HOST", "localhost");
    private static final String PORT = env("BENCH_PORT", "8090");
    private static final String BASE_URL = SCHEME + "://" + HOST + ":" + PORT;
    private static final String TENANT_SLUG = env("BENCH_TENANT_SLUG", "default");
    private static final String USERNAME = env("BENCH_USERNAME", "benchuser");
    private static final String PASSWORD = env("BENCH_PASSWORD", "Bench@User123!");
    private static final String ACTION = env("BENCH_ACTION", "read");
    private static final String RESOURCE_ID = env("BENCH_RESOURCE_ID", "bench-resource");
    private static final String TARGET = env("BENCH_TARGET", "axiam");
    private static final String PROFILE = env("BENCH_PROFILE", "p0-plaintext");

    private static final String[] OP_KEYS = {"login", "refresh", "check_access", "batch_check"};

    /** An SDK operation timed by one iteration; may throw (counted as an error). */
    @FunctionalInterface
    private interface Op {
        void run() throws Exception;
    }

    /** Latency stats for one op (matches the JSON contract's per-op object). */
    private static final class Stats {
        double p50;
        double p95;
        double p99;
        double throughputRps;
        int errors;
    }

    public static void main(String[] args) {
        // A logged-in client shared by refresh/check_access/batch_check; login
        // builds its own fresh client per iteration below.
        AxiamClient client;
        List<AxiamClient.AccessCheck> checks;
        try {
            client = AxiamClient.builder(BASE_URL, TENANT_SLUG).build();
            client.login(USERNAME, PASSWORD);
            // Batch of 3 checks, all against the SAME resource id (no suffix).
            checks = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                checks.add(new AxiamClient.AccessCheck(ACTION, RESOURCE_ID));
            }
        } catch (Exception exc) {
            // Server unreachable / seed missing / auth failed — nothing to
            // time. Emit an error record and exit 0 (per HARNESS-SPEC).
            System.out.println(render("error", zeroOps(), 0, 0,
                    "server unreachable or setup failed: " + describe(exc)));
            return;
        }

        final AxiamClient sharedClient = client;
        final List<AxiamClient.AccessCheck> sharedChecks = checks;

        Op login = () -> {
            try (AxiamClient fresh = AxiamClient.builder(BASE_URL, TENANT_SLUG).build()) {
                fresh.login(USERNAME, PASSWORD);
            }
        };
        Op refresh = sharedClient::refresh;
        Op checkAccess = () -> sharedClient.checkAccess(ACTION, RESOURCE_ID);
        Op batchCheck = () -> sharedClient.batchCheck(sharedChecks);

        List<Stats> results = new ArrayList<>();
        // refresh runs SERIALLY (concurrency 1) — the SDK's refresh() is
        // single-flight-guarded, so parallel callers would collapse into one
        // in-flight call and mis-measure it. The other three run at CONC.
        results.add(timeOp(login, CONC));
        results.add(timeOp(refresh, 1));
        results.add(timeOp(checkAccess, CONC));
        results.add(timeOp(batchCheck, CONC));

        try {
            sharedClient.close();
        } catch (Exception ignored) {
            // best-effort cleanup
        }

        System.out.println(render("ok", results, ITER, CONC, ""));
    }

    private static Stats timeOp(Op fn, int concurrency) {
        AtomicInteger errors = new AtomicInteger(0);

        // warm-up (uncounted latencies; failures still counted, mirroring the
        // python/typescript reference harnesses)
        for (int i = 0; i < WARMUP; i++) {
            try {
                fn.run();
            } catch (Exception e) {
                errors.incrementAndGet();
            }
        }

        ConcurrentLinkedQueue<Double> lat = new ConcurrentLinkedQueue<>();
        long start = System.nanoTime();

        int workers = Math.max(1, concurrency);
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < ITER; i++) {
            futures.add(pool.submit(() -> {
                long t0 = System.nanoTime();
                try {
                    fn.run();
                    lat.add((System.nanoTime() - t0) / 1_000_000.0);
                } catch (Exception e) {
                    errors.incrementAndGet();
                }
            }));
        }
        for (Future<?> f : futures) {
            try {
                f.get();
            } catch (Exception e) {
                // A failure inside the task is already counted via `errors`;
                // get() itself failing is not an SDK op error.
            }
        }
        pool.shutdown();

        double secs = (System.nanoTime() - start) / 1_000_000_000.0;
        List<Double> samples = new ArrayList<>(lat);

        Stats s = new Stats();
        s.p50 = pct(samples, 50);
        s.p95 = pct(samples, 95);
        s.p99 = pct(samples, 99);
        s.throughputRps = secs > 0 ? samples.size() / secs : 0.0;
        s.errors = errors.get();
        return s;
    }

    /** Linear-interpolation percentile — identical method to the reference harnesses. */
    private static double pct(List<Double> arr, double p) {
        if (arr.isEmpty()) {
            return 0.0;
        }
        List<Double> s = new ArrayList<>(arr);
        s.sort(null);
        double k = (s.size() - 1) * (p / 100.0);
        int lo = (int) Math.floor(k);
        int hi = Math.min(lo + 1, s.size() - 1);
        return s.get(lo) + (s.get(hi) - s.get(lo)) * (k - lo);
    }

    // ------------------------------------------------------------------
    // JSON contract (axiam.sdk-bench/v1) — assembled by hand, no JSON lib.
    // ------------------------------------------------------------------

    private static List<Stats> zeroOps() {
        List<Stats> zeros = new ArrayList<>();
        for (int i = 0; i < OP_KEYS.length; i++) {
            zeros.add(new Stats());
        }
        return zeros;
    }

    private static String render(String status, List<Stats> ops, int iterations, int concurrency, String notes) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"schema\": \"axiam.sdk-bench/v1\",\n");
        sb.append("  \"sdk\": \"java\",\n");
        sb.append("  \"sdk_version\": \"1.0.0-alpha2\",\n");
        sb.append("  \"language_runtime\": ").append(jsonString("java " + System.getProperty("java.version"))).append(",\n");
        sb.append("  \"target\": ").append(jsonString(TARGET)).append(",\n");
        sb.append("  \"profile\": ").append(jsonString(PROFILE)).append(",\n");
        sb.append("  \"status\": ").append(jsonString(status)).append(",\n");
        sb.append("  \"iterations\": ").append(iterations).append(",\n");
        sb.append("  \"concurrency\": ").append(concurrency).append(",\n");
        sb.append("  \"ops\": {\n");
        for (int i = 0; i < OP_KEYS.length; i++) {
            sb.append("    ").append(jsonString(OP_KEYS[i])).append(": ").append(opJson(ops.get(i)));
            sb.append(i < OP_KEYS.length - 1 ? ",\n" : "\n");
        }
        sb.append("  },\n");
        sb.append("  \"client_cpu_ms_total\": 0,\n");
        sb.append("  \"client_rss_mib_peak\": 0,\n");
        sb.append("  \"notes\": ").append(jsonString(notes)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    private static String opJson(Stats s) {
        return "{ \"p50_ms\": " + num(s.p50)
                + ", \"p95_ms\": " + num(s.p95)
                + ", \"p99_ms\": " + num(s.p99)
                + ", \"throughput_rps\": " + num(s.throughputRps)
                + ", \"errors\": " + s.errors + " }";
    }

    private static String num(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            return "0";
        }
        return Double.toString(d);
    }

    private static String jsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append("\"").toString();
    }

    // ------------------------------------------------------------------
    // Env helpers
    // ------------------------------------------------------------------

    private static String env(String key, String def) {
        String v = System.getenv(key);
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static int envInt(String key, int def) {
        String v = System.getenv(key);
        if (v == null || v.isEmpty()) {
            return def;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static String describe(Throwable t) {
        String msg = t.getMessage();
        return t.getClass().getSimpleName() + (msg != null ? ": " + msg : "");
    }

    private Bench() {
    }
}
