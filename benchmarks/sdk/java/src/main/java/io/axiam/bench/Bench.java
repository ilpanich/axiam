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
// Run: mvn -q exec:java   (or: just sdk=java sdk-bench)
package io.axiam.bench;

import io.axiam.sdk.AxiamClient;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
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
    private static final String ORG_SLUG = env("BENCH_ORG_SLUG", "bench-org");
    private static final String USERNAME = env("BENCH_USERNAME", "benchuser");
    private static final String PASSWORD = env("BENCH_PASSWORD", "Bench@User123!");
    private static final String ACTION = env("BENCH_ACTION", "read");
    private static final String RESOURCE_ID = env("BENCH_RESOURCE_ID", "bench-resource");
    private static final String TARGET = env("BENCH_TARGET", "axiam");
    private static final String PROFILE = env("BENCH_PROFILE", "p0-plaintext");
    // H8 fix: HARNESS-SPEC.md documents BENCH_CA_CERT (a PEM file path) as
    // an input every SDK bench should honor under the TLS profiles (p2),
    // but this bench never read it — every p2 run failed at the first
    // HTTPS call against the profile's throwaway CA. Empty under
    // p0/plaintext (BENCH_CA_CERT unset).
    private static final String CA_CERT_PATH = env("BENCH_CA_CERT", "");
    // p3-mtls client identity (CONTRACT.md §6.1) — the same cert/key pair k6
    // hands to `tlsAuth` and seed.sh to `curl --cert`. Both empty on p0/p1/p2,
    // where no builder call is made and the SDK's default bearer-cookie
    // behavior is untouched (§6.1 rule 5: mTLS is opt-in).
    private static final String CLIENT_CERT_PATH = env("BENCH_CLIENT_CERT", "");
    private static final String CLIENT_KEY_PATH = env("BENCH_CLIENT_KEY", "");

    /** {@link AxiamClient.Builder} pre-seeded with org context and — under a
     * TLS profile — the trusted custom CA plus, under p3-mtls, the §6.1
     * client-certificate identity. Reads BENCH_CA_CERT/BENCH_CLIENT_CERT/
     * BENCH_CLIENT_KEY lazily (not at class-init time) so an unreadable path
     * surfaces through main()'s existing try/catch as a normal
     * `status:"error"` record instead of an uncaught
     * ExceptionInInitializerError crashing the JVM before any
     * HARNESS-SPEC-conformant output is printed.
     *
     * <p>Every client this bench builds — the long-lived shared one AND the
     * fresh one the {@code login} op builds per iteration — comes from here,
     * so the TLS wiring cannot drift between them; a login client missing the
     * identity would fail the p3 handshake while the other three ops
     * succeeded. */
    private static AxiamClient.Builder newClientBuilder() throws IOException {
        AxiamClient.Builder b = AxiamClient.builder(BASE_URL, TENANT_SLUG).orgSlug(ORG_SLUG);
        if (!CA_CERT_PATH.isEmpty()) {
            b = b.customCa(Files.readAllBytes(Path.of(CA_CERT_PATH)));
        }
        if (CLIENT_CERT_PATH.isEmpty() != CLIENT_KEY_PATH.isEmpty()) {
            // The SDK validates this too (§6.1 rule 1), but failing here names
            // the env var the operator actually got wrong.
            throw new IOException(
                "BENCH_CLIENT_CERT=\"" + CLIENT_CERT_PATH + "\" and BENCH_CLIENT_KEY=\""
                + CLIENT_KEY_PATH + "\" must be set together — mTLS needs both"
                + " (CONTRACT.md §6.1 rule 1)");
        }
        if (!CLIENT_CERT_PATH.isEmpty()) {
            b = b.clientCertificate(
                Files.readAllBytes(Path.of(CLIENT_CERT_PATH)),
                Files.readAllBytes(Path.of(CLIENT_KEY_PATH)));
        }
        return b;
    }

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

    // I9 (improvement-after-run4-benchmark.md §C): a floor below which a
    // measured `refresh` latency is not plausibly a real HTTP round trip. The
    // C# bench recorded p50 1.2 microseconds ("752 k rps") because its SDK's
    // RefreshGuard cached a completed token result on a shared client for up
    // to ~15 minutes (wall-clock freshness, no observed-token check), so only
    // the FIRST refresh in a ~2200-call run ever touched the wire. This SDK's
    // io.axiam.sdk.internal.RefreshGuard keys on the caller's currently
    // observed access token instead, which this bench's client::refresh call
    // updates after every real refresh — so a same-client loop keeps hitting
    // the wire — but this floor is kept as a language-agnostic regression
    // guard against that class of bug reappearing here too (a cache hit
    // completes in low single-digit microseconds; every genuine wire call
    // recorded across this harness' 11 languages averages ~17 ms, so 0.2 ms
    // leaves a wide margin).
    private static final double MIN_PLAUSIBLE_REFRESH_MS = 0.2;

    /** I9 shared-driver-style regression guard: fail loudly (non-zero exit)
     * instead of silently publishing a fake number if {@code refresh} looks
     * like it never left the process. */
    private static void assertRefreshHitTheWire(Stats refresh, int iterations) {
        boolean hadSamples = refresh.errors < iterations;
        if (hadSamples && refresh.p50 < MIN_PLAUSIBLE_REFRESH_MS) {
            System.err.printf(
                "[java] I9 guard: refresh p50=%.4fms is below the %.1fms plausible-wire-call "
                    + "floor despite successful samples — this looks like a cached no-op "
                    + "(CONTRACT.md §9 guard reuse), not a real HTTP round trip. Failing the "
                    + "bench run instead of publishing a fake number "
                    + "(see improvement-after-run4-benchmark.md I9).%n",
                refresh.p50, MIN_PLAUSIBLE_REFRESH_MS);
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        // A logged-in client shared by refresh/check_access/batch_check; login
        // builds its own fresh client per iteration below.
        AxiamClient client;
        List<AxiamClient.AccessCheck> checks;
        try {
            client = newClientBuilder().build();
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
            try (AxiamClient fresh = newClientBuilder().build()) {
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
        assertRefreshHitTheWire(results.get(1), ITER); // OP_KEYS[1] == "refresh"
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

    // I13 (improvement-after-run4-benchmark.md §C): `client_cpu_ms_total`/
    // `client_rss_mib_peak` recorded 0.0 for every SDK bench — the sampler
    // was never wired. `com.sun.management.OperatingSystemMXBean` (a
    // de-facto-standard OpenJDK/HotSpot JMX extension, present in every JDK
    // this bench realistically runs under) gives the JVM's cumulative CPU
    // time (getProcessCpuTime(), ns) directly — no polling thread needed.
    // The JVM exposes no standard peak-RSS API, so peak resident set size is
    // read from /proc/self/status's VmHWM (Linux-only, matching this
    // harness' Docker/K8s deployment target per CLAUDE.md); returns 0 for
    // either metric if the corresponding source is unavailable rather than
    // throwing.
    private static double[] clientResourceUsage() {
        double cpuMsTotal = 0.0;
        try {
            Object osBean = ManagementFactory.getOperatingSystemMXBean();
            if (osBean instanceof com.sun.management.OperatingSystemMXBean sunBean) {
                long cpuNs = sunBean.getProcessCpuTime(); // -1 if unsupported
                if (cpuNs >= 0) {
                    cpuMsTotal = cpuNs / 1_000_000.0;
                }
            }
        } catch (Throwable ignored) {
            // Best-effort telemetry only — never fail the bench over it.
        }
        double rssMiBPeak = 0.0;
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("VmHWM:")) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length >= 2) {
                        rssMiBPeak = Double.parseDouble(parts[1]) / 1024.0; // kB -> MiB
                    }
                    break;
                }
            }
        } catch (Exception ignored) {
            // /proc unavailable (non-Linux) — leave at 0.
        }
        return new double[] {cpuMsTotal, rssMiBPeak};
    }

    private static String render(String status, List<Stats> ops, int iterations, int concurrency, String notes) {
        double[] resourceUsage = clientResourceUsage();
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
        sb.append("  \"client_cpu_ms_total\": ").append(num(resourceUsage[0])).append(",\n");
        sb.append("  \"client_rss_mib_peak\": ").append(num(resourceUsage[1])).append(",\n");
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
