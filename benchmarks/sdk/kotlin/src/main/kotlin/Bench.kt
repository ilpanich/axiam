// AXIAM Kotlin SDK benchmark (wired to io.github.ilpanich:axiam-sdk-kotlin).
//
// Times io.axiam.sdk.AxiamClient's canonical CONTRACT.md §1 operations: login, refresh,
// checkAccess/can, batchCheck (emitted under the snake_case op keys login / refresh /
// check_access / batch_check). oauth2_token / introspect / userinfo are protocol-level
// ops with no SDK wrapper (see ../HARNESS-SPEC.md) and are not measured here.
//
// This mirrors the reference harnesses ../python/bench.py and ../typescript/bench.mjs
// (and the closest sibling, ../java/src/main/java/io/axiam/bench/Bench.java): warm-up +
// measured loop, the same linear-interpolation percentile math, and the stdout JSON
// contract (axiam.sdk-bench/v1), which must stay intact. No JSON library is used — the
// record is assembled by hand so the contract keys are exact.
//
// Concurrency: login/check_access/batch_check run at SDK_BENCH_CONCURRENCY concurrent
// coroutines (bounded by a Semaphore); refresh runs serially (concurrency 1) — the SDK
// guards refresh() with a single-flight lock, so concurrent callers would coalesce into
// ~1 wire call and mis-measure it (see HARNESS-SPEC.md).
//
// Run: ./gradlew -q --console=plain run   (or: just sdk=kotlin sdk-bench)
package io.axiam.bench

import io.axiam.sdk.AccessCheck
import io.axiam.sdk.AxiamClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

private val ITER = envInt("SDK_BENCH_ITERATIONS", 2000)
private val WARMUP = envInt("SDK_BENCH_WARMUP", 200)
private val CONC = envInt("SDK_BENCH_CONCURRENCY", 16)

private val SCHEME = env("BENCH_SCHEME", "http")
private val HOST = env("BENCH_HOST", "localhost")
private val PORT = env("BENCH_PORT", "8090")
private val BASE_URL = "$SCHEME://$HOST:$PORT"
private val TENANT_SLUG = env("BENCH_TENANT_SLUG", "default")
private val ORG_SLUG = env("BENCH_ORG_SLUG", "bench-org")
private val USERNAME = env("BENCH_USERNAME", "benchuser")
private val PASSWORD = env("BENCH_PASSWORD", "Bench@User123!")
private val ACTION = env("BENCH_ACTION", "read")
private val RESOURCE_ID = env("BENCH_RESOURCE_ID", "bench-resource")
private val TARGET = env("BENCH_TARGET", "axiam")
private val PROFILE = env("BENCH_PROFILE", "p0-plaintext")

private val OP_KEYS = listOf("login", "refresh", "check_access", "batch_check")

/** Latency stats for one op (matches the JSON contract's per-op object). */
private data class Stats(
    val p50: Double = 0.0,
    val p95: Double = 0.0,
    val p99: Double = 0.0,
    val throughputRps: Double = 0.0,
    val errors: Int = 0,
)

fun main() = runBlocking {
    // A logged-in client shared by refresh/check_access/batch_check; login builds its
    // own fresh client per iteration below.
    val client: AxiamClient
    val checks: List<AccessCheck>
    try {
        client = AxiamClient.builder(BASE_URL, TENANT_SLUG).orgSlug(ORG_SLUG).build()
        client.login(USERNAME, PASSWORD)
        // Batch of 3 checks, all against the SAME resource id (no suffix) — the server
        // rejects non-UUID resource_ids, so per-index suffixing would 400.
        checks = List(3) { AccessCheck(ACTION, RESOURCE_ID) }
        // Fail fast if the grant is missing — otherwise we'd silently benchmark the
        // deny fast-path instead of a real allow decision.
        val warm = client.checkAccess(ACTION, RESOURCE_ID)
        if (!warm.allowed) {
            throw IllegalStateException(
                "warm-up check_access denied for action=$ACTION resource_id=$RESOURCE_ID " +
                    "— seed the resource/role/grant (see runner/seed.sh)",
            )
        }
    } catch (exc: Exception) {
        // Server unreachable / seed missing / auth failed — nothing to time. Emit an
        // error record and exit 0 (per HARNESS-SPEC).
        println(render("error", zeroOps(), 0, 0, "server unreachable or setup failed: ${describe(exc)}"))
        return@runBlocking
    }

    suspend fun doLogin() {
        AxiamClient.builder(BASE_URL, TENANT_SLUG).orgSlug(ORG_SLUG).build().use { fresh ->
            fresh.login(USERNAME, PASSWORD)
        }
    }

    val results = linkedMapOf<String, Stats>()
    results["login"] = timeOp(CONC) { doLogin() }
    // refresh runs SERIALLY (concurrency 1) — see file header.
    results["refresh"] = timeOp(1) { client.refresh() }
    results["check_access"] = timeOp(CONC) { client.checkAccess(ACTION, RESOURCE_ID) }
    results["batch_check"] = timeOp(CONC) { client.batchCheck(checks) }

    try {
        client.close()
    } catch (_: Exception) {
        // best-effort cleanup
    }

    println(render("ok", results, ITER, CONC, ""))
}

private suspend fun timeOp(concurrency: Int, op: suspend () -> Unit): Stats {
    val errors = AtomicInteger(0)

    // warm-up (uncounted latencies; failures still counted, mirroring the
    // python/typescript/java reference harnesses)
    for (i in 0 until WARMUP) {
        try {
            op()
        } catch (e: Exception) {
            errors.incrementAndGet()
        }
    }

    val lat = ConcurrentLinkedQueue<Double>()
    val start = System.nanoTime()
    val sem = Semaphore(maxOf(1, concurrency))
    coroutineScope {
        (0 until ITER).map {
            async(Dispatchers.IO) {
                sem.withPermit {
                    val t0 = System.nanoTime()
                    try {
                        op()
                        lat.add((System.nanoTime() - t0) / 1_000_000.0)
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }.awaitAll()
    }
    val secs = (System.nanoTime() - start) / 1_000_000_000.0
    val samples = lat.toList()

    return Stats(
        p50 = pct(samples, 50.0),
        p95 = pct(samples, 95.0),
        p99 = pct(samples, 99.0),
        throughputRps = if (secs > 0) samples.size / secs else 0.0,
        errors = errors.get(),
    )
}

/** Linear-interpolation percentile — identical method to the reference harnesses. */
private fun pct(arr: List<Double>, p: Double): Double {
    if (arr.isEmpty()) return 0.0
    val s = arr.sorted()
    val k = (s.size - 1) * (p / 100.0)
    val lo = k.toInt()
    val hi = minOf(lo + 1, s.size - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)
}

// ------------------------------------------------------------------
// JSON contract (axiam.sdk-bench/v1) — assembled by hand, no JSON lib.
// ------------------------------------------------------------------

private fun zeroOps(): Map<String, Stats> = OP_KEYS.associateWith { Stats() }

private fun render(status: String, ops: Map<String, Stats>, iterations: Int, concurrency: Int, notes: String): String {
    val sb = StringBuilder()
    sb.append("{\n")
    sb.append("  \"schema\": \"axiam.sdk-bench/v1\",\n")
    sb.append("  \"sdk\": \"kotlin\",\n")
    sb.append("  \"sdk_version\": \"1.0.0-alpha13\",\n")
    sb.append("  \"language_runtime\": ")
        .append(jsonString("kotlin ${KotlinVersion.CURRENT} (jvm ${System.getProperty("java.version")})"))
        .append(",\n")
    sb.append("  \"target\": ").append(jsonString(TARGET)).append(",\n")
    sb.append("  \"profile\": ").append(jsonString(PROFILE)).append(",\n")
    sb.append("  \"status\": ").append(jsonString(status)).append(",\n")
    sb.append("  \"iterations\": ").append(iterations).append(",\n")
    sb.append("  \"concurrency\": ").append(concurrency).append(",\n")
    sb.append("  \"ops\": {\n")
    OP_KEYS.forEachIndexed { i, key ->
        sb.append("    ").append(jsonString(key)).append(": ").append(opJson(ops[key] ?: Stats()))
        sb.append(if (i < OP_KEYS.size - 1) ",\n" else "\n")
    }
    sb.append("  },\n")
    sb.append("  \"client_cpu_ms_total\": 0,\n")
    sb.append("  \"client_rss_mib_peak\": 0,\n")
    sb.append("  \"notes\": ").append(jsonString(notes)).append("\n")
    sb.append("}")
    return sb.toString()
}

private fun opJson(s: Stats): String =
    "{ \"p50_ms\": ${num(s.p50)}, \"p95_ms\": ${num(s.p95)}, \"p99_ms\": ${num(s.p99)}, " +
        "\"throughput_rps\": ${num(s.throughputRps)}, \"errors\": ${s.errors} }"

private fun num(d: Double): String = if (d.isNaN() || d.isInfinite()) "0" else d.toString()

private fun jsonString(s: String): String {
    val sb = StringBuilder("\"")
    for (c in s) {
        when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
    }
    sb.append("\"")
    return sb.toString()
}

// ------------------------------------------------------------------
// Env helpers
// ------------------------------------------------------------------

private fun env(key: String, def: String): String {
    val v = System.getenv(key)
    return if (v.isNullOrEmpty()) def else v
}

private fun envInt(key: String, def: Int): Int {
    val v = System.getenv(key)
    if (v.isNullOrEmpty()) return def
    return v.trim().toIntOrNull() ?: def
}

private fun describe(t: Throwable): String {
    val msg = t.message
    return t::class.simpleName + (if (msg != null) ": $msg" else "")
}
