// AXIAM Swift SDK benchmark (wired to AxiamSDK, the sibling axiam-swift-sdk
// checkout).
//
// Times AxiamClient's canonical CONTRACT.md §1 operations — login, refresh,
// checkAccess, batchCheck — against a running, seeded AXIAM target.
// oauth2_token/introspect/userinfo are protocol-level ops with no SDK wrapper
// (see ../HARNESS-SPEC.md) and are not measured here. Mirrors the timing
// loop, percentile math, and JSON contract of ../python/bench.py and
// ../typescript/bench.mjs (the reference harnesses). The stdout JSON
// contract (axiam.sdk-bench/v1) must stay intact.
//
// Run: swift run -c release axiam-bench   (or: cd benchmarks && just sdk=swift sdk-bench)

import Foundation
import AxiamSDK

// MARK: - Env (see ../HARNESS-SPEC.md "Inputs (environment)")

func env(_ key: String, _ fallback: String) -> String {
    guard let value = ProcessInfo.processInfo.environment[key], !value.isEmpty else { return fallback }
    return value
}

func envOptional(_ key: String) -> String? {
    guard let value = ProcessInfo.processInfo.environment[key], !value.isEmpty else { return nil }
    return value
}

func envInt(_ key: String, _ fallback: Int) -> Int {
    guard let value = ProcessInfo.processInfo.environment[key], let n = Int(value) else { return fallback }
    return n
}

let ITER = envInt("SDK_BENCH_ITERATIONS", 2000)
let WARMUP = envInt("SDK_BENCH_WARMUP", 200)
let CONC = envInt("SDK_BENCH_CONCURRENCY", 16)

struct Config: Sendable {
    let baseURL: String
    let tenantSlug: String
    let orgSlug: String
    let username: String
    let password: String
    let action: String
    let resourceID: String
    // p3-mtls / custom-CA inputs (file paths — see benchmarks/docs/security-profiles.md and
    // the p1/p2/p3 profile envs). Swift is one of the SDKs that grew a §6.1 client-cert mTLS
    // option (CONTRACT.md §6.1, README "TLS & mutual TLS"), unlike the languages
    // HARNESS-SPEC.md's "Security-profile limitation" note was written against — see swift's
    // TODO.md for the wiring instruction that motivated adding this.
    let caCertPath: String?
    let clientCertPath: String?
    let clientKeyPath: String?
}

let cfg = Config(
    baseURL: "\(env("BENCH_SCHEME", "http"))://\(env("BENCH_HOST", "localhost")):\(env("BENCH_PORT", "8090"))",
    tenantSlug: env("BENCH_TENANT_SLUG", "default"),
    orgSlug: env("BENCH_ORG_SLUG", "bench-org"),
    username: env("BENCH_USERNAME", "benchuser"),
    password: env("BENCH_PASSWORD", "Bench@User123!"),
    action: env("BENCH_ACTION", "read"),
    resourceID: env("BENCH_RESOURCE_ID", "bench-resource"),
    caCertPath: envOptional("BENCH_CA_CERT"),
    clientCertPath: envOptional("BENCH_CLIENT_CERT"),
    clientKeyPath: envOptional("BENCH_CLIENT_KEY")
)

let OP_KEYS = ["login", "refresh", "check_access", "batch_check"]

// MARK: - Percentile (linear interpolation between nearest ranks — mirrors
// python/bench.py's `pct()` and typescript/bench.mjs's `pct()` exactly).

func pct(_ values: [Double], _ p: Double) -> Double {
    if values.isEmpty { return 0 }
    let sorted = values.sorted()
    let k = Double(sorted.count - 1) * (p / 100.0)
    let lo = Int(k)
    let hi = min(lo + 1, sorted.count - 1)
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (k - Double(lo))
}

// MARK: - JSON contract (axiam.sdk-bench/v1)

struct OpResult: Codable {
    let p50_ms: Double
    let p95_ms: Double
    let p99_ms: Double
    let throughput_rps: Double
    let errors: Int
}

func zeroOpResult() -> OpResult { OpResult(p50_ms: 0, p95_ms: 0, p99_ms: 0, throughput_rps: 0, errors: 0) }

func zeroOps() -> [String: OpResult] {
    Dictionary(uniqueKeysWithValues: OP_KEYS.map { ($0, zeroOpResult()) })
}

struct BenchOutput: Codable {
    let schema: String
    let sdk: String
    let sdk_version: String
    let language_runtime: String
    let target: String
    let profile: String
    let status: String
    let iterations: Int
    let concurrency: Int
    let ops: [String: OpResult]
    let client_cpu_ms_total: Int
    let client_rss_mib_peak: Int
    let notes: String
}

/// Best-effort `swift --version` first line, mirroring "python 3.x" / "node x.y.z" in the
/// other reference harnesses. Falls back to a generic string if the toolchain can't be
/// introspected this way (e.g. a restricted PATH in the runtime environment).
func swiftRuntimeVersion() -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["swift", "--version"]
    let stdout = Pipe()
    process.standardOutput = stdout
    process.standardError = Pipe()
    do {
        try process.run()
        process.waitUntilExit()
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        if let text = String(data: data, encoding: .utf8),
           let line = text.split(separator: "\n").first(where: { $0.lowercased().contains("swift version") }) {
            return line.trimmingCharacters(in: .whitespaces)
        }
    } catch {
        // Fall through to the generic default below.
    }
    return "swift unknown"
}

func emit(status: String, ops: [String: OpResult], iterations: Int, concurrency: Int, notes: String) {
    let output = BenchOutput(
        schema: "axiam.sdk-bench/v1",
        sdk: "swift",
        // Kept in sync with axiam-swift-sdk/CHANGELOG.md's latest entry.
        sdk_version: "1.0.0-alpha12",
        language_runtime: swiftRuntimeVersion(),
        target: env("BENCH_TARGET", "axiam"),
        profile: env("BENCH_PROFILE", "p0-plaintext"),
        status: status,
        iterations: iterations,
        concurrency: concurrency,
        ops: ops,
        client_cpu_ms_total: 0,
        client_rss_mib_peak: 0,
        notes: notes
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted]
    if let data = try? encoder.encode(output), let json = String(data: data, encoding: .utf8) {
        print(json)
    } else {
        // Should never happen for this fixed shape; fall back to a minimal valid record
        // rather than crashing (graceful degradation applies to encoding too).
        print("{\"schema\":\"axiam.sdk-bench/v1\",\"sdk\":\"swift\",\"status\":\"error\",\"notes\":\"failed to encode bench output\"}")
    }
}

// MARK: - Building the four ops

struct BenchSetupError: Error, CustomStringConvertible {
    let message: String
    init(_ message: String) { self.message = message }
    var description: String { message }
}

typealias OpFn = @Sendable () async -> Bool

func loadPEM(_ path: String?) throws -> Data? {
    guard let path else { return nil }
    return try Data(contentsOf: URL(fileURLWithPath: path))
}

func loadClientCertificate(certPath: String?, keyPath: String?) throws -> ClientCertificate? {
    guard let certPath, let keyPath else { return nil }
    let certificate = try Data(contentsOf: URL(fileURLWithPath: certPath))
    let privateKey = try Data(contentsOf: URL(fileURLWithPath: keyPath))
    return .pem(certificate: certificate, privateKey: privateKey)
}

/// Build one logged-in `AxiamClient` and return `{opKey: zero-arg async fn}`.
///
/// `login` builds and discards its own short-lived client per call (a fresh, unauthenticated
/// session per iteration mirrors what the op measures); `refresh`/`checkAccess`/`batchCheck`
/// share one already-authenticated client — refresh is routed through the SDK's single-flight
/// `actor` guard (§9 of CONTRACT.md), so concurrent callers are safe.
func buildOps() async throws -> [String: OpFn] {
    guard let baseURL = URL(string: cfg.baseURL) else {
        throw BenchSetupError("invalid BENCH_SCHEME/BENCH_HOST/BENCH_PORT combination: \(cfg.baseURL)")
    }
    let caData = try loadPEM(cfg.caCertPath)
    let clientCert = try loadClientCertificate(certPath: cfg.clientCertPath, keyPath: cfg.clientKeyPath)

    func makeConfig() throws -> AxiamConfig {
        try AxiamConfig(
            baseURL: baseURL,
            tenantSlug: cfg.tenantSlug,
            orgSlug: cfg.orgSlug,
            customCA: caData,
            clientCertificate: clientCert
        )
    }

    let client = try AxiamClient(config: makeConfig())
    _ = try await client.login(email: cfg.username, password: cfg.password)

    // Every check reuses the one seeded resource UUID: the server rejects non-UUID
    // resource_ids, so per-index-suffixed ids would 400.
    let checks = (0..<3).map { _ in AccessCheck(action: cfg.action, resource: cfg.resourceID) }

    // Fail fast if the grant is missing — otherwise we'd silently benchmark the deny
    // fast-path instead of a real allow decision.
    let warm = try await client.checkAccess(cfg.action, resource: cfg.resourceID)
    guard warm.allowed else {
        throw BenchSetupError(
            "warm-up check_access denied for action=\(cfg.action) resource_id=\(cfg.resourceID)"
                + " — seed the resource/role/grant (see runner/seed.sh)")
    }

    let doLogin: OpFn = {
        guard let freshConfig = try? makeConfig(), let fresh = try? AxiamClient(config: freshConfig) else {
            return false
        }
        do {
            _ = try await fresh.login(email: cfg.username, password: cfg.password)
            try? await fresh.shutdown()
            return true
        } catch {
            try? await fresh.shutdown()
            return false
        }
    }

    let doRefresh: OpFn = {
        do {
            try await client.refresh()
            return true
        } catch {
            return false
        }
    }

    let doCheckAccess: OpFn = {
        do {
            _ = try await client.checkAccess(cfg.action, resource: cfg.resourceID)
            return true
        } catch {
            return false
        }
    }

    let doBatchCheck: OpFn = {
        do {
            _ = try await client.batchCheck(checks)
            return true
        } catch {
            return false
        }
    }

    return [
        "login": doLogin,
        "refresh": doRefresh,
        "check_access": doCheckAccess,
        "batch_check": doBatchCheck,
    ]
}

// MARK: - Timing loop

actor IndexCounter {
    private var current = 0
    private let limit: Int
    init(limit: Int) { self.limit = limit }
    /// Claims the next index; returns false once `limit` calls have been claimed.
    func claim() -> Bool {
        guard current < limit else { return false }
        current += 1
        return true
    }
}

actor LatencyCollector {
    private(set) var latencies: [Double] = []
    private(set) var errorCount = 0
    func record(_ ms: Double) { latencies.append(ms) }
    func recordError() { errorCount += 1 }
}

func durationMilliseconds(_ duration: Duration) -> Double {
    let c = duration.components
    return Double(c.seconds) * 1000.0 + Double(c.attoseconds) * 1e-15
}

func durationSeconds(_ duration: Duration) -> Double {
    let c = duration.components
    return Double(c.seconds) + Double(c.attoseconds) * 1e-18
}

/// Warm-up loop (uncounted intent per its `// warm-up (uncounted)`-style comment in the
/// reference harnesses) followed by `concurrency` concurrent workers pulling from a shared
/// index until `SDK_BENCH_ITERATIONS` calls complete. Mirrors python/bench.py `time_op()` and
/// typescript/bench.mjs `timeOp()` byte-for-byte in one respect worth flagging explicitly:
/// both reference implementations fold warm-up failures into the SAME `errors` counter
/// returned in the final record (despite the "uncounted" comment only applying to latency
/// samples, not to the error tally) — replicated here for parity across SDK bench outputs.
func timeOp(_ fn: @escaping OpFn, concurrency: Int) async -> OpResult {
    let clock = ContinuousClock()
    var errors = 0

    for _ in 0..<WARMUP {
        if await fn() == false { errors += 1 }
    }

    let counter = IndexCounter(limit: ITER)
    let collector = LatencyCollector()
    let workers = max(concurrency, 1)

    let start = clock.now
    await withTaskGroup(of: Void.self) { group in
        for _ in 0..<workers {
            group.addTask {
                while await counter.claim() {
                    let t0 = clock.now
                    if await fn() {
                        await collector.record(durationMilliseconds(clock.now - t0))
                    } else {
                        await collector.recordError()
                    }
                }
            }
        }
    }
    let elapsedSecs = durationSeconds(clock.now - start)

    let latencies = await collector.latencies
    errors += await collector.errorCount

    let rps = elapsedSecs > 0 ? Double(latencies.count) / elapsedSecs : 0
    return OpResult(
        p50_ms: pct(latencies, 50),
        p95_ms: pct(latencies, 95),
        p99_ms: pct(latencies, 99),
        throughput_rps: rps,
        errors: errors
    )
}

// MARK: - Main

do {
    let opsFns = try await buildOps()

    var results: [String: OpResult] = [:]
    for key in OP_KEYS {
        guard let fn = opsFns[key] else { continue }
        // refresh is single-flight-guarded by the SDK (§9): running it concurrently would
        // measure the actor's serialization, not wire cost — run it at concurrency 1,
        // matching HARNESS-SPEC.md and every other wired bench (python/go/rust/...).
        let concurrency = (key == "refresh") ? 1 : CONC
        results[key] = await timeOp(fn, concurrency: concurrency)
    }

    emit(status: "ok", ops: results, iterations: ITER, concurrency: CONC, notes: "")
} catch {
    // Covers target unreachable, login failing at runtime, seed/grant missing, and bad
    // PEM material — nothing to time, so report gracefully instead of crashing (no `swift`
    // toolchain is present in this sandbox to exercise this path live; see swift/TODO.md).
    emit(
        status: "error", ops: zeroOps(), iterations: 0, concurrency: 0,
        notes: "server unreachable or setup failed: \(error)")
}
