// AXIAM C++ SDK benchmark (wired to ilpanich/axiam-cplusplus-sdk, axiam::Client).
//
// Times the SDK's canonical CONTRACT.md §1 operations — login, refresh,
// check_access, batch_check — against a running, seeded AXIAM target.
// oauth2_token/introspect/userinfo are protocol-level ops with no SDK
// wrapper (see ../HARNESS-SPEC.md) and are not measured here. Mirrors the
// reference harnesses in ../python/bench.py and ../typescript/bench.mjs
// (timing loop, percentile math, JSON contract). The stdout JSON contract
// (axiam.sdk-bench/v1) must stay intact — this is the only thing this
// process prints to stdout.
//
// Run: ./build/axiam-bench   (or: cd benchmarks && just sdk=cpp sdk-bench)
//
// Degradation: a build failure never reaches this binary (run.sh falls back
// to a 'pending' record). At runtime, an unreachable server / failed login /
// missing seed grant is caught and reported as a zeroed 'error' record
// (exit 0) rather than a crash.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <vector>

#include <axiam/axiam.hpp>

namespace {

// ---- env helpers ----------------------------------------------------------

std::string env_str(const char* key, const std::string& def) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : def;
}

int env_int(const char* key, int def) {
    const char* v = std::getenv(key);
    if (!v || !*v) return def;
    try {
        return std::stoi(v);
    } catch (...) {
        return def;
    }
}

// Reads a whole file (used for the optional CA / client-cert / client-key PEM
// paths). Returns std::nullopt if the path is unset or unreadable.
std::optional<std::string> read_file(const std::string& path) {
    if (path.empty()) return std::nullopt;
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// ---- config -----------------------------------------------------------

struct Config {
    std::string base_url;
    std::string tenant_slug;
    std::string org_slug;
    std::string username;
    std::string password;
    std::string action;
    std::string resource_id;
    // Optional TLS material (p1/p2 custom-CA and p3-mtls profiles — see
    // HARNESS-SPEC.md "Security-profile limitation"; the C++ SDK exposes a
    // client-cert option (CONTRACT §6.1) via Client::Builder, so we wire it
    // through when the runner sets these paths, but the bench works fine
    // without them for p0/p1/p2).
    std::optional<std::string> ca_pem;
    std::optional<std::string> client_cert_pem;
    std::optional<std::string> client_key_pem;
    // Non-empty when a TLS input is unusable. build_ops() rethrows it inside
    // main()'s try, so it reaches the operator as the harness' contractual
    // status:"error" record — load_config() itself must not throw, because it
    // is called OUTSIDE that try and an escaping exception would terminate
    // with no record at all.
    std::string setup_error;
};

// Resolve one PATH-valued TLS env var to PEM content, recording a message
// that names the env var if it cannot be read. An unreadable path used to
// collapse to std::nullopt here, silently downgrading the run to "no client
// certificate configured" — which under p3-mtls surfaces as an unexplained
// handshake rejection rather than as the configuration error it is.
std::optional<std::string> load_pem(const char* var, std::string& setup_error) {
    const std::string path = env_str(var, "");
    if (path.empty()) return std::nullopt;
    std::optional<std::string> pem = read_file(path);
    if (!pem || pem->empty()) {
        if (setup_error.empty()) {
            setup_error = std::string(var) + "=\"" + path + "\" could not be read (or is empty)";
        }
        return std::nullopt;
    }
    return pem;
}

Config load_config() {
    Config c;
    const std::string scheme = env_str("BENCH_SCHEME", "http");
    const std::string host = env_str("BENCH_HOST", "localhost");
    const std::string port = env_str("BENCH_PORT", "8090");
    c.base_url = scheme + "://" + host + ":" + port;
    c.tenant_slug = env_str("BENCH_TENANT_SLUG", "default");
    c.org_slug = env_str("BENCH_ORG_SLUG", "bench-org");
    c.username = env_str("BENCH_USERNAME", "benchuser");
    c.password = env_str("BENCH_PASSWORD", "Bench@User123!");
    c.action = env_str("BENCH_ACTION", "read");
    c.resource_id = env_str("BENCH_RESOURCE_ID", "bench-resource");
    c.ca_pem = load_pem("BENCH_CA_CERT", c.setup_error);
    c.client_cert_pem = load_pem("BENCH_CLIENT_CERT", c.setup_error);
    c.client_key_pem = load_pem("BENCH_CLIENT_KEY", c.setup_error);

    // CONTRACT.md §6.1 rule 1: the mTLS identity is all-or-nothing. This used
    // to fall through make_client's `if (cert && key)` and silently drop the
    // half-configured identity, so a typo in one of the two vars produced a
    // handshake rejection that named neither. Report it naming BOTH vars —
    // sdk/test-client-cert-wiring.sh's phase A asserts exactly this for every
    // language.
    if (c.setup_error.empty() &&
        c.client_cert_pem.has_value() != c.client_key_pem.has_value()) {
        c.setup_error =
            "BENCH_CLIENT_CERT and BENCH_CLIENT_KEY must be set together (cert=\"" +
            env_str("BENCH_CLIENT_CERT", "") + "\", key=\"" + env_str("BENCH_CLIENT_KEY", "") +
            "\") — mTLS needs both (CONTRACT.md §6.1 rule 1)";
    }
    return c;
}

// Builds a fresh, unauthenticated Client from cfg (used once per timed
// 'login' iteration, and once up-front for the shared client).
axiam::Client make_client(const Config& cfg) {
    axiam::Client::Builder b = axiam::Client::builder()
        .base_url(cfg.base_url)
        .tenant_slug(cfg.tenant_slug)
        .org_slug(cfg.org_slug);
    if (cfg.ca_pem) b.with_custom_ca(*cfg.ca_pem);
    if (cfg.client_cert_pem && cfg.client_key_pem) {
        b.with_client_cert(*cfg.client_cert_pem, *cfg.client_key_pem);
    }
    return b.build();
}

// ---- percentile math (mirrors python/bench.py & typescript/bench.mjs) -----

double pct(std::vector<double> s, double p) {
    if (s.empty()) return 0.0;
    std::sort(s.begin(), s.end());
    const double k = static_cast<double>(s.size() - 1) * (p / 100.0);
    const std::size_t lo = static_cast<std::size_t>(k);
    const std::size_t hi = std::min(lo + 1, s.size() - 1);
    return s[lo] + (s[hi] - s[lo]) * (k - static_cast<double>(lo));
}

// ---- I13 (improvement-after-run4-benchmark.md §C) client resource sampler:
// `client_cpu_ms_total`/`client_rss_mib_peak` recorded 0.0 for every SDK
// bench — the sampler was never wired. POSIX `getrusage(RUSAGE_SELF, ...)`
// gives an exact, cheap high-water-mark read with no polling thread needed:
// `ru_maxrss` is already a lifetime peak (not a snapshot), and
// `ru_utime`/`ru_stime` are cumulative CPU time since process start.
// `ru_maxrss` is in KiB on Linux (matches this harness' Docker/K8s
// deployment target per CLAUDE.md). ----------------------------------------

void client_resource_usage(double& cpu_ms_total, double& rss_mib_peak) {
    cpu_ms_total = 0.0;
    rss_mib_peak = 0.0;
    struct rusage ru {};
    if (getrusage(RUSAGE_SELF, &ru) != 0) return;
    cpu_ms_total = static_cast<double>(ru.ru_utime.tv_sec) * 1000.0 +
                   static_cast<double>(ru.ru_utime.tv_usec) / 1000.0 +
                   static_cast<double>(ru.ru_stime.tv_sec) * 1000.0 +
                   static_cast<double>(ru.ru_stime.tv_usec) / 1000.0;
    rss_mib_peak = static_cast<double>(ru.ru_maxrss) / 1024.0;  // KiB -> MiB (Linux)
}

// ---- JSON output (fixed axiam.sdk-bench/v1 shape; hand-rolled to avoid a
// second JSON dependency — the SDK's nlohmann/json.hpp is a private
// implementation detail, not part of its public include/ surface) ---------

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

struct OpResult {
    double p50_ms = 0.0;
    double p95_ms = 0.0;
    double p99_ms = 0.0;
    double throughput_rps = 0.0;
    int errors = 0;
};

const std::vector<std::string> kOpKeys = {"login", "refresh", "check_access", "batch_check"};

std::string ops_json(const std::vector<std::pair<std::string, OpResult>>& ops) {
    std::ostringstream j;
    j << "{\n";
    for (std::size_t i = 0; i < ops.size(); ++i) {
        const auto& [key, r] = ops[i];
        j << "    \"" << key << "\": {"
          << "\"p50_ms\": " << r.p50_ms << ", "
          << "\"p95_ms\": " << r.p95_ms << ", "
          << "\"p99_ms\": " << r.p99_ms << ", "
          << "\"throughput_rps\": " << r.throughput_rps << ", "
          << "\"errors\": " << r.errors << "}";
        if (i + 1 < ops.size()) j << ",";
        j << "\n";
    }
    j << "  }";
    return j.str();
}

std::vector<std::pair<std::string, OpResult>> zero_ops() {
    std::vector<std::pair<std::string, OpResult>> ops;
    for (const auto& k : kOpKeys) ops.emplace_back(k, OpResult{});
    return ops;
}

void emit(const std::string& status, const std::vector<std::pair<std::string, OpResult>>& ops,
          int iterations, int concurrency, const std::string& notes) {
    double cpu_ms_total = 0.0, rss_mib_peak = 0.0;
    client_resource_usage(cpu_ms_total, rss_mib_peak);
    std::ostringstream j;
    j << "{\n"
      << "  \"schema\": \"axiam.sdk-bench/v1\",\n"
      << "  \"sdk\": \"cpp\",\n"
      << "  \"sdk_version\": \"" << axiam::kVersion << "\",\n"
      << "  \"language_runtime\": \"" << json_escape(
             "g++ " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) +
             "." + std::to_string(__GNUC_PATCHLEVEL__) + " (C++" +
             std::to_string(__cplusplus / 100 % 100) + ")") << "\",\n"
      << "  \"target\": \"" << json_escape(env_str("BENCH_TARGET", "axiam")) << "\",\n"
      << "  \"profile\": \"" << json_escape(env_str("BENCH_PROFILE", "p0-plaintext")) << "\",\n"
      << "  \"status\": \"" << status << "\",\n"
      << "  \"iterations\": " << iterations << ",\n"
      << "  \"concurrency\": " << concurrency << ",\n"
      << "  \"ops\": " << ops_json(ops) << ",\n"
      << "  \"client_cpu_ms_total\": " << cpu_ms_total << ",\n"
      << "  \"client_rss_mib_peak\": " << rss_mib_peak << ",\n"
      << "  \"notes\": \"" << json_escape(notes) << "\"\n"
      << "}";
    std::cout << j.str() << std::endl;
}

// ---- timing loop ------------------------------------------------------

using OpFn = std::function<void()>;

// Runs `warmup` uncounted calls (serial) then `iter` measured calls spread
// across `conc` worker threads (an atomic counter hands out iteration
// indices — mirrors the worker-pool pattern in ../go/main.go). Per-call
// latency is recorded in milliseconds; any exception counts as an error
// (no latency sample).
OpResult time_op(const OpFn& fn, int iter, int warmup, int conc) {
    if (conc < 1) conc = 1;

    std::atomic<int> errors{0};
    for (int i = 0; i < warmup; ++i) {
        try {
            fn();
        } catch (...) {
            errors.fetch_add(1, std::memory_order_relaxed);
        }
    }

    std::atomic<int> next_idx{0};
    std::mutex lat_mtx;
    std::vector<double> lat;
    lat.reserve(static_cast<std::size_t>(iter));

    const auto start = std::chrono::steady_clock::now();

    auto worker = [&]() {
        std::vector<double> local;
        for (;;) {
            const int i = next_idx.fetch_add(1, std::memory_order_relaxed);
            if (i >= iter) break;
            const auto t0 = std::chrono::steady_clock::now();
            try {
                fn();
                const auto t1 = std::chrono::steady_clock::now();
                local.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
            } catch (...) {
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        }
        std::lock_guard<std::mutex> lock(lat_mtx);
        lat.insert(lat.end(), local.begin(), local.end());
    };

    std::vector<std::thread> pool;
    pool.reserve(static_cast<std::size_t>(conc));
    for (int w = 0; w < conc; ++w) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    OpResult r;
    r.p50_ms = pct(lat, 50);
    r.p95_ms = pct(lat, 95);
    r.p99_ms = pct(lat, 99);
    r.throughput_rps = secs > 0 ? static_cast<double>(lat.size()) / secs : 0.0;
    r.errors = errors.load();
    return r;
}

// Builds one logged-in shared Client and returns {op_key: zero-arg fn}.
// `login` builds and discards its own short-lived client per call (a fresh,
// unauthenticated session per iteration mirrors what the op measures);
// `refresh`/`check_access`/`batch_check` share one already-authenticated
// client — `Client` is a thin handle over a mutex-guarded impl (§9
// single-flight refresh guard), so concurrent calls through copies of it are
// safe.
std::vector<std::pair<std::string, OpFn>> build_ops(const Config& cfg) {
    // Surface an unusable TLS input before touching the network: main() calls
    // this from inside its try, so it becomes a status:"error" record naming
    // the env var at fault instead of a handshake failure that names nothing.
    if (!cfg.setup_error.empty()) throw std::runtime_error(cfg.setup_error);
    axiam::Client client = make_client(cfg);
    axiam::LoginResult login = client.login(cfg.username, cfg.password);
    if (login.mfa_required) {
        throw std::runtime_error(
            "login requires MFA — the bench user must not have MFA enabled (see runner/seed.sh)");
    }

    std::vector<axiam::AccessCheck> checks;
    for (int i = 0; i < 3; ++i) {
        // Every check reuses the one seeded resource UUID: the server
        // rejects non-UUID resource_ids, so a per-index suffix would 400.
        checks.push_back(axiam::AccessCheck{cfg.action, cfg.resource_id, std::nullopt, std::nullopt});
    }

    // Fail fast if the grant is missing — otherwise we'd silently benchmark
    // the deny fast-path instead of a real allow decision.
    axiam::AccessDecision warm = client.check_access(cfg.action, cfg.resource_id);
    if (!warm.allowed) {
        throw std::runtime_error(
            "warm-up check_access denied for action=" + cfg.action +
            " resource_id=" + cfg.resource_id + " — seed the resource/role/grant (see runner/seed.sh)");
    }

    std::vector<std::pair<std::string, OpFn>> ops;
    ops.emplace_back("login", [cfg]() {
        axiam::Client fresh = make_client(cfg);
        fresh.login(cfg.username, cfg.password);
    });
    ops.emplace_back("refresh", [client]() mutable { client.refresh(); });
    ops.emplace_back("check_access", [client, cfg]() mutable {
        client.check_access(cfg.action, cfg.resource_id);
    });
    ops.emplace_back("batch_check", [client, checks]() mutable { client.batch_check(checks); });
    return ops;
}

// I9 (improvement-after-run4-benchmark.md §C): a floor below which a
// measured `refresh` latency is not plausibly a real HTTP round trip. The
// C# bench recorded p50 1.2 microseconds ("752 k rps") because its SDK's
// RefreshGuard cached a completed token result on a shared client for up to
// ~15 minutes (wall-clock freshness, no observed-token check), so only the
// FIRST refresh in a ~2200-call run ever touched the wire. This SDK's
// refresh_guard.hpp keys on the caller's currently observed access token
// instead, which this bench's `client.refresh()` call updates after every
// real refresh — so a same-client loop keeps hitting the wire — but this
// floor is kept as a language-agnostic regression guard against that class
// of bug reappearing here too (a cache hit completes in low single-digit
// microseconds; every genuine wire call recorded across this harness' 11
// languages averages ~17 ms, so 0.2 ms leaves a wide margin).
constexpr double kMinPlausibleRefreshMs = 0.2;

// I9 shared-driver-style regression guard: fail loudly (non-zero exit)
// instead of silently publishing a fake number if `refresh` looks like it
// never left the process.
void assert_refresh_hit_the_wire(const OpResult& refresh, int iterations) {
    const bool had_samples = refresh.errors < iterations;
    if (had_samples && refresh.p50_ms < kMinPlausibleRefreshMs) {
        std::cerr << "[cpp] I9 guard: refresh p50=" << refresh.p50_ms << "ms is below the "
                  << kMinPlausibleRefreshMs
                  << "ms plausible-wire-call floor despite successful samples — this looks "
                     "like a cached no-op (CONTRACT.md §9 guard reuse), not a real HTTP round "
                     "trip. Failing the bench run instead of publishing a fake number "
                     "(see improvement-after-run4-benchmark.md I9)."
                  << std::endl;
        std::exit(1);
    }
}

}  // namespace

int main() {
    const Config cfg = load_config();
    const int iter = env_int("SDK_BENCH_ITERATIONS", 2000);
    const int warmup = env_int("SDK_BENCH_WARMUP", 200);
    const int conc = env_int("SDK_BENCH_CONCURRENCY", 16);

    std::vector<std::pair<std::string, OpFn>> ops_fns;
    try {
        ops_fns = build_ops(cfg);
    } catch (const axiam::AxiamError& e) {
        emit("error", zero_ops(), 0, 0, std::string("server unreachable or setup failed: ") + e.what());
        return 0;
    } catch (const std::exception& e) {
        emit("error", zero_ops(), 0, 0, std::string("server unreachable or setup failed: ") + e.what());
        return 0;
    }

    std::vector<std::pair<std::string, OpResult>> results;
    for (const auto& [key, fn] : ops_fns) {
        // refresh is single-flight-guarded by the SDK (§9), so running it
        // concurrently would measure the guard, not the wire cost — run it
        // serially (concurrency 1). All other ops run at SDK_BENCH_CONCURRENCY.
        const int op_conc = (key == "refresh") ? 1 : conc;
        results.emplace_back(key, time_op(fn, iter, warmup, op_conc));
    }

    emit("ok", results, iter, conc, "");
    for (const auto& [key, r] : results) {
        if (key == "refresh") assert_refresh_hit_the_wire(r, iter);
    }
    return 0;
}
