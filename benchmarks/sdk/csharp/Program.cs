// AXIAM C# SDK benchmark (wired to Axiam.Sdk 1.0.0-alpha2).
//
// Times the canonical CONTRACT.md §1 operations exposed by Axiam.Sdk's
// AxiamClient — login, refresh, check_access, batch_check — against a running,
// seeded AXIAM target. oauth2_token/introspect/userinfo are protocol-level ops
// with no SDK wrapper (see ../HARNESS-SPEC.md) and are not measured here.
//
// Mirrors ../python/bench.py and ../typescript/bench.mjs: warm-up + measured
// loop, percentile math, and the stdout JSON contract (axiam.sdk-bench/v1) —
// which must stay intact for sdk/collect.py.
//
// Note on op keys: the emitted JSON keys are snake_case ("check_access",
// "batch_check") per the contract, even though the C# SDK methods are
// PascalCase (CheckAccessAsync, BatchCheckAsync).
//
// Run: dotnet run -c Release   (or: just sdk=csharp sdk-bench)

using System.Diagnostics;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Options;
using AccessCheck = Axiam.Sdk.Rest.AuthzRestClient.AccessCheck;

// ---------------------------------------------------------------------------
// Config (same env the server harness + reference SDK benches read)
// ---------------------------------------------------------------------------
static string Env(string key, string fallback) =>
    Environment.GetEnvironmentVariable(key) is { Length: > 0 } v ? v : fallback;

int ITER = int.Parse(Env("SDK_BENCH_ITERATIONS", "2000"));
int WARMUP = int.Parse(Env("SDK_BENCH_WARMUP", "200"));
int CONC = int.Parse(Env("SDK_BENCH_CONCURRENCY", "16"));

string scheme = Env("BENCH_SCHEME", "http");
string host = Env("BENCH_HOST", "localhost");
string port = Env("BENCH_PORT", "8090");
string baseUrl = $"{scheme}://{host}:{port}";
string tenantSlug = Env("BENCH_TENANT_SLUG", "default");
string orgSlug = Env("BENCH_ORG_SLUG", "bench-org");
string username = Env("BENCH_USERNAME", "benchuser");
string password = Env("BENCH_PASSWORD", "Bench@User123!");
string action = Env("BENCH_ACTION", "read");
string resourceIdRaw = Env("BENCH_RESOURCE_ID", "");
// TLS inputs (HARNESS-SPEC.md), all file PATHS: BENCH_CA_CERT is the trusted
// custom CA under every TLS profile, BENCH_CLIENT_CERT/BENCH_CLIENT_KEY the
// p3-mtls client identity (CONTRACT.md §6.1). AxiamClientOptions wants PEM
// BYTES, so the files are read below — inside the setup try/catch, so an
// unreadable path becomes the contractual status:"error" record rather than
// an unhandled exception with no record at all.
string caCertPath = Env("BENCH_CA_CERT", "");
string clientCertPath = Env("BENCH_CLIENT_CERT", "");
string clientKeyPath = Env("BENCH_CLIENT_KEY", "");

string[] OP_KEYS = { "login", "refresh", "check_access", "batch_check" };

// ---------------------------------------------------------------------------
// Percentile + JSON helpers (mirror the reference harnesses)
// ---------------------------------------------------------------------------
static double Pct(List<double> arr, double p)
{
    if (arr.Count == 0) return 0.0;
    var s = new List<double>(arr);
    s.Sort();
    double k = (s.Count - 1) * (p / 100.0);
    int lo = (int)Math.Floor(k);
    int hi = Math.Min(lo + 1, s.Count - 1);
    return s[lo] + (s[hi] - s[lo]) * (k - lo);
}

static Dictionary<string, object?> OpRecord(double p50, double p95, double p99, double rps, int errors) =>
    new()
    {
        ["p50_ms"] = p50,
        ["p95_ms"] = p95,
        ["p99_ms"] = p99,
        ["throughput_rps"] = rps,
        ["errors"] = errors,
    };

Dictionary<string, object?> ZeroOps()
{
    var ops = new Dictionary<string, object?>();
    foreach (var k in OP_KEYS) ops[k] = OpRecord(0, 0, 0, 0, 0);
    return ops;
}

// I13 (improvement-after-run4-benchmark.md §C): `client_cpu_ms_total`/
// `client_rss_mib_peak` recorded 0.0 for every SDK bench — the sampler was
// never wired. .NET's Process API gives both directly and precisely, no
// polling needed: TotalProcessorTime is cumulative CPU time since process
// start (user+kernel), and PeakWorkingSet64 is already a lifetime
// high-water mark (not a snapshot) on every platform .NET runs on —
// unlike the procfs-based samplers this file's siblings use, this one is
// not Linux-specific.
(double CpuMsTotal, double RssMiBPeak) ClientResourceUsage()
{
    try
    {
        using var proc = System.Diagnostics.Process.GetCurrentProcess();
        return (proc.TotalProcessorTime.TotalMilliseconds, proc.PeakWorkingSet64 / 1024.0 / 1024.0);
    }
    catch
    {
        return (0.0, 0.0); // best-effort telemetry only — never fail the bench over it
    }
}

void Emit(string status, Dictionary<string, object?> ops, int iterations, int concurrency, string notes)
{
    var (cpuMsTotal, rssMiBPeak) = ClientResourceUsage();
    var record = new Dictionary<string, object?>
    {
        ["schema"] = "axiam.sdk-bench/v1",
        ["sdk"] = "csharp",
        ["sdk_version"] = "1.0.0-alpha2",
        ["language_runtime"] = $".NET {Environment.Version}",
        ["target"] = Env("BENCH_TARGET", "axiam"),
        ["profile"] = Env("BENCH_PROFILE", "p0-plaintext"),
        ["status"] = status,
        ["iterations"] = iterations,
        ["concurrency"] = concurrency,
        ["ops"] = ops,
        ["client_cpu_ms_total"] = cpuMsTotal,
        ["client_rss_mib_peak"] = rssMiBPeak,
        ["notes"] = notes,
    };
    Console.WriteLine(JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true }));
}

// ---------------------------------------------------------------------------
// I9 fix (improvement-after-run4-benchmark.md §C): `refresh` measured a
// cached no-op (p50 1.2 microseconds / "752 k rps"). Axiam.Sdk's RefreshGuard
// (Axiam.Sdk/Auth/RefreshGuard.cs in the sibling axiam-csharp-sdk checkout)
// reuses a completed TokenPair whenever it is still more than FreshnessMargin
// (5s) short of expiry — and, unlike the Go/Python/Rust/Java/Kotlin/PHP/C
// SDKs' guards (which key on the CALLER's currently observed access token,
// so a same-client loop always sees "fresh" again right after a real refresh
// updates that token and therefore keeps hitting the wire), the C# guard's
// RefreshIfNeededAsync() takes no observed-token parameter at all — it is a
// pure wall-clock cache. Against a ~15-minute access-token TTL, the FIRST
// call on a shared client performs the real POST /api/v1/auth/refresh; every
// one of the following ~2199 calls in the same run returns the cached result
// with no HTTP call whatsoever.
//
// Axiam.Sdk exposes no ForceRefreshAsync/expiry-override escape hatch (this
// is a harness-only fix, not an SDK change — that repo is out of scope
// here), so the fix is structural: give `refresh` a FRESH client + login
// (both untimed) on every iteration. A brand-new AxiamClient owns a brand-new
// RefreshGuard with no cached result, so its RefreshAsync() always performs
// the real wire call — only that call is timed, not the login that seeds it.
// See TimeForcedRefreshOp() below; `refresh` no longer goes through the
// generic TimeOp()+shared-client path other three ops still use.
// ---------------------------------------------------------------------------

// I9: a floor below which a measured refresh latency is not plausibly a real
// HTTP round trip (a cache hit typically completes in low single-digit
// microseconds; every genuine wire call recorded across this harness' 11
// languages averages ~17 ms). 0.2 ms leaves a large margin against fast
// networks while still catching a reintroduced cached-no-op bug of this
// class outright (this file's original bug measured 0.0012 ms). Mirrors the
// identical constant/check added to every other sdk/<lang> bench runner.
const double MinPlausibleRefreshMs = 0.2;

// ---------------------------------------------------------------------------
// Timed op loop: serial warm-up (uncounted) then measured, bounded concurrency.
// `refresh` is run with concurrency 1 — it is single-flight-guarded in the SDK,
// so timing it serially reflects the guarded call cost without contention noise.
// ---------------------------------------------------------------------------
async Task<Dictionary<string, object?>> TimeOp(Func<Task> fn, int concurrency)
{
    var lat = new List<double>();
    var latLock = new object();
    int errors = 0;

    for (int i = 0; i < WARMUP; i++)
    {
        try { await fn(); }
        catch { Interlocked.Increment(ref errors); }
    }

    var sw = Stopwatch.StartNew();
    int index = 0;

    async Task Worker()
    {
        while (true)
        {
            int cur = Interlocked.Increment(ref index);
            if (cur > ITER) break;
            long t0 = Stopwatch.GetTimestamp();
            try
            {
                await fn();
                double ms = (Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency;
                lock (latLock) { lat.Add(ms); }
            }
            catch { Interlocked.Increment(ref errors); }
        }
    }

    var workers = Enumerable.Range(0, Math.Max(1, concurrency)).Select(_ => Worker()).ToArray();
    await Task.WhenAll(workers);
    sw.Stop();

    double secs = sw.Elapsed.TotalSeconds;
    double rps = secs > 0 ? lat.Count / secs : 0.0;
    return OpRecord(Pct(lat, 50), Pct(lat, 95), Pct(lat, 99), rps, errors);
}

// I9 fix: forces one genuine `POST /api/v1/auth/refresh` wire call per
// iteration by giving `refresh` a fresh client (fresh RefreshGuard, so
// nothing to cache) + login on every pass, serially (concurrency 1, per
// HARNESS-SPEC.md). Only the RefreshAsync() call itself is timed; the login
// that seeds each fresh client is untimed setup, mirroring how `login`'s own
// op already builds and discards a fresh client per call.
async Task<Dictionary<string, object?>> TimeForcedRefreshOp()
{
    var lat = new List<double>();
    int errors = 0;

    async Task<double?> OneForcedRefresh()
    {
        AxiamClient fresh;
        try
        {
            fresh = new AxiamClient(new Uri(baseUrl), tenantSlug, NewOptions());
            await fresh.LoginAsync(username, password);
        }
        catch
        {
            return null; // setup failure: an error, nothing to time
        }
        try
        {
            long t0 = Stopwatch.GetTimestamp();
            await fresh.RefreshAsync();
            return (Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency;
        }
        catch
        {
            return null;
        }
        finally
        {
            fresh.Dispose();
        }
    }

    for (int i = 0; i < WARMUP; i++)
    {
        if (await OneForcedRefresh() is null) errors++;
    }

    var sw = Stopwatch.StartNew();
    foreach (var _ in Enumerable.Range(0, ITER))
    {
        var ms = await OneForcedRefresh();
        if (ms is null) errors++;
        else lat.Add(ms.Value);
    }
    sw.Stop();

    double secs = sw.Elapsed.TotalSeconds;
    double rps = secs > 0 ? lat.Count / secs : 0.0;
    return OpRecord(Pct(lat, 50), Pct(lat, 95), Pct(lat, 99), rps, errors);
}

// I9: shared-driver-style regression guard — if `refresh` ever again reports
// a p50 implausibly below a real HTTP round trip while it had successful
// samples, this is very likely the cached-no-op bug (or an equivalent)
// reappearing, not a genuinely fast server. Fails loudly (non-zero exit,
// after the record is already on stdout for inspection) rather than letting
// a silently-wrong number reach the report.
void AssertRefreshHitTheWire(Dictionary<string, object?> refreshOp)
{
    var errors = (int)refreshOp["errors"]!;
    var p50 = (double)refreshOp["p50_ms"]!;
    bool hadSamples = errors < ITER; // at least one real measured sample exists
    if (hadSamples && p50 < MinPlausibleRefreshMs)
    {
        Console.Error.WriteLine(
            $"[csharp] I9 guard: refresh p50={p50:F4}ms is below the {MinPlausibleRefreshMs}ms " +
            "plausible-wire-call floor despite successful samples — this looks like a cached " +
            "no-op (CONTRACT.md §9 guard reuse), not a real HTTP round trip. Failing the bench " +
            "run instead of publishing a fake number (see improvement-after-run4-benchmark.md I9).");
        Environment.Exit(1);
    }
}

// ---------------------------------------------------------------------------
// Setup: parse resource id, build one logged-in client shared by
// refresh/check_access/batch_check; `login` builds a fresh client per call.
// ---------------------------------------------------------------------------
Guid resourceId;
AxiamClient client;
List<AccessCheck> checks;

// One options factory for every client this bench builds — the shared one and
// the fresh one `login` builds per iteration. Configuring only the shared
// client would pass three ops and fail `login` at the TLS handshake, which
// reads like a server problem rather than a harness one.
AxiamClientOptions NewOptions()
{
    if (string.IsNullOrEmpty(clientCertPath) != string.IsNullOrEmpty(clientKeyPath))
    {
        // The SDK validates this too (§6.1 rule 1), but failing here names the
        // env var the operator actually got wrong.
        throw new InvalidOperationException(
            $"BENCH_CLIENT_CERT=\"{clientCertPath}\" and BENCH_CLIENT_KEY=\"{clientKeyPath}\" must be set together — mTLS needs both (CONTRACT.md §6.1 rule 1)");
    }
    return new AxiamClientOptions
    {
        BaseUrl = new Uri(baseUrl),
        TenantId = tenantSlug,
        OrgSlug = orgSlug,
        CustomCaPem = caCertPath.Length > 0 ? File.ReadAllBytes(caCertPath) : null,
        ClientCertificatePem = clientCertPath.Length > 0 ? File.ReadAllBytes(clientCertPath) : null,
        ClientKeyPem = clientKeyPath.Length > 0 ? File.ReadAllBytes(clientKeyPath) : null,
    };
}

try
{
    resourceId = Guid.Parse(resourceIdRaw); // FormatException -> status "error"

    client = new AxiamClient(new Uri(baseUrl), tenantSlug, NewOptions());
    await client.LoginAsync(username, password);

    // Batch of 3 checks, all against the SAME resource (no per-item suffixing —
    // the C# resource id is a single Guid).
    checks = new List<AccessCheck>
    {
        new(action, resourceId),
        new(action, resourceId),
        new(action, resourceId),
    };
}
catch (Exception ex)
{
    // Covers a bad/blank BENCH_RESOURCE_ID as well as an unreachable server,
    // missing seed data, or failed auth. Nothing to time — report gracefully
    // and exit 0 so the aggregator records an "error", not a crash.
    Emit("error", ZeroOps(), 0, 0, $"setup failed: {ex.Message}");
    return;
}

// ---------------------------------------------------------------------------
// Measure the four ops.
// ---------------------------------------------------------------------------
// I9: `refresh` is NOT in this table — it goes through TimeForcedRefreshOp()
// below, which forces a fresh client + login per iteration so RefreshAsync()
// always performs a genuine wire call instead of hitting the shared client's
// RefreshGuard cache. See the I9 comment above TimeOp() for why.
var opsFns = new Dictionary<string, (Func<Task> Fn, int Concurrency)>
{
    ["login"] = (async () =>
    {
        var fresh = new AxiamClient(new Uri(baseUrl), tenantSlug, NewOptions());
        try { await fresh.LoginAsync(username, password); }
        finally { fresh.Dispose(); }
    }, CONC),
    ["check_access"] = (() => client.Authz.CheckAccessAsync(action, resourceId), CONC),
    ["batch_check"] = (() => client.Authz.BatchCheckAsync(checks), CONC),
};

var ops = new Dictionary<string, object?>();
foreach (var key in OP_KEYS)
{
    ops[key] = key == "refresh"
        ? await TimeForcedRefreshOp()
        : await TimeOp(opsFns[key].Fn, opsFns[key].Concurrency);
}

client.Dispose();
AssertRefreshHitTheWire((Dictionary<string, object?>)ops["refresh"]!);
Emit("ok", ops, ITER, CONC, "");
