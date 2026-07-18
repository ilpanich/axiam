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

void Emit(string status, Dictionary<string, object?> ops, int iterations, int concurrency, string notes)
{
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
        ["client_cpu_ms_total"] = 0,
        ["client_rss_mib_peak"] = 0,
        ["notes"] = notes,
    };
    Console.WriteLine(JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true }));
}

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

// ---------------------------------------------------------------------------
// Setup: parse resource id, build one logged-in client shared by
// refresh/check_access/batch_check; `login` builds a fresh client per call.
// ---------------------------------------------------------------------------
Guid resourceId;
AxiamClient client;
List<AccessCheck> checks;
try
{
    resourceId = Guid.Parse(resourceIdRaw); // FormatException -> status "error"

    client = new AxiamClient(new Uri(baseUrl), tenantSlug, new AxiamClientOptions { OrgSlug = orgSlug });
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
var opsFns = new Dictionary<string, (Func<Task> Fn, int Concurrency)>
{
    ["login"] = (async () =>
    {
        var fresh = new AxiamClient(new Uri(baseUrl), tenantSlug, new AxiamClientOptions { OrgSlug = orgSlug });
        try { await fresh.LoginAsync(username, password); }
        finally { fresh.Dispose(); }
    }, CONC),
    ["refresh"] = (() => client.RefreshAsync(), 1), // serial: single-flight-guarded
    ["check_access"] = (() => client.Authz.CheckAccessAsync(action, resourceId), CONC),
    ["batch_check"] = (() => client.Authz.BatchCheckAsync(checks), CONC),
};

var ops = new Dictionary<string, object?>();
foreach (var key in OP_KEYS)
{
    var (fn, concurrency) = opsFns[key];
    ops[key] = await TimeOp(fn, concurrency);
}

client.Dispose();
Emit("ok", ops, ITER, CONC, "");
