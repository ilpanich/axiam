<?php

declare(strict_types=1);

/*
 * AXIAM PHP SDK benchmark (wired to axiam/axiam-sdk).
 *
 * Times Axiam\Sdk\AxiamClient's canonical CONTRACT.md §1 operations —
 * login, refresh, checkAccess, batchCheck — against a running, seeded AXIAM
 * target. oauth2_token/introspect/userinfo are protocol-level ops with no SDK
 * wrapper (see ../HARNESS-SPEC.md) and are not measured here.
 *
 * Unlike the Python/TypeScript reference harnesses, the PHP SDK is synchronous
 * with no async client, so this bench is single-process and runs every
 * iteration serially: concurrency is always reported as 1.
 *
 * Keep the stdout JSON contract (axiam.sdk-bench/v1) intact.
 *
 * Run: php bench.php   (or: just sdk=php sdk-bench)
 */

$env = static fn (string $k, string $d): string => ($v = getenv($k)) !== false && $v !== '' ? $v : $d;

$ITER = (int) $env('SDK_BENCH_ITERATIONS', '2000');
$WARMUP = (int) $env('SDK_BENCH_WARMUP', '200');
// SDK_BENCH_CONCURRENCY is read for parity with the server harness / sibling
// SDK benches, but the PHP SDK is synchronous (no async client), so this bench
// is single-process and always runs serially: concurrency is pinned to 1.
$CONC = 1;

$cfg = [
    'base_url' => sprintf(
        '%s://%s:%s',
        $env('BENCH_SCHEME', 'http'),
        $env('BENCH_HOST', 'localhost'),
        $env('BENCH_PORT', '8090'),
    ),
    'tenant_slug' => $env('BENCH_TENANT_SLUG', 'default'),
    'org_slug' => $env('BENCH_ORG_SLUG', 'bench-org'),
    'username' => $env('BENCH_USERNAME', 'benchuser'),
    'password' => $env('BENCH_PASSWORD', 'Bench@User123!'),
    'action' => $env('BENCH_ACTION', 'read'),
    'resource_id' => $env('BENCH_RESOURCE_ID', 'bench-resource'),
    // H8 fix: HARNESS-SPEC.md documents BENCH_CA_CERT (a PEM file path) as
    // an input every SDK bench should honor under the TLS profiles (p2),
    // but this bench never read it — every p2 run failed at the first
    // HTTPS call against the profile's throwaway CA. AxiamClient's
    // $customCa constructor param is a CA bundle FILE PATH (not inline PEM
    // content), so pass BENCH_CA_CERT straight through unchanged.
    'custom_ca' => $env('BENCH_CA_CERT', '') ?: null,
    // p3-mtls client identity (CONTRACT.md §6.1). HARNESS-SPEC.md documents
    // BENCH_CLIENT_CERT/BENCH_CLIENT_KEY as file PATHS, but AxiamClient's
    // $clientCert/$clientKey params want PEM CONTENT (unlike $customCa above,
    // which is a path — Guzzle's `verify` takes a bundle path while `cert`/
    // `ssl_key` take material), so these are read in new_client() below.
    'client_cert_path' => $env('BENCH_CLIENT_CERT', '') ?: null,
    'client_key_path' => $env('BENCH_CLIENT_KEY', '') ?: null,
];

const OP_KEYS = ['login', 'refresh', 'check_access', 'batch_check'];

/** Linear-interpolated percentile — mirrors python/bench.py and typescript/bench.mjs. */
function pct(array $arr, float $p): float
{
    if ($arr === []) {
        return 0.0;
    }
    sort($arr);
    $n = count($arr);
    $k = ($n - 1) * ($p / 100.0);
    $lo = (int) floor($k);
    $hi = min($lo + 1, $n - 1);

    return $arr[$lo] + ($arr[$hi] - $arr[$lo]) * ($k - $lo);
}

function zero_ops(): array
{
    $ops = [];
    foreach (OP_KEYS as $k) {
        $ops[$k] = ['p50_ms' => 0, 'p95_ms' => 0, 'p99_ms' => 0, 'throughput_rps' => 0, 'errors' => 0];
    }

    return $ops;
}

function sdk_version(): string
{
    // Resolve the installed SDK version if Composer's runtime metadata is
    // available (path/dev installs report e.g. "dev-main"); fall back to the
    // last known alpha tag otherwise.
    if (class_exists(\Composer\InstalledVersions::class)) {
        try {
            $v = \Composer\InstalledVersions::getPrettyVersion('axiam/axiam-sdk');
            if (is_string($v) && $v !== '') {
                return $v;
            }
        } catch (\Throwable) {
            // fall through to default
        }
    }

    return '1.0.0-alpha2';
}

/**
 * I13 (improvement-after-run4-benchmark.md §C): `client_cpu_ms_total`/
 * `client_rss_mib_peak` recorded 0.0 for every SDK bench — the sampler was
 * never wired. PHP core ships `getrusage()` (POSIX `RUSAGE_SELF` under the
 * hood) directly — no polling needed: `ru_maxrss` is already a lifetime
 * peak (not a snapshot), and `ru_utime`/`ru_stime` are cumulative CPU time
 * since process start. `ru_maxrss` is in KiB on Linux (matches this
 * harness' Docker/K8s deployment target per CLAUDE.md).
 *
 * @return array{0: float, 1: float} [cpu_ms_total, rss_mib_peak]
 */
function client_resource_usage(): array
{
    if (!function_exists('getrusage')) {
        return [0.0, 0.0];
    }
    $ru = getrusage();
    $cpu_ms_total = (
        ($ru['ru_utime.tv_sec'] ?? 0) + ($ru['ru_stime.tv_sec'] ?? 0)
    ) * 1000.0 + (
        ($ru['ru_utime.tv_usec'] ?? 0) + ($ru['ru_stime.tv_usec'] ?? 0)
    ) / 1000.0;
    $rss_mib_peak = ($ru['ru_maxrss'] ?? 0) / 1024.0; // KiB -> MiB (Linux)

    return [$cpu_ms_total, $rss_mib_peak];
}

function emit(string $status, array $ops, int $iterations, int $concurrency, string $notes): void
{
    [$cpu_ms_total, $rss_mib_peak] = client_resource_usage();
    echo json_encode([
        'schema' => 'axiam.sdk-bench/v1',
        'sdk' => 'php',
        'sdk_version' => sdk_version(),
        'language_runtime' => 'php ' . PHP_VERSION,
        'target' => (($t = getenv('BENCH_TARGET')) !== false && $t !== '') ? $t : 'axiam',
        'profile' => (($p = getenv('BENCH_PROFILE')) !== false && $p !== '') ? $p : 'p0-plaintext',
        'status' => $status,
        'iterations' => $iterations,
        'concurrency' => $concurrency,
        'ops' => $ops,
        'client_cpu_ms_total' => $cpu_ms_total,
        'client_rss_mib_peak' => $rss_mib_peak,
        'notes' => $notes,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
}

/**
 * Build one logged-in AxiamClient and return {op_key: callable}.
 *
 * `login` builds and discards its own short-lived client per call (a fresh,
 * unauthenticated session per iteration mirrors what the op measures);
 * `refresh`/`check_access`/`batch_check` share one already-authenticated client.
 * All ops run serially — the SDK is synchronous, so there is no single-flight
 * concurrency to guard against here.
 *
 * @return array<string,callable>
 */
function build_ops(array $cfg): array
{
    // §6.1 client identity, read ONCE here (not per `login` iteration) and
    // shared by every client this bench builds. The pair is all-or-nothing:
    // the SDK throws InvalidArgumentException on a half-configured identity
    // too, but failing here names the env var the operator actually got
    // wrong. Both null on p0/p1/p2, which leaves the SDK's default
    // bearer-cookie behaviour untouched (§6.1 rule 5).
    $certPath = $cfg['client_cert_path'];
    $keyPath = $cfg['client_key_path'];
    if (($certPath === null) !== ($keyPath === null)) {
        throw new \RuntimeException(sprintf(
            'BENCH_CLIENT_CERT="%s" and BENCH_CLIENT_KEY="%s" must be set together — mTLS needs both (CONTRACT.md §6.1 rule 1)',
            (string) $certPath,
            (string) $keyPath,
        ));
    }
    $clientCert = null;
    $clientKey = null;
    if ($certPath !== null) {
        $clientCert = @file_get_contents($certPath);
        if ($clientCert === false) {
            throw new \RuntimeException(sprintf('BENCH_CLIENT_CERT="%s" could not be read', $certPath));
        }
        $clientKey = @file_get_contents($keyPath);
        if ($clientKey === false) {
            throw new \RuntimeException(sprintf('BENCH_CLIENT_KEY="%s" could not be read', $keyPath));
        }
    }

    // Single construction site, so the TLS wiring cannot drift between the
    // shared client and the fresh one `login` builds per iteration —
    // configuring only the shared client would pass three ops and fail
    // `login` at the handshake, which reads like a server problem rather than
    // a harness one.
    $newClient = static fn (): \Axiam\Sdk\AxiamClient => new \Axiam\Sdk\AxiamClient(
        $cfg['base_url'],
        $cfg['tenant_slug'],
        $cfg['org_slug'],
        null,
        $cfg['custom_ca'],
        $clientCert,
        $clientKey,
    );

    $client = $newClient();
    $client->login($cfg['username'], $cfg['password']);

    // 3 checks, all using the SAME resource id (batch preserves input order).
    // Keys match the SDK's documented shape: list<array{action, resourceId, scope?}>.
    $checks = [];
    for ($i = 0; $i < 3; $i++) {
        $checks[] = ['action' => $cfg['action'], 'resourceId' => $cfg['resource_id']];
    }

    return [
        'login' => static function () use ($cfg, $newClient): void {
            $fresh = $newClient();
            $fresh->login($cfg['username'], $cfg['password']);
        },
        'refresh' => static fn (): mixed => $client->refresh(),
        'check_access' => static fn (): bool => $client->checkAccess($cfg['action'], $cfg['resource_id']),
        'batch_check' => static fn (): array => $client->batchCheck($checks),
    ];
}

// I9 (improvement-after-run4-benchmark.md §C): a floor below which a
// measured `refresh` latency is not plausibly a real HTTP round trip. The
// C# bench recorded p50 1.2 microseconds ("752 k rps") because its SDK's
// RefreshGuard cached a completed token result on a shared client for up to
// ~15 minutes (wall-clock freshness, no observed-token check), so only the
// FIRST refresh in a ~2200-call run ever touched the wire. This SDK's
// Axiam\Sdk\Auth\RefreshGuard clears its promise slot on both the success
// and failure path of every refresh (see Session.php), so a same-client
// loop keeps hitting the wire on every sequential call — but this floor is
// kept as a language-agnostic regression guard against that class of bug
// reappearing here too (a cache hit completes in low single-digit
// microseconds; every genuine wire call recorded across this harness' 11
// languages averages ~17 ms, so 0.2 ms leaves a wide margin).
const MIN_PLAUSIBLE_REFRESH_MS = 0.2;

/**
 * I9 shared-driver-style regression guard: fail loudly (non-zero exit)
 * instead of silently publishing a fake number if `refresh` looks like it
 * never left the process.
 */
function assert_refresh_hit_the_wire(array $refresh_op, int $iterations): void
{
    $had_samples = $refresh_op['errors'] < $iterations;
    if ($had_samples && $refresh_op['p50_ms'] < MIN_PLAUSIBLE_REFRESH_MS) {
        fwrite(STDERR, sprintf(
            "[php] I9 guard: refresh p50=%.4fms is below the %.1fms plausible-wire-call floor "
                . "despite successful samples — this looks like a cached no-op (CONTRACT.md §9 "
                . "guard reuse), not a real HTTP round trip. Failing the bench run instead of "
                . "publishing a fake number (see improvement-after-run4-benchmark.md I9).\n",
            $refresh_op['p50_ms'],
            MIN_PLAUSIBLE_REFRESH_MS,
        ));
        exit(1);
    }
}

function time_op(callable $fn, int $warmup, int $iter): array
{
    $errors = 0;
    for ($i = 0; $i < $warmup; $i++) {
        try {
            $fn();
        } catch (\Throwable) {
            $errors++;
        }
    }

    $lat = [];
    $start = hrtime(true);
    for ($i = 0; $i < $iter; $i++) {
        $t0 = hrtime(true);
        try {
            $fn();
            $lat[] = (hrtime(true) - $t0) / 1_000_000.0; // ns -> ms
        } catch (\Throwable) {
            $errors++;
        }
    }
    $secs = (hrtime(true) - $start) / 1_000_000_000.0;

    return [
        'p50_ms' => pct($lat, 50),
        'p95_ms' => pct($lat, 95),
        'p99_ms' => pct($lat, 99),
        'throughput_rps' => $secs > 0 ? count($lat) / $secs : 0.0,
        'errors' => $errors,
    ];
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

$autoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoload)) {
    // Graceful degradation, mirroring how python/typescript report a missing
    // SDK: no vendor/ means nothing to time, so emit a `pending` record.
    emit(
        'pending',
        zero_ops(),
        0,
        0,
        'axiam/axiam-sdk not installed — run `composer install` in benchmarks/sdk/php '
            . '(resolves the SDK from the sibling axiam-php-sdk checkout via the path repository).',
    );
    exit(0);
}

require $autoload;

try {
    $ops_fns = build_ops($cfg);
} catch (\Throwable $e) {
    // server not running / seed missing / auth failed
    emit('error', zero_ops(), 0, 0, 'server unreachable or setup failed: ' . $e->getMessage());
    exit(0);
}

$ops = [];
foreach (OP_KEYS as $k) {
    $ops[$k] = time_op($ops_fns[$k], $WARMUP, $ITER);
}

emit(
    'ok',
    $ops,
    $ITER,
    $CONC,
    'single-process synchronous PHP SDK — all ops timed serially (concurrency pinned to 1); '
        . 'SDK_BENCH_CONCURRENCY is ignored.',
);
assert_refresh_hit_the_wire($ops['refresh'], $ITER);
