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

function emit(string $status, array $ops, int $iterations, int $concurrency, string $notes): void
{
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
        'client_cpu_ms_total' => 0,
        'client_rss_mib_peak' => 0,
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
    $client = new \Axiam\Sdk\AxiamClient($cfg['base_url'], $cfg['tenant_slug'], $cfg['org_slug']);
    $client->login($cfg['username'], $cfg['password']);

    // 3 checks, all using the SAME resource id (batch preserves input order).
    // Keys match the SDK's documented shape: list<array{action, resourceId, scope?}>.
    $checks = [];
    for ($i = 0; $i < 3; $i++) {
        $checks[] = ['action' => $cfg['action'], 'resourceId' => $cfg['resource_id']];
    }

    return [
        'login' => static function () use ($cfg): void {
            $fresh = new \Axiam\Sdk\AxiamClient($cfg['base_url'], $cfg['tenant_slug'], $cfg['org_slug']);
            $fresh->login($cfg['username'], $cfg['password']);
        },
        'refresh' => static fn (): mixed => $client->refresh(),
        'check_access' => static fn (): bool => $client->checkAccess($cfg['action'], $cfg['resource_id']),
        'batch_check' => static fn (): array => $client->batchCheck($checks),
    ];
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
