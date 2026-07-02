<?php

declare(strict_types=1);

/**
 * examples/grpc_checkaccess.php — demonstrates the OPT-IN gRPC authorization transport
 * (AuthzDispatcher -> AuthzGrpcClient, CONTRACT.md §1/§6/§9, D-03/D-12).
 *
 * ============================================================================
 *  RUNTIME REQUIREMENT (SC#3 — READ BEFORE RUNNING):
 *
 *  The gRPC transport requires:
 *    1. The `grpc` PECL extension installed and enabled (`extension_loaded('grpc')`
 *       must return true) — NOT available on a stock PHP install.
 *    2. A LONG-RUNNING PHP runtime: Swoole, RoadRunner, or a plain CLI script/worker.
 *       A classic PHP-FPM request (share-nothing, per-request process/thread) is NOT a
 *       suitable host for a reused gRPC channel — every request would pay full
 *       TLS+HTTP/2 handshake cost, defeating the entire point of choosing gRPC over
 *       REST. This example is itself a plain CLI script (`php examples/
 *       grpc_checkaccess.php`), the simplest form of "long-running enough" runtime.
 *    3. Without BOTH of the above, `AuthzDispatcher` transparently and correctly
 *       routes over REST instead (D-03) — this is not a degraded mode, it is the
 *       INTENDED behavior, and no code change is required to fall back; simply run
 *       this same example on a REST-only host and every call below still returns a
 *       correct decision, just over `POST /api/v1/authz/check[/batch]` instead of gRPC.
 * ============================================================================
 *
 * This example is illustrative/compilable — it never fatals even when `ext-grpc` is
 * absent (the actual condition in this SDK's own CI/dev sandbox), because
 * AuthzDispatcher's `extension_loaded('grpc')` guard (Pitfall 4 / T-22-16) transparently
 * falls back to REST. Running the gRPC branch for real additionally requires a
 * reachable AXIAM gRPC endpoint.
 *
 * Run: php examples/grpc_checkaccess.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AuthzDispatcher;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$baseUrl = envOr('AXIAM_BASE_URL', 'https://localhost:8443');
$grpcTarget = envOr('AXIAM_GRPC_TARGET', 'localhost:9443');
$tenantId = envOr('AXIAM_TENANT_ID', '00000000-0000-0000-0000-000000000000');
$subjectId = envOr('AXIAM_SUBJECT_ID', '00000000-0000-0000-0000-000000000000');
$resourceId = envOr('AXIAM_RESOURCE_ID', '00000000-0000-0000-0000-000000000000');

// A minimal Guzzle client for the always-available REST fallback — a real
// integration wires this the same way Session does (CookieJar + HandlerStack with
// AuthMiddleware/RefreshMiddleware); this example keeps it minimal to stay focused on
// the gRPC-vs-REST dispatch behavior itself.
$http = new Client([
    'base_uri' => $baseUrl,
    'cookies' => new CookieJar(),
    'verify' => true, // §6/D-12: strict TLS always on, no bypass in this example
]);
$restClient = new AuthzRestClient($http);

// The token accessor and subject-id accessor below would normally read live off the
// SAME Session instance backing $restClient (D-06 — never a second refresh mechanism).
// This example hardcodes an env-supplied token for illustration only.
$dispatcher = new AuthzDispatcher(
    restClient: $restClient,
    grpcTarget: $grpcTarget,
    tenantId: $tenantId,
    tokenAccessor: static fn (): ?string => getenv('AXIAM_ACCESS_TOKEN') ?: null,
    subjectIdAccessor: static fn (): string => $subjectId,
);

// extension_loaded('grpc') is checked internally on EVERY call — no separate
// "which transport am I using" branch is needed in application code (SC#3's whole
// point: the SAME method call works everywhere).
$transport = extension_loaded('grpc') ? 'gRPC (if AXIAM_GRPC_TARGET is reachable)' : 'REST (grpc extension absent — automatic fallback, D-03)';
printf("AuthzDispatcher will route over: %s\n", $transport);

$allowed = $dispatcher->checkAccess('resource:read', $resourceId);
printf("checkAccess('resource:read') -> allowed: %s\n", $allowed ? 'true' : 'false');

$results = $dispatcher->batchCheck([
    ['action' => 'resource:read', 'resourceId' => $resourceId],
    ['action' => 'resource:delete', 'resourceId' => $resourceId, 'scope' => 'admin'],
]);
foreach ($results as $i => $result) {
    printf("batchCheck[%d] -> allowed: %s\n", $i, $result ? 'true' : 'false');
}
