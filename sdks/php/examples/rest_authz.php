<?php

declare(strict_types=1);

/**
 * examples/rest_authz.php — demonstrates `checkAccess()`/`can()`/`batchCheck()` over the
 * ALWAYS-available REST authz transport (FND-04, CONTRACT.md §1, D-03), via the public
 * `AxiamClient` facade only — the same three methods transparently upgrade to gRPC when
 * the `grpc` PECL extension is available (see examples/grpc_checkaccess.php), with no
 * application code change required.
 *
 * This example constructs the client with `restOnly: true` explicitly, since it is only
 * demonstrating the REST path; a real application typically leaves `restOnly` at its
 * default (`null`, auto-resolving to REST-only unless a `grpcTarget` is configured).
 *
 * Run: php examples/rest_authz.php
 * (requires a reachable AXIAM server at AXIAM_BASE_URL and an authenticated session —
 * see examples/login_mfa.php; a failure here is expected in a sandbox with no live
 * server — this example is illustrative/compilable, not a live-server smoke test.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\AxiamException;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$baseUrl = envOr('AXIAM_BASE_URL', 'https://localhost:8443');
$tenant = envOr('AXIAM_TENANT', 'acme'); // §5/D-13: tenant is a REQUIRED constructor arg
$resourceId = envOr('AXIAM_RESOURCE_ID', 'doc-0001');

// §6/D-12: `verify` defaults to strict TLS; AXIAM_CUSTOM_CA (a CA bundle FILE PATH) is
// the ONLY escape hatch — never a TLS-disable option.
$customCa = getenv('AXIAM_CUSTOM_CA') ?: null;

$client = new AxiamClient(
    baseUrl: $baseUrl,
    tenant: $tenant, // required, no default (D-13)
    customCa: $customCa,
    restOnly: true, // this example is illustrating the REST transport specifically
);

// A real application logs in first (see examples/login_mfa.php) so the shared session
// (§4 cookie jar) carries a valid access token before calling checkAccess(); this
// example assumes that has already happened (e.g. within the same process, or a prior
// request in the same PHP-FPM worker).

try {
    // `checkAccess` (CONTRACT.md §1): explicit action + resource.
    $allowed = $client->checkAccess('document:read', $resourceId);
    printf("checkAccess('document:read', '%s') -> allowed: %s\n", $resourceId, $allowed ? 'true' : 'false');

    // `can` (CONTRACT.md §1 note): the browser/UI-scenario alias — same endpoint,
    // same (action, resource) argument order as `checkAccess()` (SDK-Q09).
    $canRead = $client->can('document:read', $resourceId);
    printf("can('document:read', '%s') -> %s\n", $resourceId, $canRead ? 'true' : 'false');

    // `batchCheck` (CONTRACT.md §1): results preserve input order.
    $results = $client->batchCheck([
        ['action' => 'document:read', 'resourceId' => $resourceId],
        ['action' => 'document:delete', 'resourceId' => $resourceId, 'scope' => 'admin'],
    ]);
    foreach ($results as $i => $result) {
        printf("batchCheck[%d] -> allowed: %s\n", $i, $result ? 'true' : 'false');
    }
} catch (AuthzError $e) {
    fwrite(STDERR, "authorization denied: " . $e->getMessage() . "\n");
    exit(1);
} catch (AxiamException $e) {
    fwrite(STDERR, "authz request failed (expected without a live server/session): " . $e->getMessage() . "\n");
    exit(1);
}
