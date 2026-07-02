<?php

declare(strict_types=1);

/**
 * examples/login_mfa.php — demonstrates the one-line `composer require` +
 * `$client->login(...)` developer experience (SC#1, CONTRACT.md §1), including the
 * two-phase MFA flow: `login()` -> branch on `mfaRequired` -> `verifyMfa()`.
 *
 * Uses ONLY the public `AxiamClient` API — no internal collaborator (Session,
 * AuthMiddleware, AuthzDispatcher, ...) is touched directly, exactly as an application
 * consuming this SDK would.
 *
 * Run: php examples/login_mfa.php
 * (requires a reachable AXIAM server at AXIAM_BASE_URL; a login/MFA failure here is
 * expected in a sandbox with no live server — this example is illustrative/compilable,
 * not a live-server smoke test.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Auth\LoginResult;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AxiamException;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$baseUrl = envOr('AXIAM_BASE_URL', 'https://localhost:8443');
$tenant = envOr('AXIAM_TENANT', 'acme'); // §5/D-13: tenant is a REQUIRED constructor arg
$email = envOr('AXIAM_EMAIL', 'alice@acme.test');
$password = envOr('AXIAM_PASSWORD', 'correct horse battery staple');

// §6/D-12: `verify` defaults to strict TLS. AXIAM_CUSTOM_CA (a CA bundle FILE PATH) is
// the ONLY escape hatch, intended for local development against a self-signed cert —
// there is no option on this class that disables TLS verification.
$customCa = getenv('AXIAM_CUSTOM_CA') ?: null;

$client = new AxiamClient(
    baseUrl: $baseUrl,
    tenant: $tenant, // required, no default (D-13) — this line alone proves SC#1
    customCa: $customCa,
);

try {
    $result = $client->login($email, $password);
} catch (AuthError $e) {
    fwrite(STDERR, "login failed: " . $e->getMessage() . "\n");
    exit(1);
} catch (AxiamException $e) {
    fwrite(STDERR, "login request failed: " . $e->getMessage() . "\n");
    exit(1);
}

// login() ALWAYS returns a typed LoginResult (D-09) — never a raw array/stdClass.
assert($result instanceof LoginResult);

if ($result->mfaRequired) {
    printf("MFA challenge required for %s — completing the second phase...\n", $email);

    // In a real application, the TOTP code comes from the user (an authenticator app),
    // not an environment variable — AXIAM_TOTP_CODE exists here purely so this example
    // stays a single non-interactive script.
    $totpCode = envOr('AXIAM_TOTP_CODE', '000000');

    try {
        // $result->challengeToken is a Sensitive-wrapped value (D-11) — passed straight
        // through to verifyMfa() without ever being revealed as a plain string here.
        $result = $client->verifyMfa($result->challengeToken, $totpCode);
    } catch (AuthError $e) {
        fwrite(STDERR, "MFA verification failed: " . $e->getMessage() . "\n");
        exit(1);
    }
}

// $result->mfaRequired is now false: a fully-authenticated session is established.
printf("Logged in as user %s (tenant: %s)\n", $result->userId ?? '(unknown)', $result->tenantId ?? $tenant);

// checkAccess()/can()/batchCheck() (see examples/rest_authz.php) are now usable on this
// SAME $client instance — the authenticated session's cookies/CSRF are shared
// automatically (§4 cookie jar, §3 non-browser CSRF).

// refresh() reuses the SAME single-flight guard RefreshMiddleware triggers reactively on
// a 401 (D-06, §9) — calling it explicitly here is optional; most applications never
// need to.
try {
    $client->refresh();
    echo "Token refreshed.\n";
} catch (AuthError $e) {
    fwrite(STDERR, "refresh failed (expected without a live server): " . $e->getMessage() . "\n");
}

// logout() clears the local cookie jar and captured CSRF token (this example's own
// session, not the server's other active sessions).
try {
    $client->logout();
    echo "Logged out.\n";
} catch (AuthError $e) {
    fwrite(STDERR, "logout failed: " . $e->getMessage() . "\n");
}
