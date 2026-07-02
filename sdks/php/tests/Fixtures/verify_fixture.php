#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Standalone fixture self-check (22-02 Task 1).
 *
 * Confirms empirically (mirroring the Java/C# siblings' "confirm before committing"
 * approach) that the committed `ed25519_signed_jwt.txt` verifies against the committed
 * `ed25519_jwks.json` via firebase/php-jwt: parses the JWKS with `JWK::parseKeySet`,
 * decodes the JWT, and prints the `tenant_id` claim. Exits non-zero on any failure.
 *
 * Run: `cd sdks/php && php tests/Fixtures/verify_fixture.php`
 */

require __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

$fixturesDir = __DIR__;

$jwks = json_decode(
    (string) file_get_contents($fixturesDir . '/ed25519_jwks.json'),
    true
);
$jwt = trim((string) file_get_contents($fixturesDir . '/ed25519_signed_jwt.txt'));

if (!is_array($jwks)) {
    fwrite(STDERR, "FAIL: ed25519_jwks.json did not decode to an array\n");
    exit(1);
}

$keys = JWK::parseKeySet($jwks);
$decoded = JWT::decode($jwt, $keys);
$claims = (array) $decoded;

if (!isset($claims['tenant_id'])) {
    fwrite(STDERR, "FAIL: decoded claims missing tenant_id\n");
    exit(1);
}

echo "OK: fixture JWT verifies against fixture JWKS via firebase/php-jwt\n";
echo "tenant_id: " . $claims['tenant_id'] . "\n";
echo "sub: " . ($claims['sub'] ?? '(none)') . "\n";

exit(0);
