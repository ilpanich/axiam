<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\AxiamException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;

/**
 * Local EdDSA/Ed25519 JWKS verification (CONTRACT.md D-08).
 *
 * Keys are sourced via OIDC discovery (`GET /.well-known/openid-configuration` ->
 * `jwks_uri`, falling back to `{baseUrl}/oauth2/jwks` if discovery is unavailable or
 * omits `jwks_uri`), TTL-cached, and refetched exactly once when an unknown `kid` is
 * encountered before failing closed.
 *
 * Two security invariants (every sibling SDK independently confirmed both):
 *  - Pitfall 5 / T-alg-confusion: the header `alg` is pinned to `EdDSA` BEFORE any key
 *    lookup is attempted. A token never gets to choose its own verification algorithm.
 *  - Pitfall 3 / T-cross-tenant: `GET /oauth2/jwks` is organization-wide, not
 *    tenant-scoped, so a validly-signed token for a different tenant under the same
 *    organization must still be rejected. The `tenant_id` claim is checked AFTER
 *    signature verification succeeds.
 *
 * Deliberately does NOT use firebase/php-jwt's `CachedKeySet` convenience class — it
 * requires a PSR-18 client + PSR-17 request factory + PSR-6 cache pool, a dependency
 * chain D-07 explicitly avoids. This hand-rolled TTL cache mirrors every sibling SDK's
 * own JWKS-cache shape (e.g. `sdks/python/src/axiam_sdk/_jwks.py`).
 *
 * `verify()` never throws on attacker-controlled token input — malformed/short/
 * non-3-part tokens, unknown algorithms, unknown kids, and bad signatures all return
 * `null` (fail closed). The only thrown exception is the `ext-sodium`-missing guard,
 * which is an environment/deployment misconfiguration, not attacker input.
 */
final class JwksVerifier
{
    /** @var array<string,\Firebase\JWT\Key>|null */
    private ?array $keysByKid = null;

    private int $fetchedAt = 0;

    public function __construct(
        private readonly ClientInterface $http,
        private readonly string $baseUrl,
        private readonly int $cacheTtlSeconds = 300,
    ) {
    }

    /**
     * @return array<string,mixed>|null Verified claims, or null on any verification
     *                                   failure (never throws on attacker input).
     */
    public function verify(string $jwt, string $expectedTenantId): ?array
    {
        if (!extension_loaded('sodium')) {
            // ext-sodium is compiled into PHP core by default since 7.2, but a small
            // subset of minimal/distroless builds compile --without-sodium. Fail with
            // a clear, actionable error rather than a cryptic "Call to undefined
            // function" fatal deep inside firebase/php-jwt's EdDSA branch.
            throw new AxiamException(
                'ext-sodium is required for EdDSA JWT verification but is not loaded'
            );
        }

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }

        $header = $this->decodeHeader($parts[0]);
        if ($header === null || ($header['alg'] ?? null) !== 'EdDSA') {
            // Alg-pin BEFORE key lookup (Pitfall 5) — never trust the token to select
            // its own verifier, and never attempt a key lookup for a rejected alg.
            return null;
        }

        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            return null;
        }

        $this->ensureFresh($kid);
        if (!isset($this->keysByKid[$kid])) {
            return null; // unknown kid even after a forced refetch
        }

        try {
            $decoded = JWT::decode($jwt, $this->keysByKid);
        } catch (\Throwable) {
            return null;
        }
        $claims = (array) $decoded;

        // JWKS is organization-wide, not tenant-scoped (Pitfall 3) — signature
        // validity alone does NOT imply tenant authorization. Checked strictly AFTER
        // signature verification succeeds.
        if (($claims['tenant_id'] ?? null) !== $expectedTenantId) {
            return null;
        }

        return $claims;
    }

    /** @return array<string,mixed>|null */
    private function decodeHeader(string $headerSegment): ?array
    {
        $decoded = base64_decode(strtr($headerSegment, '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        try {
            $header = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($header) ? $header : null;
    }

    private function ensureFresh(string $unknownKid): void
    {
        $expired = (time() - $this->fetchedAt) > $this->cacheTtlSeconds;
        $unknown = !isset($this->keysByKid[$unknownKid]);
        if ($this->keysByKid !== null && !$expired && !$unknown) {
            return;
        }

        // Resolve jwks_uri fresh via OIDC discovery on every refetch (cheap, avoids a
        // second hardcoded path constant drifting from the server's actual
        // configuration).
        $jwksUri = $this->baseUrl . '/oauth2/jwks';
        try {
            $discoveryBody = (string) $this->http
                ->request('GET', '/.well-known/openid-configuration')
                ->getBody();
            $discovery = json_decode($discoveryBody, true);
            if (is_array($discovery) && is_string($discovery['jwks_uri'] ?? null) && $discovery['jwks_uri'] !== '') {
                $jwksUri = $discovery['jwks_uri'];
            }
        } catch (\Throwable) {
            // Discovery unavailable — fall back to the conventional /oauth2/jwks path.
        }

        try {
            $jwksBody = (string) $this->http->request('GET', $jwksUri)->getBody();
            $jwksJson = json_decode($jwksBody, true);
            if (!is_array($jwksJson)) {
                return; // leave the existing (possibly null) cache untouched on failure
            }
            $this->keysByKid = JWK::parseKeySet($jwksJson);
            $this->fetchedAt = time();
        } catch (\Throwable) {
            // Fetch/parse failure — leave the existing cache (if any) untouched;
            // verify() will fail closed on an unknown/missing kid.
        }
    }
}
