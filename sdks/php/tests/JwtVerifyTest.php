<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\JwksVerifier;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Drives JwksVerifier's four security-critical behaviors against the real
 * Ed25519/JWKS/JWT fixtures committed in tests/Fixtures/ (22-02 Task 1):
 *  - Pitfall 5 / T-alg-confusion: alg-pin rejection before any key lookup.
 *  - Pitfall 3 / T-cross-tenant: post-signature tenant_id mismatch rejection.
 *  - Happy path: valid signature + matching tenant_id returns claims.
 *  - D-08 / T-DoS: an unknown kid triggers exactly one JWKS refetch, still-unknown
 *    after refetch fails closed (never loops).
 */
final class JwtVerifyTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const FIXTURE_TENANT = 'acme-tenant';

    /** @return array<string,mixed> */
    private function jwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded, 'fixture ed25519_jwks.json must decode to an array');

        return $decoded;
    }

    private function jwt(): string
    {
        return trim((string) file_get_contents(self::FIXTURES . '/ed25519_signed_jwt.txt'));
    }

    /** @return array{0:string,1:string} [base64url secret key, kid] from the committed keypair fixture. */
    private function keypair(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($decoded);

        return [$decoded['secret_key_b64url'], $decoded['kid']];
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks']));
    }

    private function jwksResponse(): Response
    {
        return new Response(200, [], (string) json_encode($this->jwks()));
    }

    private function clientWithQueue(array $queue, array &$history = []): Client
    {
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($history));

        return new Client(['handler' => $stack]);
    }

    private function base64url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private function base64urlDecode(string $b64url): string
    {
        return (string) base64_decode(strtr($b64url, '-_', '+/'), true);
    }

    // --- Happy path -----------------------------------------------------------------

    public function testHappyPathReturnsClaims(): void
    {
        $client = $this->clientWithQueue([$this->discoveryResponse(), $this->jwksResponse()]);
        $verifier = new JwksVerifier($client, 'https://api.test');

        $claims = $verifier->verify($this->jwt(), self::FIXTURE_TENANT);

        self::assertIsArray($claims);
        self::assertSame(self::FIXTURE_TENANT, $claims['tenant_id']);
        self::assertSame('user-fixture-0001', $claims['sub']);
    }

    // --- Pitfall 5 / T-alg-confusion: alg-pin BEFORE key lookup ----------------------

    public function testAlgPinRejectsNoneAlgWithoutAnyKeyLookup(): void
    {
        // Empty mock queue: if verify() attempted a key lookup, Guzzle's MockHandler
        // would throw "Mock queue is empty" instead of the verifier returning null --
        // proving the rejection happens strictly before any HTTP call.
        $client = $this->clientWithQueue([]);
        $verifier = new JwksVerifier($client, 'https://api.test');

        $tampered = $this->withTamperedHeader($this->jwt(), ['alg' => 'none']);

        self::assertNull($verifier->verify($tampered, self::FIXTURE_TENANT));
    }

    public function testAlgPinRejectsRs256WithoutAnyKeyLookup(): void
    {
        $client = $this->clientWithQueue([]);
        $verifier = new JwksVerifier($client, 'https://api.test');

        $tampered = $this->withTamperedHeader($this->jwt(), ['alg' => 'RS256']);

        self::assertNull($verifier->verify($tampered, self::FIXTURE_TENANT));
    }

    // --- Pitfall 3 / T-cross-tenant: post-signature tenant_id check ------------------

    public function testTenantMismatchOnOriginalFixtureReturnsNull(): void
    {
        $client = $this->clientWithQueue([$this->discoveryResponse(), $this->jwksResponse()]);
        $verifier = new JwksVerifier($client, 'https://api.test');

        self::assertNull($verifier->verify($this->jwt(), 'some-other-tenant'));
    }

    public function testTenantMismatchOnReSignedTokenReturnsNull(): void
    {
        // Build a wrong-tenant variant by re-signing a fresh payload with the
        // committed fixture keypair -- a validly-signed token whose tenant_id simply
        // does not match what the caller expects. Signature validity alone must NOT
        // be enough (JWKS is organization-wide, not tenant-scoped).
        [$secretKeyB64Url, $kid] = $this->keypair();
        $secretKey = $this->base64urlDecode($secretKeyB64Url);
        $wrongTenantJwt = JWT::encode(
            ['sub' => 'user-fixture-0001', 'tenant_id' => 'wrong-tenant', 'exp' => 4102444800],
            base64_encode($secretKey),
            'EdDSA',
            $kid
        );

        $client = $this->clientWithQueue([$this->discoveryResponse(), $this->jwksResponse()]);
        $verifier = new JwksVerifier($client, 'https://api.test');

        self::assertNull($verifier->verify($wrongTenantJwt, self::FIXTURE_TENANT));
    }

    // --- D-08: unknown kid triggers exactly one refetch, then fails closed ----------

    public function testUnknownKidTriggersExactlyOneRefetchThenFailsClosed(): void
    {
        $history = [];
        // Exactly 2 responses queued (1 discovery + 1 jwks). If the verifier attempted
        // a second refetch, Guzzle's MockHandler would throw "Mock queue is empty"
        // instead of returning null -- proving at most one refetch occurs.
        $client = $this->clientWithQueue([$this->discoveryResponse(), $this->jwksResponse()], $history);
        $verifier = new JwksVerifier($client, 'https://api.test');

        $tampered = $this->withTamperedHeader($this->jwt(), ['kid' => 'totally-unknown-kid']);

        self::assertNull($verifier->verify($tampered, self::FIXTURE_TENANT));
        self::assertCount(2, $history, 'expected exactly one discovery + one jwks fetch (one refetch attempt)');
    }

    // --- SDK-19 / T-key-substitution: discovered jwks_uri must be same-origin https --

    private function discoveryWith(string $jwksUri): Response
    {
        return new Response(200, [], (string) json_encode(['jwks_uri' => $jwksUri]));
    }

    public function testSameOriginHttpsJwksUriIsHonoured(): void
    {
        $history = [];
        $client = $this->clientWithQueue(
            [$this->discoveryWith('https://api.test/oauth2/jwks'), $this->jwksResponse()],
            $history,
        );
        $verifier = new JwksVerifier($client, 'https://api.test');

        $claims = $verifier->verify($this->jwt(), self::FIXTURE_TENANT);

        self::assertIsArray($claims, 'a valid same-origin https jwks_uri must be used and yield claims');
        self::assertSame('https://api.test/oauth2/jwks', (string) $history[1]['request']->getUri());
    }

    public function testOffHostJwksUriIsRejectedAndFallsBackToBaseUrl(): void
    {
        $history = [];
        $client = $this->clientWithQueue(
            [$this->discoveryWith('https://evil.example/oauth2/jwks'), $this->jwksResponse()],
            $history,
        );
        $verifier = new JwksVerifier($client, 'https://api.test');

        // Still resolves (the fallback URL is served from the queue), but the
        // attacker-controlled off-host URL must NEVER be the one fetched.
        self::assertIsArray($verifier->verify($this->jwt(), self::FIXTURE_TENANT));
        self::assertSame('https://api.test/oauth2/jwks', (string) $history[1]['request']->getUri());
    }

    public function testPlaintextHttpJwksUriIsRejectedAndFallsBackToBaseUrl(): void
    {
        $history = [];
        $client = $this->clientWithQueue(
            [$this->discoveryWith('http://api.test/oauth2/jwks'), $this->jwksResponse()],
            $history,
        );
        $verifier = new JwksVerifier($client, 'https://api.test');

        self::assertIsArray($verifier->verify($this->jwt(), self::FIXTURE_TENANT));
        self::assertSame('https://api.test/oauth2/jwks', (string) $history[1]['request']->getUri());
    }

    public function testOffPortJwksUriIsRejectedAndFallsBackToBaseUrl(): void
    {
        $history = [];
        $client = $this->clientWithQueue(
            [$this->discoveryWith('https://api.test:9443/oauth2/jwks'), $this->jwksResponse()],
            $history,
        );
        $verifier = new JwksVerifier($client, 'https://api.test');

        self::assertIsArray($verifier->verify($this->jwt(), self::FIXTURE_TENANT));
        self::assertSame('https://api.test/oauth2/jwks', (string) $history[1]['request']->getUri());
    }

    // --- Malformed input: never throws, always fails closed --------------------------

    public function testMalformedTokenInputReturnsNullNeverThrows(): void
    {
        $client = $this->clientWithQueue([]);
        $verifier = new JwksVerifier($client, 'https://api.test');

        self::assertNull($verifier->verify('not-a-jwt', self::FIXTURE_TENANT));
        self::assertNull($verifier->verify('', self::FIXTURE_TENANT));
        self::assertNull($verifier->verify('only.two-parts', self::FIXTURE_TENANT));
    }

    /** @param array<string,mixed> $overrides */
    private function withTamperedHeader(string $jwt, array $overrides): string
    {
        [$headerB64, $payloadB64, $sigB64] = explode('.', $jwt);
        $header = json_decode($this->base64urlDecode($headerB64), true);
        self::assertIsArray($header);
        $header = array_merge($header, $overrides);
        $tamperedHeaderB64 = $this->base64url((string) json_encode($header));

        return $tamperedHeaderB64 . '.' . $payloadB64 . '.' . $sigB64;
    }
}
