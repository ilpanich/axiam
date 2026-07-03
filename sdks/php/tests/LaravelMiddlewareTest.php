<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\AxiamGate;
use Axiam\Sdk\Laravel\AxiamMiddleware;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * SC#4-Laravel proof (CONTRACT.md §10, D-02): drives {@see AxiamMiddleware} and
 * {@see AxiamGate} — both auth (401 on missing/invalid token, identity population on a
 * valid one) and authz (`can()` -> 403 on deny, pass on allow) — through a REAL
 * {@see AxiamClient} instance wired with a `MockHandler` (the same
 * `transportHandler`-seam idiom every other REST test in this suite already uses, e.g.
 * {@see JwtVerifyTest}, {@see ClientConstructionTest}), never a PHPUnit mock object
 * (which cannot double `AxiamClient` — it is `final`, by design). This directly proves
 * the D-02 prohibition ("never duplicate JWKS-verify or refresh logic in the bridge —
 * call AxiamClient methods") because the SAME `JwksVerifier`/`AuthzRestClient` code
 * paths {@see JwtVerifyTest}/{@see AuthzDispatcherFallbackTest} already cover run here,
 * reached exclusively through the public `AxiamClient` surface the bridge calls.
 */
final class LaravelMiddlewareTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const FIXTURE_TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    private function fixtureJwt(): string
    {
        return trim((string) file_get_contents(self::FIXTURES . '/ed25519_signed_jwt.txt'));
    }

    /** @return array<string,mixed> */
    private function fixtureJwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded, 'fixture ed25519_jwks.json must decode to an array');

        return $decoded;
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks']));
    }

    private function jwksResponse(): Response
    {
        return new Response(200, [], (string) json_encode($this->fixtureJwks()));
    }

    /** @param list<Response> $queue */
    private function clientWith(array $queue, string $tenant = self::FIXTURE_TENANT): AxiamClient
    {
        return new AxiamClient(self::BASE_URL, $tenant, transportHandler: new MockHandler($queue));
    }

    private function passthroughNext(): \Closure
    {
        return static fn (Request $request): JsonResponse => new JsonResponse(['ok' => true], 200);
    }

    // --- Auth (D-02, §10): 401 on missing token -------------------------------------

    public function testMissingTokenReturns401(): void
    {
        // Empty MockHandler queue: the middleware must reject BEFORE ever reaching the
        // client (no HTTP call attempted) when no token is present at all.
        $client = $this->clientWith([]);
        $middleware = new AxiamMiddleware($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('AuthError', $body['error']);
        self::assertNull($request->attributes->get('axiam_user'));
    }

    // --- Auth (D-02, §10): 401 on an invalid/malformed token (fail-closed) ----------

    public function testInvalidTokenReturns401(): void
    {
        // A malformed token fails JwksVerifier::verify() immediately (not a 3-part
        // JWT); verifyLocallyOrFallback() then attempts the reactive-refresh fallback,
        // which itself fails against the empty MockHandler queue and is caught,
        // returning null (fail-closed) -- proving 401 even when a fallback is
        // attempted and fails, not just on the "never even tried" happy path above.
        $client = $this->clientWith([]);
        $middleware = new AxiamMiddleware($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer not-a-real-jwt');
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertNull($request->attributes->get('axiam_user'));
    }

    // --- Auth (D-02, §10): valid token populates axiam_user and passes through ------

    public function testValidTokenPopulatesIdentityAndPasses(): void
    {
        $client = $this->clientWith([$this->discoveryResponse(), $this->jwksResponse()]);
        $middleware = new AxiamMiddleware($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->fixtureJwt());
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(200, $response->getStatusCode(), 'a valid token must reach $next($request)');
        self::assertSame(
            ['user_id' => 'user-fixture-0001', 'tenant_id' => self::FIXTURE_TENANT, 'roles' => []],
            $request->attributes->get('axiam_user'),
        );
    }

    // --- Authz (D-02): can() deny -> 403 ----------------------------------------

    public function testGateDenyReturns403(): void
    {
        // Two responses queued: `allows()` and `authorize()` below each independently
        // call through to AxiamClient::can() (no client-side caching, D-02) — this is
        // two real REST round-trips, not one.
        $client = $this->clientWith([
            new Response(200, [], (string) json_encode(['allowed' => false])),
            new Response(200, [], (string) json_encode(['allowed' => false])),
        ]);
        $gate = new AxiamGate($client);

        self::assertFalse($gate->allows('documents', 'read'));

        $response = $gate->authorize('documents', 'read');
        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('AuthzError', $body['error']);
    }

    // --- Authz (D-02): can() allow -> passes (null, caller proceeds) ---------------

    public function testGateAllowPasses(): void
    {
        $client = $this->clientWith([
            new Response(200, [], (string) json_encode(['allowed' => true])),
            new Response(200, [], (string) json_encode(['allowed' => true])),
        ]);
        $gate = new AxiamGate($client);

        self::assertTrue($gate->allows('documents', 'read'));
        self::assertNull($gate->authorize('documents', 'read'), 'an allowed check must return null (caller proceeds)');
    }
}
