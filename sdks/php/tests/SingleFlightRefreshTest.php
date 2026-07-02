<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Rest\AuthMiddleware;
use Axiam\Sdk\Rest\RefreshMiddleware;
use Axiam\Sdk\Session;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Utils;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * SC#2 regression test (CONTRACT.md §9, D-06): N (=5) concurrent Guzzle async
 * promises against an expired token MUST trigger exactly ONE
 * `/api/v1/auth/refresh` call, with all five original requests retried once the
 * shared refresh resolves.
 *
 * Non-vacuous by construction: the `MockHandler` queue is deliberately ordered with
 * ALL FIVE 401 responses BEFORE the single refresh 200. `MockHandler` dequeues
 * synchronously at the point each request is dispatched, but Guzzle promise
 * callbacks (including `RefreshMiddleware`'s 401 check and `Session::refreshIfNeeded`)
 * are drained from a FIFO task queue only once `Utils::all(...)->wait()` runs — so
 * all five 401-triggered callbacks observe `refreshIfNeeded()` BEFORE the refresh
 * call's own resolution (which clears the guard) is processed. If the responses were
 * queued 401→refresh→200→401→refresh→200..., the single-flight guard would never be
 * genuinely exercised and this test would pass even if the shared-promise guard were
 * removed — this ordering is load-bearing for a meaningful assertion.
 *
 * Also asserts the refresh request BODY (not just the call count): the fixture access
 * token seeded into the shared cookie jar carries `tenant_id`/`org_id` claims, and the
 * captured `/api/v1/auth/refresh` request must send exactly `{tenant_id, org_id}` per
 * `sdks/openapi.json`'s `RefreshRequest` schema — never a bare `tenant` slug field
 * (the pre-fix defect: see `Session::refreshIfNeeded()`'s doc comment).
 */
final class SingleFlightRefreshTest extends TestCase
{
    private const TENANT = 'acme';
    private const FIXTURE_TENANT_ID = '11111111-1111-1111-1111-111111111111';
    private const FIXTURE_ORG_ID = '22222222-2222-2222-2222-222222222222';

    /**
     * A JWT-SHAPED (header.payload.signature) access token whose payload carries
     * `tenant_id`/`org_id` claims — deliberately UNSIGNED (arbitrary third segment):
     * {@see Session}'s refresh-body resolution only ever base64url-decodes the
     * payload segment and never checks the signature (that is exclusively
     * {@see \Axiam\Sdk\Auth\JwksVerifier::verify()}'s job), so a real signature adds
     * nothing to this test's non-vacuousness.
     */
    private function fixtureAccessToken(): string
    {
        $header = $this->base64url((string) json_encode(['alg' => 'EdDSA', 'typ' => 'JWT']));
        $payload = $this->base64url((string) json_encode([
            'sub' => 'user-fixture-0001',
            'tenant_id' => self::FIXTURE_TENANT_ID,
            'org_id' => self::FIXTURE_ORG_ID,
            'exp' => 9999999999,
        ]));

        return $header . '.' . $payload . '.unsigned-test-fixture-signature';
    }

    private function base64url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    public function testFiveConcurrentExpiredRequestsTriggerExactlyOneRefresh(): void
    {
        $container = [];
        $history = Middleware::history($container);

        $mock = new MockHandler([
            // 5 initial calls against an expired token — ALL queued BEFORE the
            // refresh response so the guard is genuinely exercised (see class doc).
            new Response(401),
            new Response(401),
            new Response(401),
            new Response(401),
            new Response(401),
            // The ONE refresh call.
            new Response(200, ['X-CSRF-Token' => 'csrf-abc'], '{}'),
            // 5 retries, now succeeding with the refreshed session.
            new Response(200),
            new Response(200),
            new Response(200),
            new Response(200),
            new Response(200),
        ]);

        $stack = HandlerStack::create($mock);
        $stack->push($history, 'history');

        // Seed the shared cookie jar with a claims-bearing access token BEFORE any
        // request fires, so Session::refreshIfNeeded() can resolve tenant_id/org_id
        // from it (mirrors a real post-login state) — see Session::accessToken().
        $cookieJar = new CookieJar();
        $cookieJar->setCookie(new SetCookie([
            'Name' => 'axiam_access',
            'Value' => $this->fixtureAccessToken(),
            'Domain' => 'api.test',
            'Path' => '/',
        ]));

        // Session's own refresh POST is sent through this SAME stack/mock queue, so
        // the refresh call is counted by the same $container as the 5 concurrent
        // requests below.
        $refreshHttp = new Client(['handler' => $stack]);
        $session = new Session('https://api.test', self::TENANT, $refreshHttp, $cookieJar);

        $stack->push(new AuthMiddleware($session), 'axiam_auth');
        $stack->push(new RefreshMiddleware($session), 'axiam_refresh');

        $client = new Client(['handler' => $stack]);

        $promises = [];
        for ($i = 0; $i < 5; $i++) {
            $promises[] = $client->getAsync('/api/v1/authz/check');
        }

        $responses = Utils::all($promises)->wait();

        foreach ($responses as $response) {
            self::assertSame(200, $response->getStatusCode(), 'every original request must succeed after the shared refresh');
        }

        $refreshCalls = array_values(array_filter(
            $container,
            static fn (array $transaction): bool => $transaction['request']->getUri()->getPath() === '/api/v1/auth/refresh',
        ));

        self::assertCount(
            1,
            $refreshCalls,
            'expected exactly one refresh call across 5 concurrent requests sharing an expired token',
        );

        $refreshBody = json_decode((string) $refreshCalls[0]['request']->getBody(), true);
        self::assertIsArray($refreshBody, 'refresh request body must be valid JSON');
        self::assertSame(
            self::FIXTURE_TENANT_ID,
            $refreshBody['tenant_id'] ?? null,
            'refresh request body must carry tenant_id resolved from the access token claims (sdks/openapi.json RefreshRequest)',
        );
        self::assertSame(
            self::FIXTURE_ORG_ID,
            $refreshBody['org_id'] ?? null,
            'refresh request body must carry org_id resolved from the access token claims (sdks/openapi.json RefreshRequest)',
        );
        self::assertArrayNotHasKey(
            'tenant',
            $refreshBody,
            'refresh request body must NOT send a bare tenant slug field — RefreshRequest has no such field',
        );

        self::assertSame(
            'csrf-abc',
            $session->csrfToken(),
            'the X-CSRF-Token captured from the refresh response must be stored on the session',
        );
    }
}
