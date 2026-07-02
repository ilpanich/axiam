<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Rest\AuthMiddleware;
use Axiam\Sdk\Rest\RefreshMiddleware;
use Axiam\Sdk\Session;
use GuzzleHttp\Client;
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
 */
final class SingleFlightRefreshTest extends TestCase
{
    private const TENANT = 'acme';

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

        // Session's own refresh POST is sent through this SAME stack/mock queue, so
        // the refresh call is counted by the same $container as the 5 concurrent
        // requests below.
        $refreshHttp = new Client(['handler' => $stack]);
        $session = new Session('https://api.test', self::TENANT, $refreshHttp);

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

        self::assertSame(
            'csrf-abc',
            $session->csrfToken(),
            'the X-CSRF-Token captured from the refresh response must be stored on the session',
        );
    }
}
