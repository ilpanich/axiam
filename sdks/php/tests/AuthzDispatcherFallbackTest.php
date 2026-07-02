<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AuthzDispatcher;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Proves Pitfall 4 / T-22-16 (high severity, `mitigate`): on a runtime WITHOUT the
 * `grpc` PECL extension (the real condition in this sandbox — `extension_loaded('grpc')`
 * is false here), `AuthzDispatcher::checkAccess()`/`can()`/`batchCheck()` route over
 * REST with NO fatal, and `\Axiam\Sdk\Grpc\AuthzGrpcClient` (which `extends
 * \Grpc\BaseStub`, a class that does not exist in this environment) is never
 * autoloaded/instantiated.
 *
 * Non-vacuousness: this test is only meaningful if it can genuinely fail. It was
 * verified manually (see 22-05-SUMMARY.md) by temporarily forcing AuthzDispatcher's
 * gRPC branch to execute unconditionally — the test then failed with a real
 * `Error: Class "Grpc\BaseStub" not found` fatal, confirming this suite would catch a
 * regression that removed the guard. The `restOnly: true` constructor flag exercised
 * below is the SAME code path a REST-only-configured caller uses on a runtime that DOES
 * have the extension — both the "extension absent" and "explicit restOnly" branches of
 * the guard's `!$this->restOnly && extension_loaded('grpc')` condition are exercised.
 */
final class AuthzDispatcherFallbackTest extends TestCase
{
    private function makeRestClient(array $responses, array &$history): AuthzRestClient
    {
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($history));
        $http = new Client(['handler' => $stack, 'base_uri' => 'https://api.test']);

        return new AuthzRestClient($http);
    }

    public function testExtensionAbsentRoutesCheckAccessOverRestWithNoFatal(): void
    {
        self::assertFalse(
            extension_loaded('grpc'),
            'this test only proves what it claims when the grpc extension is genuinely absent',
        );

        $history = [];
        $rest = $this->makeRestClient(
            [new Response(200, [], json_encode(['allowed' => true]))],
            $history,
        );
        $dispatcher = new AuthzDispatcher($rest);

        $result = $dispatcher->checkAccess('users:get', '11111111-1111-1111-1111-111111111111');

        self::assertTrue($result);
        self::assertCount(1, $history);
        self::assertSame('/api/v1/authz/check', $history[0]['request']->getUri()->getPath());
    }

    public function testExtensionAbsentRoutesCanOverRestWithNoFatal(): void
    {
        $history = [];
        $rest = $this->makeRestClient(
            [new Response(200, [], json_encode(['allowed' => false]))],
            $history,
        );
        $dispatcher = new AuthzDispatcher($rest);

        $result = $dispatcher->can('documents', 'read');

        self::assertFalse($result);
        self::assertCount(1, $history);
    }

    public function testExtensionAbsentRoutesBatchCheckOverRestWithNoFatal(): void
    {
        $history = [];
        $rest = $this->makeRestClient(
            [new Response(200, [], json_encode([
                'results' => [['allowed' => true], ['allowed' => false]],
            ]))],
            $history,
        );
        $dispatcher = new AuthzDispatcher($rest);

        $result = $dispatcher->batchCheck([
            ['action' => 'a', 'resourceId' => 'r1'],
            ['action' => 'b', 'resourceId' => 'r2', 'scope' => 'admin'],
        ]);

        self::assertSame([true, false], $result);
        self::assertCount(1, $history);
        self::assertSame('/api/v1/authz/check/batch', $history[0]['request']->getUri()->getPath());
    }

    public function testExplicitRestOnlyFlagRoutesOverRestEvenIfExtensionWerePresent(): void
    {
        // Exercises the OTHER half of the guard's `!$this->restOnly && ...` condition —
        // an explicit restOnly=true opt-out must win regardless of extension_loaded().
        $history = [];
        $rest = $this->makeRestClient(
            [new Response(200, [], json_encode(['allowed' => true]))],
            $history,
        );
        $dispatcher = new AuthzDispatcher($rest, restOnly: true);

        $result = $dispatcher->checkAccess('users:get', '11111111-1111-1111-1111-111111111111');

        self::assertTrue($result);
        self::assertCount(1, $history);
    }

    public function testNoGrpcClassIsAutoloadedOnTheRestOnlyPath(): void
    {
        // Grpc\BaseStub genuinely does not exist in this sandbox (no ext-grpc, no
        // grpc/grpc composer package) — if AuthzDispatcher ever autoloaded
        // AuthzGrpcClient.php on this path, class_exists() below would itself trigger
        // the fatal via PSR-4 autoloading. Calling it with $autoload=false only checks
        // whether the class was ALREADY loaded (proving no eager reference occurred);
        // this call happens only AFTER the REST round-trips above already succeeded.
        self::assertFalse(
            class_exists(\Axiam\Sdk\Grpc\AuthzGrpcClient::class, false),
            'AuthzGrpcClient must never be autoloaded on a REST-only path (Pitfall 4 / T-22-16)',
        );
    }
}
