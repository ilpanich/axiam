<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\JwksVerifier;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * D-08/D-09 (RESEARCH Pitfall 6): proves JwksVerifier's Guzzle-promise-based
 * in-flight guard collapses N genuinely concurrent, not-yet-awaited
 * `verify()`-triggered refetches to exactly ONE discovery request + ONE JWKS
 * request, even though every caller observes the same cold/unknown-kid cache
 * state before the shared fetch has any chance to resolve.
 *
 * Non-vacuous by construction (Pitfall 6): a plain sequential PHPUnit loop
 * calling `verify()` N times cannot exercise this guard under classic
 * synchronous PHP-FPM -- one request per worker process, no shared memory,
 * no possible interleaving (see {@see JwtVerifyTest::testUnknownKidTriggersExactlyOneRefetchThenFailsClosed()}
 * for that single-call-only scenario). This test instead drives
 * `JwksVerifier`'s internal async fetch entry point (`ensureFreshAsync` --
 * intentionally private; `verify()` itself stays a synchronous public API
 * per CONTRACT.md, it just `->wait()`s on the same guard internally) directly
 * via Reflection: 8 calls are issued WITHOUT individually awaiting the
 * returned promise, so all 8 must join the SAME shared in-flight promise
 * before any of them are driven to completion via
 * `Promise\Utils::settle(...)->wait()` -- genuinely interleaving multiple
 * in-flight fetches within ONE PHP process/request via Guzzle's curl-multi
 * handler, exactly mirroring {@see SingleFlightRefreshTest}'s public-API
 * pattern for token refresh.
 *
 * The MockHandler queue is deliberately sized to exactly 2 responses (1
 * discovery + 1 JWKS): if the guard were missing and each of the 8 calls
 * independently dispatched its own discovery+JWKS request, the queue would
 * run dry well before all 8 are served, producing MANY more than 2 recorded
 * HTTP requests (a mix of served and "Mock queue is empty" failures) instead
 * of exactly 2 -- so this test fails loudly, non-vacuously, if the guard
 * regresses.
 */
final class JwksSingleFlightTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';

    /** @return array<string,mixed> */
    private function jwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded, 'fixture ed25519_jwks.json must decode to an array');

        return $decoded;
    }

    private function callEnsureFreshAsync(JwksVerifier $verifier, string $kid): PromiseInterface
    {
        $method = new ReflectionMethod(JwksVerifier::class, 'ensureFreshAsync');
        $method->setAccessible(true);

        /** @var PromiseInterface $promise */
        $promise = $method->invoke($verifier, $kid);

        return $promise;
    }

    public function testEightInterleavedFetchesTriggerExactlyOneJwksRequest(): void
    {
        $history = [];
        $mock = new MockHandler([
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->jwks())),
        ]);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($history));
        $client = new Client(['handler' => $stack]);

        $verifier = new JwksVerifier($client, 'https://api.test');

        // Fire 8 calls WITHOUT waiting on any individual promise -- all 8
        // observe the same cold, unknown-kid cache state before the shared
        // in-flight fetch has settled.
        $promises = [];
        for ($i = 0; $i < 8; $i++) {
            $promises[] = $this->callEnsureFreshAsync($verifier, 'totally-unknown-kid');
        }

        Utils::settle($promises)->wait();

        self::assertCount(
            2,
            $history,
            'expected exactly one discovery request + one JWKS request across 8 interleaved in-flight fetches',
        );

        $jwksRequests = array_values(array_filter(
            $history,
            static fn (array $t): bool => $t['request']->getUri()->getPath() === '/oauth2/jwks',
        ));
        self::assertCount(
            1,
            $jwksRequests,
            'expected exactly one JWKS request across 8 interleaved in-flight fetches sharing one in-flight guard',
        );

        $discoveryRequests = array_values(array_filter(
            $history,
            static fn (array $t): bool => $t['request']->getUri()->getPath() === '/.well-known/openid-configuration',
        ));
        self::assertCount(
            1,
            $discoveryRequests,
            'the discovery request must also be coalesced under the shared in-flight promise',
        );
    }

    public function testAllJoinedPromisesResolveOnceTheSharedFetchSettles(): void
    {
        $mock = new MockHandler([
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->jwks())),
        ]);
        $client = new Client(['handler' => HandlerStack::create($mock)]);

        $verifier = new JwksVerifier($client, 'https://api.test');

        $promises = [];
        for ($i = 0; $i < 8; $i++) {
            $promises[] = $this->callEnsureFreshAsync($verifier, 'totally-unknown-kid');
        }

        $results = Utils::settle($promises)->wait();

        foreach ($results as $result) {
            self::assertSame(
                'fulfilled',
                $result['state'],
                'every joined caller must observe the shared fetch settle successfully',
            );
        }
    }

    public function testSubsequentVerifyAfterTheSharedFetchReusesTheCacheWithNoExtraFetch(): void
    {
        $history = [];
        // Exactly 2 responses queued (1 discovery + 1 jwks). A second
        // verify() call for a NOW-known kid must be served entirely from the
        // populated cache -- if it attempted another fetch, the MockHandler
        // queue would be empty and the request would fail.
        $mock = new MockHandler([
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->jwks())),
        ]);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($history));
        $client = new Client(['handler' => $stack]);

        $verifier = new JwksVerifier($client, 'https://api.test');

        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($keypair);
        $kid = (string) $keypair['kid'];

        $promises = [];
        for ($i = 0; $i < 8; $i++) {
            $promises[] = $this->callEnsureFreshAsync($verifier, $kid);
        }
        Utils::settle($promises)->wait();

        self::assertCount(2, $history, 'the initial burst must resolve to exactly one discovery + one JWKS request');

        // A subsequent call for the now-cached kid must not touch the HTTP
        // client at all (fresh cache, known kid).
        $this->callEnsureFreshAsync($verifier, $kid)->wait();

        self::assertCount(
            2,
            $history,
            'a subsequent call for an already-cached kid must reuse the resolved keyset with no extra fetch',
        );
    }
}
