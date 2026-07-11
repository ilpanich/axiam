<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Amqp\AmqpDropMessage;
use Axiam\Sdk\Amqp\Consumer;
use Axiam\Sdk\Amqp\ReplayGuard;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for Consumer::verifyAndDispatch's full NEW-4 pipeline
 * (CONTRACT.md §8 "v2 — Replay Protection"): HMAC verification, THEN the
 * ReplayGuard gates (key_version, issued_at freshness, nonce replay), THEN
 * the handler/ack-nack matrix -- exercised without a live broker via fake
 * ack/nack/handler callables (Consumer::verifyAndDispatch is extracted
 * exactly for this purpose).
 */
final class ConsumerReplayProtectionTest extends TestCase
{
    private const SIGNING_KEY = 'consumer-replay-protection-test-key';

    /**
     * Signs $bodyWithoutSig using the exact canonicalization Hmac::verify
     * uses (json_encode with JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
     * and returns the full wire body with `hmac_signature` appended last.
     *
     * @param array<string, mixed> $bodyWithoutSig
     */
    private static function signedWireBody(array $bodyWithoutSig, string $key = self::SIGNING_KEY): string
    {
        $canonical = json_encode($bodyWithoutSig, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        self::assertIsString($canonical);
        $sigHex = hash_hmac('sha256', $canonical, $key);

        $withSig = $bodyWithoutSig;
        $withSig['hmac_signature'] = $sigHex;
        $encoded = json_encode($withSig, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        self::assertIsString($encoded);

        return $encoded;
    }

    private static function isoAt(int $unixTs): string
    {
        return (new \DateTimeImmutable('@' . $unixTs))->format('Y-m-d\TH:i:s\Z');
    }

    /**
     * @return array{acked: int, nackedNoRequeue: int, nackedRequeue: int, handlerCalls: array<int, array<string, mixed>>}
     */
    private static function runDelivery(Consumer $consumer, string $body, ?callable $handler = null): array
    {
        $result = ['acked' => 0, 'nackedNoRequeue' => 0, 'nackedRequeue' => 0, 'handlerCalls' => []];
        $handler ??= static function (array $event) use (&$result): void {
            $result['handlerCalls'][] = $event;
        };

        $consumer->verifyAndDispatch(
            $body,
            $handler,
            ack: static function () use (&$result): void {
                ++$result['acked'];
            },
            nackNoRequeue: static function () use (&$result): void {
                ++$result['nackedNoRequeue'];
            },
            nackRequeue: static function () use (&$result): void {
                ++$result['nackedRequeue'];
            },
        );

        return $result;
    }

    public function testAcceptsAValidV2MessageInvokesHandlerAndAcks(): void
    {
        $now = 1_800_000_000;
        $guard = new ReplayGuard(300, static fn (): int => $now);
        $consumer = new Consumer(self::SIGNING_KEY, replayGuard: $guard);

        $body = self::signedWireBody([
            'correlation_id' => '11111111-1111-1111-1111-111111111111',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'subject_id' => '33333333-3333-3333-3333-333333333333',
            'action' => 'read',
            'resource_id' => '44444444-4444-4444-4444-444444444444',
            'key_version' => 2,
            'nonce' => 'accept-nonce-1',
            'issued_at' => self::isoAt($now),
        ]);

        $result = self::runDelivery($consumer, $body);

        self::assertSame(1, $result['acked']);
        self::assertSame(0, $result['nackedNoRequeue']);
        self::assertSame(0, $result['nackedRequeue']);
        self::assertCount(1, $result['handlerCalls']);
        self::assertSame('read', $result['handlerCalls'][0]['action']);
        self::assertArrayNotHasKey('hmac_signature', $result['handlerCalls'][0]);
    }

    public function testHmacVerificationFailureNacksWithoutRequeueAndNeverInvokesHandler(): void
    {
        $guard = new ReplayGuard(300, static fn (): int => 1_800_000_000);
        $consumer = new Consumer(self::SIGNING_KEY, replayGuard: $guard);

        // Signed with the WRONG key -> HMAC verification fails before the
        // replay gate is ever reached.
        $body = self::signedWireBody([
            'correlation_id' => '11111111-1111-1111-1111-111111111111',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'subject_id' => '33333333-3333-3333-3333-333333333333',
            'action' => 'read',
            'resource_id' => '44444444-4444-4444-4444-444444444444',
            'key_version' => 2,
            'nonce' => 'wrong-key-nonce',
            'issued_at' => self::isoAt(1_800_000_000),
        ], key: 'a-completely-different-key');

        $result = self::runDelivery($consumer, $body);

        self::assertSame(0, $result['acked']);
        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame(0, $result['nackedRequeue']);
        self::assertCount(0, $result['handlerCalls']);
    }

    public function testRejectsKeyVersion1NacksWithoutRequeueAndNeverInvokesHandler(): void
    {
        $now = 1_800_000_000;
        $guard = new ReplayGuard(300, static fn (): int => $now);
        $consumer = new Consumer(self::SIGNING_KEY, replayGuard: $guard);

        // A validly HMAC-signed v1 body (no replay-protection fields) --
        // proves the HMAC gate passes and the key_version gate is what
        // rejects it (hard cutover, NEW-4, no grace path).
        $body = self::signedWireBody([
            'correlation_id' => '11111111-1111-1111-1111-111111111111',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'subject_id' => '33333333-3333-3333-3333-333333333333',
            'action' => 'read',
            'resource_id' => '44444444-4444-4444-4444-444444444444',
            'key_version' => 1,
            'nonce' => 'v1-nonce',
            'issued_at' => self::isoAt($now),
        ]);

        $result = self::runDelivery($consumer, $body);

        self::assertSame(0, $result['acked']);
        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame(0, $result['nackedRequeue']);
        self::assertCount(0, $result['handlerCalls']);
    }

    public function testRejectsStaleIssuedAtNacksWithoutRequeueAndNeverInvokesHandler(): void
    {
        $now = 1_800_000_000;
        $guard = new ReplayGuard(300, static fn (): int => $now);
        $consumer = new Consumer(self::SIGNING_KEY, replayGuard: $guard);

        $body = self::signedWireBody([
            'correlation_id' => '11111111-1111-1111-1111-111111111111',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'subject_id' => '33333333-3333-3333-3333-333333333333',
            'action' => 'read',
            'resource_id' => '44444444-4444-4444-4444-444444444444',
            'key_version' => 2,
            'nonce' => 'stale-nonce',
            'issued_at' => self::isoAt($now - 3600), // 1 hour stale, default skew is 300s
        ]);

        $result = self::runDelivery($consumer, $body);

        self::assertSame(0, $result['acked']);
        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame(0, $result['nackedRequeue']);
        self::assertCount(0, $result['handlerCalls']);
    }

    public function testRejectsAReplayedNonceOnSecondDeliveryWhileFirstDeliveryStillAcks(): void
    {
        $now = 1_800_000_000;
        $guard = new ReplayGuard(300, static fn (): int => $now);
        $consumer = new Consumer(self::SIGNING_KEY, replayGuard: $guard);

        $bodyFields = [
            'correlation_id' => '11111111-1111-1111-1111-111111111111',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'subject_id' => '33333333-3333-3333-3333-333333333333',
            'action' => 'read',
            'resource_id' => '44444444-4444-4444-4444-444444444444',
            'key_version' => 2,
            'nonce' => 'duplicate-nonce',
            'issued_at' => self::isoAt($now),
        ];
        $body = self::signedWireBody($bodyFields);

        // First delivery of this nonce: HMAC verifies, replay gate passes,
        // handler runs, message acks.
        $first = self::runDelivery($consumer, $body);
        self::assertSame(1, $first['acked']);
        self::assertSame(0, $first['nackedNoRequeue']);
        self::assertCount(1, $first['handlerCalls']);

        // Second delivery of the SAME nonce (same Consumer instance -- one
        // ReplayGuard shared across deliveries, per NEW-4): HMAC verifies
        // again, but the replay gate now rejects it.
        $second = self::runDelivery($consumer, $body);
        self::assertSame(0, $second['acked']);
        self::assertSame(1, $second['nackedNoRequeue']);
        self::assertSame(0, $second['nackedRequeue']);
        self::assertCount(0, $second['handlerCalls'], 'handler must not be invoked again on a replayed nonce');
    }

    public function testHandlerThrowingAmqpDropMessageNacksWithoutRequeueAfterReplayGatePasses(): void
    {
        $now = 1_800_000_000;
        $guard = new ReplayGuard(300, static fn (): int => $now);
        $consumer = new Consumer(self::SIGNING_KEY, replayGuard: $guard);

        $body = self::signedWireBody([
            'correlation_id' => '11111111-1111-1111-1111-111111111111',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'subject_id' => '33333333-3333-3333-3333-333333333333',
            'action' => 'read',
            'resource_id' => '44444444-4444-4444-4444-444444444444',
            'key_version' => 2,
            'nonce' => 'poison-nonce',
            'issued_at' => self::isoAt($now),
        ]);

        $result = self::runDelivery($consumer, $body, static function (): void {
            throw new AmqpDropMessage('poison');
        });

        self::assertSame(0, $result['acked']);
        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame(0, $result['nackedRequeue']);
    }

    public function testHandlerThrowingGenericExceptionNacksWithRequeueAfterReplayGatePasses(): void
    {
        $now = 1_800_000_000;
        $guard = new ReplayGuard(300, static fn (): int => $now);
        $consumer = new Consumer(self::SIGNING_KEY, replayGuard: $guard);

        $body = self::signedWireBody([
            'correlation_id' => '11111111-1111-1111-1111-111111111111',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'subject_id' => '33333333-3333-3333-3333-333333333333',
            'action' => 'read',
            'resource_id' => '44444444-4444-4444-4444-444444444444',
            'key_version' => 2,
            'nonce' => 'transient-nonce',
            'issued_at' => self::isoAt($now),
        ]);

        $result = self::runDelivery($consumer, $body, static function (): void {
            throw new \RuntimeException('transient failure');
        });

        self::assertSame(0, $result['acked']);
        self::assertSame(0, $result['nackedNoRequeue']);
        self::assertSame(1, $result['nackedRequeue']);
    }
}
