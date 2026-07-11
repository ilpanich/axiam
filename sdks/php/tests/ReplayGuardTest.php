<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Amqp\ReplayGuard;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the NEW-4 (CONTRACT.md §8 "v2 — Replay Protection") gates
 * in isolation, independent of HMAC verification or the AMQP transport.
 */
final class ReplayGuardTest extends TestCase
{
    private const FIXED_NOW = 1_800_000_000; // arbitrary fixed unix timestamp

    private static function guard(int $skewSeconds = 300, int $now = self::FIXED_NOW): ReplayGuard
    {
        return new ReplayGuard($skewSeconds, static fn (): int => $now);
    }

    private static function isoAt(int $unixTs): string
    {
        return (new \DateTimeImmutable('@' . $unixTs))->format('Y-m-d\TH:i:s\Z');
    }

    public function testAcceptsAFreshV2MessageAndRecordsItsNonce(): void
    {
        $guard = self::guard();

        $result = $guard->check([
            'key_version' => 2,
            'nonce' => 'nonce-1',
            'issued_at' => self::isoAt(self::FIXED_NOW),
        ]);

        self::assertNull($result);
        self::assertSame(1, $guard->trackedNonceCount());
    }

    public function testRejectsKeyVersionBelowMinimum(): void
    {
        $guard = self::guard();

        $result = $guard->check([
            'key_version' => 1,
            'nonce' => 'nonce-kv1',
            'issued_at' => self::isoAt(self::FIXED_NOW),
        ]);

        self::assertSame('key_version', $result);
    }

    public function testRejectsMissingKeyVersion(): void
    {
        $guard = self::guard();

        $result = $guard->check([
            'nonce' => 'nonce-missing-kv',
            'issued_at' => self::isoAt(self::FIXED_NOW),
        ]);

        self::assertSame('key_version', $result);
    }

    public function testRejectsStaleIssuedAtInThePast(): void
    {
        $guard = self::guard(skewSeconds: 300);

        $result = $guard->check([
            'key_version' => 2,
            'nonce' => 'nonce-stale-past',
            'issued_at' => self::isoAt(self::FIXED_NOW - 301),
        ]);

        self::assertSame('issued_at', $result);
    }

    public function testRejectsIssuedAtTooFarInTheFuture(): void
    {
        $guard = self::guard(skewSeconds: 300);

        $result = $guard->check([
            'key_version' => 2,
            'nonce' => 'nonce-stale-future',
            'issued_at' => self::isoAt(self::FIXED_NOW + 301),
        ]);

        self::assertSame('issued_at', $result);
    }

    public function testAcceptsIssuedAtExactlyAtTheSkewBoundary(): void
    {
        $guard = self::guard(skewSeconds: 300);

        $result = $guard->check([
            'key_version' => 2,
            'nonce' => 'nonce-boundary',
            'issued_at' => self::isoAt(self::FIXED_NOW - 300),
        ]);

        self::assertNull($result);
    }

    public function testRejectsMalformedIssuedAt(): void
    {
        $guard = self::guard();

        $result = $guard->check([
            'key_version' => 2,
            'nonce' => 'nonce-malformed',
            'issued_at' => 'not-a-timestamp',
        ]);

        self::assertSame('issued_at', $result);
    }

    public function testRejectsMissingOrEmptyNonce(): void
    {
        $guard = self::guard();

        $missing = $guard->check([
            'key_version' => 2,
            'issued_at' => self::isoAt(self::FIXED_NOW),
        ]);
        self::assertSame('nonce', $missing);

        $empty = $guard->check([
            'key_version' => 2,
            'nonce' => '',
            'issued_at' => self::isoAt(self::FIXED_NOW),
        ]);
        self::assertSame('nonce', $empty);
    }

    public function testRejectsAReplayedNonceOnSecondDelivery(): void
    {
        $guard = self::guard();
        $message = [
            'key_version' => 2,
            'nonce' => 'nonce-replay',
            'issued_at' => self::isoAt(self::FIXED_NOW),
        ];

        self::assertNull($guard->check($message), 'first delivery of this nonce must be accepted');
        self::assertSame('nonce', $guard->check($message), 'second delivery of the SAME nonce must be rejected as a replay');
    }

    public function testDifferentNoncesAreIndependentlyTracked(): void
    {
        $guard = self::guard();

        self::assertNull($guard->check(['key_version' => 2, 'nonce' => 'a', 'issued_at' => self::isoAt(self::FIXED_NOW)]));
        self::assertNull($guard->check(['key_version' => 2, 'nonce' => 'b', 'issued_at' => self::isoAt(self::FIXED_NOW)]));
        self::assertSame(2, $guard->trackedNonceCount());
    }

    public function testNonceEntriesArePrunedAfterTwiceTheSkewWindow(): void
    {
        $skew = 300;
        $guard = new ReplayGuard($skew, static fn (): int => self::FIXED_NOW);

        self::assertNull($guard->check([
            'key_version' => 2,
            'nonce' => 'nonce-to-be-pruned',
            'issued_at' => self::isoAt(self::FIXED_NOW),
        ]));
        self::assertSame(1, $guard->trackedNonceCount());

        // Advance the clock past the nonce's TTL (2xskew) by constructing a
        // guard with the SAME backing seen-set is not possible (state is
        // private), so instead verify pruning behavior indirectly: a guard
        // whose clock has moved past the TTL, when checking a brand new
        // unrelated nonce, must prune the old bounded entry. We emulate an
        // advancing clock with a mutable reference.
        $now = self::FIXED_NOW;
        $advancingGuard = new ReplayGuard($skew, static function () use (&$now): int {
            return $now;
        });

        self::assertNull($advancingGuard->check([
            'key_version' => 2,
            'nonce' => 'nonce-expiring',
            'issued_at' => self::isoAt($now),
        ]));
        self::assertSame(1, $advancingGuard->trackedNonceCount());

        // Move the clock forward past the TTL (2xskew = 600s).
        $now += (2 * $skew) + 1;

        // A fresh, unrelated check at the new time both prunes the expired
        // entry and is itself accepted.
        self::assertNull($advancingGuard->check([
            'key_version' => 2,
            'nonce' => 'nonce-fresh-at-later-time',
            'issued_at' => self::isoAt($now),
        ]));
        self::assertSame(1, $advancingGuard->trackedNonceCount(), 'the expired nonce must have been pruned, leaving only the new one');

        // And the original nonce, if it were replayed "now", would in fact
        // no longer be tracked -- but note its issued_at would also now be
        // stale, so this proves pruning happened via the count above rather
        // than re-testing acceptance of a now-stale timestamp.
    }

    public function testConstructorRejectsNonPositiveSkew(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ReplayGuard(0);
    }
}
