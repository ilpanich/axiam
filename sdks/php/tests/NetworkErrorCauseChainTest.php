<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\NetworkError;
use PHPUnit\Framework\TestCase;

/**
 * SDK-Q02: proves {@see NetworkError::fromException()} chains a cause (CONTRACT.md
 * §2 MUST: "`NetworkError` MUST carry the underlying OS/transport error as a `cause`
 * (or equivalent chained exception)"), while preserving the redact-before-wrap
 * guarantee from CR-04 (see {@see NetworkError} class doc) — the chained previous
 * throwable is a sanitized stand-in, never the raw caught exception.
 */
final class NetworkErrorCauseChainTest extends TestCase
{
    public function testGetPreviousIsNonNull(): void
    {
        $original = new \RuntimeException('connection refused');

        $networkError = NetworkError::fromException($original, 'socket error');

        self::assertNotNull($networkError->getPrevious());
    }

    /**
     * Non-vacuous control: the chained previous is NOT the same instance as the raw
     * caught exception — it must be a fresh, sanitized stand-in, since the raw
     * exception (or something it wraps) could itself carry a live PSR-7 response with
     * sensitive header values (see NetworkError class doc / CR-04).
     */
    public function testPreviousIsASanitizedStandInNotTheRawException(): void
    {
        $original = new \RuntimeException('connect failed, Authorization: Bearer super-secret-token-xyz');

        $networkError = NetworkError::fromException($original, 'socket error');
        $previous = $networkError->getPrevious();

        self::assertNotSame($original, $previous);
        self::assertNotNull($previous);
        self::assertStringNotContainsString('super-secret-token-xyz', $previous->getMessage());
        self::assertStringContainsString('[SENSITIVE]', $previous->getMessage());
        self::assertStringNotContainsString('super-secret-token-xyz', $networkError->getMessage());
    }
}
