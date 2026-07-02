<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

use Psr\Http\Message\ResponseInterface;

/**
 * Central status→error mapper (CONTRACT.md §2, D-10). {@see self::fromStatus()} is the
 * single translation point from an HTTP status code to a typed {@see AxiamException}
 * subtype — no other class in the SDK is permitted to hand-roll this branching:
 * 401 → {@see AuthError}; 403/409 → {@see AuthzError}; everything else
 * (400/408/429/5xx/transport) → {@see NetworkError}.
 */
final class ErrorMapper
{
    /**
     * The single translation point. When a live PSR-7 `$response` is available, pass
     * it so a resulting {@see NetworkError} can build its redacted header summary via
     * {@see NetworkError::fromResponse()}; otherwise a status-only {@see NetworkError}
     * is built via {@see NetworkError::fromException()}.
     */
    public static function fromStatus(
        int $status,
        ?ResponseInterface $response = null,
        string $context = 'AXIAM API error',
    ): AxiamException {
        return match (true) {
            $status === 401 => new AuthError(sprintf('%s: unauthenticated (HTTP 401)', $context)),
            \in_array($status, [403, 409], true) => new AuthzError(sprintf('%s: forbidden (HTTP %d)', $context, $status)),
            $response !== null => NetworkError::fromResponse($response, $context),
            default => NetworkError::fromException(new \RuntimeException(sprintf('HTTP %d', $status)), $context),
        };
    }

    /**
     * Convenience wrapper for callers that already hold a live PSR-7 response —
     * delegates to {@see self::fromStatus()}, the single translation point.
     */
    public static function fromResponse(ResponseInterface $response, string $context = 'AXIAM API error'): AxiamException
    {
        return self::fromStatus($response->getStatusCode(), $response, $context);
    }
}
