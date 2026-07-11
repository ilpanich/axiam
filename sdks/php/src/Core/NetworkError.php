<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

use Psr\Http\Message\ResponseInterface;

/**
 * Transport-level failure: connection refused, timeout, TLS error, DNS failure, or a
 * server-side 5xx (CONTRACT.md §2).
 *
 * Redact-before-wrap (D-10/D-11, CR-04 carry-forward): {@see self::fromResponse()} is
 * the ONLY construction path that accepts a live PSR-7 {@see ResponseInterface}, and it
 * strips the `Set-Cookie`/`Authorization`/`Cookie` header VALUES into a sanitized
 * summary string BEFORE the constructor ever runs. There is no public constructor and
 * no path that stores the raw `$response` object (or any wrapped exception that might
 * itself carry one) as this exception's message, cause, or any other property — this
 * structurally prevents the token-leak-via-error class of bug first found in the
 * TypeScript sibling SDK (Phase 17 CR-04, `sdks/typescript/src/core/errorMapper.ts`
 * `sanitizeAxiosError`) and mirrored by every later sibling SDK's `NetworkError`.
 */
final class NetworkError extends AxiamException
{
    /** @var list<string> lowercase header names whose VALUES are never echoed. */
    private const SENSITIVE_HEADERS = ['set-cookie', 'authorization', 'cookie'];

    private function __construct(string $message, ?\Throwable $previous = null)
    {
        // $previous, when given, MUST already be sanitized by the caller (a fresh
        // \RuntimeException carrying only a redacted summary string) — never the raw
        // wrapped exception or response object, since either can carry a live PSR-7
        // response with the same sensitive headers (see class doc). This satisfies
        // CONTRACT.md §2's cause-chaining requirement (getPrevious() !== null) without
        // reintroducing the token-leak-via-cause class of bug the class doc describes.
        parent::__construct($message, previous: $previous);
    }

    /**
     * Builds a NetworkError from a live PSR-7 response. Header NAMES are preserved for
     * debuggability; VALUES of `Set-Cookie`/`Authorization`/`Cookie` are replaced with
     * `[SENSITIVE]` before the summary string is built. The `$response` argument itself
     * is never stored — only the resulting sanitized string survives past this method.
     */
    public static function fromResponse(ResponseInterface $response, string $context = 'HTTP error'): self
    {
        $sanitizedHeaders = [];
        foreach (array_keys($response->getHeaders()) as $name) {
            $value = \in_array(strtolower($name), self::SENSITIVE_HEADERS, true)
                ? '[SENSITIVE]'
                : $response->getHeaderLine($name);
            $sanitizedHeaders[] = $name . ': ' . $value;
        }

        $message = sprintf(
            '%s: HTTP %d — headers: [%s]',
            $context,
            $response->getStatusCode(),
            implode('; ', $sanitizedHeaders)
        );

        return new self($message);
    }

    /**
     * Builds a NetworkError from a caught transport exception (socket/TLS/DNS/timeout
     * failure). The caught exception's own message is defensively regex-sanitized in
     * case a lower-level exception echoed a sensitive header verbatim; the exception
     * itself is never stored as a cause (see class doc).
     */
    public static function fromException(\Throwable $exception, string $context = 'Transport error'): self
    {
        $sanitizedSummary = sprintf('%s: %s', $exception::class, self::sanitizeMessage($exception->getMessage()));

        $message = sprintf('%s: %s', $context, $sanitizedSummary);

        // Chain a SANITIZED stand-in for the original exception as $previous, so
        // getPrevious() !== null (CONTRACT.md §2 MUST: "carry the underlying OS/
        // transport error as a cause"), without ever attaching the raw $exception
        // itself — it (or something it wraps) could carry a live PSR-7 response with
        // the same sensitive headers this class exists to redact (see class doc).
        return new self($message, new \RuntimeException($sanitizedSummary));
    }

    /**
     * Defense-in-depth: strips any `set-cookie`/`authorization`/`cookie`-shaped
     * fragment from an arbitrary string, in case a leaked header fragment reaches a
     * message via a path other than {@see self::fromResponse()}.
     */
    private static function sanitizeMessage(string $raw): string
    {
        return (string) preg_replace(
            '/(set-cookie|authorization|cookie)\s*:\s*[^\r\n]+/i',
            '$1: [SENSITIVE]',
            $raw
        );
    }
}
