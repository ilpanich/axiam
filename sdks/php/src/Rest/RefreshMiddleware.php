<?php

declare(strict_types=1);

namespace Axiam\Sdk\Rest;

use Axiam\Sdk\Session;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * `HandlerStack` middleware: on a `401` response, triggers the session's single-flight
 * refresh (CONTRACT.md §9, D-06, SC#2) and retries the ORIGINAL request exactly once
 * via the inner `$handler` — never a loop. All concurrent 401-triggering requests on
 * one {@see Session} share the SAME refresh `PromiseInterface`
 * ({@see Session::refreshIfNeeded()}), so N concurrent expired-token requests still
 * result in exactly one `/api/v1/auth/refresh` call.
 *
 * Registered OUTSIDE (further from the base handler than) {@see AuthMiddleware} on the
 * `HandlerStack`, so the retry — invoked via the `$handler` captured here, which is
 * everything BELOW this middleware, i.e. `AuthMiddleware` + the base handler — never
 * re-enters this middleware's own 401 check a second time (retry-exactly-once by
 * construction, not by an explicit retry counter).
 */
final class RefreshMiddleware
{
    /** @param Session $session Session whose access token is refreshed on a 401. */
    public function __construct(private readonly Session $session)
    {
    }

    /**
     * Wraps the next Guzzle handler so a 401 triggers a single-flight token refresh and one
     * replay of the original request.
     *
     * The replay is issued through the NEXT handler rather than the top of the stack, so it
     * cannot re-enter this middleware's 401 check — retry-exactly-once by construction, with no
     * explicit retry counter and no infinite refresh loop.
     *
     * @param callable $handler Next handler in the Guzzle stack.
     *
     * @return callable Decorated handler.
     */
    public function __invoke(callable $handler): callable
    {
        return function (RequestInterface $request, array $options) use ($handler) {
            return $handler($request, $options)->then(
                function (ResponseInterface $response) use ($request, $options, $handler) {
                    if ($response->getStatusCode() !== 401) {
                        return $response;
                    }

                    // Single-flight: every concurrent 401-triggering request calls
                    // refreshIfNeeded() and is handed back the SAME Promise (D-06) —
                    // the retry below fires exactly once per request, no loop.
                    return $this->session->refreshIfNeeded()->then(
                        static fn (): \GuzzleHttp\Promise\PromiseInterface => $handler($request, $options),
                    );
                },
            );
        };
    }
}
