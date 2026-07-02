<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Auth\RefreshGuard;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Per-`AxiamClient` session state (CONTRACT.md §3/§4/§5/§9): owns the shared Guzzle
 * `CookieJar` (§4), captures/exposes the non-browser CSRF token (§3), and is the
 * single-flight home for the shared refresh `Promise` (§9, D-06).
 *
 * `tenant` is a required constructor parameter with no nullable default (D-13) — there
 * is no default-tenant fallback anywhere in this class or in any of its callers.
 *
 * `refreshIfNeeded()` returns the SAME `PromiseInterface` to every concurrent caller
 * until it settles. The check-and-store below (the `null` check immediately followed
 * by the assignment) executes synchronously — nothing in between calls `->wait()` or
 * yields — so it is safe without a mutex even under N concurrent async callers sharing
 * one `Session` instance (D-06's "fiber-safe by construction" claim; PHP Fibers are
 * cooperative/non-preemptive, and Guzzle's own promise resolution never interleaves
 * mid-statement).
 *
 * The `$http` client passed in is used directly for the refresh POST. In production
 * wiring (a later plan assembles `AxiamClient`), that client is expected to be
 * constructed WITHOUT `RefreshMiddleware` attached, so a 401 response to the refresh
 * call itself can never recursively re-enter the single-flight guard; this plan does
 * not need to solve that wiring, only provide the guard itself.
 */
final class Session
{
    private ?PromiseInterface $refreshPromise = null;

    private ?string $csrfToken = null;

    private readonly CookieJar $cookieJar;

    public function __construct(
        private readonly string $baseUrl,
        private readonly string $tenant,
        private readonly Client $http,
        ?CookieJar $cookieJar = null,
    ) {
        $this->cookieJar = $cookieJar ?? new CookieJar();
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    public function tenant(): string
    {
        return $this->tenant;
    }

    /** §4: the single cookie jar every REST-facing Guzzle client MUST share. */
    public function cookieJar(): CookieJar
    {
        return $this->cookieJar;
    }

    /** §3 non-browser CSRF: the most recently captured `X-CSRF-Token` response header. */
    public function csrfToken(): ?string
    {
        return $this->csrfToken;
    }

    /**
     * The current access token, read live from the shared cookie jar's `axiam_access`
     * entry rather than cached separately — avoids a second, potentially-stale, copy
     * of the token (mirrors `sdks/java`'s `SessionState::cachedAccessToken()` and
     * `sdks/go`'s `cookieValue()` helper).
     */
    public function accessToken(): ?string
    {
        return $this->cookieValue('axiam_access');
    }

    private function cookieValue(string $name): ?string
    {
        foreach ($this->cookieJar as $cookie) {
            if ($cookie->getName() === $name) {
                return $cookie->getValue();
            }
        }

        return null;
    }

    /**
     * Returns the SAME `PromiseInterface` to every caller until it resolves (SC#2,
     * D-06). On success: captures the `X-CSRF-Token` response header, then clears the
     * stored promise. On failure: clears the stored promise and rejects with
     * `AuthError` — no retry loop (§9.3). Clear-on-both-paths bookkeeping and the
     * failure-to-`AuthError` translation are factored into {@see RefreshGuard::settle()}
     * so REST and (later) gRPC never re-implement — or drift on — that one mechanism;
     * {@see RefreshGuard::settle()}'s `$onClear` closure below is invoked on EITHER
     * outcome, never on both, never on neither.
     */
    public function refreshIfNeeded(): PromiseInterface
    {
        if ($this->refreshPromise !== null) {
            return $this->refreshPromise;
        }

        // Check-and-store completes synchronously here — nothing above this point
        // awaits or yields, so no concurrent caller can observe a null
        // $refreshPromise again until this whole method returns.
        $refreshCall = $this->http->postAsync('/api/v1/auth/refresh', [
            'json' => ['tenant' => $this->tenant],
        ]);

        $this->refreshPromise = RefreshGuard::settle(
            $refreshCall,
            onClear: function (): void {
                $this->refreshPromise = null;
            },
            onSuccess: function (ResponseInterface $response): ResponseInterface {
                $this->captureCsrfToken($response);
                return $response;
            },
        );

        return $this->refreshPromise;
    }

    private function captureCsrfToken(ResponseInterface $response): void
    {
        // §3 non-browser CSRF: capture the X-CSRF-Token response header, echoed later
        // on mutating requests by AuthMiddleware.
        $token = $response->getHeaderLine('X-CSRF-Token');
        if ($token !== '') {
            $this->csrfToken = $token;
        }
    }
}
