<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Auth\RefreshGuard;
use Axiam\Sdk\Core\AuthError;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Promise\Create;
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
     * Clears the captured CSRF token — called by {@see \Axiam\Sdk\AxiamClient::logout()} so a
     * logged-out session never echoes a stale `X-CSRF-Token` on a subsequent (re-authenticated)
     * request. Purely additive: does not change {@see self::csrfToken()}'s or
     * {@see self::refreshIfNeeded()}'s existing behavior in any other way.
     */
    public function resetCsrf(): void
    {
        $this->csrfToken = null;
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
        // $refreshPromise again until this whole method returns. This holds
        // whether buildRefreshCall() below returns a real in-flight HTTP
        // promise or an immediately-rejected one (unresolvable tenant_id/org_id) —
        // either way exactly ONE PromiseInterface is stored and shared.
        $refreshCall = $this->buildRefreshCall();

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

    /**
     * Builds the `/api/v1/auth/refresh` request per `sdks/openapi.json`'s
     * `RefreshRequest` schema (`{tenant_id, org_id}`, both UUIDs — there is no
     * `tenant` slug field on this endpoint). Both identifiers are resolved from the
     * CURRENT access token's unverified claims (mirrors the C# sibling's
     * `AxiamClient::DoHttpRefreshAsync`/`DecodeUnverifiedClaims`): this is a base64url
     * decode of the JWT payload segment only — the signature is never checked here,
     * since the token was already trusted at login/verify time and this call only
     * reads the SDK's own claims to build the wire body.
     *
     * When no access token is available, or `tenant_id`/`org_id` cannot be resolved
     * from it, an immediately-rejected promise carrying an {@see AuthError} is
     * returned instead of throwing synchronously — so this failure still flows
     * through the SAME single-flight `RefreshGuard::settle()` clear-on-both-paths
     * bookkeeping as a real HTTP failure, and every concurrent caller sharing this
     * `Session` observes the identical rejection (SC#2's single-flight guarantee is
     * not weakened by this validation step).
     */
    private function buildRefreshCall(): PromiseInterface
    {
        $accessToken = $this->accessToken();
        if ($accessToken === null) {
            return Create::rejectionFor(
                new AuthError('no access token to refresh — login must succeed before refresh'),
            );
        }

        $claims = $this->decodeUnverifiedClaims($accessToken);

        $tenantId = is_array($claims) ? ($claims['tenant_id'] ?? null) : null;
        if (!is_string($tenantId) || $tenantId === '') {
            return Create::rejectionFor(
                new AuthError(
                    'tenant_id could not be resolved from the current access token; login must succeed before refresh',
                ),
            );
        }

        $orgId = is_array($claims) ? ($claims['org_id'] ?? null) : null;
        if (!is_string($orgId) || $orgId === '') {
            return Create::rejectionFor(
                new AuthError(
                    'org_id could not be resolved from the current access token; login must succeed before refresh',
                ),
            );
        }

        return $this->http->postAsync('/api/v1/auth/refresh', [
            'json' => ['tenant_id' => $tenantId, 'org_id' => $orgId],
        ]);
    }

    /**
     * Unverified decode of a JWT's payload segment (base64url + JSON, NO signature
     * check) — used ONLY to resolve `tenant_id`/`org_id` for the refresh request body
     * above. Never used for an authorization decision (that is exclusively
     * {@see \Axiam\Sdk\Auth\JwksVerifier::verify()}'s job); mirrors
     * `AxiamClient::currentClaimsOrNull()`'s identical decode logic, kept local here
     * so `Session` does not depend on `AxiamClient`.
     *
     * @return array<string,mixed>|null
     */
    private function decodeUnverifiedClaims(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (\count($parts) !== 3) {
            return null;
        }

        $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        try {
            $claims = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($claims) ? $claims : null;
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
