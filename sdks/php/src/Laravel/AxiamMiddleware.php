<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\AxiamClient;
use Closure;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Laravel authentication middleware (D-02, CONTRACT.md §10): extracts the bearer/cookie
 * token, verifies it via {@see AxiamClient::verifyLocallyOrFallback()} — local JWKS
 * verification first, falling back to the shared single-flight refresh (§9, D-06) — and
 * populates the `axiam_user` request attribute with `user_id`/`tenant_id`/`roles` on
 * success. Returns a standardized 401 JSON error body on any failure (missing token,
 * invalid signature, expired-and-unrefreshable token). Never duplicates JWKS-verify or
 * refresh logic itself (D-02 prohibition) — every security-critical decision is made by
 * {@see AxiamClient}.
 *
 * Type-hinted against `Symfony\Component\HttpFoundation\Request` rather than
 * `Illuminate\Http\Request`: a real `Illuminate\Http\Request` instance IS a
 * `Symfony\Component\HttpFoundation\Request` (it directly extends it, adding only
 * Laravel-specific convenience methods this class does not need), so Laravel's own HTTP
 * kernel/pipeline can call `handle($request, $next)` with its real request object
 * unchanged. This keeps the class's own dependency footprint to a package every Laravel
 * installation already ships transitively (via `illuminate/http`), without requiring a
 * new `illuminate/http` dev/runtime dependency just to type-hint the parameter (D-01:
 * illuminate/* stays dev-only, and only the packages actually needed are declared).
 *
 * CSRF (cookie double-submit, CONTRACT.md §3): when the credential was sourced from the
 * `axiam_access` COOKIE (not the `Authorization` header) and the request method is
 * state-changing (anything other than GET/HEAD/OPTIONS), this middleware additionally
 * requires the `X-CSRF-Token` request header to be present and equal (constant-time) to
 * the `axiam_csrf` cookie value, rejecting with 403 on mismatch/absence. Bearer-header
 * requests are CSRF-immune by construction — a cross-site attacker cannot set arbitrary
 * request headers — but a cookie automatically attached by the browser is not, and in
 * any same-site deployment where `axiam_access` reaches this app, the non-httpOnly
 * `axiam_csrf` cookie does too. This mirrors, locally, the same double-submit check the
 * AXIAM server performs on its own endpoints (§3).
 */
final class AxiamMiddleware
{
    private const CSRF_COOKIE_NAME = 'axiam_csrf';
    private const CSRF_HEADER_NAME = 'X-CSRF-Token';

    /** @var list<string> */
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    /**
     * @param AxiamClient $client Client used to verify the presented token against the cached JWKS.
     * @param string      $tenant Tenant slug the verified token's claim must match (cross-tenant
     *                            control: a JWKS is organization-wide, so a valid signature alone
     *                            never implies tenant authorization).
     */
    public function __construct(
        private readonly AxiamClient $client,
        private readonly string $tenant,
    ) {
    }

    /**
     * Authenticates the inbound request and, for cookie-authenticated writes, enforces CSRF.
     *
     * Sequence: extract the credential (`Authorization: Bearer` first, then the `axiam_access`
     * cookie) → verify the JWT locally → enforce the cross-tenant claim check → inject the
     * identity → call the next middleware.
     *
     * CSRF (CONTRACT.md §3a): when the credential came from the COOKIE and the method is
     * state-changing (not GET/HEAD/OPTIONS), the `X-CSRF-Token` header must be present and equal
     * (constant-time) to the `axiam_csrf` cookie, else the request is rejected with 403.
     * Bearer-authenticated requests are exempt — a cross-site attacker cannot set custom headers.
     *
     * @param Request $request Inbound request.
     * @param Closure $next    Next middleware in the pipeline.
     *
     * @return mixed The next middleware's response, or a 401/403 JSON error response.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $credential = $this->extractToken($request);
        if ($credential === null) {
            return $this->unauthorized('missing authentication credentials');
        }

        if (
            $credential['fromCookie']
            && !in_array(strtoupper($request->getMethod()), self::SAFE_METHODS, true)
            && !$this->isCsrfValid($request)
        ) {
            return $this->csrfValidationFailed();
        }

        $token = $credential['token'];

        // §10: "read the X-Tenant-ID header (or use the client's configured tenant)".
        $tenantId = $request->headers->get('X-Tenant-ID') ?: $this->tenant;

        $claims = $this->client->verifyLocallyOrFallback($token, $tenantId);
        if ($claims === null) {
            return $this->unauthorized('invalid or expired token');
        }

        $userId = $claims['sub'] ?? null;
        $claimedTenantId = $claims['tenant_id'] ?? null;
        if (!is_string($userId) || $userId === '' || !is_string($claimedTenantId) || $claimedTenantId === '') {
            // A signature-valid token with a malformed claim shape must still degrade to
            // the standardized 401, never an unhandled error further downstream.
            return $this->unauthorized('invalid or expired token');
        }

        $request->attributes->set('axiam_user', [
            'user_id' => $userId,
            'tenant_id' => $claimedTenantId,
            'roles' => $this->rolesFromClaims($claims),
        ]);

        return $next($request);
    }

    /**
     * Bearer header first, cookie fallback second — the SAME ordering as every sibling
     * SDK's own auth middleware (e.g. `sdks/python/src/axiam_sdk/django/middleware.py`'s
     * `_extract_token`, `sdks/go/middleware/nethttp.go`'s `extractToken`), a Shared
     * Pattern documented across every framework bridge in this repository.
     *
     * Returns which source the credential came from so {@see self::handle()} can gate
     * state-changing cookie-sourced requests behind the CSRF double-submit check — a
     * Bearer-header credential never needs that check (§3).
     *
     * @return array{token: string, fromCookie: bool}|null
     */
    private function extractToken(Request $request): ?array
    {
        $header = (string) $request->headers->get('Authorization', '');
        if ($header !== '') {
            [$scheme, $credentials] = array_pad(explode(' ', $header, 2), 2, '');
            if (strtolower($scheme) === 'bearer' && trim($credentials) !== '') {
                return ['token' => trim($credentials), 'fromCookie' => false];
            }

            return null;
        }

        $cookie = $request->cookies->get('axiam_access');

        return is_string($cookie) && $cookie !== '' ? ['token' => $cookie, 'fromCookie' => true] : null;
    }

    /**
     * Cookie double-submit check (CONTRACT.md §3): the `X-CSRF-Token` header must be
     * present and equal, constant-time (mirrors {@see \Axiam\Sdk\Amqp\Hmac::verify()}'s
     * use of `hash_equals()`), to the `axiam_csrf` cookie value.
     */
    private function isCsrfValid(Request $request): bool
    {
        $header = (string) $request->headers->get(self::CSRF_HEADER_NAME, '');
        if ($header === '') {
            return false;
        }

        $cookie = $request->cookies->get(self::CSRF_COOKIE_NAME);
        if (!is_string($cookie) || $cookie === '') {
            return false;
        }

        return hash_equals($cookie, $header);
    }

    /**
     * @param array<string,mixed> $claims
     * @return list<string>
     */
    private function rolesFromClaims(array $claims): array
    {
        $rolesClaim = $claims['roles'] ?? $claims['scope'] ?? [];
        if (is_array($rolesClaim)) {
            return array_values(array_filter($rolesClaim, 'is_string'));
        }
        if (is_string($rolesClaim) && $rolesClaim !== '') {
            return array_values(array_filter(explode(' ', $rolesClaim)));
        }

        return [];
    }

    private function unauthorized(string $message): JsonResponse
    {
        // CONTRACT.md §10: AuthError -> HTTP 401 with a standardized JSON error body; no
        // raw token value is ever included in the response (mirrors every sibling SDK).
        return new JsonResponse(['error' => 'AuthError', 'message' => $message], 401);
    }

    private function csrfValidationFailed(): JsonResponse
    {
        // CONTRACT.md §3/§10: a cookie-sourced credential on a state-changing request
        // without a valid double-submit token is an authorization failure -> HTTP 403,
        // same "AuthzError" shape {@see \Axiam\Sdk\Laravel\AxiamGate::authorize()} uses.
        return new JsonResponse(['error' => 'AuthzError', 'message' => 'csrf validation failed'], 403);
    }
}
