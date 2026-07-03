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
 */
final class AxiamMiddleware
{
    public function __construct(
        private readonly AxiamClient $client,
        private readonly string $tenant,
    ) {
    }

    public function handle(Request $request, Closure $next): mixed
    {
        $token = $this->extractToken($request);
        if ($token === null) {
            return $this->unauthorized('missing authentication credentials');
        }

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
     */
    private function extractToken(Request $request): ?string
    {
        $header = (string) $request->headers->get('Authorization', '');
        if ($header !== '') {
            [$scheme, $credentials] = array_pad(explode(' ', $header, 2), 2, '');
            if (strtolower($scheme) === 'bearer' && trim($credentials) !== '') {
                return trim($credentials);
            }

            return null;
        }

        $cookie = $request->cookies->get('axiam_access');

        return is_string($cookie) && $cookie !== '' ? $cookie : null;
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
}
