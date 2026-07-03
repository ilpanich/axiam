<?php

declare(strict_types=1);

namespace Axiam\Sdk\Symfony;

use Axiam\Sdk\AxiamClient;

// D-01: the entire class definition is wrapped in an `interface_exists` guard (mirrors
// the Laravel `AxiamServiceProvider`'s `class_exists` wrapper, defense-in-depth) so this
// file never fatals if `symfony/event-dispatcher`/`symfony/http-kernel` happen to be
// absent — a non-Symfony consumer of `axiam/axiam-sdk` never references this class by
// name, so PSR-4's lazy autoloading never even `require`s this file in that case.
if (interface_exists(\Symfony\Component\EventDispatcher\EventSubscriberInterface::class)) {
    /**
     * Symfony authentication subscriber (D-02, CONTRACT.md §10): listens to
     * `kernel.request`, extracts the bearer/cookie token, verifies it via
     * {@see AxiamClient::verifyLocallyOrFallback()} — local JWKS verification first,
     * falling back to the shared single-flight refresh (§9, D-06) — and populates the
     * `axiam_user` request attribute with `user_id`/`tenant_id`/`roles` on success.
     * Short-circuits the request with a standardized 401 JSON error body on any failure
     * (missing token, invalid signature, expired-and-unrefreshable token). Never
     * duplicates JWKS-verify or refresh logic itself (D-02 prohibition) — every
     * security-critical decision is made by {@see AxiamClient}.
     *
     * MUST be manually registered (Pitfall 5): Symfony has no Laravel-style zero-config
     * auto-discovery for a plain `composer require` without a published Flex recipe (out
     * of scope this phase). A consuming app must tag this class
     * `kernel.event_subscriber` in its own `config/services.yaml` in addition to listing
     * {@see AxiamBundle} in `config/bundles.php` — see `examples/symfony_app/`.
     */
    final class AxiamAuthSubscriber implements \Symfony\Component\EventDispatcher\EventSubscriberInterface
    {
        public function __construct(
            private readonly AxiamClient $client,
            private readonly string $tenant,
        ) {
        }

        /** @return array<string,string> */
        public static function getSubscribedEvents(): array
        {
            return [\Symfony\Component\HttpKernel\KernelEvents::REQUEST => 'onKernelRequest'];
        }

        public function onKernelRequest(\Symfony\Component\HttpKernel\Event\RequestEvent $event): void
        {
            $request = $event->getRequest();

            $token = $this->extractToken($request);
            if ($token === null) {
                $event->setResponse($this->unauthorized('missing authentication credentials'));

                return;
            }

            // §10: "read the X-Tenant-ID header (or use the client's configured tenant)".
            $tenantId = $request->headers->get('X-Tenant-ID') ?: $this->tenant;

            $claims = $this->client->verifyLocallyOrFallback($token, $tenantId);
            if ($claims === null) {
                $event->setResponse($this->unauthorized('invalid or expired token'));

                return;
            }

            $userId = $claims['sub'] ?? null;
            $claimedTenantId = $claims['tenant_id'] ?? null;
            if (!is_string($userId) || $userId === '' || !is_string($claimedTenantId) || $claimedTenantId === '') {
                // A signature-valid token with a malformed claim shape must still degrade
                // to the standardized 401, never an unhandled error further downstream.
                $event->setResponse($this->unauthorized('invalid or expired token'));

                return;
            }

            $request->attributes->set('axiam_user', [
                'user_id' => $userId,
                'tenant_id' => $claimedTenantId,
                'roles' => $this->rolesFromClaims($claims),
            ]);
        }

        /**
         * Bearer header first, cookie fallback second — the SAME ordering as every
         * sibling SDK's own auth middleware/subscriber (e.g. this SDK's own
         * `Laravel\AxiamMiddleware::extractToken()`, `sdks/python/src/axiam_sdk/django/
         * middleware.py`'s `_extract_token`, `sdks/go/middleware/nethttp.go`'s
         * `extractToken`), a Shared Pattern documented across every framework bridge in
         * this repository.
         */
        private function extractToken(\Symfony\Component\HttpFoundation\Request $request): ?string
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

        private function unauthorized(string $message): \Symfony\Component\HttpFoundation\JsonResponse
        {
            // CONTRACT.md §10: AuthError -> HTTP 401 with a standardized JSON error
            // body; no raw token value is ever included in the response (mirrors every
            // sibling SDK).
            return new \Symfony\Component\HttpFoundation\JsonResponse(
                ['error' => 'AuthError', 'message' => $message],
                401,
            );
        }
    }
}
