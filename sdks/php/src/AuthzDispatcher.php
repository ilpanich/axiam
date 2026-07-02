<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Rest\AuthzRestClient;

/**
 * Transparent REST/gRPC authz transport selection (CONTRACT.md §1, D-03, SC#3).
 *
 * `checkAccess()`/`can()`/`batchCheck()` ALWAYS work: with no `grpc` PECL extension (or
 * `restOnly: true`) they route over `POST /api/v1/authz/check[/batch]` via
 * {@see AuthzRestClient} (FND-04). When the extension IS present and `restOnly` is
 * false, the SAME public methods transparently upgrade to
 * {@see \Axiam\Sdk\Grpc\AuthzGrpcClient} — callers never need to know which transport
 * actually ran.
 *
 * PITFALL 4 / T-22-16 (high severity, `mitigate`): `\Axiam\Sdk\Grpc\AuthzGrpcClient`
 * (which `extends \Grpc\BaseStub`) is referenced ONLY inside the
 * `!$this->restOnly && extension_loaded('grpc')` branches below and inside
 * {@see self::grpcClient()}, which those branches are the only callers of. On a
 * REST-only runtime (no `grpc` PECL extension — the actual condition in this SDK's own
 * CI/dev sandbox) that class is never autoloaded, so no "Class 'Grpc\BaseStub' not
 * found" fatal is possible — {@see \Axiam\Sdk\Tests\AuthzDispatcherFallbackTest} proves
 * this empirically. The typed property {@see self::$grpcClient} and
 * {@see self::grpcClient()}'s return type both name `AuthzGrpcClient`, but PHP resolves
 * class names used only in type declarations lazily (confirmed empirically: a typed
 * property/return-type naming a nonexistent class does not fatal a class that never
 * assigns/invokes it) — the guard is what matters, not merely avoiding the class name in
 * source text.
 *
 * D-06: the gRPC path shares {@see \Axiam\Sdk\Session}'s single-flight refresh/token —
 * `$tokenAccessor` is expected to be `Session::accessToken(...)` (or an equivalent live
 * reader), never a second independent refresh mechanism.
 */
final class AuthzDispatcher
{
    private ?\Axiam\Sdk\Grpc\AuthzGrpcClient $grpcClient = null;

    /**
     * @param callable(): (string|null) $tokenAccessor Reads the CURRENT access token
     *        live (D-06) — required only for the gRPC path; ignored entirely when
     *        `restOnly` is true or the `grpc` extension is absent.
     * @param callable(): string $subjectIdAccessor Reads the current authenticated
     *        user's subject UUID — the gRPC wire contract (unlike REST) requires
     *        `subject_id` explicitly, cross-validated server-side against the verified
     *        JWT (SEC-003); required only for the gRPC path.
     */
    public function __construct(
        private readonly AuthzRestClient $restClient,
        private readonly bool $restOnly = false,
        private readonly ?string $grpcTarget = null,
        private readonly ?string $tenantId = null,
        private readonly mixed $tokenAccessor = null,
        private readonly mixed $subjectIdAccessor = null,
        private readonly ?string $customCaPem = null,
    ) {
    }

    /** `checkAccess` (CONTRACT.md §1). */
    public function checkAccess(string $action, string $resourceId, ?string $scope = null): bool
    {
        if (!$this->restOnly && extension_loaded('grpc')) {
            // Class referenced ONLY inside this guarded branch (Pitfall 4 / T-22-16) —
            // on a runtime without the grpc PECL extension, this line never executes,
            // so Grpc/AuthzGrpcClient.php (which extends \Grpc\BaseStub) is never
            // autoloaded.
            $response = $this->grpcClient()->checkAccess(
                $this->tenantId ?? '',
                $this->currentSubjectId(),
                $action,
                $resourceId,
                $scope,
            );

            return $response->getAllowed();
        }

        // D-03: authz ALWAYS works — transparent fallback, not a degraded mode.
        return $this->restClient->checkAccess($action, $resourceId, $scope);
    }

    /** `can` (CONTRACT.md §1) — the browser/UI-scenario alias for {@see self::checkAccess()}. */
    public function can(string $resource, string $action): bool
    {
        return $this->checkAccess($action, $resource);
    }

    /**
     * `batchCheck` (CONTRACT.md §1) — results preserve input order, mirroring
     * {@see AuthzRestClient::batchCheck()}'s contract exactly regardless of transport.
     *
     * @param list<array{action: string, resourceId: string, scope?: string|null}> $checks
     * @return list<bool>
     */
    public function batchCheck(array $checks): array
    {
        if (!$this->restOnly && extension_loaded('grpc')) {
            // Class referenced ONLY inside this guarded branch (Pitfall 4 / T-22-16).
            $request = new \Axiam\Sdk\Grpc\Gen\BatchCheckAccessRequest();
            $subjectId = $this->currentSubjectId();

            $items = [];
            foreach ($checks as $check) {
                $item = new \Axiam\Sdk\Grpc\Gen\CheckAccessRequest();
                $item->setTenantId($this->tenantId ?? '');
                $item->setSubjectId($subjectId);
                $item->setAction($check['action']);
                $item->setResourceId($check['resourceId']);
                if (($check['scope'] ?? null) !== null) {
                    $item->setScope($check['scope']);
                }
                $items[] = $item;
            }
            $request->setRequests($items);

            $response = $this->grpcClient()->batchCheckAccess($request);

            $results = [];
            foreach ($response->getResults() as $result) {
                $results[] = $result->getAllowed();
            }

            return $results;
        }

        // D-03: authz ALWAYS works — transparent fallback, not a degraded mode.
        return $this->restClient->batchCheck($checks);
    }

    /**
     * Lazily constructs the gRPC client the FIRST time a guarded branch above actually
     * needs it (`??=`) — never called from anywhere else in this class, and this class
     * is the only caller in the whole SDK (Pitfall 4 / T-22-16).
     */
    private function grpcClient(): \Axiam\Sdk\Grpc\AuthzGrpcClient
    {
        return $this->grpcClient ??= new \Axiam\Sdk\Grpc\AuthzGrpcClient(
            $this->grpcTarget ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: grpcTarget must be configured to use the gRPC transport',
            ),
            $this->tokenAccessor ?? static fn (): ?string => null,
            $this->tenantId ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: tenantId must be configured to use the gRPC transport',
            ),
            $this->customCaPem,
        );
    }

    private function currentSubjectId(): string
    {
        return $this->subjectIdAccessor !== null ? (string) ($this->subjectIdAccessor)() : '';
    }
}
