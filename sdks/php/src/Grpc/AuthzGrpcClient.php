<?php

declare(strict_types=1);

namespace Axiam\Sdk\Grpc;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Grpc\Gen\BatchCheckAccessRequest;
use Axiam\Sdk\Grpc\Gen\BatchCheckAccessResponse;
use Axiam\Sdk\Grpc\Gen\CheckAccessRequest;
use Axiam\Sdk\Grpc\Gen\CheckAccessResponse;

/**
 * gRPC authorization transport (CONTRACT.md §1/§6/§9, D-03/D-06/D-12).
 *
 * PITFALL 4 / T-22-16 (`extension_loaded('grpc')` guard, high severity): this class
 * `extends \Grpc\BaseStub`. PHP only resolves an `extends` clause's target when THIS
 * FILE is actually included/executed (which PSR-4 autoloading defers until something
 * references `Axiam\Sdk\Grpc\AuthzGrpcClient` by name) — so simply having this class
 * exist in the SDK never fatals a REST-only runtime. The invariant this SDK MUST
 * preserve is: **nothing outside {@see \Axiam\Sdk\AuthzDispatcher}'s
 * `extension_loaded('grpc')`-guarded branches may ever reference this class name** (not
 * a `use` import that gets executed, not a type-hint on a called method, not an
 * `instanceof` check) — {@see \Axiam\Sdk\AuthzDispatcher} is the ONLY call site in this
 * SDK, and it references this class exclusively inside that guard.
 *
 * No grpc_php_plugin was available in this development sandbox to generate a
 * `*ServiceClient` stub (buf CLI unavailable — see 22-05-SUMMARY.md), so this class
 * hand-implements `CheckAccess`/`BatchCheckAccess` directly against
 * `\Grpc\BaseStub::_simpleRequest()` — the exact same primitive grpc_php_plugin's own
 * generated service-client classes call internally, using the committed message stubs
 * in {@see \Axiam\Sdk\Grpc\Gen}.
 *
 * D-06: this class NEVER re-implements token refresh. `$tokenAccessor` is a
 * non-blocking closure supplied by whatever assembles the client (AxiamClient, a later
 * plan) that reads the CURRENT access token live — the exact same "read live, never
 * cache a second copy" discipline {@see \Axiam\Sdk\Session::accessToken()} already
 * follows for REST. This class never triggers a refresh itself; on an UNAUTHENTICATED
 * gRPC status it surfaces {@see AuthError} and lets the caller's own refresh-and-retry
 * policy (mirroring {@see \Axiam\Sdk\Rest\RefreshMiddleware}'s REST behavior) decide
 * whether to retry.
 *
 * §6/D-12: the channel is ALWAYS constructed via `\Grpc\ChannelCredentials::createSsl()`
 * (strict TLS, system trust roots) or, when `$customCaPem` is supplied, that same
 * factory with the custom CA bytes — the ONLY escape hatch (§6). There is no
 * insecure-channel construction path anywhere in this class.
 *
 * §5: `x-tenant-id` metadata is injected on EVERY RPC; `authorization` metadata is
 * injected whenever `$tokenAccessor` returns a non-empty token.
 */
final class AuthzGrpcClient extends \Grpc\BaseStub
{
    /**
     * @param string $hostname gRPC target, e.g. "api.axiam.example:9443".
     * @param callable(): (string|null) $tokenAccessor Reads the CURRENT access token
     *        live (shares the Session single-flight refresh mechanism, D-06) — never
     *        caches a copy, never triggers a refresh itself.
     * @param string $tenantId Injected as the `x-tenant-id` metadata key on every RPC (§5).
     * @param string|null $customCaPem PEM-encoded custom CA bundle (§6's ONLY escape
     *        hatch); omit to use the system trust roots.
     * @param array<string, mixed> $options Additional `\Grpc\BaseStub` constructor
     *        options (e.g. a caller-supplied per-call deadline); `credentials` is always
     *        set by this constructor and cannot be overridden via `$options`.
     */
    public function __construct(
        string $hostname,
        private readonly mixed $tokenAccessor,
        private readonly string $tenantId,
        private readonly ?string $customCaPem = null,
        array $options = [],
    ) {
        $credentials = $this->customCaPem !== null
            ? \Grpc\ChannelCredentials::createSsl($this->customCaPem)
            : \Grpc\ChannelCredentials::createSsl();

        parent::__construct($hostname, array_merge($options, [
            'credentials' => $credentials,
        ]));
    }

    /**
     * `CheckAccess` (CONTRACT.md §1). `$tenantId`/`$subjectId` are cross-validated by
     * the server against the verified JWT claims carried in the call's own auth
     * metadata (SEC-003) — a mismatch is rejected server-side with `PERMISSION_DENIED`.
     */
    public function checkAccess(
        string $tenantId,
        string $subjectId,
        string $action,
        string $resourceId,
        ?string $scope = null,
    ): CheckAccessResponse {
        $request = new CheckAccessRequest();
        $request->setTenantId($tenantId);
        $request->setSubjectId($subjectId);
        $request->setAction($action);
        $request->setResourceId($resourceId);
        if ($scope !== null) {
            $request->setScope($scope);
        }

        return $this->unary(
            '/axiam.v1.AuthorizationService/CheckAccess',
            $request,
            [CheckAccessResponse::class, 'decode'],
        );
    }

    /** `BatchCheckAccess` (CONTRACT.md §1) — results preserve input order. */
    public function batchCheckAccess(BatchCheckAccessRequest $request): BatchCheckAccessResponse
    {
        return $this->unary(
            '/axiam.v1.AuthorizationService/BatchCheckAccess',
            $request,
            [BatchCheckAccessResponse::class, 'decode'],
        );
    }

    /**
     * @template T of object
     * @param callable $deserialize
     * @return T
     */
    private function unary(string $method, object $argument, callable $deserialize): object
    {
        [$response, $status] = $this->_simpleRequest(
            $method,
            $argument,
            $deserialize,
            $this->metadata(),
        )->wait();

        if ($status->code !== \Grpc\STATUS_OK) {
            throw $this->mapStatus((int) $status->code, (string) ($status->details ?? 'gRPC call failed'));
        }

        return $response;
    }

    /** §5: Authorization + x-tenant-id metadata on EVERY RPC. */
    private function metadata(): array
    {
        $metadata = ['x-tenant-id' => [$this->tenantId]];

        $token = ($this->tokenAccessor)();
        if (\is_string($token) && $token !== '') {
            $metadata['authorization'] = ['Bearer ' . $token];
        }

        return $metadata;
    }

    /** CONTRACT.md §2 gRPC status -> error-type mapping. */
    private function mapStatus(int $code, string $details): \Axiam\Sdk\Core\AxiamException
    {
        return match ($code) {
            \Grpc\STATUS_UNAUTHENTICATED => new AuthError(sprintf('authz gRPC call failed: unauthenticated — %s', $details)),
            \Grpc\STATUS_PERMISSION_DENIED => new AuthzError(sprintf('authz gRPC call failed: permission denied — %s', $details)),
            default => NetworkError::fromException(new \RuntimeException($details), 'authz gRPC call failed'),
        };
    }
}
