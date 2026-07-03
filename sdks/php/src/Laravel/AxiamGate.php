<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\AxiamClient;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Laravel authorization gate (D-02, CONTRACT.md §1/§10): a one-line delegation to
 * {@see AxiamClient::can()} — the server's additive-only RBAC engine (allow-wins,
 * default-deny, no explicit deny-override) is ALWAYS the authoritative decision-maker.
 * This class never caches a decision beyond the token's own TTL and never implements a
 * client-side deny-override (project RBAC constraint, CLAUDE.md).
 *
 * Zero Illuminate references — this class has no framework dependency of its own (the
 * `JsonResponse` used by {@see self::authorize()} is `Symfony\Component\HttpFoundation`,
 * already a transitive dependency of every Laravel installation via
 * `illuminate/http`/`laravel/framework`, so no new `illuminate/*` package is required to
 * define or test this class). {@see AxiamServiceProvider::boot()} wires this class into
 * both the idiomatic Laravel `Gate::define('axiam', ...)` ability (used by the
 * `can:axiam,<resource>,<action>` route-middleware syntax) and, for apps that prefer not
 * to depend on the full Gate/`illuminate/auth` machinery, {@see self::authorize()} can be
 * called directly as a standalone authorization step.
 */
final class AxiamGate
{
    public function __construct(private readonly AxiamClient $client)
    {
    }

    /**
     * The ability callback Laravel's `Gate::define('axiam', ...)` registers (D-02): true
     * on allow, false on deny. Laravel's own `can:axiam,<resource>,<action>` middleware
     * (illuminate/auth's `Authorize` middleware) turns a `false` result into a 403
     * response automatically — this method never builds an HTTP response itself.
     */
    public function allows(string $resource, string $action): bool
    {
        return $this->client->can($resource, $action);
    }

    /**
     * A standalone authorization check that returns the 403 response directly (D-02,
     * §10: "AuthzError" -> HTTP 403 with a standardized JSON error body) rather than
     * relying on the full Laravel Gate/`illuminate/auth` `Authorize` middleware pipeline.
     * Returns `null` on allow (caller proceeds to `$next($request)` itself); a
     * {@see JsonResponse} with status 403 on deny.
     */
    public function authorize(string $resource, string $action): ?JsonResponse
    {
        if ($this->allows($resource, $action)) {
            return null;
        }

        return new JsonResponse(
            ['error' => 'AuthzError', 'message' => "forbidden: cannot {$action} {$resource}"],
            403,
        );
    }
}
