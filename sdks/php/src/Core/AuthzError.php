<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Authorization failure: the caller is authenticated but lacks permission for the
 * requested operation (CONTRACT.md §2). Always constructed via {@see ErrorMapper} so
 * REST and gRPC transports cannot drift on the error taxonomy.
 *
 * {@see self::getAction()} and {@see self::getResourceId()} are populated when the
 * server's `authorization_denied` body reports them: `action` is present when known;
 * `resourceId` is present only for a resource-scoped denial. Both may be `null` when
 * the server did not report them (or for a non-authz-shaped error).
 */
final class AuthzError extends AxiamException
{
    /**
     * @param string      $message    Human-readable denial reason from the server.
     * @param string|null $action     Action that was denied (e.g. `users:delete`), when the
     *                                server reported it.
     * @param string|null $resourceId Resource the denial applies to; `null` for a denial that
     *                                is not resource-scoped.
     */
    public function __construct(
        string $message,
        private readonly ?string $action = null,
        private readonly ?string $resourceId = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Action the caller was denied (e.g. `users:delete`).
     *
     * @return string|null `null` when the server did not report an action.
     */
    public function getAction(): ?string
    {
        return $this->action;
    }

    /**
     * Resource the denial applies to.
     *
     * @return string|null `null` for a global (non-resource-scoped) denial, or when the
     *                     server did not report a resource.
     */
    public function getResourceId(): ?string
    {
        return $this->resourceId;
    }
}
