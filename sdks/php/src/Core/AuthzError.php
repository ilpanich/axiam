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
    public function __construct(
        string $message,
        private readonly ?string $action = null,
        private readonly ?string $resourceId = null,
    ) {
        parent::__construct($message);
    }

    public function getAction(): ?string
    {
        return $this->action;
    }

    public function getResourceId(): ?string
    {
        return $this->resourceId;
    }
}
