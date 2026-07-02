<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Authorization failure: the caller is authenticated but lacks permission for the
 * requested operation (CONTRACT.md §2). Always constructed via {@see ErrorMapper} so
 * REST and gRPC transports cannot drift on the error taxonomy.
 */
final class AuthzError extends AxiamException
{
}
