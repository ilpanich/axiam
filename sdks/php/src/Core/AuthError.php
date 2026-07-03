<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Authentication failure: wrong credentials, expired session, MFA failure, or a 401
 * on refresh (CONTRACT.md §2). Always constructed via {@see ErrorMapper} so REST and
 * gRPC transports cannot drift on the error taxonomy.
 */
final class AuthError extends AxiamException
{
}
