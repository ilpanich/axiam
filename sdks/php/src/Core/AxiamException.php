<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Base exception for all AXIAM SDK errors (CONTRACT.md §2, D-10).
 *
 * The taxonomy is a class hierarchy — {@see AuthError}, {@see AuthzError}, and
 * {@see NetworkError} all extend this base — NOT a flat enum-of-codes on a single
 * exception type. Instances should be constructed via {@see ErrorMapper} so REST and
 * (later) gRPC transports cannot drift on the mapping.
 */
class AxiamException extends \RuntimeException
{
}
