<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * Poison-message sentinel. Application handlers throw this to signal that a
 * message is unprocessable and must NOT be requeued (e.g. a permanently
 * malformed or unsupported event) — distinct from a transient failure, which
 * should be requeued for retry.
 */
final class AmqpDropMessage extends \RuntimeException
{
}
