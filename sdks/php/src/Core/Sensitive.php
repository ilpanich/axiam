<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Wraps a token-carrying value so it can never be accidentally exposed via
 * `__toString()`, `var_export()`/`print_r()`, or JSON serialization
 * (CONTRACT.md §7, D-11).
 *
 * The wrapped value is stored in a private static {@see \WeakMap}, keyed by the
 * `Sensitive` instance itself, rather than as a normal instance property. This means
 * the object carries zero introspectable properties: `print_r()`/`var_export()`/
 * `var_dump()` on a `Sensitive` show an empty object, since there is nothing on the
 * instance for PHP's reflection-based dumpers to enumerate. `reveal()` is the ONLY way
 * to obtain the underlying value; SDK-internal code that needs the raw token (e.g. to
 * build an `Authorization` header) calls it explicitly, at the point of use.
 */
final class Sensitive implements \JsonSerializable
{
    private const REDACTED = '[SENSITIVE]';

    /** @var \WeakMap<self, string> */
    private static \WeakMap $values;

    public function __construct(string $value)
    {
        self::$values ??= new \WeakMap();
        self::$values[$this] = $value;
    }

    /** Always returns the redacted literal, never the wrapped value. */
    public function __toString(): string
    {
        return self::REDACTED;
    }

    /** JSON hardening (D-11): json_encode() never emits the real value. */
    public function jsonSerialize(): string
    {
        return self::REDACTED;
    }

    /** The ONLY way to obtain the real value — call explicitly at the point of use. */
    public function reveal(): string
    {
        return self::$values[$this];
    }
}
