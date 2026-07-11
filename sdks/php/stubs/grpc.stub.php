<?php

/**
 * PHPStan-only signature stub for the `grpc` PECL extension's pure-PHP wrapper classes
 * (`Grpc\BaseStub`, `Grpc\ChannelCredentials`) and the `google/protobuf` runtime base
 * class (`Google\Protobuf\Internal\Message`) the committed {@see \Axiam\Sdk\Grpc\Gen}
 * message stubs extend.
 *
 * THIS FILE IS NEVER AUTOLOADED/EXECUTED — it exists ONLY so PHPStan level 6 (see
 * `phpstan.neon.dist`'s `stubFiles` entry) can type-check
 * {@see \Axiam\Sdk\Grpc\AuthzGrpcClient} and the `Grpc\Gen\*` message classes without
 * `ext-grpc`/`grpc/grpc`/`google/protobuf` actually installed (Pitfall 4 /
 * T-22-16 — the whole point of the `extension_loaded('grpc')` guard is that these
 * packages are NEVER hard-required at runtime, D-03). Method bodies below are
 * deliberately empty/throwing — only the declared shape (parameter/return types)
 * matters to PHPStan.
 */

namespace Grpc {
    class BaseStub
    {
        /** @param array<string, mixed> $opts */
        public function __construct(string $hostname, array $opts)
        {
        }

        /**
         * @param callable|array $deserialize
         * @param array<string, list<string>> $metadata
         * @param array<string, mixed> $options
         */
        protected function _simpleRequest(
            string $method,
            object $argument,
            $deserialize,
            array $metadata = [],
            array $options = [],
        ): UnaryCall {
            throw new \LogicException('stub only');
        }
    }

    final class UnaryCall
    {
        /** @return array{0: object, 1: object{code: int, details: ?string}} */
        public function wait(): array
        {
            throw new \LogicException('stub only');
        }
    }

    final class ChannelCredentials
    {
        public static function createSsl(?string $pemRootCerts = null): self
        {
            throw new \LogicException('stub only');
        }
    }

    const STATUS_OK = 0;
    const STATUS_UNAUTHENTICATED = 16;
    const STATUS_PERMISSION_DENIED = 7;
}

namespace Google\Protobuf\Internal {
    abstract class Message
    {
        /** @param array<string, mixed>|null $data */
        public function __construct($data = null)
        {
        }

        /**
         * Deserializes a wire-format payload into the concrete message type.
         *
         * Declared here because the gRPC-PHP deserializer convention is to pass
         * `[MessageClass::class, 'decode']` as the deserialize callable. Without this
         * signature PHPStan cannot infer what that array-callable returns, and every
         * `unary()` call fails level 6 with "Unable to resolve the template type T".
         *
         * @return static
         */
        public static function decode(string $data): static
        {
            throw new \LogicException('stub only');
        }
    }

    /**
     * Repeated (list) protobuf field. Declared here because generated message getters —
     * e.g. BatchCheckAccessResponse::getResults() — return one, and AuthzDispatcher
     * `foreach`es over it; without this, PHPStan level 6 fails with "Iterating over an
     * object of an unknown class".
     *
     * @template T
     * @implements \IteratorAggregate<int, T>
     */
    class RepeatedField implements \IteratorAggregate, \ArrayAccess, \Countable
    {
        /** @return \Traversable<int, T> */
        public function getIterator(): \Traversable
        {
            throw new \LogicException('stub only');
        }

        public function offsetExists(mixed $offset): bool
        {
            throw new \LogicException('stub only');
        }

        /** @return T */
        public function offsetGet(mixed $offset): mixed
        {
            throw new \LogicException('stub only');
        }

        /** @param T $value */
        public function offsetSet(mixed $offset, mixed $value): void
        {
            throw new \LogicException('stub only');
        }

        public function offsetUnset(mixed $offset): void
        {
            throw new \LogicException('stub only');
        }

        public function count(): int
        {
            throw new \LogicException('stub only');
        }
    }
}
