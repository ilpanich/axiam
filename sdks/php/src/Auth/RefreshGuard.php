<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\AuthError;
use GuzzleHttp\Promise\PromiseInterface;

/**
 * Shared-promise clear-on-both-paths helper (CONTRACT.md §9, D-06).
 *
 * {@see self::settle()} wraps a refresh call's raw `PromiseInterface` so that,
 * regardless of success or failure, the caller's `$onClear` closure runs exactly
 * once — clearing the caller's own stored promise slot (e.g. `Session::$refreshPromise`)
 * so the NEXT 401 always starts a brand-new refresh attempt (§9.3: no retry loop; a
 * failed refresh is never cached for the next caller, mirroring the C# sibling
 * `Axiam.Sdk.Auth.RefreshGuard`'s "never cache a faulted refresh" invariant).
 *
 * PHP has no cross-object mutable-reference primitive that would let this helper
 * safely OWN a mutable promise-slot on behalf of multiple unrelated session objects
 * (unlike C#'s field-holding `RefreshGuard` class), so the slot itself stays on the
 * owning session (`Axiam\Sdk\Session` today; a future gRPC session would hold its own
 * field the same way). What this class DOES factor out — and what every such session
 * must apply identically — is the clear-on-both-paths bookkeeping and the
 * normalize-to-`AuthError` failure translation, so REST and (later) gRPC never drift
 * on that one piece of behavior (D-06's "ONE mechanism" requirement).
 */
final class RefreshGuard
{
    /**
     * @param PromiseInterface $refreshCall The raw in-flight refresh request promise.
     * @param \Closure(): void $onClear Clears the caller's stored promise slot. Invoked
     *        exactly once, on EITHER the success or the failure path — never on both,
     *        never on neither.
     * @param (\Closure(mixed): mixed)|null $onSuccess Optional success-path transform
     *        (e.g. CSRF-token capture) run AFTER `$onClear`, before the settled value
     *        is handed back to the caller.
     */
    public static function settle(
        PromiseInterface $refreshCall,
        \Closure $onClear,
        ?\Closure $onSuccess = null,
    ): PromiseInterface {
        return $refreshCall->then(
            function (mixed $result) use ($onClear, $onSuccess): mixed {
                $onClear(); // clear on success (§9.3) — the next 401 starts fresh
                return $onSuccess !== null ? $onSuccess($result) : $result;
            },
            function (\Throwable $reason) use ($onClear): never {
                $onClear(); // clear on failure too (§9.3) — no retry loop, never cached
                throw $reason instanceof AuthError
                    ? $reason
                    : new AuthError('token refresh failed: ' . $reason->getMessage());
            },
        );
    }
}
