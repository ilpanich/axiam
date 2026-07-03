<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\Sensitive;

/**
 * Result of `AxiamClient::login()` (CONTRACT.md §1, D-09).
 *
 * A readonly DTO — never thrown as an exception. Callers MUST check
 * {@see self::$mfaRequired} before assuming a fully-authenticated session was
 * established: when `true`, `$challengeToken` carries the opaque MFA challenge token
 * to pass to `verifyMfa()`; when `false`, `$userId`/`$tenantId` describe the
 * authenticated principal and `$challengeToken` is `null`.
 *
 * Any token-carrying field MUST be typed {@see Sensitive} (CONTRACT.md §7 blanket
 * rule, mirrors the Java SDK's 20-03 `challengeToken` decision) — no raw token string
 * is ever exposed as a plain public property.
 */
final readonly class LoginResult
{
    public function __construct(
        public bool $mfaRequired,
        public ?Sensitive $challengeToken = null,
        public ?string $userId = null,
        public ?string $tenantId = null,
    ) {
    }
}
