<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\ErrorMapper;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * SDK-Q02: proves {@see ErrorMapper} parses the server's `authorization_denied` body
 * (CONTRACT.md §2: "`AuthzError` ... SHOULD carry the denied `action` and
 * `resource_id` if available from the response body") into the corresponding
 * {@see AuthzError} getters, and that both fields degrade to `null` — never throwing —
 * when the body doesn't carry them.
 */
final class AuthzErrorFieldsTest extends TestCase
{
    public function testActionAndResourceIdArePopulatedFromBody(): void
    {
        $response = new Response(
            403,
            [],
            json_encode([
                'error' => 'authorization_denied',
                'message' => 'caller lacks permission',
                'action' => 'users:get',
                'resource_id' => '11111111-1111-1111-1111-111111111111',
            ]),
        );

        $error = ErrorMapper::fromResponse($response, 'checkAccess failed');

        self::assertInstanceOf(AuthzError::class, $error);
        self::assertSame('users:get', $error->getAction());
        self::assertSame('11111111-1111-1111-1111-111111111111', $error->getResourceId());
        self::assertStringContainsString('forbidden', $error->getMessage());
    }

    public function testResourceIdIsNullWhenBodyOnlyCarriesAction(): void
    {
        // A global (non-resource-scoped) denial: `resource_id` is absent entirely,
        // not merely empty.
        $response = new Response(
            409,
            [],
            json_encode([
                'error' => 'authorization_denied',
                'message' => 'global permission denied',
                'action' => 'users:delete',
            ]),
        );

        $error = ErrorMapper::fromResponse($response, 'delete failed');

        self::assertInstanceOf(AuthzError::class, $error);
        self::assertSame('users:delete', $error->getAction());
        self::assertNull($error->getResourceId());
    }

    /**
     * Non-vacuous control: a non-authz-shaped body (neither key present) must not
     * crash the mapper and must leave both fields `null`, proving the parsing is
     * defensive rather than assuming the keys always exist.
     */
    public function testBothFieldsAreNullWhenBodyHasNeitherKey(): void
    {
        $response = new Response(403, [], json_encode(['error' => 'some_other_error', 'message' => 'x']));

        $error = ErrorMapper::fromResponse($response, 'other failed');

        self::assertInstanceOf(AuthzError::class, $error);
        self::assertNull($error->getAction());
        self::assertNull($error->getResourceId());
    }

    public function testFromStatusWithoutALiveResponseStillConstructsAuthzError(): void
    {
        $error = ErrorMapper::fromStatus(403, null, 'no body available');

        self::assertInstanceOf(AuthzError::class, $error);
        self::assertNull($error->getAction());
        self::assertNull($error->getResourceId());
    }
}
