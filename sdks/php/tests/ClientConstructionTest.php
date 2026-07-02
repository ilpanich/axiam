<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Auth\LoginResult;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\Sensitive;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * SC#1 proof (CONTRACT.md §1/§5/§6, D-09, D-11, D-12, D-13): `AxiamClient`'s constructor
 * requires a tenant slug with no nullable default, `login()` returns a typed
 * {@see LoginResult} (never a raw array/stdClass), and the Guzzle `verify` option defaults
 * to strict TLS with a `customCa` bundle path as the ONLY escape hatch.
 *
 * `login()`/`verifyMfa()` are driven through a `MockHandler` injected via the
 * `transportHandler` test-only constructor seam (last, optional parameter — verified below
 * to never interfere with the `tenant` reflection check) rather than a real socket, mirroring
 * every other REST test in this suite (e.g. {@see JwtVerifyTest}, `AuthzDispatcherFallbackTest`).
 */
final class ClientConstructionTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme';

    // --- SC#1 / D-13: tenant is a required constructor parameter, no nullable default ---

    public function testTenantConstructorParameterIsRequiredWithNoDefault(): void
    {
        $ctor = new ReflectionMethod(AxiamClient::class, '__construct');

        $tenantParam = null;
        foreach ($ctor->getParameters() as $param) {
            if ($param->getName() === 'tenant') {
                $tenantParam = $param;
                break;
            }
        }

        self::assertNotNull($tenantParam, 'AxiamClient::__construct must declare a `tenant` parameter');
        self::assertFalse(
            $tenantParam->isOptional(),
            'tenant must be a REQUIRED constructor parameter (D-13) — it must not be optional',
        );
        self::assertFalse(
            $tenantParam->isDefaultValueAvailable(),
            'tenant must have NO default value (D-13/SC#1) — there is no default tenant',
        );

        // §5 runtime backstop: an empty string tenant is rejected exactly like an omitted
        // argument would be (PHP's type system alone cannot forbid a blank string).
        $this->expectException(\InvalidArgumentException::class);
        new AxiamClient(self::BASE_URL, '');
    }

    public function testTenantParameterIsTheFirstOptionalityBoundary(): void
    {
        // Every parameter declared BEFORE `tenant` must also be required (i.e. `tenant`
        // is not "required-after-an-optional-param", which PHP would reject at the
        // language level anyway, but this documents the ordering explicitly for SC#1).
        $ctor = new ReflectionMethod(AxiamClient::class, '__construct');
        $params = $ctor->getParameters();

        $tenantIndex = null;
        foreach ($params as $i => $param) {
            if ($param->getName() === 'tenant') {
                $tenantIndex = $i;
                break;
            }
        }

        self::assertNotNull($tenantIndex);
        for ($i = 0; $i <= $tenantIndex; $i++) {
            self::assertFalse(
                $params[$i]->isOptional(),
                sprintf('parameter #%d (%s) must be required — tenant (D-13) must not follow an optional param', $i, $params[$i]->getName()),
            );
        }
    }

    // --- SC#1 / D-09: login() returns a typed LoginResult ---

    public function testLoginReturnsTypedLoginResultOnSuccess(): void
    {
        $mock = new MockHandler([
            new Response(200, [], (string) json_encode([
                'user' => ['id' => 'user-0001', 'username' => 'alice', 'email' => 'alice@acme.test'],
                'session_id' => 'sess-0001',
                'expires_in' => 900,
            ])),
        ]);

        $client = new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $mock);

        $result = $client->login('alice@acme.test', 'correct horse battery staple');

        self::assertInstanceOf(LoginResult::class, $result);
        self::assertFalse($result->mfaRequired);
        self::assertSame('user-0001', $result->userId);
        self::assertSame(self::TENANT, $result->tenantId);
        self::assertNull($result->challengeToken);
    }

    public function testLoginReturnsMfaRequiredLoginResultOnChallenge(): void
    {
        $mock = new MockHandler([
            new Response(202, [], (string) json_encode([
                'mfa_required' => true,
                'challenge_token' => 'challenge-abc-123',
                'available_methods' => ['totp'],
            ])),
        ]);

        $client = new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $mock);

        $result = $client->login('alice@acme.test', 'correct horse battery staple');

        self::assertInstanceOf(LoginResult::class, $result);
        self::assertTrue($result->mfaRequired);
        self::assertInstanceOf(Sensitive::class, $result->challengeToken);
        // D-11: the raw challenge token is never exposed via __toString()/JSON.
        self::assertSame('[SENSITIVE]', (string) $result->challengeToken);
        self::assertSame('challenge-abc-123', $result->challengeToken->reveal());
    }

    public function testVerifyMfaCompletesTwoPhaseFlowReturningLoginResult(): void
    {
        $mock = new MockHandler([
            new Response(202, [], (string) json_encode([
                'mfa_required' => true,
                'challenge_token' => 'challenge-xyz-789',
                'available_methods' => ['totp'],
            ])),
            new Response(200, [], (string) json_encode([
                'user' => ['id' => 'user-0002', 'username' => 'bob', 'email' => 'bob@acme.test'],
                'session_id' => 'sess-0002',
                'expires_in' => 900,
            ])),
        ]);

        $client = new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $mock);

        $loginResult = $client->login('bob@acme.test', 'password');
        self::assertTrue($loginResult->mfaRequired);
        self::assertInstanceOf(Sensitive::class, $loginResult->challengeToken);

        $verifyResult = $client->verifyMfa($loginResult->challengeToken, '123456');

        self::assertInstanceOf(LoginResult::class, $verifyResult);
        self::assertFalse($verifyResult->mfaRequired);
        self::assertSame('user-0002', $verifyResult->userId);
    }

    public function testLoginWithInvalidCredentialsThrowsAuthError(): void
    {
        $mock = new MockHandler([new Response(401)]);
        $client = new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $mock);

        $this->expectException(AuthError::class);
        $client->login('alice@acme.test', 'wrong-password');
    }

    // --- SC#1 / §6 / D-12: strict TLS default, customCa the ONLY escape hatch ---

    public function testDefaultTlsVerificationIsStrict(): void
    {
        $client = new AxiamClient(self::BASE_URL, self::TENANT);

        self::assertTrue(
            $client->debugVerifyOption(),
            'default Guzzle `verify` option must be `true` (strict TLS, §6/D-12) — never disabled',
        );
    }

    public function testCustomCaPathFlowsToGuzzleVerifyOption(): void
    {
        $caBundlePath = '/etc/ssl/certs/axiam-dev-ca.pem';

        $client = new AxiamClient(self::BASE_URL, self::TENANT, customCa: $caBundlePath);

        self::assertSame(
            $caBundlePath,
            $client->debugVerifyOption(),
            'customCa must flow directly to Guzzle\'s `verify` option as the CA bundle path',
        );
    }

    public function testCustomCaNeverDisablesVerification(): void
    {
        // Regardless of what customCa is set to, `verify` is never boolean false — it is
        // either the literal `true` default or a non-empty string path (§6/D-12 absolute
        // prohibition on a TLS-bypass value).
        $client = new AxiamClient(self::BASE_URL, self::TENANT, customCa: '/tmp/custom-ca.pem');

        self::assertNotFalse($client->debugVerifyOption());
    }
}
