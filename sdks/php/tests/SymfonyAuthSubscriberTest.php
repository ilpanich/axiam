<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Symfony\AxiamAuthSubscriber;
use Axiam\Sdk\Symfony\AxiamVoter;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

/**
 * SC#4-Symfony proof (CONTRACT.md §10, D-02): drives {@see AxiamAuthSubscriber} and
 * {@see AxiamVoter} — both auth (401 on missing/invalid token, identity population on a
 * valid one) and authz (`can()` -> ACCESS_DENIED/ACCESS_GRANTED) — through a REAL
 * {@see AxiamClient} instance wired with a `MockHandler` (the same `transportHandler`
 * seam idiom every other REST test in this suite already uses, e.g.
 * {@see LaravelMiddlewareTest}, {@see JwtVerifyTest}), never a PHPUnit mock object
 * (which cannot double `AxiamClient` — it is `final`, by design). This directly proves
 * the D-02 prohibition ("never duplicate JWKS-verify or refresh logic in the bridge —
 * call AxiamClient methods") because the SAME `JwksVerifier`/`AuthzRestClient` code
 * paths already covered elsewhere in this suite run here, reached exclusively through
 * the public `AxiamClient` surface the bridge calls.
 */
final class SymfonyAuthSubscriberTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const FIXTURE_TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    private function fixtureJwt(): string
    {
        return trim((string) file_get_contents(self::FIXTURES . '/ed25519_signed_jwt.txt'));
    }

    /** @return array<string,mixed> */
    private function fixtureJwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded, 'fixture ed25519_jwks.json must decode to an array');

        return $decoded;
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks']));
    }

    private function jwksResponse(): Response
    {
        return new Response(200, [], (string) json_encode($this->fixtureJwks()));
    }

    /** @param list<Response> $queue */
    private function clientWith(array $queue, string $tenant = self::FIXTURE_TENANT): AxiamClient
    {
        return new AxiamClient(self::BASE_URL, $tenant, transportHandler: new MockHandler($queue));
    }

    private function requestEvent(Request $request): RequestEvent
    {
        $kernel = new class implements HttpKernelInterface {
            public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };

        return new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
    }

    /** A minimal TokenInterface double — AxiamVoter::voteOnAttribute() never reads it. */
    private function fakeToken(): TokenInterface
    {
        return new class implements TokenInterface {
            public function __toString(): string
            {
                return '';
            }

            public function getUserIdentifier(): string
            {
                return 'test-user';
            }

            public function getRoleNames(): array
            {
                return [];
            }

            public function getUser(): ?\Symfony\Component\Security\Core\User\UserInterface
            {
                return null;
            }

            public function setUser(\Symfony\Component\Security\Core\User\UserInterface $user): void
            {
            }

            public function getAttributes(): array
            {
                return [];
            }

            public function setAttributes(array $attributes): void
            {
            }

            public function hasAttribute(string $name): bool
            {
                return false;
            }

            public function getAttribute(string $name): mixed
            {
                throw new \InvalidArgumentException($name);
            }

            public function setAttribute(string $name, mixed $value): void
            {
            }

            public function __serialize(): array
            {
                return [];
            }

            public function __unserialize(array $data): void
            {
            }

            /**
             * Still declared (though deprecated) on Symfony 7.4's TokenInterface, so an
             * implementing class MUST define it — omitting it makes this anonymous class
             * abstract and PHP fatals before a single test in this file can run.
             */
            public function eraseCredentials(): void
            {
            }
        };
    }

    // --- Auth (D-02, §10): 401 on missing token -------------------------------------

    public function testMissingTokenReturns401(): void
    {
        // Empty MockHandler queue: the subscriber must reject BEFORE ever reaching the
        // client (no HTTP call attempted) when no token is present at all.
        $client = $this->clientWith([]);
        $subscriber = new AxiamAuthSubscriber($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        $response = $event->getResponse();
        self::assertNotNull($response);
        self::assertSame(401, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('AuthError', $body['error']);
        self::assertNull($request->attributes->get('axiam_user'));
    }

    // --- Auth (D-02, §10): 401 on an invalid/malformed token (fail-closed) ----------

    public function testInvalidTokenReturns401(): void
    {
        // A malformed token fails JwksVerifier::verify() immediately (not a 3-part
        // JWT); verifyLocallyOrFallback() then attempts the reactive-refresh fallback,
        // which itself fails against the empty MockHandler queue and is caught,
        // returning null (fail-closed) -- proving 401 even when a fallback is
        // attempted and fails, not just on the "never even tried" happy path above.
        $client = $this->clientWith([]);
        $subscriber = new AxiamAuthSubscriber($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer not-a-real-jwt');
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        self::assertSame(401, $event->getResponse()?->getStatusCode());
        self::assertNull($request->attributes->get('axiam_user'));
    }

    // --- Auth (D-02, §10): valid token populates axiam_user and does not short-circuit

    public function testValidTokenPopulatesIdentityAndDoesNotShortCircuit(): void
    {
        $client = $this->clientWith([$this->discoveryResponse(), $this->jwksResponse()]);
        $subscriber = new AxiamAuthSubscriber($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->fixtureJwt());
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse(), 'a valid token must never short-circuit the request');
        self::assertSame(
            ['user_id' => 'user-fixture-0001', 'tenant_id' => self::FIXTURE_TENANT, 'roles' => []],
            $request->attributes->get('axiam_user'),
        );
    }

    // --- Authz (D-02): Voter deny -> ACCESS_DENIED (-> 403 via Symfony's own AccessDeniedException) --

    public function testVoterDenyReturnsAccessDenied(): void
    {
        $client = $this->clientWith([
            new Response(200, [], (string) json_encode(['allowed' => false])),
        ]);
        $voter = new AxiamVoter($client);

        $result = $voter->vote($this->fakeToken(), null, ['documents:read']);

        self::assertSame(VoterInterface::ACCESS_DENIED, $result);
    }

    // --- Authz (D-02): Voter allow -> ACCESS_GRANTED ---------------------------------

    public function testVoterAllowReturnsAccessGranted(): void
    {
        $client = $this->clientWith([
            new Response(200, [], (string) json_encode(['allowed' => true])),
        ]);
        $voter = new AxiamVoter($client);

        $result = $voter->vote($this->fakeToken(), null, ['documents:read']);

        self::assertSame(VoterInterface::ACCESS_GRANTED, $result);
    }

    // --- Authz: an unsupported (non "resource:action") attribute abstains -----------

    public function testVoterAbstainsOnUnsupportedAttribute(): void
    {
        // No MockHandler response queued: an unsupported attribute must never even
        // reach AxiamClient::can() (no HTTP call attempted).
        $client = $this->clientWith([]);
        $voter = new AxiamVoter($client);

        $result = $voter->vote($this->fakeToken(), null, ['ROLE_ADMIN']);

        self::assertSame(VoterInterface::ACCESS_ABSTAIN, $result);
    }

    // --- CSRF (cookie double-submit, CONTRACT.md §3): cookie-auth state-changing request
    // --- without X-CSRF-Token header -> 403, never reaches AxiamClient ---------------

    public function testCookieAuthPostWithoutCsrfHeaderReturns403(): void
    {
        // Empty MockHandler queue: the CSRF check must reject BEFORE ever calling
        // AxiamClient::verifyLocallyOrFallback() (no HTTP call attempted).
        $client = $this->clientWith([]);
        $subscriber = new AxiamAuthSubscriber($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'POST');
        $request->cookies->set('axiam_access', $this->fixtureJwt());
        $request->cookies->set('axiam_csrf', 'csrf-secret-value');
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        $response = $event->getResponse();
        self::assertNotNull($response);
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('AuthzError', $body['error']);
        self::assertNull($request->attributes->get('axiam_user'));
    }

    // --- CSRF: cookie-auth state-changing request with matching X-CSRF-Token header + --
    // --- axiam_csrf cookie -> passes auth (does not short-circuit) ------------------

    public function testCookieAuthPostWithMatchingCsrfTokenPasses(): void
    {
        $client = $this->clientWith([$this->discoveryResponse(), $this->jwksResponse()]);
        $subscriber = new AxiamAuthSubscriber($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'POST');
        $request->cookies->set('axiam_access', $this->fixtureJwt());
        $request->cookies->set('axiam_csrf', 'csrf-secret-value');
        $request->headers->set('X-CSRF-Token', 'csrf-secret-value');
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse(), 'a matching CSRF token must never short-circuit the request');
        self::assertSame(
            ['user_id' => 'user-fixture-0001', 'tenant_id' => self::FIXTURE_TENANT, 'roles' => []],
            $request->attributes->get('axiam_user'),
        );
    }

    // --- CSRF: Bearer-auth state-changing request without CSRF -> passes (Bearer is ---
    // --- immune by construction; a cross-site attacker cannot set custom headers) ---

    public function testBearerAuthPostWithoutCsrfPasses(): void
    {
        $client = $this->clientWith([$this->discoveryResponse(), $this->jwksResponse()]);
        $subscriber = new AxiamAuthSubscriber($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'POST');
        $request->headers->set('Authorization', 'Bearer ' . $this->fixtureJwt());
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse(), 'Bearer-sourced credentials never require CSRF validation');
    }

    // --- CSRF: cookie-auth safe-method (GET) request without CSRF -> passes ----------

    public function testCookieAuthGetWithoutCsrfPasses(): void
    {
        $client = $this->clientWith([$this->discoveryResponse(), $this->jwksResponse()]);
        $subscriber = new AxiamAuthSubscriber($client, self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->cookies->set('axiam_access', $this->fixtureJwt());
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse(), 'a safe method never requires CSRF validation');
    }
}
