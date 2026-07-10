<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Auth\LoginResult;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\ErrorMapper;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Rest\AuthMiddleware;
use Axiam\Sdk\Rest\AuthzRestClient;
use Axiam\Sdk\Rest\RefreshMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The AXIAM PHP SDK's public REST entry point (CONTRACT.md §1–§9, SC#1).
 *
 * `tenant` is a REQUIRED, non-nullable-defaulted constructor parameter (D-13, §5) — there
 * is no overload or default that lets a caller omit it; AXIAM is multi-tenant and there is
 * no default tenant. `login($email, $password)` returns a typed {@see LoginResult}, never a
 * raw array/stdClass (D-09); a two-phase MFA flow is completed via {@see self::verifyMfa()}.
 * `checkAccess`/`can`/`batchCheck` delegate to {@see AuthzDispatcher} — this class never
 * hand-rolls REST/gRPC transport selection (D-03). {@see self::verifyLocallyOrFallback()} is
 * the seam the Laravel/Symfony framework bridges (a later plan) call: local {@see JwksVerifier}
 * verification first, falling back to the reactive single-flight refresh path (D-02, D-06).
 *
 * Composition, not reimplementation: this class wires together the already-built wave-2/3
 * pieces — {@see Session} (CookieJar + CSRF + single-flight refresh promise, D-06),
 * {@see AuthMiddleware}/{@see RefreshMiddleware} (the `HandlerStack` auth/refresh mechanism),
 * {@see JwksVerifier} (local EdDSA/JWKS verification), and {@see AuthzDispatcher}
 * (REST-default, gRPC-when-available authz, D-03) — it does not reimplement any of their
 * internal mechanisms.
 *
 * Two Guzzle clients share ONE {@see CookieJar} (§4):
 *  - `$plainHttp` carries ONLY {@see AuthMiddleware} (tenant/auth/CSRF header injection, no
 *    401-triggered refresh-and-retry). This is the client handed to {@see Session}'s own
 *    constructor for its internal `/api/v1/auth/refresh` POST (per {@see Session}'s own doc
 *    comment: the refresh call itself must never be able to recursively re-enter the
 *    single-flight guard), and is also used for `login()`/`verifyMfa()`/`logout()` — a failed
 *    login/logout attempt (401/403) must surface as its own clear error, not trigger an
 *    unrelated token-refresh attempt first.
 *  - `$authzHttp` carries BOTH {@see AuthMiddleware} and {@see RefreshMiddleware} — the full
 *    production stack — and is the client {@see AuthzRestClient} (and therefore
 *    {@see AuthzDispatcher}'s REST path) sends every authz request through, so a 401 on an
 *    authz call transparently triggers the shared single-flight refresh-and-retry-once (D-06).
 *
 * §6/D-12: the Guzzle `verify` option is ALWAYS `true` (strict TLS, system trust roots) unless
 * `$customCa` (a CA bundle FILE PATH) is supplied, in which case `verify` is set to that path —
 * the ONLY escape hatch. There is no code path in this class that sets `verify` to `false` or
 * any other TLS-bypass value.
 */
final class AxiamClient
{
    private const LOGIN_PATH = '/api/v1/auth/login';
    private const MFA_VERIFY_PATH = '/api/v1/auth/mfa/verify';
    private const LOGOUT_PATH = '/api/v1/auth/logout';

    private readonly string $tenant;

    private readonly ?string $orgSlug;

    private readonly ?string $orgId;

    private readonly LoggerInterface $logger;

    private readonly Session $session;

    /** AuthMiddleware only — login/verifyMfa/logout, and Session's own internal refresh POST. */
    private readonly Client $plainHttp;

    /** AuthMiddleware + RefreshMiddleware — the full production stack; authz traffic. */
    private readonly Client $authzHttp;

    private readonly JwksVerifier $jwksVerifier;

    private readonly AuthzDispatcher $authzDispatcher;

    /**
     * @param string $baseUrl The AXIAM server's base URL (e.g. `https://api.axiam.example`).
     * @param string $tenant The tenant slug — REQUIRED, no nullable default anywhere on this
     *        signature (D-13, §5). There is no default tenant; constructing this client
     *        without one is a compile-time (missing required argument) error, and an empty
     *        string is rejected at runtime as a backstop.
     * @param string|null $orgSlug Organization slug — mutually exclusive with `$orgId`. The
     *        real login/refresh handlers require an org identifier beyond CONTRACT.md §5's
     *        tenant-only minimum (mirrors the Python/C# sibling SDKs' `org_slug`/`org_id`
     *        constructor options).
     * @param string|null $orgId Organization UUID — mutually exclusive with `$orgSlug`.
     * @param string|null $customCa A CA bundle FILE PATH (PEM-encoded) — the ONLY TLS escape
     *        hatch (§6/D-12). Never pass a value here to disable TLS verification; there is no
     *        such option on this class.
     * @param LoggerInterface|null $logger Injectable logger (D-15: diagnostic-only — status
     *        codes and operation names, NEVER a token/credential value). Defaults to a silent
     *        {@see NullLogger}.
     * @param bool|null $restOnly Force REST-only authz transport. `null` (default) resolves to
     *        `true` when `$grpcTarget` is not supplied (there would be nothing to connect the
     *        gRPC transport to) and `false` otherwise — an explicit `true`/`false` always wins.
     *        REST authz ALWAYS works regardless of this setting (D-03).
     * @param int $cacheTtlSeconds {@see JwksVerifier}'s local JWKS TTL cache lifetime.
     * @param string|null $grpcTarget gRPC target host:port (e.g. `api.axiam.example:9443`),
     *        required only to actually use the gRPC authz transport.
     * @param callable|null $transportHandler Test-only seam (NOT part of the public API
     *        contract, trailing/optional so it never affects SC#1's "tenant is required"
     *        reflection check): a raw Guzzle handler (e.g. `GuzzleHttp\Handler\MockHandler`)
     *        used as the base handler for both internal `HandlerStack`s instead of Guzzle's
     *        default cURL/stream handler. Mirrors the C# sibling SDK's `CreateForTesting`
     *        internal seam, adapted to Guzzle's own documented
     *        `HandlerStack::create($mockHandler)` testing idiom
     *        (docs.guzzlephp.org/en/stable/testing.html) — never used by production code.
     */
    public function __construct(
        string $baseUrl,
        string $tenant,
        ?string $orgSlug = null,
        ?string $orgId = null,
        ?string $customCa = null,
        ?LoggerInterface $logger = null,
        ?bool $restOnly = null,
        int $cacheTtlSeconds = 300,
        ?string $grpcTarget = null,
        ?callable $transportHandler = null,
    ) {
        if ($tenant === '') {
            // D-13/§5 runtime backstop: PHP's type system alone cannot forbid an empty
            // string, only a missing argument. AXIAM is multi-tenant — there is no default
            // tenant, so a blank one is rejected exactly like an omitted one would be.
            throw new \InvalidArgumentException(
                'tenant is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)'
            );
        }
        if ($orgSlug !== null && $orgId !== null) {
            throw new \InvalidArgumentException('orgSlug and orgId are mutually exclusive — supply at most one');
        }

        $this->tenant = $tenant;
        $this->orgSlug = $orgSlug;
        $this->orgId = $orgId;
        $this->logger = $logger ?? new NullLogger();

        $cookieJar = new CookieJar();
        // §6/D-12: verify is ALWAYS true unless a customCa bundle PATH is supplied — never a
        // TLS-disable value. There is no other branch that can set `verify` to `false`.
        $verify = $customCa ?? true;

        $commonConfig = [
            'base_uri' => $baseUrl,
            'cookies' => $cookieJar, // §4: the ONE cookie jar every REST-facing client shares
            'verify' => $verify,
        ];

        // $plainHttp: AuthMiddleware only, no RefreshMiddleware — handed to Session below for
        // its own refresh POST (so a 401 on the refresh call itself can never recursively
        // re-enter the single-flight guard) and used directly for login/verifyMfa/logout,
        // which must never trigger an unrelated token-refresh attempt on their own failures.
        $plainStack = HandlerStack::create($transportHandler);
        $this->plainHttp = new Client($commonConfig + ['handler' => $plainStack]);

        $this->session = new Session($baseUrl, $tenant, $this->plainHttp, $cookieJar);

        // AuthMiddleware needs the Session instance it decorates requests for; pushed after
        // Session exists but before any request is actually sent (HandlerStack::resolve() is
        // lazy and cached on first send, so this ordering is safe).
        $plainStack->push(new AuthMiddleware($this->session), 'axiam_auth');

        // $authzHttp: the full production stack (AuthMiddleware + RefreshMiddleware) — every
        // authz call transparently benefits from the shared single-flight refresh-on-401
        // (D-06), matching the plan's own prescribed push order.
        $authzStack = HandlerStack::create($transportHandler);
        $authzStack->push(new AuthMiddleware($this->session), 'axiam_auth');
        $authzStack->push(new RefreshMiddleware($this->session), 'axiam_refresh');
        $this->authzHttp = new Client($commonConfig + ['handler' => $authzStack]);

        $this->jwksVerifier = new JwksVerifier($this->plainHttp, $baseUrl, $cacheTtlSeconds);

        $resolvedRestOnly = $restOnly ?? ($grpcTarget === null);

        $this->authzDispatcher = new AuthzDispatcher(
            restClient: new AuthzRestClient($this->authzHttp),
            restOnly: $resolvedRestOnly,
            grpcTarget: $grpcTarget,
            tenantId: $tenant,
            tokenAccessor: fn (): ?string => $this->session->accessToken(),
            subjectIdAccessor: fn (): string => $this->currentSubjectId(),
            customCaPem: $customCa,
        );
    }

    // ------------------------------------------------------------------
    // Test-only seam (not part of the public API contract) — lets
    // ClientConstructionTest assert the TLS `verify` option actually configured
    // on this client's Guzzle transport without reaching into private state via
    // Reflection.
    // ------------------------------------------------------------------

    /** @return string|bool The Guzzle `verify` option: `true`, or a CA bundle path (never `false`). */
    public function debugVerifyOption(): string|bool
    {
        return $this->authzHttp->getConfig('verify');
    }

    // ------------------------------------------------------------------
    // Auth flow (CONTRACT.md §1): login / verifyMfa / refresh / logout
    // ------------------------------------------------------------------

    /**
     * `POST /api/v1/auth/login` (CONTRACT.md §1). Returns a typed {@see LoginResult} — an MFA
     * challenge (HTTP 202) is an expected outcome, not an exception: callers MUST check
     * {@see LoginResult::$mfaRequired} before assuming a session was established (SC#1).
     */
    public function login(string $email, string $password): LoginResult
    {
        $response = $this->post($this->plainHttp, self::LOGIN_PATH, $this->loginBody($email, $password));

        return $this->handleLoginResponse($response);
    }

    /**
     * `POST /api/v1/auth/mfa/verify` (CONTRACT.md §1) — completes the two-phase flow started by
     * {@see self::login()} when {@see LoginResult::$mfaRequired} was `true`. `$challengeToken`
     * is the `Sensitive`-wrapped value from that `LoginResult` (D-11: never a raw string on the
     * public surface).
     */
    public function verifyMfa(Sensitive $challengeToken, string $totpCode): LoginResult
    {
        $response = $this->post($this->plainHttp, self::MFA_VERIFY_PATH, [
            'challenge_token' => $challengeToken->reveal(),
            'totp_code' => $totpCode,
        ]);

        return $this->handleLoginResponse($response);
    }

    /**
     * `POST /api/v1/auth/refresh` (CONTRACT.md §1), routed through {@see Session}'s
     * single-flight guard (§9, D-06) — the SAME mechanism {@see RefreshMiddleware} triggers
     * reactively on a `401`. A failure surfaces as {@see AuthError} with no retry (§9.3).
     */
    public function refresh(): void
    {
        $this->logger->debug('axiam_sdk: token refresh triggered');
        $this->session->refreshIfNeeded()->wait();
    }

    /**
     * `POST /api/v1/auth/logout` (CONTRACT.md §1) and clears local session state: the shared
     * cookie jar (§4) and the captured CSRF token (§3). The session id comes from the current
     * access token's `jti` claim (unverified decode — an operational hint only, never an
     * authorization decision, mirroring the Python/C# sibling SDKs).
     */
    public function logout(): void
    {
        $claims = $this->currentClaimsOrNull();
        $jti = is_array($claims) ? ($claims['jti'] ?? null) : null;
        if (!is_string($jti) || $jti === '') {
            throw new AuthError('no active session to log out');
        }

        $response = $this->post($this->plainHttp, self::LOGOUT_PATH, ['session_id' => $jti]);
        if ($response->getStatusCode() >= 300) {
            throw ErrorMapper::fromResponse($response, 'logout failed');
        }

        // Clears cookies/CSRF/local state (this plan's own behavior contract).
        $this->session->cookieJar()->clear();
        $this->session->resetCsrf();
    }

    // ------------------------------------------------------------------
    // Authz (CONTRACT.md §1, FND-04, D-03) — transparent REST/gRPC delegation
    // ------------------------------------------------------------------

    /** `checkAccess` — delegates to {@see AuthzDispatcher} (REST default, gRPC when available). */
    public function checkAccess(string $action, string $resourceId, ?string $scope = null): bool
    {
        return $this->authzDispatcher->checkAccess($action, $resourceId, $scope);
    }

    /**
     * `can` — the browser/UI-scenario alias for {@see self::checkAccess()} (CONTRACT.md §1
     * note). Argument order is `(action, resource)` — matching {@see self::checkAccess()}
     * and every other AXIAM SDK's `can`/`Can` (D-09/SDK-Q09; this was previously reversed
     * relative to the rest of the SDK family).
     */
    public function can(string $action, string $resource): bool
    {
        return $this->authzDispatcher->can($resource, $action);
    }

    /**
     * `batchCheck` — results preserve input order (CONTRACT.md §1).
     *
     * @param list<array{action: string, resourceId: string, scope?: string|null}> $checks
     * @return list<bool>
     */
    public function batchCheck(array $checks): array
    {
        return $this->authzDispatcher->batchCheck($checks);
    }

    // ------------------------------------------------------------------
    // Framework-bridge seam (D-02): local verify, reactive-refresh fallback
    // ------------------------------------------------------------------

    /**
     * Local-first JWT verification with a reactive-refresh fallback (D-02) — the seam the
     * Laravel/Symfony framework bridges (a later plan) call for every incoming request.
     * Tries {@see JwksVerifier::verify()} first (no network call on the happy path); if that
     * fails (expired/unknown-kid/invalid token), attempts the shared single-flight refresh
     * (§9, D-06) and re-verifies the FRESH access token. Returns `null` — never unverified
     * claims — on any failure; this method is fail-closed exactly like {@see JwksVerifier}
     * itself, since callers use the result for an authorization decision.
     *
     * @return array<string,mixed>|null Verified claims, or null.
     */
    public function verifyLocallyOrFallback(string $token, string $tenant): ?array
    {
        $claims = $this->jwksVerifier->verify($token, $tenant);
        if ($claims !== null) {
            return $claims;
        }

        try {
            $this->session->refreshIfNeeded()->wait();
        } catch (\Throwable) {
            return null;
        }

        $refreshedToken = $this->session->accessToken();
        if ($refreshedToken === null) {
            return null;
        }

        return $this->jwksVerifier->verify($refreshedToken, $tenant);
    }

    // ------------------------------------------------------------------
    // Wire-body construction + response handling
    // ------------------------------------------------------------------

    /** @return array<string,string> */
    private function loginBody(string $email, string $password): array
    {
        $body = [
            'tenant_slug' => $this->tenant,
            'username_or_email' => $email,
            'password' => $password,
        ];
        if ($this->orgId !== null) {
            $body['org_id'] = $this->orgId;
        } elseif ($this->orgSlug !== null) {
            $body['org_slug'] = $this->orgSlug;
        }

        return $body;
    }

    /**
     * Maps a `LoginSuccessResponse` (HTTP 200) or `MfaRequiredResponse` (HTTP 202) — the two
     * non-error outcomes of both `POST /api/v1/auth/login` and `POST /api/v1/auth/mfa/verify`
     * (sdks/openapi.json) — to a typed {@see LoginResult}. Any other status is a mapped error.
     */
    private function handleLoginResponse(ResponseInterface $response): LoginResult
    {
        $status = $response->getStatusCode();
        $wire = json_decode((string) $response->getBody(), true);

        if ($status === 200) {
            $userId = is_array($wire) ? ($wire['user']['id'] ?? null) : null;
            if (!is_string($userId) || $userId === '') {
                throw NetworkError::fromResponse($response, 'login: malformed response body');
            }

            return new LoginResult(mfaRequired: false, userId: $userId, tenantId: $this->tenant);
        }

        if ($status === 202) {
            $challengeToken = is_array($wire) ? ($wire['challenge_token'] ?? null) : null;
            if (!is_string($challengeToken) || $challengeToken === '') {
                throw NetworkError::fromResponse($response, 'login: MFA challenge response missing challenge_token');
            }

            return new LoginResult(mfaRequired: true, challengeToken: new Sensitive($challengeToken));
        }

        $this->logger->warning('axiam_sdk: login/verify_mfa failed: status={status}', ['status' => $status]);

        throw ErrorMapper::fromResponse($response, 'login/verifyMfa failed');
    }

    /**
     * POSTs `$body` as JSON to `$path` via `$http`, mapping any non-2xx response (thrown by
     * Guzzle as a {@see RequestException} by default) through {@see ErrorMapper} (CONTRACT.md
     * §2, D-10) — the single translation point every transport in this SDK uses.
     *
     * @param array<string,mixed> $body
     */
    private function post(Client $http, string $path, array $body): ResponseInterface
    {
        try {
            return $http->post($path, ['json' => $body]);
        } catch (RequestException $e) {
            $response = $e->getResponse();
            if ($response !== null) {
                throw ErrorMapper::fromResponse($response, $path . ' failed');
            }

            throw NetworkError::fromException($e, $path . ' failed');
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $path . ' failed');
        }
    }

    /**
     * Unverified decode of the CURRENT access token's payload segment (base64url + JSON, NO
     * signature check) — used ONLY to resolve operational identifiers (`jti` for logout,
     * `sub` for the gRPC authz subject id), mirroring the Python/C# sibling SDKs'
     * `_decode_unverified_claims`/`DecodeUnverifiedClaims` helpers. NEVER used for an
     * authorization decision — that is exclusively {@see JwksVerifier::verify()}'s job
     * (SEC-003); this method deliberately does not check `tenant_id` or any signature.
     *
     * @return array<string,mixed>|null
     */
    private function currentClaimsOrNull(): ?array
    {
        $token = $this->session->accessToken();
        if ($token === null) {
            return null;
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        try {
            $claims = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($claims) ? $claims : null;
    }

    /** The `sub` claim of the current (unverified) access token, or `''` if unavailable. */
    private function currentSubjectId(): string
    {
        $claims = $this->currentClaimsOrNull();
        $sub = is_array($claims) ? ($claims['sub'] ?? null) : null;

        return is_string($sub) ? $sub : '';
    }
}
