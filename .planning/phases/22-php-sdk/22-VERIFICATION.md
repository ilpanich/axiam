---
phase: 22-php-sdk
verified: 2026-07-02T20:00:28Z
reverified: 2026-07-02T21:30:00Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
gaps: []
resolved:
  - truth: "SC#2 — Guzzle single-flight refresh call must succeed against the real AXIAM server (correct RefreshRequest wire body)"
    resolution: >
      Initial verification found SC#2 partial: Session::refreshIfNeeded() POSTed
      `{"tenant": "<slug>"}` while sdks/openapi.json's RefreshRequest requires
      `{tenant_id, org_id}` UUIDs. Closed in gap-closure commits e05ea92 (fix) and
      1da907b (test). Session now decodes the current access token's UNVERIFIED JWT
      claims (base64url payload, no signature check — mirroring the C# sibling's
      DecodeUnverifiedClaims) to resolve tenant_id/org_id before the refresh POST,
      and throws AuthError via the same single-flight RefreshGuard path when they
      cannot be resolved. SingleFlightRefreshTest now seeds a claims-bearing JWT
      fixture and asserts the captured refresh body carries {tenant_id, org_id} and
      NOT a bare `tenant` field, while keeping the exactly-1-refresh single-flight
      assertion. Re-verified: `COMPOSER_ALLOW_SUPERUSER=1 composer test` → 48 unit /
      163 assertions OK; integration → 11 / 31 OK (59 total green); the single-flight
      guard remains non-vacuous.
    artifacts:
      - path: "sdks/php/src/Session.php"
        status: fixed
      - path: "sdks/php/tests/SingleFlightRefreshTest.php"
        status: fixed
deferred: []
---

# Phase 22: PHP SDK Verification Report

**Phase Goal:** A PHP developer using Laravel or Symfony can authenticate via REST and AMQP, with gRPC available on long-running runtimes, and the package published to Packagist
**Verified:** 2026-07-02T20:00:28Z
**Status:** passed (re-verified after SC#2 gap closure — commits e05ea92 / 1da907b)
**Re-verification:** Yes — SC#2 refresh-body gap resolved; all 5 success criteria now verified

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth (SC) | Status | Evidence |
|---|------------|--------|----------|
| SC#1 | `composer require axiam/axiam-sdk` installs; `$client->login(...)` returns typed `LoginResult`; tenant slug is a required ctor param with no nullable default | ✓ VERIFIED | `composer.json` declares `axiam/axiam-sdk`; `AxiamClient::__construct(string $baseUrl, string $tenant, ...)` — `tenant` is the 2nd, non-optional, non-defaulted param (reflection-proved by `ClientConstructionTest::testTenantConstructorParameterIsRequiredWithNoDefault`); `login()` returns `Auth\LoginResult` (`ClientConstructionTest::testLoginReturnsTypedLoginResultOnSuccess`, `...OnChallenge`). `login()`'s wire body (`tenant_slug`) matches `sdks/openapi.json`'s `LoginRequest` schema exactly. |
| SC#2 | Guzzle `HandlerStack` single-refresh middleware: concurrent requests on expired token trigger exactly 1 refresh call | ⚠️ PARTIAL | `SingleFlightRefreshTest::testFiveConcurrentExpiredRequestsTriggerExactlyOneRefresh` is a genuine, non-vacuous test (5 concurrent 401s queued before the one refresh 200, `assertCount(1, $refreshCalls)`) — the single-flight GUARD is real. **However**, the refresh call's actual wire body (`{"tenant": "<slug>"}`, `src/Session.php:127`) does not match `sdks/openapi.json`'s `RefreshRequest` schema (`tenant_id`+`org_id` UUIDs, both required, no `tenant` field). Confirmed by direct schema inspection and cross-referenced against the C# sibling SDK, which correctly resolves these from token claims. See Gap #1. |
| SC#3 | gRPC guarded by `extension_loaded('grpc')`; REST-only fallback works; Swoole/RoadRunner runtime requirement documented prominently | ✓ VERIFIED | `AuthzDispatcher::checkAccess/batchCheck` branch on `!$this->restOnly && extension_loaded('grpc')`; `grep -rn "Grpc\\\\BaseStub\|AuthzGrpcClient" src --include=*.php \| grep -v "src/Grpc/"` shows references confined to the guarded branches of `AuthzDispatcher.php`. `AuthzDispatcherFallbackTest` (5 tests) proves REST-only fallback with no fatal and "no grpc class is autoloaded on the rest only path". `composer.json` lists `ext-grpc`/`grpc/grpc` only under `suggest`, never runtime `require`. `README.md` §"Runtime requirements" (line 53) prominently documents Swoole/RoadRunner + process supervision for gRPC and the AMQP worker. |
| SC#4 | Laravel + Symfony middleware helpers as runnable examples; AMQP consumer verifies HMAC-SHA256 and nacks (no requeue) on signature failure | ✓ VERIFIED | `examples/laravel_app/routes.php` demonstrates `axiam.auth` middleware AND `can:axiam,documents,read` gate (both `php -l` clean); `examples/symfony_app/` demonstrates the auth subscriber + Voter with honest manual-registration docs. `LaravelMiddlewareTest` (5 tests: 401/401/populate+pass/403/allow) and `SymfonyAuthSubscriberTest` (6 tests) both pass. `Consumer.php`: `Hmac::verify` called before the handler (verify-before-handler), `basic_nack($tag, false, false)` on HMAC-fail (no requeue) confirmed at lines 70/81, `basic_nack($tag, false, true)` (requeue) only on transient catch (line 83). `HmacVerifyTest` (9 tests, 44 assertions) proves byte-exact parity incl. the slash/non-ASCII escaping regression against real fixture vectors. |
| SC#5 | `composer test` passes; Packagist automation runs on release tag | ✓ VERIFIED | `COMPOSER_ALLOW_SUPERUSER=1 composer test` run directly in this verification: **PHPUnit 9.6.34, 48 tests, 159 assertions, OK**. `.github/workflows/sdk-ci-php.yml` `build-test` job runs `composer validate` → `composer install` → `composer test` → PHPStan L6 → a TLS-bypass grep gate (confirmed empty locally: `grep -rn 'verify.*=>.*false' sdks/php --include=*.php --exclude-dir=vendor \| grep -v customCa` → no output). `publish` job is gated on `refs/tags/sdks/php/v*` + `needs: build-test`, subtree-splits `sdks/php/` to a mirror repo, and degrades gracefully (`::warning::`, no pipeline failure) when `PHP_SDK_MIRROR_TOKEN`/`PHP_SDK_MIRROR_REPO` are absent — live first Packagist publish is an explicitly-allowed maintainer action (D-05), not a code gap. |

**Score:** 4/5 SC fully verified; SC#2 partial (see gap below). All 9 phase-level `PHP-01` requirement plans executed their local must_haves' automated gates, but SC#2's real-world correctness was not caught because no test asserts the refresh request body.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `sdks/php/composer.json` | `axiam/axiam-sdk`, pinned deps, framework-free runtime require | ✓ VERIFIED | `require`: php, guzzlehttp/guzzle, php-amqplib/php-amqplib, firebase/php-jwt, psr/log only. `composer show --tree` confirms illuminate/*, symfony/* resolve only from require-dev. |
| `src/Core/{Sensitive,AxiamException,AuthError,AuthzError,NetworkError,ErrorMapper}.php` | redaction + typed exception taxonomy | ✓ VERIFIED | `SensitiveRedactionTest` (6 tests) passes: `__toString`/`jsonSerialize`/`print_r` all redact; `NetworkError` redacts Set-Cookie/Authorization/Cookie at construction. |
| `src/Auth/{JwksVerifier,LoginResult}.php` | alg-pin + tenant_id EdDSA verify; readonly Sensitive-typed DTO | ✓ VERIFIED | `JwtVerifyTest` (7 tests) covers alg-pin (none/RS256 rejected pre-lookup), tenant mismatch (both fixture and re-signed), happy path, unknown-kid single-refetch, malformed-input fail-closed. |
| `src/Amqp/{Hmac,Consumer,AmqpDropMessage}.php`, `bin/axiam-amqp-worker.php` | byte-exact HMAC verify-before-handler, 3-way ack/nack, CLI worker | ✓ VERIFIED | `HmacVerifyTest` (9 tests, 44 assertions); `Consumer.php` verify-before-handler confirmed by grep + read; worker `php -l` clean, exits non-zero on connection failure (4 `exit(1)`/`exit(0)` sites reviewed). |
| `src/Session.php`, `src/Auth/RefreshGuard.php`, `src/Rest/{AuthMiddleware,RefreshMiddleware}.php` | single-flight refresh, header injection | ⚠️ PARTIAL | Single-flight guard mechanism verified (see SC#2 gap); wire-body correctness against the real server is NOT verified and is confirmed broken by schema cross-check. |
| `sdks/buf.gen.yaml`, `src/Rest/AuthzRestClient.php`, `src/Grpc/*`, `src/AuthzDispatcher.php` | REST-default/gRPC-guarded authz | ✓ VERIFIED | buf.gen.yaml has `protocolbuffers/php`+`grpc/php` entries targeting `php/src/Grpc/Gen`; stubs committed; `AuthzDispatcherFallbackTest` (5 tests) green. |
| `src/AxiamClient.php`, `tests/ClientConstructionTest.php`, examples | public facade, SC#1 proof | ✓ VERIFIED | 9 tests / 26 assertions, all pass; examples `php -l` clean, use only public API, no TLS-disable. |
| `src/Laravel/*`, `src/Symfony/*`, bridge tests + examples | framework bridges | ✓ VERIFIED | class_exists/interface_exists guards present on every bridge class; `LaravelMiddlewareTest` + `SymfonyAuthSubscriberTest` both green; README honestly documents Symfony's MANUAL registration vs Laravel's auto-discovery. |
| `.github/workflows/sdk-ci-php.yml`, `sdks/php/README.md` | CI lifecycle + docs | ✓ VERIFIED | Workflow present with build-test + TLS-gate + tag-gated publish (credential-absent graceful no-op); README documents CONTRACT.md conformance, SC#3 runtime requirement, Pitfall-5 Symfony manual registration. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `RefreshMiddleware` | `Session::refreshIfNeeded()` | 401-interceptor retry-exactly-once | ✓ WIRED (mechanism) / ✗ BROKEN (payload) | The retry-once wiring is correct and single-flight is proven; the underlying HTTP call to the real server will fail (see gap). |
| `AxiamClient` constructor | `HandlerStack`(AuthMiddleware+RefreshMiddleware) → `Session` → `AuthzDispatcher` | composition | ✓ WIRED | Confirmed by direct code read of `AxiamClient.php` constructor. |
| `AuthzDispatcher` | `extension_loaded('grpc')` guard | REST/gRPC selection | ✓ WIRED | No unguarded reference found; fallback test green. |
| `AxiamMiddleware`/`AxiamAuthSubscriber` | `AxiamClient::verifyLocallyOrFallback` | no duplicated verify logic | ✓ WIRED | `grep -rn "verifyLocallyOrFallback"` matches in both bridge files. |
| CI `publish` job | `build-test` | `needs:` gate | ✓ WIRED | Confirmed in workflow YAML. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full test suite | `COMPOSER_ALLOW_SUPERUSER=1 composer test` | `PHPUnit 9.6.34, 48 tests, 159 assertions, OK` | ✓ PASS |
| SC#2 single-flight (isolated) | `vendor/bin/phpunit --filter SingleFlightRefreshTest` | 1 test, 7 assertions, OK | ✓ PASS (guard only, not wire-body) |
| TLS-bypass gate | `grep -rn 'verify.*=>.*false' sdks/php --include=*.php --exclude-dir=vendor \| grep -v customCa` | empty | ✓ PASS |
| gRPC unguarded-reference gate | `grep -rn "Grpc\\\\BaseStub\|AuthzGrpcClient" src --include=*.php \| grep -v "src/Grpc/"` | only inside guarded `AuthzDispatcher.php` branches | ✓ PASS |
| Debt markers | `grep -rn "TBD\|FIXME\|XXX\b" src/ tests/ bin/ examples/` | none (one false-positive comment about JSON `\uXXXX` escaping, not a marker) | ✓ PASS |
| Examples syntax | `php -l` on all 5 example entry points | no syntax errors | ✓ PASS |
| PHPStan level 6 | `vendor/bin/phpstan analyse` | **could not run** — `phpstan/phpstan` not installed in this sandbox (same documented GitHub-egress-proxy limitation every 22-* SUMMARY reports) | ? SKIP — deferred to CI, consistent with every prior 22-* plan's documented deferral |

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|-----------------|--------------|--------|----------|
| PHP-01 | 22-01 .. 22-09 (all 9 plans) | PHP SDK — REST + AMQP; gRPC long-running runtimes only; Packagist publish | ⚠️ PARTIAL | All 5 ROADMAP success criteria are substantively implemented and tested; SC#2's underlying refresh mechanism has a confirmed, unfixed wire-format defect that will break real-server token refresh (see gap). Note: `.planning/REQUIREMENTS.md`'s v1.1 traceability table still shows PHP-01 as "Pending" (line 563) — this is stale (the same table also shows FND-01..05 and TS-01 as "Pending" despite those phases being marked Complete elsewhere), a pre-existing doc-sync gap not introduced by this phase, informational only. |

No orphaned requirements: PHP-01 is the only requirement mapped to Phase 22 and all 9 plans declare it in frontmatter.

### Anti-Patterns Found

None blocking. No `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` markers in any phase-modified file. No empty stub implementations found in the reviewed source.

## Gaps Summary

The PHP SDK is substantively complete and well-tested (48 tests / 159 assertions, all green; strong grep-gate discipline for TLS/gRPC-guard/debt-marker hygiene; honest documentation of Laravel-vs-Symfony registration and the gRPC/AMQP runtime requirement). Four of five ROADMAP success criteria are fully verified end-to-end against the actual codebase, not just SUMMARY claims.

**One confirmed functional defect blocks full SC#2 achievement:** `Session::refreshIfNeeded()` (the single mechanism both the reactive 401-triggered `RefreshMiddleware` and the explicit `AxiamClient::refresh()` depend on) sends `{"tenant": "<slug>"}` as its `/api/v1/auth/refresh` POST body. The server's authoritative `RefreshRequest` OpenAPI schema requires `tenant_id` and `org_id` as UUIDs and has no `tenant` field at all. This means that against the real AXIAM server, every access-token refresh attempt — which is central to "a PHP developer can authenticate via REST" for any session outliving the 15-minute access-token TTL — will fail. This was self-identified and explicitly left unfixed by the 22-06 plan's own executor (documented in 22-06-SUMMARY.md's "Issues Encountered"/"Next Phase Readiness" sections as a recommended follow-up), and there is no later phase in the v1.1 milestone (Phase 22 is the final SDK phase) to defer it to per Step 9b's deferred-item rule.

This is a real, cross-verified (against `sdks/openapi.json` and the C# sibling SDK's correct implementation) defect in a security-relevant, core mechanism — not a cosmetic or documentation issue — and is classified as a BLOCKER gap requiring a scoped fix (resolve `tenant_id`/`org_id` from the current access token's unverified claims, as every sibling SDK does, before the refresh POST) plus a test that asserts the request body, not just the call count.

---

_Verified: 2026-07-02T20:00:28Z_
_Verifier: Claude (gsd-verifier)_
