---
phase: 22-php-sdk
plan: 04
subsystem: sdk
tags: [php, guzzle, handlerstack, single-flight, refresh, csrf, tenant, session]

# Dependency graph
requires:
  - phase: 22-php-sdk
    provides: "22-01: Axiam\\Sdk\\Core\\{AuthError,AxiamException} — error taxonomy the refresh-failure path wraps into"
provides:
  - "Axiam\\Sdk\\Session — Guzzle CookieJar + CSRF-token capture + refreshIfNeeded(): PromiseInterface shared-promise single-flight; tenant required ctor (D-13)"
  - "Axiam\\Sdk\\Auth\\RefreshGuard::settle() — shared clear-on-both-paths + failure-to-AuthError translation, reused by REST today and any future gRPC session"
  - "Axiam\\Sdk\\Rest\\AuthMiddleware — HandlerStack middleware injecting Authorization/X-Tenant-ID/X-CSRF-Token"
  - "Axiam\\Sdk\\Rest\\RefreshMiddleware — HandlerStack middleware: 401 -> single-flight refresh -> retry exactly once"
  - "tests/SingleFlightRefreshTest.php — SC#2 proof, non-vacuous (verified RED when the guard is removed)"
affects: [22-05, 22-06, 22-07, 22-08, 22-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Check-and-store single-flight: Session::refreshIfNeeded() nulls-checks then assigns $this->refreshPromise synchronously (no revolt/event-loop mutex, D-06 fiber-safe by construction)"
    - "RefreshGuard::settle() factors the clear-on-both-paths + AuthError-normalization mechanism out of Session so a future gRPC session reuses the SAME behavior instead of re-implementing it"
    - "AuthMiddleware reads the access token live from the shared CookieJar's axiam_access entry (no separate in-memory cache), mirroring sdks/java's SessionState::cachedAccessToken() and sdks/go's cookieValue() helper"
    - "RefreshMiddleware retries via its captured inner $handler (everything below it on the HandlerStack), never re-entering itself — retry-exactly-once by construction, not an explicit counter"

key-files:
  created:
    - sdks/php/src/Session.php
    - sdks/php/src/Auth/RefreshGuard.php
    - sdks/php/src/Rest/AuthMiddleware.php
    - sdks/php/src/Rest/RefreshMiddleware.php
    - sdks/php/tests/SingleFlightRefreshTest.php
  modified: []

key-decisions:
  - "RefreshGuard::settle() takes the raw refresh Promise plus an onClear closure (defined in Session.php, so `$this->refreshPromise = null;` is still literally present and readable in Session.php) rather than owning the promise slot itself via a by-reference parameter — PHP's lack of a clean cross-object mutable-reference idiom made a fully-generic by-reference design less readable than this hybrid; the SAME onClear closure fires on both the success and failure `then()` branches inside RefreshGuard::settle, so the clear-on-both-paths guarantee is enforced once, centrally, not duplicated per call site"
  - "Session's internal $http client is passed in via the constructor (not built internally) so a test can wire it against the exact same MockHandler + Middleware::history instance used by the decorated 'main' client — matches 22-RESEARCH.md Pattern 1's test shape exactly; production AxiamClient wiring (a later plan) is expected to hand Session a client WITHOUT RefreshMiddleware attached, so a 401 on the refresh call itself can never recursively re-enter the guard — noted as a doc comment, not solved in this plan's scope"
  - "AuthMiddleware reads the access token live from the CookieJar (axiam_access) rather than caching a copy on Session — avoids a second, potentially-stale token copy, consistent with the Java/Go sibling SDKs' cookie-jar-is-the-source-of-truth pattern"

patterns-established:
  - "Single-flight-with-clear-on-both-paths as a small reusable static helper (RefreshGuard::settle) rather than a stateful lock object — PHP's cooperative (non-preemptive) execution model makes the synchronous check-and-store on the owning object safe without a mutex; the reusable piece is the failure-normalization + clear bookkeeping, not the mutable state itself"

requirements-completed: [PHP-01]

coverage:
  - id: D1
    description: "Session::refreshIfNeeded() returns the SAME PromiseInterface to every concurrent caller until it settles; check-and-store is synchronous (no revolt/event-loop mutex, D-06)"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SingleFlightRefreshTest.php#testFiveConcurrentExpiredRequestsTriggerExactlyOneRefresh"
        status: pass
      - kind: other
        ref: "grep -nE 'revolt|event-loop' src/Session.php src/Auth/RefreshGuard.php (empty)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Refresh promise is cleared on BOTH success (after CSRF capture) and failure (before rethrow as AuthError, no retry loop, §9.3)"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SingleFlightRefreshTest.php (asserts session->csrfToken() captured post-refresh, and the guard resets between test runs)"
        status: pass
      - kind: other
        ref: "manual RED/GREEN proof: removing the check-and-store guard makes the test fail with 'Mock queue is empty' (documented below); restored and re-verified green"
        status: pass
    human_judgment: false
  - id: D3
    description: "AuthMiddleware injects Authorization + X-Tenant-ID on every request and X-CSRF-Token only on state-changing methods (POST/PUT/PATCH/DELETE)"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "manual scratch verification (uncommitted): GET request carries Authorization+X-Tenant-ID and NO X-CSRF-Token; POST request echoes a captured CSRF token — see Verification section below"
        status: pass
    human_judgment: false
  - id: D4
    description: "RefreshMiddleware retries the original request exactly once on 401, via the captured inner handler (no loop/recursion)"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SingleFlightRefreshTest.php (5 initial 401s each retry exactly once and succeed with 200 -- queue would underflow with 'Mock queue is empty' on any extra retry attempt)"
        status: pass
    human_judgment: false
  - id: D5
    description: "SC#2: 5 concurrent Guzzle async promises against an expired token trigger exactly 1 refresh call, proven non-vacuously (deliberately-ordered MockHandler queue, all 5 401s before the one refresh 200)"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SingleFlightRefreshTest.php#testFiveConcurrentExpiredRequestsTriggerExactlyOneRefresh (assertCount(1, $refreshCalls) via Middleware::history)"
        status: pass
    human_judgment: false
  - id: D6
    description: "PHPStan level 6 static analysis clean on the four new source files"
    verification: []
    human_judgment: true
    rationale: "PHPStan could not be installed in this sandbox — same root cause documented in 22-01/22-02/22-03: composer's dist download for phpstan/phpstan returns 'Could not authenticate against github.com' via this sandbox's egress proxy, and the package ships no Packagist 'source' field for a git-clone fallback. Re-attempted in this plan (composer require --dev phpstan/phpstan) and confirmed the same failure; composer.json/composer.lock were left untouched (the require aborted before writing them). Code was manually reviewed for level-6 compliance (full type declarations on every property/param/return; strict_types=1 in every file; the one generic PHPDoc @template block on RefreshGuard::settle() documents its Closure signatures precisely). Deferred to the sdk-ci-php.yml CI workflow (a later plan), which runs on unrestricted infrastructure."

# Metrics
duration: 25min
completed: 2026-07-02
status: complete
---

# Phase 22 Plan 04: Session + RefreshGuard + Auth/Refresh HandlerStack Middlewares Summary

**Guzzle `HandlerStack`-based REST transport heart: `Session` owns the CookieJar/CSRF/single-flight refresh Promise, `RefreshGuard` factors out the clear-on-both-paths mechanism, and `AuthMiddleware`/`RefreshMiddleware` wire header injection and single-flight-refresh-and-retry-once — proven by a non-vacuous PHPUnit test where 5 concurrent expired-token requests trigger exactly 1 refresh call (SC#2).**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 5 (0 modified, 5 created)

## Accomplishments

- `Axiam\Sdk\Session`: owns the Guzzle `CookieJar` (§4), captures the `X-CSRF-Token` response header (§3), and is the single-flight home for the shared refresh `PromiseInterface` (§9, D-06). `tenant` is a required constructor parameter with no nullable default anywhere in the class (D-13). `refreshIfNeeded()`'s check-and-store completes synchronously before any `await`/`wait()`, so N concurrent async callers safely share the exact same promise with zero mutex (`revolt/event-loop` grep confirmed empty).
- `Axiam\Sdk\Auth\RefreshGuard::settle()`: wraps a raw refresh-call promise so a caller-supplied `onClear` closure fires exactly once regardless of outcome, and normalizes any non-`AuthError` failure into `AuthError` — the ONE mechanism REST's `Session` uses today and any future gRPC session would reuse (D-06), rather than each transport re-implementing the clear-on-both-paths bookkeeping.
- `Axiam\Sdk\Rest\AuthMiddleware`: injects `Authorization: Bearer <token>` (read live from the shared cookie jar's `axiam_access` entry) and `X-Tenant-ID` on every request; adds `X-CSRF-Token` only on `POST`/`PUT`/`PATCH`/`DELETE` (§3 non-browser CSRF, §5 tenant context).
- `Axiam\Sdk\Rest\RefreshMiddleware`: intercepts `401` responses, calls `Session::refreshIfNeeded()` (all concurrent 401s on one `Session` share the SAME promise), and retries the original request exactly once via the captured inner handler — structurally incapable of looping since the retry never re-enters `RefreshMiddleware` itself.
- `tests/SingleFlightRefreshTest.php`: fires 5 concurrent `getAsync()` calls against a `MockHandler` whose queue is deliberately ordered with all 5 `401`s BEFORE the single refresh `200` (so the guard is genuinely exercised, not trivially passed), then asserts via `Middleware::history` that exactly ONE `/api/v1/auth/refresh` call occurred and that the refresh response's `X-CSRF-Token` was captured onto the session.

## Task Commits

Each task was committed atomically:

1. **Task 1: Session + RefreshGuard shared-promise single-flight** - `0c2db42` (feat)
2. **Task 2: AuthMiddleware + RefreshMiddleware on the HandlerStack** - `2070117` (feat)
3. **Task 3: SingleFlightRefreshTest (SC#2, MockHandler-counted)** - `035ea1b` (test)

## Files Created/Modified

- `sdks/php/src/Session.php` - CookieJar + CSRF capture + shared refresh-promise single-flight; tenant required ctor
- `sdks/php/src/Auth/RefreshGuard.php` - `settle()`: clear-on-both-paths + failure-to-AuthError translation, reusable across transports
- `sdks/php/src/Rest/AuthMiddleware.php` - Authorization/X-Tenant-ID/X-CSRF-Token header injection
- `sdks/php/src/Rest/RefreshMiddleware.php` - 401 interception, single-flight refresh, retry-exactly-once
- `sdks/php/tests/SingleFlightRefreshTest.php` - SC#2 concurrency proof, MockHandler-counted, non-vacuous

## Decisions Made

- `RefreshGuard::settle()` takes the raw refresh `PromiseInterface` plus an `onClear` closure defined in `Session.php` (so `$this->refreshPromise = null;` remains literally present and readable directly in `Session.php`), rather than a fully-generic by-reference-parameter design that would move the nulling text entirely into `RefreshGuard.php`. The `onClear` closure is the SAME instance invoked from both the success and the failure `then()` branch inside `RefreshGuard::settle()`, so the "cleared on both paths" guarantee is centrally enforced (in `RefreshGuard.php`) exactly once, not duplicated per call site — verified empirically (see Verification below) rather than assumed.
- `Session`'s internal `$http` client is accepted via the constructor (not built internally) so tests can wire it against the exact same `MockHandler` + `Middleware::history` instance the decorated "main" client uses — this matches `22-RESEARCH.md` Pattern 1's illustrative test shape exactly. Production `AxiamClient` wiring (a later plan, 22-06) is expected to hand `Session` a plain client WITHOUT `RefreshMiddleware` attached, so a `401` on the refresh call itself can never recursively re-enter the guard; this plan documents that expectation as a doc comment but does not need to solve the full `AxiamClient` wiring itself.
- `AuthMiddleware::accessToken()`-equivalent logic lives on `Session` (`Session::accessToken()`), reading the `axiam_access` cookie live out of the shared `CookieJar` rather than caching a separate copy — avoids a second, potentially-stale token store, consistent with `sdks/java`'s `SessionState::cachedAccessToken()` and `sdks/go`'s `cookieValue()` precedent.

## Verification

Beyond the plan's own `<verify>` commands:

- **Non-vacuousness proof (required by the environment notes):** temporarily removed the `if ($this->refreshPromise !== null) { return $this->refreshPromise; }` check-and-store guard in `Session::refreshIfNeeded()`, re-ran `vendor/bin/phpunit --filter SingleFlightRefreshTest` — the test genuinely failed RED (`OutOfBoundsException: Mock queue is empty`, since every 401-triggered callback would then start its own refresh call, exhausting the deliberately-limited 11-item mock queue). Restored the guard and re-verified green (1 test, 7 assertions). This confirms the test is load-bearing, not vacuous.
- **AuthMiddleware header-injection behavior** (uncommitted scratch script, not part of the deliverable): confirmed a `GET` request carries `Authorization: Bearer <access-token>` (read from a cookie seeded into the shared jar) and `X-Tenant-ID: acme`, with NO `X-CSRF-Token` (none captured yet); confirmed a subsequent `POST` echoes a previously-captured `X-CSRF-Token` value. Both match §3/§5's requirements.
- `vendor/bin/phpunit --testsuite=unit`: 23 tests, 90 assertions, all green (includes 22-01/22-02/22-03's existing suites plus this plan's new test).
- `composer validate --no-check-publish`: valid (pre-existing "version field" warning, unrelated to this plan).
- Grep gates: `refreshPromise` nulling visible in `src/Session.php`; `revolt|event-loop` absent from `src/Session.php` and `src/Auth/RefreshGuard.php`; `tenant` constructor parameter has no default value; `X-CSRF-Token`/`X-Tenant-ID` present in `AuthMiddleware.php`; `refreshIfNeeded` present in `RefreshMiddleware.php` with no `while`-loop; no TLS-bypass pattern (`verify => false`, etc.) anywhere under `src/`.

## Deviations from Plan

None — plan executed as written. The `RefreshGuard`/`Session` split described above is an implementation-detail interpretation of the plan's "factors out the shared-promise clear-on-both-paths helper" instruction (the plan did not prescribe an exact function signature), chosen and verified empirically as described in "Decisions Made" above; it satisfies every stated `<must_haves>` truth and `<acceptance_criteria>` grep gate.

## Issues Encountered

- **PHPStan level-6 verification could not run in this sandbox** — same root cause as 22-01/22-02/22-03 (`phpstan/phpstan`'s dist download fails GitHub authentication via this sandbox's egress proxy, and the package ships no Packagist `source` field for a git-clone fallback). Re-attempted via `composer require --dev phpstan/phpstan:^2.2` in this plan; failed identically with `Could not authenticate against github.com`. `composer.json`/`composer.lock` were left untouched — the failed `require` aborted before writing either file (confirmed via `git status`/`git diff`, no changes). All four new source files were manually reviewed for level-6 compliance (full type declarations on every property/param/return; `declare(strict_types=1)` in every file). Deferred to the `sdk-ci-php.yml` CI workflow (a later plan in this phase), which runs on unrestricted infrastructure.
- All other verification commands ran successfully — see "Verification" section above.

## Known Stubs

None — all code shipped in this plan is fully implemented. PHPStan level-6 verification itself could not run in this sandbox (see Issues Encountered) but this is a tooling-access gap, not a code stub.

## Threat Flags

None — this plan's new surface (the refresh POST, the two `HandlerStack` middlewares) is exactly the surface the plan's own `<threat_model>` (T-22-12 through T-22-15) already covers; no new endpoint/auth-path/schema surface was introduced beyond what was planned and mitigated.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `Axiam\Sdk\{Session, Auth\RefreshGuard, Rest\AuthMiddleware, Rest\RefreshMiddleware}` are ready for 22-05 (`AuthzRestClient` + gRPC guard/dispatcher, which will share `Session`'s single-flight mechanism via the same `RefreshGuard::settle()` pattern) and 22-06 (`AxiamClient` facade, which will assemble the actual `HandlerStack` wiring — `AuthMiddleware` pushed before `RefreshMiddleware` — around `Session`, and construct `Session`'s internal `$http` client WITHOUT `RefreshMiddleware` attached per the doc comment left in `Session.php`).
- `tests/SingleFlightRefreshTest.php`'s wiring pattern (shared `MockHandler`/`Middleware::history` between `Session`'s internal client and the decorated "main" client) is reusable for any future concurrency test in this SDK.
- **Follow-up for a maintainer or the `sdk-ci-php.yml` plan:** run `vendor/bin/phpstan analyse src/Session.php src/Auth/RefreshGuard.php src/Rest/AuthMiddleware.php src/Rest/RefreshMiddleware.php --level=6` on a machine/CI runner with unrestricted GitHub access to close the one deferred acceptance criterion from this plan (same deferral as 22-01/22-02/22-03).

---
*Phase: 22-php-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 5 created files confirmed present on disk; all 3 task commit hashes
(`0c2db42`, `2070117`, `035ea1b`) confirmed present in `git log --oneline --all`.
