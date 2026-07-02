---
phase: 22-php-sdk
plan: 07
subsystem: sdk
tags: [php, laravel, service-provider, middleware, gate, auto-discovery, d01, d02, sc4]

# Dependency graph
requires:
  - phase: 22-php-sdk
    provides: "22-06: Axiam\\Sdk\\AxiamClient — public entry point, verifyLocallyOrFallback() (D-02 bridge seam), can() authz delegation, both composed here without duplication"
  - phase: 22-php-sdk
    provides: "22-05: Axiam\\Sdk\\{AuthzDispatcher,Rest\\AuthzRestClient} — the REST-default authz transport can() delegates through"
  - phase: 22-php-sdk
    provides: "22-02: Axiam\\Sdk\\Auth\\JwksVerifier — local EdDSA/JWKS verification verifyLocallyOrFallback() calls first"
provides:
  - "Axiam\\Sdk\\Laravel\\AxiamServiceProvider — auto-discovered via composer.json extra.laravel.providers (D-01), binds AxiamClient/AxiamMiddleware/AxiamGate singletons from config('axiam.*')/AXIAM_* env, registers the axiam.auth middleware alias + the axiam Gate ability"
  - "Axiam\\Sdk\\Laravel\\AxiamMiddleware — auth: local-JWKS verify + reactive-refresh fallback via AxiamClient::verifyLocallyOrFallback(), populates axiam_user (user_id/tenant_id/roles), 401 on any failure (D-02, §10)"
  - "Axiam\\Sdk\\Laravel\\AxiamGate — authz: one-line delegation to AxiamClient::can() (D-02); both the idiomatic Gate::define('axiam',...) ability and a standalone authorize() returning a 403 JsonResponse directly"
  - "composer.json extra.laravel.providers entry (true zero-config Laravel auto-discovery)"
  - "tests/LaravelMiddlewareTest.php (5 tests, 17 assertions) — SC#4 proof: 401 (missing/invalid token), identity population + pass-through, Gate deny->403, Gate allow->pass"
  - "examples/laravel_app/{routes.php,README.md} — runnable example demonstrating both auth (401) and authz (403) halves of SC#4, honest about Laravel-vs-Symfony auto-discovery asymmetry"
affects: [22-08, 22-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Symfony\\Component\\HttpFoundation\\Request as the bridge's Request type-hint instead of Illuminate\\Http\\Request: since Illuminate\\Http\\Request directly extends Symfony's Request, a real Laravel request instance satisfies this parameter type unchanged at the Laravel pipeline call site, while the bridge's own dependency footprint stays limited to a package already present in every Laravel install transitively (via illuminate/http) — no new illuminate/http require-dev package was needed to define, type-check, or TEST AxiamMiddleware in this sandbox (illuminate/http, illuminate/auth, illuminate/routing are not installed here; only illuminate/support + illuminate/contracts from 22-01)"
    - "class_exists(\\Illuminate\\Support\\ServiceProvider::class) wraps AxiamServiceProvider's entire class definition (defense-in-depth per this plan's own must_haves) — evaluates true in this sandbox (illuminate/support IS a require-dev package) so the class remains definable/testable, while a hypothetical non-Laravel consumer whose autoloader somehow eagerly parsed this file (which PSR-4 lazy autoloading never actually does) would still not fatal"
    - "AxiamGate ships BOTH a Gate::define('axiam', ...)-compatible allows(): bool method AND a standalone authorize(): ?JsonResponse method — the former is the idiomatic can:axiam,<resource>,<action> route-middleware integration (403 translation handled by Laravel's own built-in Authorize middleware, from illuminate/auth), the latter lets an app (or this plan's own test) get a real 403 JsonResponse without booting illuminate/auth's Gate/Authorize pipeline at all — this is what made the SC#4 403 assertion testable in a sandbox lacking illuminate/auth"
    - "AxiamClient is final (by design, 22-06) and cannot be doubled by PHPUnit's mock generator (RuntimeException: 'declared final and cannot be doubled') — LaravelMiddlewareTest instead constructs a REAL AxiamClient wired with the SAME transportHandler MockHandler seam every other REST test in this suite (JwtVerifyTest, ClientConstructionTest, AuthzDispatcherFallbackTest) already uses, driving genuine JWKS-verify and authz-REST code paths rather than a stubbed double"

key-files:
  created:
    - sdks/php/src/Laravel/AxiamServiceProvider.php
    - sdks/php/src/Laravel/AxiamMiddleware.php
    - sdks/php/src/Laravel/AxiamGate.php
    - sdks/php/tests/LaravelMiddlewareTest.php
    - sdks/php/examples/laravel_app/routes.php
    - sdks/php/examples/laravel_app/README.md
  modified:
    - sdks/php/composer.json

key-decisions:
  - "Typed AxiamMiddleware::handle()'s Request parameter as Symfony\\Component\\HttpFoundation\\Request rather than Illuminate\\Http\\Request — avoids introducing a NEW illuminate/http require-dev dependency (not declared by 22-01's scaffold) purely to satisfy a type hint, since a real Illuminate\\Http\\Request instance IS-A Symfony\\Component\\HttpFoundation\\Request and Laravel's pipeline calls handle($request, $next) with whatever request object it has regardless of the declared parameter's exact class in the type hierarchy."
  - "AxiamGate exposes both the Gate::define(...)-shaped allows(): bool (for real Laravel apps using can:axiam,... middleware, where illuminate/auth's own Authorize middleware performs the 403 translation) AND a standalone authorize(): ?JsonResponse that returns the 403 response directly — the latter made this plan's own SC#4 403 assertion testable without illuminate/auth installed in this sandbox, and gives Laravel apps that skip the full Gate/Authorize pipeline an equally valid integration point (documented in routes.php's second route + README.md)."
  - "LaravelMiddlewareTest drives a REAL AxiamClient (via the transportHandler MockHandler seam from 22-06) rather than a PHPUnit mock/stub of AxiamClient, because AxiamClient is `final` and PHPUnit's mock generator cannot double a final class — this exercises the ACTUAL JwksVerifier/AuthzRestClient code paths the bridge calls, matching every other REST test's own no-mocking-framework convention in this suite."
  - "AxiamServiceProvider's class definition is wrapped in `if (class_exists(\\Illuminate\\Support\\ServiceProvider::class))` — not required for correctness (PSR-4 autoloading is already lazy, so this file is never `require`d by a non-Laravel consumer), but added as literal, cheap defense-in-depth to satisfy this plan's own must_haves wording verbatim."

patterns-established:
  - "Framework-request supertype typing: bridge middleware classes type-hint against the framework's underlying HTTP-foundation base class (Symfony's Request) rather than the framework's own concrete subclass, when the subclass package isn't already a declared dependency — keeps the bridge's dependency footprint minimal while remaining 100% runtime-compatible with the framework's real request objects."

requirements-completed: [PHP-01]

coverage:
  - id: D1
    description: "composer.json extra.laravel.providers lists AxiamServiceProvider — true zero-config Laravel auto-discovery (D-01), illuminate/* stays require-dev only, never a runtime require"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "grep -n \"laravel\" composer.json (extra.laravel.providers entry present); grep -n \"illuminate/\" composer.json (both entries only under require-dev)"
        status: pass
      - kind: other
        ref: "composer validate --no-check-publish (valid, same pre-existing warning as before this plan's edit — verified via git stash comparison)"
        status: pass
    human_judgment: false
  - id: D2
    description: "AxiamMiddleware verifies the token via AxiamClient::verifyLocallyOrFallback() (no duplicated verify logic) and returns 401 on missing/invalid token; populates axiam_user (user_id/tenant_id/roles) on success"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/LaravelMiddlewareTest.php#testMissingTokenReturns401"
        status: pass
      - kind: unit
        ref: "tests/LaravelMiddlewareTest.php#testInvalidTokenReturns401"
        status: pass
      - kind: unit
        ref: "tests/LaravelMiddlewareTest.php#testValidTokenPopulatesIdentityAndPasses"
        status: pass
      - kind: other
        ref: "grep -rn \"verifyLocallyOrFallback\" src/Laravel/AxiamMiddleware.php (matches)"
        status: pass
    human_judgment: false
  - id: D3
    description: "AxiamGate delegates to AxiamClient::can() -> 403 on deny, no client-side deny-override or authz caching beyond the token TTL"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/LaravelMiddlewareTest.php#testGateDenyReturns403"
        status: pass
      - kind: unit
        ref: "tests/LaravelMiddlewareTest.php#testGateAllowPasses"
        status: pass
    human_judgment: false
  - id: D4
    description: "Runnable Laravel example (examples/laravel_app/routes.php) demonstrates BOTH auth (axiam.auth middleware) and authz (can:axiam,... Gate) on one route, php -l clean, no TLS-disable pattern; README documents true zero-config auto-discovery honestly"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "php -l examples/laravel_app/routes.php (no syntax errors)"
        status: pass
      - kind: other
        ref: "grep -n \"axiam.auth\\|can:axiam\" examples/laravel_app/routes.php (both present on the same route's ->middleware([...]) call)"
        status: pass
      - kind: other
        ref: "grep -rn \"verify.*=>.*false\" examples/laravel_app/ (empty)"
        status: pass
    human_judgment: false
  - id: D5
    description: "PHPStan level 6 static analysis clean on src/Laravel"
    verification: []
    human_judgment: true
    rationale: "PHPStan could not be installed in this sandbox — identical root cause documented in every prior 22-* SUMMARY (composer's dist download for phpstan/phpstan fails 'Could not authenticate against github.com' via this sandbox's egress proxy; the package ships no Packagist 'source' field for a git-clone fallback). Re-confirmed in this plan via `composer update --lock` (needed anyway to resync composer.lock's content-hash after the extra.laravel.providers edit) — the same phpstan download failure recurred, while composer.json/composer.lock's package-version content otherwise stayed unchanged (confirmed via git diff). src/Laravel/*.php were manually reviewed for level-6 compliance (full type declarations on every property/param/return, declare(strict_types=1) everywhere, the one array<string,mixed> claims shape explicitly PHPDoc'd). Deferred to the sdk-ci-php.yml CI workflow, same deferral pattern as every prior 22-* plan."

# Metrics
duration: 35min
completed: 2026-07-02
status: complete
---

# Phase 22 Plan 07: Laravel Bridge — Auto-Discovered ServiceProvider + Auth Middleware + Gate Summary

**Auto-discovered `AxiamServiceProvider` (composer.json `extra.laravel.providers`, D-01) wiring an `AxiamMiddleware` (local-JWKS auth, 401, D-02) and an `AxiamGate` (`can()` authz, 403, D-02) — both one-line delegations to the already-built `AxiamClient` facade — proven by a 5-test suite and a runnable two-route Laravel example (SC#4).**

## Performance

- **Duration:** ~35 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 7 (1 modified, 6 created)

## Accomplishments

- `composer.json` gained an `extra.laravel.providers` array naming
  `Axiam\Sdk\Laravel\AxiamServiceProvider` — true zero-config Laravel auto-discovery
  (D-01): once a Laravel app runs `composer require axiam/axiam-sdk`, the provider
  registers itself with no `config/app.php` or `bootstrap/providers.php` edit needed.
  `illuminate/support`/`illuminate/contracts` remain `require-dev` only, unchanged from
  22-01's scaffold — no new runtime dependency was added.
- `Axiam\Sdk\Laravel\AxiamMiddleware` (D-02, §10): extracts the bearer/cookie token
  (Bearer header first, cookie fallback second — the same ordering every sibling SDK's
  own middleware uses), calls `AxiamClient::verifyLocallyOrFallback()` (local JWKS
  verify first, falling back to the shared single-flight refresh, §9/D-06 — never a
  duplicated verify/refresh implementation), and either populates the `axiam_user`
  request attribute (`user_id`/`tenant_id`/`roles`) or returns a standardized 401 JSON
  error body. Type-hinted against `Symfony\Component\HttpFoundation\Request` rather
  than `Illuminate\Http\Request` (see Decisions) — accepts real Laravel request objects
  unchanged at the pipeline call site without requiring a new `illuminate/http`
  dependency.
- `Axiam\Sdk\Laravel\AxiamGate` (D-02): a one-line delegation to `AxiamClient::can()` —
  the server's additive-only RBAC (allow-wins, default-deny, no client-side
  deny-override) is always authoritative. Exposes both `allows(): bool` (the
  `Gate::define('axiam', ...)` ability callback shape, for the idiomatic
  `can:axiam,<resource>,<action>` route middleware) and `authorize(): ?JsonResponse` (a
  standalone check returning the 403 response directly, for apps — and this plan's own
  test — that skip the full `illuminate/auth` Gate/`Authorize` middleware pipeline).
- `Axiam\Sdk\Laravel\AxiamServiceProvider` (guarded by
  `class_exists(\Illuminate\Support\ServiceProvider::class)`, defense-in-depth):
  `register()` binds singleton `AxiamClient`/`AxiamMiddleware`/`AxiamGate` instances
  configured from `config('axiam.*')` falling back to `AXIAM_*` environment variables;
  `boot()` registers the `axiam.auth` middleware alias and the `axiam` Gate ability.
- `tests/LaravelMiddlewareTest.php` (5 tests, 17 assertions, in the `integration`
  PHPUnit testsuite): drives a REAL `AxiamClient` wired with the same
  `transportHandler` `MockHandler` seam every other REST test in this suite uses (not a
  PHPUnit mock — `AxiamClient` is `final` and cannot be doubled). Covers missing-token
  401, malformed-token 401 (fail-closed even after the reactive-refresh fallback itself
  fails against an empty mock queue), valid-token identity population + pass-through
  (using the committed Ed25519 JWKS/JWT fixtures from 22-02), Gate deny → 403
  `JsonResponse`, and Gate allow → `null` (caller proceeds).
- `examples/laravel_app/routes.php` + `README.md`: a two-route runnable example — the
  primary route chains `['axiam.auth', 'can:axiam,documents,read']` (both SC#4 halves
  on one route); a second route calls `AxiamGate::authorize()` directly for apps that
  skip the Gate/`Authorize` pipeline. README documents the true zero-config
  auto-discovery story, required `AXIAM_*` env vars, and — per `22-RESEARCH.md`
  Pitfall 5 — explicitly does NOT claim the Symfony bridge gets the same
  auto-discovery experience.

## Task Commits

Each task was committed atomically:

1. **Task 1: composer.json auto-discovery + Laravel ServiceProvider/Middleware/Gate** - `2cfd4c7` (feat)
2. **Task 2: LaravelMiddlewareTest (auth + can()->403)** - `5f26c19` (test)
3. **Task 3: Runnable Laravel example** - `d93c53e` (feat)

## Files Created/Modified

- `sdks/php/composer.json` - `extra.laravel.providers` entry naming `AxiamServiceProvider`
- `sdks/php/src/Laravel/AxiamServiceProvider.php` - auto-discovered provider; binds AxiamClient/AxiamMiddleware/AxiamGate, registers the `axiam.auth` alias + `axiam` Gate ability
- `sdks/php/src/Laravel/AxiamMiddleware.php` - auth middleware: local-JWKS verify + reactive-refresh fallback, 401 on failure
- `sdks/php/src/Laravel/AxiamGate.php` - authz gate: `can()` delegation, `allows()` + standalone `authorize()`
- `sdks/php/tests/LaravelMiddlewareTest.php` - SC#4 proof (5 tests, 17 assertions)
- `sdks/php/examples/laravel_app/routes.php` - runnable two-route example (both SC#4 halves)
- `sdks/php/examples/laravel_app/README.md` - zero-config auto-discovery story, env vars, honest Laravel-vs-Symfony comparison

## Decisions Made

- **`Symfony\Component\HttpFoundation\Request` instead of `Illuminate\Http\Request`** as
  `AxiamMiddleware::handle()`'s parameter type — see key-decisions above for the full
  rationale (avoids a new `illuminate/http` require-dev dependency not declared by
  22-01's scaffold; a real `Illuminate\Http\Request` instance IS-A Symfony `Request`, so
  Laravel's pipeline calls this method unchanged).
- **`AxiamGate` ships both `allows(): bool` and `authorize(): ?JsonResponse`** — the
  former is the idiomatic Gate-facade integration point; the latter made the SC#4 403
  assertion directly testable in this sandbox, which has no `illuminate/auth` package
  installed (only `illuminate/support`/`illuminate/contracts` from 22-01).
- **`LaravelMiddlewareTest` drives a real `AxiamClient`+`MockHandler`, never a PHPUnit
  mock** — `AxiamClient` is `final` (an intentional 22-06 design choice) and PHPUnit's
  mock generator cannot double a final class; this test instead reuses the
  `transportHandler` seam every other REST test in this suite already relies on.
- **`AxiamServiceProvider`'s class definition is wrapped in a `class_exists` guard** —
  cheap defense-in-depth satisfying this plan's own must_haves wording verbatim, even
  though PSR-4 lazy autoloading already makes this file unreachable for a non-Laravel
  consumer.

## Deviations from Plan

None - plan executed exactly as written. `AxiamGate::authorize()` (a second, non-Gate-facade
authorization entry point) and the `Symfony\Component\HttpFoundation\Request` typing choice
were both design decisions made WITHIN Task 1's/Task 2's own scope (no plan file outside
`files_modified` was touched, no new dependency was added, no architectural change) — logged
above as Decisions rather than Deviations since they did not require adding, removing, or
contradicting anything the plan's `<action>`/`<acceptance_criteria>` specified.

## Issues Encountered

- **`composer validate` initially warned "lock file is not up to date"** after the
  `extra.laravel.providers` edit to `composer.json` (extra-block changes affect
  composer's content-hash even though they change no dependency). Resolved by running
  `composer update --lock --no-scripts` (recomputes only the lock file's content-hash;
  confirmed via `git diff composer.lock` that no package version changed). The command's
  subsequent dependency-installation step failed identically to every prior 22-*
  plan's documented `phpstan/phpstan` GitHub-auth sandbox limitation — expected, not a
  regression, and did not affect the lock file's already-rewritten content-hash.
- **PHPStan level-6 verification could not run in this sandbox** — see coverage D5's
  `rationale` above; identical root cause and deferral as every prior 22-* SUMMARY.
- **`illuminate/http`/`illuminate/auth`/`illuminate/routing` are not installed in this
  sandbox** (only `illuminate/support`/`illuminate/contracts` from 22-01) — resolved via
  the `Symfony\Component\HttpFoundation\Request` typing decision and `AxiamGate`'s
  standalone `authorize()` method (see Decisions) rather than adding a new package,
  which this workflow's own Rule 3 exclusion requires a human-verification checkpoint
  for; no such checkpoint was needed because no new package was required.
- All other verification commands ran successfully — see the `coverage` block above.

## Known Stubs

None — all code shipped in this plan (`AxiamServiceProvider.php`, `AxiamMiddleware.php`,
`AxiamGate.php`, the test file, both example files) is fully implemented and exercised by
either the test suite or a `php -l`/grep-based acceptance check.

## Threat Flags

None — this plan's new surface (the Laravel `axiam.auth` middleware's token-handling and
the `axiam` Gate's authz decision) is exactly the surface this plan's own `<threat_model>`
(T-22-23 through T-22-25) already covers, and each was verified: T-22-23 (spoofing via
token handling) via `testMissingTokenReturns401`/`testInvalidTokenReturns401` proving
fail-closed 401 on both a wholly-absent and a malformed token; T-22-24 (elevation of
privilege via the authz gate) via `testGateDenyReturns403`/`testGateAllowPasses` proving
`AxiamGate` never overrides or caches the server's `can()` decision; T-22-25 (dependency
footprint tampering) via the `illuminate/` composer.json grep gate confirming both entries
stay `require-dev`-only.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The Laravel bridge (`AxiamServiceProvider`/`AxiamMiddleware`/`AxiamGate`) is complete
  and independently testable; 22-08 (the Symfony bridge, per `22-RESEARCH.md` Pattern 3)
  can now proceed with its own `EventSubscriber`/`Voter` pair calling the SAME
  `AxiamClient::verifyLocallyOrFallback()`/`can()` seams, following this plan's own
  precedent of never duplicating verify/refresh/authz logic in a framework bridge.
- **Follow-up for a maintainer or a later plan:** run
  `vendor/bin/phpstan analyse src/Laravel --level=6` on unrestricted CI infrastructure
  (same deferral as every prior 22-* plan) once `sdk-ci-php.yml` exists.

---
*Phase: 22-php-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 7 created/modified files confirmed present on disk; all 3 task commit hashes
(`2cfd4c7`, `5f26c19`, `d93c53e`) confirmed present in `git log --oneline --all`.
