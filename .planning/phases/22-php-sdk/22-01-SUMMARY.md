---
phase: 22-php-sdk
plan: 01
subsystem: sdk
tags: [php, composer, phpunit, error-taxonomy, redaction, sensitive, cr-04]

# Dependency graph
requires:
  - phase: 15-sdk-foundation
    provides: sdks/CONTRACT.md (§2 error taxonomy, §7 Sensitive requirement)
provides:
  - "sdks/php/composer.json filled with pinned runtime deps (guzzlehttp/guzzle, php-amqplib, firebase/php-jwt, psr/log) and dev-only tooling/framework-bridge deps"
  - "sdks/php/phpunit.xml.dist with unit/integration testsuite split, PHPUnit 9.6-compatible"
  - "Axiam\\Sdk\\Core\\Sensitive — WeakMap-backed token wrapper, redacted __toString/jsonSerialize/print_r"
  - "Axiam\\Sdk\\Core\\AxiamException/AuthError/AuthzError/NetworkError — D-10 class-hierarchy error taxonomy"
  - "Axiam\\Sdk\\Core\\ErrorMapper::fromStatus() — single HTTP-status-to-exception translation point"
  - "CR-04 redaction regression test with non-vacuous control case"
affects: [22-02, 22-03, 22-04, 22-05, 22-06, 22-07, 22-08, 22-09]

# Tech tracking
tech-stack:
  added: [guzzlehttp/guzzle ^7.13, php-amqplib/php-amqplib ^3.7, firebase/php-jwt ^6.11, psr/log ^3.0, phpunit/phpunit ^9.6, phpstan/phpstan ^2.2, friendsofphp/php-cs-fixer ^3.95]
  patterns:
    - "Sensitive value stored in a private static WeakMap keyed by instance (not an instance property) so no PHP dumper (print_r/var_export/var_dump) can enumerate it"
    - "NetworkError has no public constructor — only fromResponse()/fromException() factories, neither of which ever stores the raw response/exception object (redact-before-wrap, CR-04)"
    - "ErrorMapper::fromStatus() is the sole status->exception branching point; fromResponse() is a thin delegating convenience wrapper"

key-files:
  created:
    - sdks/php/phpunit.xml.dist
    - sdks/php/.gitignore
    - sdks/php/src/Core/Sensitive.php
    - sdks/php/src/Core/AxiamException.php
    - sdks/php/src/Core/AuthError.php
    - sdks/php/src/Core/AuthzError.php
    - sdks/php/src/Core/NetworkError.php
    - sdks/php/src/Core/ErrorMapper.php
    - sdks/php/tests/SensitiveRedactionTest.php
  modified:
    - sdks/php/composer.json

key-decisions:
  - "symfony/event-dispatcher-contracts pinned ^2.5||^3.0 (not ^7.0||^8.0) — that package versions independently of the Symfony component line; symfony/security-core 7.x/8.x actually requires ^2.5|^3 of it"
  - "Sensitive stores its value in a private static WeakMap keyed by $this, not a normal property, so print_r()/var_export()/var_dump() enumerate zero properties on the object — the plan's behavior spec required print_r() to never leak the value, which a plain private-property approach cannot guarantee"
  - "NetworkError never stores any wrapped exception as its previous/cause, even in fromException() — a wrapped Guzzle RequestException can itself carry a live PSR-7 response with the same sensitive headers, so the C# sibling's null-previous discipline was carried over exactly"

patterns-established:
  - "WeakMap-backed Sensitive: zero introspectable instance properties, immune to print_r/var_export leakage"
  - "Redact-before-wrap error factories: NetworkError::fromResponse()/fromException() are the only construction paths, and the raw response/exception never survives past the factory call"

requirements-completed: [PHP-01]

coverage:
  - id: D1
    description: "composer.json pinned with Guzzle/php-amqplib/firebase-php-jwt/psr-log in require, dev-only tooling+framework-bridge deps in require-dev, composer test/test-unit scripts wired"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "composer validate --no-check-publish (exit 0)"
        status: pass
      - kind: unit
        ref: "composer show --self (require block: php/guzzle/php-amqplib/firebase-php-jwt/psr-log only)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Sensitive wrapper redacts __toString/jsonSerialize/print_r; reveal() is the only real-value accessor"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SensitiveRedactionTest.php#testSensitiveToStringIsRedacted"
        status: pass
      - kind: unit
        ref: "tests/SensitiveRedactionTest.php#testSensitiveJsonSerializationIsRedacted"
        status: pass
      - kind: unit
        ref: "tests/SensitiveRedactionTest.php#testSensitivePrintRIsRedacted"
        status: pass
      - kind: unit
        ref: "tests/SensitiveRedactionTest.php#testSensitiveRevealReturnsRealValue"
        status: pass
    human_judgment: false
  - id: D3
    description: "NetworkError::fromResponse() redacts Set-Cookie/Authorization/Cookie header values before any exception property is set; AuthError/AuthzError/NetworkError extend AxiamException; ErrorMapper::fromStatus() is the single 401/403/409/else translation point"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SensitiveRedactionTest.php#testNetworkErrorRedactsSetCookieAndAuthorizationHeaders"
        status: pass
      - kind: unit
        ref: "tests/SensitiveRedactionTest.php#testNetworkErrorRedactsCookieRequestHeaderEcho"
        status: pass
      - kind: other
        ref: "grep -rnl 'class \\(AuthError\\|AuthzError\\|NetworkError\\)' src/Core (all three show 'extends AxiamException')"
        status: pass
    human_judgment: false
  - id: D4
    description: "PHPStan level 6 static analysis clean on src/"
    verification: []
    human_judgment: true
    rationale: "PHPStan could not be installed in this sandbox: composer's dist download for phpstan/phpstan returns 403 'GitHub access to this repository is not enabled for this session' from api.github.com, and phpstan/phpstan ships no Packagist 'source' field (git-clone fallback would require an ~7GB+ full-history mirror clone of a build-artifact repo, impractical in-session). This is a sandbox network-policy limitation, not a code defect — precedented elsewhere in this project's history (e.g. Phase 19's 'no GitHub network egress' notes). Code was manually reviewed for PHPStan level-6 compliance (full type declarations on all properties/params/returns, no untyped array shapes beyond documented @var/@param annotations); real verification deferred to the sdk-ci-php.yml CI workflow (a later plan) which runs on unrestricted infrastructure."

# Metrics
duration: 35min
completed: 2026-07-02
status: complete
---

# Phase 22 Plan 01: PHP SDK Scaffold + Sensitive + Error Taxonomy + ErrorMapper Summary

**Filled the `sdks/php/` Composer scaffold with pinned dependencies and a PHPUnit 9.6 harness, then implemented a WeakMap-backed `Sensitive` redaction wrapper and the `AxiamException`→`AuthError`/`AuthzError`/`NetworkError` class-hierarchy taxonomy with a central `ErrorMapper`, closing the CR-04 token-leak-via-error bug class in PHP before any transport code exists.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 9 (1 modified, 8 created)

## Accomplishments
- `sdks/php/composer.json` now pins `guzzlehttp/guzzle ^7.13`, `php-amqplib/php-amqplib ^3.7`, `firebase/php-jwt ^6.11`, `psr/log ^3.0` in `require` (zero framework runtime deps, D-01/D-07), with `phpunit`/`phpstan`/`php-cs-fixer` plus the wave-5 Laravel/Symfony bridge deps in `require-dev` only, and `composer test`/`test-unit` scripts wired (SC#5)
- `sdks/php/phpunit.xml.dist` split into `unit`/`integration` testsuites (integration = `*MiddlewareTest`/`*SubscriberTest`, reserved for future Laravel/Symfony bridge plans)
- `Axiam\Sdk\Core\Sensitive`: the wrapped value lives in a private static `WeakMap` keyed by the instance itself (not a normal property), so `print_r()`/`var_export()`/`var_dump()` enumerate zero properties on the object — `__toString()`/`jsonSerialize()` always return the literal `[SENSITIVE]`; `reveal()` is the sole real-value accessor
- `Axiam\Sdk\Core\AxiamException` base + `AuthError`/`AuthzError`/`NetworkError` typed subclasses (D-10 class hierarchy, not a flat enum-of-codes)
- `NetworkError::fromResponse()`/`fromException()` redact `Set-Cookie`/`Authorization`/`Cookie` header **values** before the exception is constructed; neither factory ever stores the raw PSR-7 response or the caught exception as a cause (CR-04 carry-forward — the wrapped exception itself could carry a live response with the same sensitive headers)
- `Axiam\Sdk\Core\ErrorMapper::fromStatus()` is the single 401→`AuthError`/403,409→`AuthzError`/else→`NetworkError` translation point; `fromResponse()` is a thin convenience delegate
- `tests/SensitiveRedactionTest.php`: 6 tests, 19 assertions, proving the redaction contract with non-vacuous control cases (a benign `X-Request-Id` marker header, and `reveal()` returning the real value) so the test would fail red on regression, not silently pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Fill composer.json + PHPUnit scaffold** - `7b57e4f` (feat)
2. **Task 2: Sensitive wrapper + error taxonomy + ErrorMapper** - `9c5f018` (feat)
3. **Task 3: Non-vacuous redaction regression test (CR-04)** - `9c79a95` (test)

_Note: Task 2 and Task 3 are both `tdd="true"`; per the plan's own task boundaries, Task 2's own files list contains no test file (the comprehensive redaction test is Task 3's deliverable). I drove Task 2 with an uncommitted scratch PHPUnit test (RED: classes not found → GREEN: implementation passes) before committing, then wrote and committed the official `SensitiveRedactionTest.php` as Task 3's `test(...)` commit, including a manual mutate-and-revert proof of the non-vacuous control case (not committed)._

## Files Created/Modified
- `sdks/php/composer.json` - Pinned require/require-dev, scripts.test/test-unit
- `sdks/php/phpunit.xml.dist` - unit/integration testsuites, PHPUnit 9.6-compatible `<coverage>` block
- `sdks/php/.gitignore` - `/vendor/`, `composer.lock`, `.phpunit.result.cache`
- `sdks/php/src/Core/Sensitive.php` - WeakMap-backed redaction wrapper
- `sdks/php/src/Core/AxiamException.php` - Base exception
- `sdks/php/src/Core/AuthError.php` - 401/auth-failure typed exception
- `sdks/php/src/Core/AuthzError.php` - 403/409/authz-failure typed exception
- `sdks/php/src/Core/NetworkError.php` - Redact-before-wrap transport-failure exception
- `sdks/php/src/Core/ErrorMapper.php` - Central status→exception translation point
- `sdks/php/tests/SensitiveRedactionTest.php` - CR-04 regression test with control cases

## Decisions Made
- `symfony/event-dispatcher-contracts` pinned `^2.5 || ^3.0` instead of the plan-stated `^7.0 || ^8.0` — this contracts package versions independently of the Symfony component line, and `symfony/security-core` 7.x/8.x actually requires `^2.5|^3` of it; discovered via a real `composer install` dependency-resolution conflict.
- `Sensitive` uses a private static `WeakMap<self, string>` rather than a plain private property, because the plan's `<behavior>` spec requires `print_r()` to never leak the wrapped value — PHP's default `print_r()`/`var_export()`/`var_dump()` enumerate private instance properties with their real values regardless of `__toString()`/`jsonSerialize()` overrides, so a plain-property implementation would fail that requirement. Storing nothing on the instance itself closes that gap structurally.
- `NetworkError::fromException()` never stores the caught `\Throwable` as `$previous` (matches the C# sibling's explicit `inner: null`) — a caught Guzzle transport exception can itself expose a live PSR-7 response via `getResponse()`, so attaching it as a chained cause would reopen the exact CR-04 leak path the redact-before-wrap design exists to close.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] symfony/event-dispatcher-contracts version constraint fixed**
- **Found during:** Task 1 (`composer install`)
- **Issue:** Plan text specified `^7.0 || ^8.0` for `symfony/event-dispatcher-contracts`; this package's Packagist versions top out around `v3.x` (contracts packages version independently of the Symfony component line), so the constraint was unsatisfiable and `composer install` failed with a resolution conflict against `symfony/security-core`'s own `^2.5|^3` requirement.
- **Fix:** Changed the constraint to `^2.5 || ^3.0`.
- **Files modified:** `sdks/php/composer.json`
- **Verification:** `composer install --no-interaction` resolves and installs cleanly.
- **Committed in:** `7b57e4f` (Task 1 commit)

**2. [Rule 1 - Bug] phpunit.xml.dist `<source>` element is PHPUnit 10+ only**
- **Found during:** Task 2 (writing the RED scratch test)
- **Issue:** Task 1's `phpunit.xml.dist` used a `<source><include>...</include></source>` block, which is PHPUnit 10's schema element; PHPUnit 9.6 (the pinned line, per D-07's PHP ≥8.1 floor) rejects it with a validation warning ("Element 'source': This element is not expected").
- **Fix:** Replaced with the PHPUnit 9.6-compatible `<coverage><include>...</include></coverage>` block.
- **Files modified:** `sdks/php/phpunit.xml.dist`
- **Verification:** `vendor/bin/phpunit` runs with zero configuration warnings.
- **Committed in:** `9c5f018` (Task 2 commit)

**3. [Rule 2 - Missing Critical] Added `.phpunit.result.cache` to `.gitignore`**
- **Found during:** Task 2 (running the test suite)
- **Issue:** PHPUnit's default result cache file (`.phpunit.result.cache`) appeared as an untracked generated file after the first test run.
- **Fix:** Added it to `sdks/php/.gitignore`.
- **Files modified:** `sdks/php/.gitignore`
- **Committed in:** `9c5f018` (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (1 blocking dependency-constraint fix, 1 bug fix, 1 missing-gitignore-entry fix)
**Impact on plan:** All three were necessary for `composer install`/`composer test` to function at all; none changed the plan's intended architecture or scope.

## Issues Encountered

- **Sandboxed environment could not install `phpstan/phpstan`.** `composer install`'s dist download for `phpstan/phpstan` (Packagist's only install path for this package — it publishes no `source` field) returns `403 {"message":"GitHub access to this repository is not enabled for this session. Use add_repo to request access."}` from `api.github.com`, in this sandbox's egress proxy. A `git clone` fallback works for the same repo but requires an unbounded full-history `--mirror` clone (observed growing past 6.9GB before being aborted) since `phpstan/phpstan`'s public repo commits a built `.phar` binary on every release across its history — this is a real, documented characteristic of that specific package (why Packagist deliberately omits its `source` field), not a proxy artifact, and made the git-source workaround impractical within this session. All other 99 dev/runtime dependencies installed successfully (via cached dist zips or git-source fallback, which worked fine for repos without this binary-history characteristic). `phpstan/phpstan ^2.2` remains correctly declared in `composer.json`'s `require-dev`; PHPStan level-6 verification is deferred to the `sdk-ci-php.yml` CI workflow (a later plan in this phase), which runs on unrestricted GitHub Actions infrastructure. Manual code review (full type coverage on every property/param/return; no untyped mixed arrays beyond documented `@var`/`@param` PHPDoc) gives high confidence the code would pass level 6 cleanly. See `## Known Stubs` — no stubs exist; this is a verification-tooling gap, not incomplete code.
- All other verification commands ran successfully: `composer validate --no-check-publish` (exit 0), `composer install` (100 packages resolved, zero `illuminate/*`/`symfony/*` in the runtime `require` tree), `vendor/bin/phpunit --version` (9.6.34), `vendor/bin/phpunit --testsuite=unit` (6 tests, 19 assertions, all green), and the `grep -A2 'class NetworkError'` / `grep -rnl 'class \(AuthError\|AuthzError\|NetworkError\)'` structural checks.

## Known Stubs

None — all code shipped in this plan is fully implemented (no placeholder/mock data paths). PHPStan level-6 verification itself could not run in this sandbox (see Issues Encountered) but this is a tooling-access gap, not a code stub.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `sdks/php/src/Core/{Sensitive,AxiamException,AuthError,AuthzError,NetworkError,ErrorMapper}.php` are the foundation every later 22-* plan (REST transport, JWKS, gRPC, AMQP, Laravel/Symfony bridges) will import for error handling and token redaction — no further changes to these six files should be needed.
- `composer test`/`composer test-unit` are live entry points; later plans just add test files under `tests/` (the `unit`/`integration` testsuite split in `phpunit.xml.dist` already anticipates the Laravel/Symfony bridge test file names).
- **Follow-up for a maintainer or the `sdk-ci-php.yml` plan:** run `vendor/bin/phpstan analyse src --level=6` on a machine/CI runner with unrestricted GitHub access to close the one deferred acceptance criterion from this plan (PHPStan could not run in this sandbox — see Issues Encountered).

---
*Phase: 22-php-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 11 created/modified files confirmed present on disk; all 4 commit hashes
(`7b57e4f`, `9c5f018`, `9c79a95`, `37aa367`) confirmed present in `git log --oneline --all`.
