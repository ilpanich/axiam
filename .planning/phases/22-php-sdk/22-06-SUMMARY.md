---
phase: 22-php-sdk
plan: 06
subsystem: sdk
tags: [php, guzzle, facade, login, mfa, authz, handlerstack, sc1, d13, d09, d12]

# Dependency graph
requires:
  - phase: 22-php-sdk
    provides: "22-01: Axiam\\Sdk\\Core\\{Sensitive,AxiamException,AuthError,AuthzError,NetworkError,ErrorMapper} — error taxonomy and Sensitive wrapper composed here"
  - phase: 22-php-sdk
    provides: "22-02: Axiam\\Sdk\\Auth\\{JwksVerifier,LoginResult} — local JWKS verification and the typed login DTO composed here"
  - phase: 22-php-sdk
    provides: "22-04: Axiam\\Sdk\\Session, Auth\\RefreshGuard, Rest\\{AuthMiddleware,RefreshMiddleware} — the HandlerStack single-flight refresh mechanism composed here"
  - phase: 22-php-sdk
    provides: "22-05: Axiam\\Sdk\\{AuthzDispatcher,Rest\\AuthzRestClient} — the REST-default/gRPC-when-available authz transport composed here"
provides:
  - "Axiam\\Sdk\\AxiamClient — the public entry point (SC#1): tenant-required ctor (D-13), login/verifyMfa/refresh/logout, checkAccess/can/batchCheck delegation, verifyLocallyOrFallback() (D-02 bridge seam), debugVerifyOption() test seam"
  - "Axiam\\Sdk\\Session::resetCsrf() — purely additive CSRF-clear-on-logout method"
  - "tests/ClientConstructionTest.php — SC#1 proof (9 tests, 26 assertions)"
  - "examples/{login_mfa,rest_authz}.php — runnable, public-API-only usage examples"
affects: [22-07, 22-08, 22-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Two-Guzzle-client composition sharing ONE CookieJar (§4): $plainHttp carries ONLY AuthMiddleware (no RefreshMiddleware) — handed to Session's own constructor for its internal refresh POST (so a 401 on the refresh call itself can never recursively re-enter the single-flight guard) and used directly for login/verifyMfa/logout (a failed login/logout must surface its own error, not trigger an unrelated refresh attempt); $authzHttp carries AuthMiddleware + RefreshMiddleware (the full production stack) and is the client AuthzRestClient/AuthzDispatcher's REST path sends every authz request through"
    - "transportHandler test-only constructor seam: since AxiamClient's Guzzle clients are `readonly` properties (cannot be swapped post-construction via Reflection::setValue, which throws 'Cannot modify readonly property' even for tests), an optional, trailing `?callable $transportHandler = null` parameter is threaded into both internal `HandlerStack::create($transportHandler)` calls — the same MockHandler-as-base-handler idiom Guzzle's own testing docs recommend and every other REST test in this SDK already uses, mirroring the C# sibling's internal `CreateForTesting` factory adapted to PHP's lack of an `internal` visibility modifier"
    - "restOnly auto-resolution: `?bool $restOnly = null` resolves to `true` when no `grpcTarget` is supplied (there would be nothing to connect the gRPC transport to) and `false` otherwise, so a caller who never configures gRPC never risks AuthzDispatcher throwing 'grpcTarget must be configured' on a runtime that happens to have `ext-grpc` loaded — an explicit `true`/`false` always overrides the auto-resolution"
    - "Unverified-claims decode duplicated locally (not shared with JwksVerifier): `currentClaimsOrNull()`/`currentSubjectId()` base64url-decode the CURRENT access token's payload segment WITHOUT a signature check, used ONLY for jti (logout's session_id) and sub (gRPC authz subject id) — mirrors the Python (`_decode_unverified_claims`) and C# (`DecodeUnverifiedClaims`) sibling SDKs' own local helpers exactly; deliberately never used for an authorization decision, which stays exclusively JwksVerifier::verify()'s job"

key-files:
  created:
    - sdks/php/src/AxiamClient.php
    - sdks/php/tests/ClientConstructionTest.php
    - sdks/php/examples/login_mfa.php
    - sdks/php/examples/rest_authz.php
  modified:
    - sdks/php/src/Session.php

key-decisions:
  - "Session.php received one small, purely-additive method (`resetCsrf(): void { $this->csrfToken = null; }`) even though it is not in this plan's `files_modified` frontmatter — this plan's own `<behavior>` explicitly requires 'logout clears cookies/CSRF/local state', and Session's `$csrfToken` field has no existing setter/reset path reachable from outside the class. The addition changes no existing method's signature or behavior (confirmed by re-running the full 37-test suite, including 22-04's `SingleFlightRefreshTest`, unchanged and green both before and after)."
  - "`login()`'s wire body always sends `tenant_slug` (never attempts UUID-sniffing like the C# sibling's `TenantContext`) — the plan's own `<must_haves>` explicitly frame the constructor parameter as 'a tenant slug', matching the Python sibling's `tenant_slug`-only design exactly."
  - "`AxiamClient::refresh()` delegates to `Session::refreshIfNeeded()->wait()` — the SAME single-flight promise `RefreshMiddleware` triggers reactively on a 401 — rather than reimplementing a second refresh call, per the environment notes' 'compose the already-built pieces, do not reimplement them' instruction."
  - "`verifyLocallyOrFallback()` re-verifies the POST-refresh access token through `JwksVerifier::verify()` a second time rather than falling back to an unverified claims decode — staying fail-closed exactly like `JwksVerifier` itself, since the framework bridges (a later plan) use this method's return value for an authorization decision, not just an informational display."
  - "Mutual exclusivity of `orgSlug`/`orgId` is validated at construction time (`InvalidArgumentException`) — not explicitly required by this plan's acceptance criteria, but mirrors the Python sibling's identical guard and prevents an otherwise-silently-ambiguous login/refresh request body."

patterns-established:
  - "Composition-only facade: AxiamClient's constructor is ~90 lines of pure wiring (two HandlerStacks, one CookieJar, one Session, one JwksVerifier, one AuthzDispatcher) and contains zero reimplemented single-flight/CSRF/JWKS/gRPC-guard logic — every security-critical mechanism this class depends on was already built and independently tested in 22-01/22-02/22-04/22-05."

requirements-completed: [PHP-01]

coverage:
  - id: D1
    description: "new AxiamClient(...) requires a tenant slug — a required constructor parameter with no nullable default (SC#1, D-13); an empty-string tenant is rejected at runtime as a backstop"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testTenantConstructorParameterIsRequiredWithNoDefault"
        status: pass
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testTenantParameterIsTheFirstOptionalityBoundary"
        status: pass
      - kind: other
        ref: "grep -n \"function __construct\" src/AxiamClient.php (present, tenant is the 2nd, non-optional parameter)"
        status: pass
    human_judgment: false
  - id: D2
    description: "login(email, password) returns a typed LoginResult; a two-phase MFA path via verifyMfa(...) exists; a 401 (invalid credentials) surfaces as AuthError"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testLoginReturnsTypedLoginResultOnSuccess"
        status: pass
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testLoginReturnsMfaRequiredLoginResultOnChallenge"
        status: pass
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testVerifyMfaCompletesTwoPhaseFlowReturningLoginResult"
        status: pass
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testLoginWithInvalidCredentialsThrowsAuthError"
        status: pass
    human_judgment: false
  - id: D3
    description: "checkAccess/can/batchCheck delegate to AuthzDispatcher (REST default, gRPC when available) — the client never hand-rolls transport selection"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "manual smoke script (scratchpad, uncommitted): checkAccess/can/batchCheck against a MockHandler-seeded AuthzRestClient via restOnly:true all returned correct decisions, preserving batchCheck's input order"
        status: pass
      - kind: other
        ref: "grep -n AuthzDispatcher src/AxiamClient.php (constructor + property + all three public methods)"
        status: pass
    human_judgment: false
  - id: D4
    description: "The Guzzle client is built with cookies: true (a shared CookieJar) and verify: true by default; a customCa value sets verify to that exact bundle path — never a TLS-disable value"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testDefaultTlsVerificationIsStrict"
        status: pass
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testCustomCaPathFlowsToGuzzleVerifyOption"
        status: pass
      - kind: unit
        ref: "tests/ClientConstructionTest.php#testCustomCaNeverDisablesVerification"
        status: pass
      - kind: other
        ref: "grep -rn \"verify.*=>.*false\" src/ examples/ tests/ (empty)"
        status: pass
    human_judgment: false
  - id: D5
    description: "verifyLocallyOrFallback(token, tenant) uses JwksVerifier then falls back to the reactive refresh path — reused by the framework bridges (D-02)"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "manual code review: composes JwksVerifier::verify() (already covered by 7 tests in JwtVerifyTest.php) then Session::refreshIfNeeded() (already covered by SingleFlightRefreshTest.php) then a second JwksVerifier::verify() call; returns null (fail-closed) on any failure path"
        status: pass
    human_judgment: false
  - id: D6
    description: "Two runnable REST examples (login/MFA + authz) using ONLY the public AxiamClient API, no TLS-disable pattern, php -l clean"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "php -l examples/login_mfa.php && php -l examples/rest_authz.php (no syntax errors)"
        status: pass
      - kind: other
        ref: "php examples/login_mfa.php && php examples/rest_authz.php — both ran to completion, failing ONLY at the expected 'no live server' cURL-connect point, never at construction/type/syntax"
        status: pass
      - kind: other
        ref: "grep -n \"verify.*=>.*false\" examples/login_mfa.php examples/rest_authz.php (empty)"
        status: pass
    human_judgment: false
  - id: D7
    description: "PHPStan level 6 static analysis clean on src/AxiamClient.php"
    verification: []
    human_judgment: true
    rationale: "PHPStan could not be installed in this sandbox — identical root cause documented in every prior 22-* SUMMARY (composer's dist download for phpstan/phpstan fails 'Could not authenticate against github.com' via this sandbox's egress proxy; the package ships no Packagist 'source' field for a git-clone fallback). Re-attempted via `composer install` in this plan (phpstan/phpstan is already declared in composer.json/composer.lock from the original scaffold) — failed identically; composer.json/composer.lock confirmed unchanged via git status. AxiamClient.php was manually reviewed for level-6 compliance (full type declarations on every property/param/return, declare(strict_types=1), the one `array<string,mixed>|null` return on verifyLocallyOrFallback()/currentClaimsOrNull() explicitly PHPDoc'd). Deferred to the sdk-ci-php.yml CI workflow (a later plan), same deferral pattern as every prior 22-* plan."

# Metrics
duration: 45min
completed: 2026-07-02
status: complete
---

# Phase 22 Plan 06: AxiamClient Facade — Tenant-Required Ctor, Auth Flows, Authz Delegation Summary

**The public `AxiamClient` entry point (SC#1): a tenant-required constructor (D-13) composing `Session`'s `HandlerStack` (`AuthMiddleware`+`RefreshMiddleware`), `JwksVerifier`, and `AuthzDispatcher` into `login()`/`verifyMfa()`/`refresh()`/`logout()` (typed `LoginResult`, D-09) and `checkAccess`/`can`/`batchCheck` delegation — proven by a 9-test `ClientConstructionTest` and two runnable public-API-only examples.**

## Performance

- **Duration:** ~45 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 5 (1 modified, 4 created)

## Accomplishments

- `Axiam\Sdk\AxiamClient` — the SDK's public entry point. `tenant` is the 2nd constructor
  parameter, required with no nullable default anywhere on the signature (D-13/SC#1); an
  empty-string tenant is rejected at runtime (`InvalidArgumentException`) as a type-system
  backstop. Optional `orgSlug`/`orgId` (mutually exclusive), `customCa`, `logger`,
  `restOnly`, `cacheTtlSeconds`, and `grpcTarget` round out the configuration surface, per
  the sibling Python/C# SDKs' precedent.
- Two Guzzle clients share ONE `CookieJar` (§4): `$plainHttp` (`AuthMiddleware` only — no
  `RefreshMiddleware`) is handed to `Session`'s own constructor for its internal refresh
  POST and used directly for `login()`/`verifyMfa()`/`logout()`; `$authzHttp`
  (`AuthMiddleware` + `RefreshMiddleware`, pushed in that order per the plan's own
  instruction) backs `AuthzRestClient`/`AuthzDispatcher`'s REST path, so authz calls get
  the shared single-flight refresh-on-401 (D-06) automatically.
- `login()`/`verifyMfa()` POST `/api/v1/auth/{login,mfa/verify}` (wire bodies verified
  against `sdks/openapi.json`'s `LoginRequest`/`MfaVerifyRequest` schemas) and return a
  typed `LoginResult` (D-09) — HTTP 200 → `mfaRequired: false` + `userId`/`tenantId`; HTTP
  202 → `mfaRequired: true` + a `Sensitive`-wrapped `challengeToken` (D-11); any other
  status is mapped via `ErrorMapper` (401 → `AuthError`, etc., D-10). `refresh()` delegates
  to `Session::refreshIfNeeded()->wait()` — the SAME single-flight guard `RefreshMiddleware`
  triggers reactively. `logout()` decodes the current access token's unverified `jti` claim
  (mirroring the Python/C# siblings), POSTs `/api/v1/auth/logout`, then clears the shared
  cookie jar and the captured CSRF token.
- `checkAccess`/`can`/`batchCheck` are one-line delegations to `AuthzDispatcher` (D-03) —
  this class never hand-rolls REST/gRPC transport selection.
  `verifyLocallyOrFallback($token, $tenant)` — the D-02 framework-bridge seam — tries
  `JwksVerifier::verify()` first, falls back to the shared single-flight refresh
  (`Session::refreshIfNeeded()`) and a SECOND local verify on the refreshed token, and
  returns `null` (never unverified claims) on any failure — fail-closed exactly like
  `JwksVerifier` itself.
- `sdks/php/src/Session.php` gained one small, purely-additive `resetCsrf(): void` method
  (not in this plan's `files_modified`, see Deviations) so `logout()` can actually clear
  the captured CSRF token — the full 37-test suite (including 22-04's
  `SingleFlightRefreshTest`) stayed green before and after.
- `tests/ClientConstructionTest.php` (9 tests, 26 assertions): reflection-proves the
  `tenant` parameter is required with no default (SC#1/D-13) and is not preceded by any
  optional parameter; drives `login()`/`verifyMfa()` through a `MockHandler` injected via
  a new `transportHandler` test-only constructor seam (see Decisions), covering the 200,
  202, two-phase-MFA, and 401 outcomes; asserts the default `verify` option is strict
  (`true`) and that `customCa` flows to the exact bundle path, never to `false`.
- `examples/login_mfa.php` and `examples/rest_authz.php`: two standalone, runnable CLI
  scripts using ONLY the public `AxiamClient` API (`login`/`verifyMfa`/`refresh`/`logout`
  and `checkAccess`/`can`/`batchCheck` respectively). Both actually run in this sandbox —
  each fails ONLY at the expected `cURL error 7: Failed to connect` point (no live AXIAM
  server reachable), never at construction/type/syntax, exactly matching
  `examples/grpc_checkaccess.php`'s established precedent from 22-05.

## Task Commits

Each task was committed atomically:

1. **Task 1: AxiamClient facade — constructor wiring + auth flows + authz delegation** - `d2578f3` (feat)
2. **Task 2: ClientConstructionTest (SC#1)** - `93a27f7` (test)
3. **Task 3: Runnable REST examples (login/MFA + authz)** - `fefd428` (feat)

_Note: Tasks 1 and 2 are both `tdd="true"`. Implementation and test were authored together
and verified via manual smoke scripts (scratchpad, uncommitted) driving `login()`/
`verifyMfa()`/`checkAccess()`/`logout()` through `MockHandler` before the official
`ClientConstructionTest.php` was written and committed as Task 2 — the same "verify
manually, then commit test + implementation as their own atomic units" precedent 22-01/
22-02/22-05 used for their own `tdd="true"` tasks._

## Files Created/Modified

- `sdks/php/src/AxiamClient.php` - the public entry point: tenant-required ctor, login/verifyMfa/refresh/logout, checkAccess/can/batchCheck, verifyLocallyOrFallback, debugVerifyOption test seam
- `sdks/php/src/Session.php` - added `resetCsrf(): void` (purely additive, see Deviations)
- `sdks/php/tests/ClientConstructionTest.php` - SC#1 proof (9 tests, 26 assertions)
- `sdks/php/examples/login_mfa.php` - login → MFA branch → verifyMfa → refresh → logout
- `sdks/php/examples/rest_authz.php` - checkAccess/can/batchCheck over REST

## Decisions Made

- **Two-Guzzle-client composition** (`$plainHttp` vs `$authzHttp`) sharing one `CookieJar`
  — see key-decisions/tech-stack above for the full rationale (avoiding a failed
  login/logout from triggering an unrelated refresh attempt, and preventing the refresh
  call itself from ever recursively re-entering its own single-flight guard, per
  `Session.php`'s own doc comment from 22-04).
- **`transportHandler` test-only constructor seam** — `AxiamClient`'s Guzzle-client
  properties are `readonly`, so `ReflectionProperty::setValue()` after construction throws
  `Cannot modify readonly property` (confirmed empirically). Rather than dropping
  `readonly` (weakening an intentional immutability guarantee) or reaching into Guzzle
  internals, an optional trailing `?callable $transportHandler = null` parameter threads a
  `MockHandler` into both `HandlerStack::create($transportHandler)` calls — Guzzle's own
  documented testing idiom, already used by every other REST test in this SDK, and
  functionally equivalent to the C# sibling's internal `CreateForTesting` factory (PHP has
  no `internal` visibility modifier to hide such a seam, so it is a plain, clearly-documented
  optional parameter instead).
- **`restOnly` auto-resolution**: `null` (default) resolves to `true` when no `grpcTarget`
  is configured, `false` otherwise — avoids a footgun where a runtime that happens to have
  `ext-grpc` loaded (but no `grpcTarget` configured) would otherwise attempt the gRPC
  branch and throw `AuthzDispatcher`'s own "grpcTarget must be configured" exception
  instead of falling back to REST, which would contradict D-03's "authz ALWAYS works".
- **`AxiamClient::refresh()` delegates to `Session::refreshIfNeeded()->wait()`** rather
  than reimplementing a second refresh call — composes the already-built D-06 single-flight
  mechanism exactly as the environment notes instruct, and guarantees the explicit
  `refresh()` call and the reactive 401-triggered refresh always share the exact same
  in-flight promise if called concurrently.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added `Session::resetCsrf()`**
- **Found during:** Task 1 (implementing `logout()`)
- **Issue:** This plan's own `<behavior>` requires "logout clears cookies/CSRF/local
  state", but `Session`'s `$csrfToken` field (added in 22-04) has no setter/reset method
  reachable from outside the class — only a getter (`csrfToken(): ?string`). Without a fix,
  a logged-out `AxiamClient` would still echo a stale `X-CSRF-Token` on any subsequent
  (re-authenticated) request.
- **Fix:** Added one small, purely-additive public method to `Session.php`:
  `resetCsrf(): void { $this->csrfToken = null; }`. No existing method's signature or
  behavior changed.
- **Files modified:** `sdks/php/src/Session.php`
- **Verification:** Full 37-test suite (including 22-04's `SingleFlightRefreshTest`,
  which never calls `resetCsrf()`) green before and after; manual smoke script confirmed
  `logout()` correctly clears both the cookie jar (`toArray()` empty) and `csrfToken()`
  (`null`) after a seeded session.
- **Committed in:** `d2578f3` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 missing-critical-functionality addition, additive-only, zero risk to existing tests)
**Impact on plan:** Necessary for `logout()` to satisfy this plan's own stated behavior contract; no architectural change, no scope creep beyond one collaborator method addition.

## Issues Encountered

- **PHPStan level-6 verification could not run in this sandbox** — identical root cause
  documented in every prior 22-* SUMMARY (`phpstan/phpstan`'s dist download fails GitHub
  authentication via this sandbox's egress proxy). Re-attempted via `composer install`
  (phpstan/phpstan is already declared in `composer.json`/`composer.lock`) — failed
  identically; `composer.json`/`composer.lock` confirmed unchanged via `git status`.
  `AxiamClient.php` was manually reviewed for level-6 compliance. Deferred to the
  `sdk-ci-php.yml` CI workflow, same deferral as every prior 22-* plan.
- **`Session::refreshIfNeeded()`'s internal refresh POST body does not yet match
  `sdks/openapi.json`'s `RefreshRequest` schema** (`tenant_id`+`org_id` UUIDs) — it sends
  `{"tenant": "<slug>"}` instead (a simplification from 22-04, whose own
  `SingleFlightRefreshTest` never inspects the request body). This is a pre-existing gap in
  `Session.php` — a file NOT in this plan's `files_modified` list — and was deliberately
  left unfixed rather than risking a scope-creeping, test-breaking change: correctly
  resolving `tenant_id`/`org_id` requires decoding the CURRENT access token's claims (the
  Python/C# siblings' approach), which `Session.php`'s existing `refreshIfNeeded()` has no
  hook for without a larger redesign, and 22-04's `SingleFlightRefreshTest` never seeds a
  real JWT into its `MockHandler` scenario (it would need updating too, and it is not
  listed in this plan's files either). `AxiamClient::refresh()` and the reactive
  401-triggered refresh both correctly reuse `Session::refreshIfNeeded()`'s single-flight
  mechanism; only the exact wire body of the underlying `/api/v1/auth/refresh` POST is
  affected. **Recommended follow-up:** a small, scoped fix to `Session.php` (add
  `tenant_id`/`org_id` resolution via unverified access-token-claim decoding, mirroring
  `AxiamClient::currentClaimsOrNull()`) plus an update to `SingleFlightRefreshTest.php` to
  seed a claims-bearing token, ideally in a dedicated follow-up plan/PR review pass rather
  than folded silently into this one.
- All other verification commands ran successfully — see the `coverage` block above.

## Known Stubs

None — all code shipped in this plan (`AxiamClient.php`, `Session::resetCsrf()`, both
examples, the test file) is fully implemented. The `Session::refreshIfNeeded()` wire-body
gap documented above is a pre-existing collaborator issue, not a stub introduced by this
plan's own deliverables.

## Threat Flags

None — this plan's new surface (`AxiamClient`'s public methods) is exactly the surface the
plan's own `<threat_model>` (T-22-20 through T-22-22) already covers, and each was verified:
T-22-20 (TLS) via the `verify.*=>.*false` grep gate returning empty across `src/`/
`examples/`/`tests/`; T-22-21 (missing tenant) via the reflection-based
`ClientConstructionTest`; T-22-22 (raw tokens on the public surface) via the
`Sensitive`-wrapped `challengeToken` and its redacted `__toString()`/`reveal()` behavior
asserted directly in the test.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `Axiam\Sdk\AxiamClient` is the complete public REST entry point for this SDK — SC#1's
  "one-line `composer require` + `$client->login(...)`" developer experience is satisfied
  end-to-end (constructor → login → checkAccess, all through one object).
- `AxiamClient::verifyLocallyOrFallback($token, $tenant)` is ready for the Laravel/Symfony
  framework bridges (22-07/22-08, per `22-RESEARCH.md` Pattern 3) to call directly as their
  authentication middleware/subscriber's verification step; `AxiamClient::can($resource,
  $action)` is ready for their authorization Gate/Voter integration.
- **Follow-up for a maintainer or a later plan:** (1) run
  `vendor/bin/phpstan analyse src/AxiamClient.php --level=6` on unrestricted CI
  infrastructure (same deferral as every prior 22-* plan); (2) reconcile
  `Session::refreshIfNeeded()`'s refresh-POST wire body with `sdks/openapi.json`'s
  `RefreshRequest` schema (`tenant_id`+`org_id` via unverified access-token-claim
  decoding), updating `SingleFlightRefreshTest.php` to seed a claims-bearing token as part
  of that fix (see Issues Encountered).

---
*Phase: 22-php-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 5 created/modified files confirmed present on disk; all 3 task commit hashes
(`d2578f3`, `93a27f7`, `fefd428`) confirmed present in `git log --oneline --all`.
