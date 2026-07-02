---
phase: 22-php-sdk
plan: 08
subsystem: sdk
tags: [php, symfony, event-subscriber, voter, manual-registration, d01, d02, sc4, pitfall5]

# Dependency graph
requires:
  - phase: 22-php-sdk
    provides: "22-06: Axiam\\Sdk\\AxiamClient — public entry point, verifyLocallyOrFallback() (D-02 bridge seam), can() authz delegation, both composed here without duplication"
  - phase: 22-php-sdk
    provides: "22-05: Axiam\\Sdk\\{AuthzDispatcher,Rest\\AuthzRestClient} — the REST-default authz transport can() delegates through"
  - phase: 22-php-sdk
    provides: "22-02: Axiam\\Sdk\\Auth\\JwksVerifier — local EdDSA/JWKS verification verifyLocallyOrFallback() calls first"
  - phase: 22-php-sdk
    provides: "22-07: established the framework-bridge precedent (never duplicate verify/refresh/authz logic; class_exists/interface_exists guard pattern; transportHandler MockHandler test seam) this plan follows exactly"
provides:
  - "Axiam\\Sdk\\Symfony\\AxiamBundle — minimal bundle bootstrap (manually registered, no container extension of its own)"
  - "Axiam\\Sdk\\Symfony\\AxiamAuthSubscriber — kernel.request subscriber: local-JWKS verify + reactive-refresh fallback via AxiamClient::verifyLocallyOrFallback(), populates axiam_user (user_id/tenant_id/roles), 401 JsonResponse on any failure (D-02, §10)"
  - "Axiam\\Sdk\\Symfony\\AxiamVoter — extends Symfony's real (installed v8.1.1) Voter; supports() matches resource:action attributes; voteOnAttribute() delegates to AxiamClient::can() (server's additive-only RBAC authoritative)"
  - "tests/SymfonyAuthSubscriberTest.php (6 tests, 14 assertions) — SC#4 proof: 401 (missing/invalid token), identity population without short-circuiting, Voter deny->ACCESS_DENIED, Voter allow->ACCESS_GRANTED, unsupported-attribute abstain"
  - "examples/symfony_app/{bundles.php,services.yaml,README.md} — runnable example with HONEST manual-registration docs (Pitfall 5), demonstrating both auth (401) and Voter->403 (SC#4)"
affects: [22-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Real (not RESEARCH.md draft) Voter::voteOnAttribute() signature used: this sandbox has symfony/security-core v8.1.1 installed, whose abstract voteOnAttribute() signature is `(string $attribute, mixed $subject, TokenInterface $token, ?Vote $vote = null): bool` — the RESEARCH.md Pattern 3 code sample omitted the TokenInterface $token parameter entirely (an older/simplified sketch); the actual installed vendor source was read directly (`vendor/symfony/security-core/Authorization/Voter/Voter.php`) and the real signature implemented, since a mismatched abstract-method signature would be a fatal PHP error at class-load time, not merely a lint warning"
    - "AxiamBundle ships NO container extension of its own — unlike a typical Symfony bundle that auto-wires its own services via a DependencyInjection\\Extension class, this bundle deliberately stays a minimal `extends Bundle` marker; AxiamAuthSubscriber/AxiamVoter tagging happens entirely in the CONSUMING application's own services.yaml (mirrored 1:1 in examples/symfony_app/services.yaml) — this is what makes the two-manual-steps registration story (bundles.php + services.yaml) literally true rather than partially automated, matching Pitfall 5's 'do not overclaim parity with Laravel' instruction as precisely as possible"
    - "SymfonyAuthSubscriberTest builds a real RequestEvent via an anonymous HttpKernelInterface double (no live kernel) and a real TokenInterface double (anonymous class implementing all 11 interface methods) — Voter::vote() requires a genuine TokenInterface argument even though AxiamVoter::voteOnAttribute() never reads it, so a minimal but complete double was necessary rather than a partial stub"

key-files:
  created:
    - sdks/php/src/Symfony/AxiamBundle.php
    - sdks/php/src/Symfony/AxiamAuthSubscriber.php
    - sdks/php/src/Symfony/AxiamVoter.php
    - sdks/php/tests/SymfonyAuthSubscriberTest.php
    - sdks/php/examples/symfony_app/bundles.php
    - sdks/php/examples/symfony_app/services.yaml
    - sdks/php/examples/symfony_app/README.md
  modified: []

key-decisions:
  - "Implemented AxiamVoter::voteOnAttribute() against the ACTUAL installed symfony/security-core v8.1.1 abstract signature (`TokenInterface $token` present) rather than RESEARCH.md Pattern 3's draft code sample (which omitted it) — verified by reading vendor/symfony/security-core/Authorization/Voter/Voter.php directly before writing the override; a signature mismatch on an abstract method is a fatal PHP compile-time error, not a style issue, so this correction was load-bearing (Rule 1 — auto-fixed bug relative to the plan's own research artifact, not a deviation requiring a checkpoint)."
  - "AxiamBundle intentionally contains zero DependencyInjection\\Extension / container-building logic — subscriber/voter tagging is 100% delegated to the consuming app's own services.yaml, mirrored in examples/symfony_app/services.yaml. This maximizes the honesty of the 'two manual steps' framing (Pitfall 5): a bundle that silently auto-wired its own services via a hidden extension class, while still requiring config/bundles.php registration, would blur the Laravel-vs-Symfony distinction this plan's must_haves explicitly require documenting precisely."
  - "SymfonyAuthSubscriberTest reuses the exact fixtureJwt()/fixtureJwks()/clientWith() helper shapes from tests/LaravelMiddlewareTest.php (same Ed25519 fixtures, same transportHandler MockHandler seam) rather than inventing a new fixture set — proves the Symfony bridge reaches the identical JwksVerifier/AuthzRestClient code paths the Laravel bridge and JwtVerifyTest/AuthzDispatcherFallbackTest already cover, with zero duplicated verify/refresh logic in either bridge (D-02)."
  - "The Symfony example's SC#4 controller demonstration lives as an inline code snippet in README.md rather than a standalone example PHP file — this plan's own files_modified frontmatter lists exactly bundles.php/services.yaml/README.md for examples/symfony_app/ (no controller file), and the core axiam/axiam-sdk package intentionally ships zero symfony/* runtime dependency (D-01), so a bootable-controller file would either need a live Symfony kernel to be meaningfully validated or would sit unvalidated — the README's inline snippet is validated by the same php -l discipline as every other example (confirmed via a standalone lint pass) while staying honest about not bundling a bootable kernel."

patterns-established:
  - "Zero-container-extension bundle: a framework bridge's top-level Bundle class can (and, for an honest manual-registration story, should) contain no auto-wiring logic of its own when the plan's own must_haves require documenting the registration experience as literally manual rather than partially-automated-but-undocumented."

requirements-completed: [PHP-01]

coverage:
  - id: D1
    description: "AxiamAuthSubscriber (kernel.request) verifies the token (local JWKS) and populates the Symfony security identity with user_id/tenant_id/roles; 401 on missing/invalid token (D-02, §10)"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SymfonyAuthSubscriberTest.php#testMissingTokenReturns401"
        status: pass
      - kind: unit
        ref: "tests/SymfonyAuthSubscriberTest.php#testInvalidTokenReturns401"
        status: pass
      - kind: unit
        ref: "tests/SymfonyAuthSubscriberTest.php#testValidTokenPopulatesIdentityAndDoesNotShortCircuit"
        status: pass
      - kind: other
        ref: "grep -rn verifyLocallyOrFallback src/Symfony/AxiamAuthSubscriber.php (matches — no duplicated verify logic)"
        status: pass
    human_judgment: false
  - id: D2
    description: "AxiamVoter calls can(resource, action) -> deny -> ACCESS_DENIED (403 via Symfony's own AccessDeniedException/handler); server additive-only RBAC is authoritative (D-02)"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/SymfonyAuthSubscriberTest.php#testVoterDenyReturnsAccessDenied"
        status: pass
      - kind: unit
        ref: "tests/SymfonyAuthSubscriberTest.php#testVoterAllowReturnsAccessGranted"
        status: pass
      - kind: unit
        ref: "tests/SymfonyAuthSubscriberTest.php#testVoterAbstainsOnUnsupportedAttribute"
        status: pass
      - kind: other
        ref: "grep -n \"->can(\" src/Symfony/AxiamVoter.php (matches — delegates to server RBAC)"
        status: pass
    human_judgment: false
  - id: D3
    description: "The Symfony bridge requires MANUAL registration (config/bundles.php + services.yaml) — documented honestly, NOT described as auto-discovered like Laravel (Pitfall 5)"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "grep -in \"config/bundles.php\\|services.yaml\\|manual\" examples/symfony_app/README.md (multiple explicit matches, including a Laravel-vs-Symfony comparison table)"
        status: pass
      - kind: other
        ref: "grep -in \"auto-discover\\|zero-config\" examples/symfony_app/README.md (every match explicitly DENIES the Symfony bridge gets this, never claims it)"
        status: pass
    human_judgment: false
  - id: D4
    description: "All Symfony classes are guarded by class_exists/interface_exists so the core has zero framework runtime deps (D-01); symfony/* stays require-dev only"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "grep -n \"symfony/\" composer.json (all three entries under require-dev only, unchanged by this plan)"
        status: pass
      - kind: other
        ref: "manual code review: AxiamBundle wrapped in class_exists(Bundle::class); AxiamAuthSubscriber wrapped in interface_exists(EventSubscriberInterface::class); AxiamVoter wrapped in class_exists(Voter::class)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Runnable Symfony example demonstrates BOTH auth subscriber and Voter->403 (SC#4); bundles.php passes php -l; services.yaml tags both services correctly"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "php -l examples/symfony_app/bundles.php (no syntax errors)"
        status: pass
      - kind: other
        ref: "python3 yaml.safe_load(services.yaml) (parses cleanly; kernel.event_subscriber + security.voter tags present) — php -l cannot lint YAML and no ext-yaml/symfony-yaml was installed in this sandbox, so a Python YAML parser was used as the syntax-validity check"
        status: pass
    human_judgment: false
  - id: D6
    description: "PHPStan level 6 static analysis clean on src/Symfony"
    verification: []
    human_judgment: true
    rationale: "PHPStan could not be installed in this sandbox — identical root cause documented in every prior 22-* SUMMARY (composer's dist download for phpstan/phpstan fails 'Could not authenticate against github.com' via this sandbox's egress proxy; the package ships no Packagist 'source' field for a git-clone fallback). Confirmed vendor/bin/phpstan absent (never installed, not merely stale) before deferring. src/Symfony/*.php were manually reviewed for level-6 compliance (full type declarations on every property/param/return, declare(strict_types=1) everywhere, the array<string,mixed> claims shape explicitly PHPDoc'd, the Voter's generic template annotated). Deferred to the sdk-ci-php.yml CI workflow (a later plan), same deferral pattern as every prior 22-* plan."

# Metrics
duration: 30min
completed: 2026-07-02
status: complete
---

# Phase 22 Plan 08: Symfony Bridge — AxiamBundle + AuthSubscriber + Voter + Honest Manual-Registration Example Summary

**`AxiamAuthSubscriber` (`kernel.request`, local-JWKS auth, 401, D-02) + `AxiamVoter` (`can()` authz delegation, D-02) wrapped in a minimal `AxiamBundle` that ships zero auto-wiring of its own — proven by a 6-test suite and a runnable example whose README explicitly and repeatedly denies Symfony gets Laravel's zero-config auto-discovery (Pitfall 5, SC#4).**

## Performance

- **Duration:** ~30 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 7 (0 modified, 7 created)

## Accomplishments

- `Axiam\Sdk\Symfony\AxiamAuthSubscriber` (D-02, §10): subscribes to
  `KernelEvents::REQUEST`. Extracts the bearer/cookie token (same Bearer-first,
  cookie-fallback ordering as `Laravel\AxiamMiddleware`), calls
  `AxiamClient::verifyLocallyOrFallback()` (local JWKS verify first, falling back to the
  shared single-flight refresh, §9/D-06 — never a duplicated verify/refresh
  implementation), and either populates the `axiam_user` request attribute
  (`user_id`/`tenant_id`/`roles`) or short-circuits the request with a standardized 401
  JSON error body via `RequestEvent::setResponse()`.
- `Axiam\Sdk\Symfony\AxiamVoter` (D-02): `extends` the REAL installed
  `symfony/security-core` v8.1.1 `Voter` class (its actual abstract
  `voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token, ?Vote $vote
  = null): bool` signature — read directly from vendor source rather than trusted from
  the RESEARCH.md draft, which omitted the `TokenInterface $token` parameter; see
  Deviations). `supports()` matches any `resource:action`-shaped attribute;
  `voteOnAttribute()` is a one-line delegation to `AxiamClient::can($resource,
  $action)` — the server's additive-only RBAC is always authoritative, no client-side
  deny-override or caching beyond the token's own TTL.
- `Axiam\Sdk\Symfony\AxiamBundle` (guarded by `class_exists(Bundle::class)`,
  defense-in-depth mirroring `Laravel\AxiamServiceProvider`'s guard): a minimal
  `extends Bundle` marker with NO container extension of its own — subscriber/voter
  tagging is entirely the consuming application's own `services.yaml` responsibility
  (see Decisions), which is what makes the "two manual steps" registration story
  literally accurate.
- `tests/SymfonyAuthSubscriberTest.php` (6 tests, 14 assertions, in the `integration`
  PHPUnit testsuite — the phpunit.xml `SubscriberTest.php` suffix match, already
  anticipated by 22-01's scaffold, required zero test-config changes): drives a REAL
  `AxiamClient` wired with the same `transportHandler` `MockHandler` seam every other
  REST test in this suite uses. Covers missing-token 401, malformed-token 401
  (fail-closed even after the reactive-refresh fallback itself fails against an empty
  mock queue), valid-token identity population without short-circuiting (using the
  same committed Ed25519 JWKS/JWT fixtures 22-02/22-07 already established), Voter
  deny → `ACCESS_DENIED`, Voter allow → `ACCESS_GRANTED`, and an unsupported attribute
  correctly abstaining with zero HTTP calls attempted.
- `examples/symfony_app/{bundles.php,services.yaml,README.md}`: `bundles.php` shows the
  manual `config/bundles.php` entry; `services.yaml` shows the manual `services:` block
  tagging `AxiamAuthSubscriber` (`kernel.event_subscriber`) and `AxiamVoter`
  (`security.voter`). `README.md` opens with an explicit "No auto-discovery — manual
  registration is REQUIRED (Pitfall 5)" section, a side-by-side Laravel-vs-Symfony
  comparison table, an inline controller snippet demonstrating both SC#4 halves
  (`denyAccessUnlessGranted('documents:read')` → Symfony's own `AccessDeniedException`
  → 403), and closes with an explicit "do not describe this bridge as auto-discovered
  or zero-config" instruction.

## Task Commits

Each task was committed atomically (all signed):

1. **Task 1: AxiamBundle + AxiamAuthSubscriber + AxiamVoter** - `fcf9f8d` (feat)
2. **Task 2: SymfonyAuthSubscriberTest (auth + Voter deny/allow/abstain)** - `ef00bd2` (test)
3. **Task 3: Runnable Symfony example with honest manual-registration docs** - `e189ae2` (feat)

## Files Created/Modified

- `sdks/php/src/Symfony/AxiamBundle.php` - minimal bundle bootstrap, zero container extension of its own
- `sdks/php/src/Symfony/AxiamAuthSubscriber.php` - kernel.request auth subscriber, 401 on failure
- `sdks/php/src/Symfony/AxiamVoter.php` - authz voter, `can()` delegation, real Voter signature
- `sdks/php/tests/SymfonyAuthSubscriberTest.php` - SC#4 proof (6 tests, 14 assertions)
- `sdks/php/examples/symfony_app/bundles.php` - manual `config/bundles.php` entry
- `sdks/php/examples/symfony_app/services.yaml` - manual `services:` tagging (kernel.event_subscriber, security.voter)
- `sdks/php/examples/symfony_app/README.md` - honest manual-registration docs, Laravel-vs-Symfony comparison, SC#4 controller snippet

## Decisions Made

- **Implemented the REAL installed `symfony/security-core` v8.1.1 `Voter::voteOnAttribute()` signature** (including the `TokenInterface $token` parameter RESEARCH.md's Pattern 3 draft omitted) rather than copying the research sample verbatim — see Deviations below for why this was necessary, not optional.
- **`AxiamBundle` ships zero `DependencyInjection\Extension`/auto-wiring logic** — see key-decisions above for the full honesty rationale (Pitfall 5).
- **`SymfonyAuthSubscriberTest` reuses the exact fixture/MockHandler idiom from `LaravelMiddlewareTest`** rather than inventing new fixtures — proves both bridges reach the identical, already-tested `JwksVerifier`/`AuthzRestClient` code paths.
- **The SC#4 controller demonstration is an inline README snippet, not a standalone example file** — matches this plan's own `files_modified` frontmatter exactly (no controller file listed) and avoids an unvalidatable file requiring a live Symfony kernel.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected `AxiamVoter::voteOnAttribute()`'s signature to match the REAL installed Symfony API, not RESEARCH.md's draft**
- **Found during:** Task 1
- **Issue:** `22-RESEARCH.md`'s Pattern 3 code sample for `AxiamVoter::voteOnAttribute()`
  omits the `TokenInterface $token` parameter entirely:
  `protected function voteOnAttribute(string $attribute, mixed $subject, \Vote|null
  $vote = null): bool`. This sandbox has `symfony/security-core` v8.1.1 genuinely
  installed (confirmed via `composer show symfony/security-core`); its actual abstract
  method (read directly from
  `vendor/symfony/security-core/Authorization/Voter/Voter.php`) is
  `abstract protected function voteOnAttribute(string $attribute, mixed $subject,
  TokenInterface $token, ?Vote $vote = null): bool`. Implementing the research
  sample's signature verbatim would produce a fatal
  `Fatal error: Declaration of AxiamVoter::voteOnAttribute() must be compatible with
  Voter::voteOnAttribute()` at class-load time — not a lint warning, a hard failure
  that would make every test in `SymfonyAuthSubscriberTest.php` error out before a
  single assertion ran.
- **Fix:** Implemented the correct four-parameter signature
  (`string $attribute, mixed $subject, TokenInterface $token, ?Vote $vote = null`),
  never reading `$token` (the RBAC decision comes exclusively from
  `AxiamClient::can()`, matching D-02's server-authoritative constraint) — the extra
  parameter is accepted purely to satisfy PHP's abstract-method-compatibility
  requirement.
- **Files modified:** `sdks/php/src/Symfony/AxiamVoter.php`
- **Verification:** `tests/SymfonyAuthSubscriberTest.php`'s three Voter tests
  (`testVoterDenyReturnsAccessDenied`, `testVoterAllowReturnsAccessGranted`,
  `testVoterAbstainsOnUnsupportedAttribute`) all pass, driving the class through
  Symfony's own public `Voter::vote()` entry point (which internally calls
  `voteOnAttribute()` with a real `TokenInterface`), proving the signature is
  genuinely compatible, not just syntactically plausible.
- **Committed in:** `fcf9f8d` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug fix relative to a research-document code sample, not the plan's own prose — the plan's own `<action>` text never specified an exact method signature, only "voteOnAttribute returns AxiamClient::can(...)"). No architectural change, no scope creep, no new dependency.

## Issues Encountered

- **PHPStan level-6 verification could not run in this sandbox** — identical root
  cause documented in every prior 22-* SUMMARY (`phpstan/phpstan`'s dist download
  fails GitHub authentication via this sandbox's egress proxy). Confirmed
  `vendor/bin/phpstan` is absent (never installed) before deferring, rather than
  assuming staleness. `src/Symfony/*.php` were manually reviewed for level-6
  compliance. Deferred to the `sdk-ci-php.yml` CI workflow, same deferral as every
  prior 22-* plan.
- **`services.yaml` syntax validation used a Python `yaml.safe_load()` check rather
  than a PHP-native tool** — this sandbox has neither `ext-yaml` nor
  `symfony/yaml` installed (only `symfony/security-core`,
  `symfony/http-kernel`, `symfony/event-dispatcher(-contracts)` per this plan's own
  `composer.json` `require-dev` scope), and `php -l` only lints PHP syntax, not
  YAML. `python3`'s stdlib-adjacent `yaml` module was already present in this
  sandbox and used as a syntax-only sanity check (parses cleanly; both
  `kernel.event_subscriber`/`security.voter` tags present in the parsed structure).
  This does not verify Symfony's own YAML config schema (e.g. valid service-argument
  binding semantics), only that the file is syntactically well-formed YAML — the
  plan's own `<verify>` block only required `php -l` on `bundles.php`, which passed
  independently.
- All other verification commands ran successfully — see the `coverage` block above.

## Known Stubs

None — all code shipped in this plan (`AxiamBundle.php`, `AxiamAuthSubscriber.php`,
`AxiamVoter.php`, the test file, all three example files) is fully implemented and
exercised by either the test suite or a `php -l`/grep/YAML-parse-based acceptance
check.

## Threat Flags

None — this plan's new surface (`AxiamAuthSubscriber`'s token-handling and
`AxiamVoter`'s authz decision) is exactly the surface this plan's own
`<threat_model>` (T-22-26 through T-22-28) already covers, and each was verified:
T-22-26 (spoofing via token handling) via
`testMissingTokenReturns401`/`testInvalidTokenReturns401` proving fail-closed 401 on
both a wholly-absent and a malformed token; T-22-27 (elevation of privilege via the
voter) via `testVoterDenyReturnsAccessDenied`/`testVoterAllowReturnsAccessGranted`
proving `AxiamVoter` never overrides or caches the server's `can()` decision;
T-22-28 (dependency footprint tampering) via the `symfony/` composer.json grep gate
confirming all three entries stay `require-dev`-only, unchanged by this plan.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Both the Laravel (22-07) and Symfony (22-08) framework bridges are now complete and
  independently testable, each reusing the same `AxiamClient::verifyLocallyOrFallback()`/
  `can()` seams with zero duplicated verify/refresh/authz logic, and each honestly
  documenting its own registration experience (Laravel: true zero-config
  auto-discovery; Symfony: two explicit manual steps, Pitfall 5).
- **Follow-up for a maintainer or a later plan:** run
  `vendor/bin/phpstan analyse src/Symfony --level=6` on unrestricted CI infrastructure
  (same deferral as every prior 22-* plan) once `sdk-ci-php.yml` exists; consider
  adding `symfony/yaml` as a require-dev dependency in a future plan if a PHP-native
  YAML syntax check of `examples/*/services.yaml` becomes a CI requirement.

---
*Phase: 22-php-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 7 created files confirmed present on disk; all 3 task commit hashes (`fcf9f8d`,
`ef00bd2`, `e189ae2`) confirmed present in `git log --oneline --all`.
