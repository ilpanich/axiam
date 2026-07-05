---
phase: 27-performance-load-hardening
plan: 04
subsystem: sdk
tags: [jwks, single-flight, jose, guzzle, promise, typescript, php, perf-03]

# Dependency graph
requires:
  - phase: 27-performance-load-hardening
    provides: JWKS single-flight guard pattern applied to Rust/Python/Go/Java/C# (27-02, 27-03)
provides:
  - TypeScript (Node) SDK JWKS single-flight proof: jose's createRemoteJWKSet already coalesces concurrent in-flight fetches via its internal RemoteJWKSet#pendingFetch guard; documented and proven by a concurrent-burst test
  - PHP SDK JWKS single-flight: a new Guzzle-promise-based in-flight guard (ensureFreshAsync + shared $inFlightFetch) coalescing concurrent verify()-triggered refetches to exactly one discovery + one JWKS request
  - PERF-03 fully closed across all 7 code SDKs (rust, go, java, csharp, python, typescript, php)
affects: [sdk-typescript, sdk-php, performance-hardening-closure]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "TS: verify-before-modify — confirm a third-party dependency's own coalescing guarantee with a burst test before adding a redundant hand-rolled guard"
    - "PHP: Guzzle-promise single-flight guard (shared ?PromiseInterface field, reset in a .then() continuation once settled) mirroring the sync mutex/lock shape used in the other 5 SDKs"

key-files:
  created:
    - sdks/php/tests/JwksSingleFlightTest.php
  modified:
    - sdks/typescript/src/node/jwks.ts
    - sdks/typescript/test/node/jwks.test.ts
    - sdks/php/src/Auth/JwksVerifier.php

key-decisions:
  - "TypeScript: no inFlightFetch guard added — jose's RemoteJWKSet.reload() already implements `this.#pendingFetch ||= fetchJwks(...).then(...)`, a lazy-promise-singleton equivalent to the pattern jwksPromise already uses; adding a second guard would be redundant. Proven by a test that mocks global fetch with a call counter and fires 8 concurrent verifyAccessToken() calls against a cold cache — asserts exactly 1 fetch."
  - "PHP: converted the entire ensureFresh path (OIDC discovery + JWKS fetch) to Guzzle's async interface (requestAsync) so the whole refetch chain is promise-based, allowing a single shared $inFlightFetch promise to genuinely coalesce concurrent callers, not just the JWKS leg."
  - "PHP test drives the private ensureFreshAsync method via Reflection (bypassing the synchronous public verify()/ensureFresh()->wait() wrapper) since verify() itself intentionally stays a synchronous public API — this is the only way to genuinely interleave N in-flight fetches within one PHPUnit process per RESEARCH Pitfall 6."

requirements-completed: [PERF-03]

coverage:
  - id: D1
    description: "TypeScript (Node) SDK: 8 concurrent verifyAccessToken() calls with an unknown kid against a cold jose getter collapse to exactly 1 JWKS fetch (jose's native pendingFetch guard, proven not assumed); a subsequent verify reuses the resolved keyset with no extra fetch"
    requirement: PERF-03
    verification:
      - kind: unit
        ref: "sdks/typescript/test/node/jwks.test.ts#collapses N concurrent verifyAccessToken calls with an unknown kid to exactly one JWKS fetch (D-08/D-09)"
        status: pass
    human_judgment: false
  - id: D2
    description: "PHP SDK: a Guzzle-promise-based in-flight guard around JwksVerifier's ensureFresh collapses 8 interleaved async fetches (Reflection-invoked ensureFreshAsync, Promise\\Utils::settle) to exactly 1 discovery request + 1 JWKS request; all 8 joined promises resolve; a subsequent call for an already-cached kid triggers no extra fetch"
    requirement: PERF-03
    verification:
      - kind: unit
        ref: "sdks/php/tests/JwksSingleFlightTest.php#testEightInterleavedFetchesTriggerExactlyOneJwksRequest"
        status: pass
      - kind: unit
        ref: "sdks/php/tests/JwksSingleFlightTest.php#testAllJoinedPromisesResolveOnceTheSharedFetchSettles"
        status: pass
      - kind: unit
        ref: "sdks/php/tests/JwksSingleFlightTest.php#testSubsequentVerifyAfterTheSharedFetchReusesTheCacheWithNoExtraFetch"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-05
status: complete
---

# Phase 27 Plan 04: TypeScript and PHP SDK JWKS Single-Flight Summary

**Proved jose's native fetch-coalescing for the TypeScript SDK and added a Guzzle-promise single-flight guard to the PHP SDK, closing PERF-03 across all 7 code SDKs.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-05T13:55Z
- **Completed:** 2026-07-05T14:15Z
- **Tasks:** 2
- **Files modified:** 4 (1 created, 3 modified)

## Accomplishments

- TypeScript (Node) SDK: added a concurrent-burst test (mocks global `fetch` with a call counter, fires 8 concurrent `verifyAccessToken()` calls against a cold cache with an unknown `kid`) that proves `jose`'s `createRemoteJWKSet` already coalesces concurrent in-flight fetches to exactly 1 — no additional guard was needed. Documented the finding in a code comment near the existing `jwksPromise` singleton.
- PHP SDK: converted `JwksVerifier`'s entire refetch path (OIDC discovery + JWKS GET) to Guzzle's async interface and added a shared `?PromiseInterface $inFlightFetch` guard so concurrent `verify()`-triggered refetches within one process join the same promise instead of each independently issuing a request. `verify()`'s public synchronous contract is unchanged (`ensureFresh()` now just `->wait()`s on the async guard internally).
- Added `sdks/php/tests/JwksSingleFlightTest.php`: drives the guard directly (via Reflection on the intentionally-private `ensureFreshAsync`) with 8 calls fired without individual awaits, then `Promise\Utils::settle(...)->wait()` — proving exactly 1 discovery request + 1 JWKS request, all 8 promises resolve, and a subsequent call for an already-cached `kid` triggers no extra fetch.
- Neither SDK's cryptographic verification path (`jose`'s `jwtVerify` / `firebase/php-jwt`'s `JWT::decode`) was touched — the guard wraps only the fetch, per D-08.
- With 27-02 and 27-03, PERF-03 is now closed across all 7 code SDKs (rust, go, java, csharp, python, typescript, php).

## Task Commits

Each task was committed atomically:

1. **Task 1: TypeScript (Node) SDK JWKS single-flight** - `08fbee9` (test)
2. **Task 2: PHP SDK JWKS single-flight (Guzzle async)** - `16f0242` (feat)

**Plan metadata:** (this commit)

_Note: Task 1 is a `test`-only commit by design — the burst test passed against the existing `jose`-delegated implementation with zero production code changes to the fetch logic (only a documentation comment was added alongside the test), matching the plan's explicitly-anticipated "jose already coalesces" outcome. Task 2 followed the full RED→GREEN cycle (see TDD Gate Compliance below)._

## Files Created/Modified

- `sdks/typescript/src/node/jwks.ts` - Added a doc comment near `jwksPromise` documenting that `jose`'s `RemoteJWKSet.reload()` already implements an internal `pendingFetch` lazy-promise-singleton guard, proven by the new burst test; no functional change
- `sdks/typescript/test/node/jwks.test.ts` - New test: 8 concurrent `verifyAccessToken()` calls against a cold cache with an unknown `kid`, mocking global `fetch` with a call counter, asserting exactly 1 fetch and that a subsequent verify reuses the cache
- `sdks/php/src/Auth/JwksVerifier.php` - `ensureFresh` now delegates to `ensureFreshAsync`, which returns an already-resolved promise when the cache is fresh, joins an existing `$inFlightFetch` promise when a fetch is already underway, or starts exactly one new async discovery+JWKS fetch chain (via Guzzle's `requestAsync`) otherwise; `$inFlightFetch` reset once settled
- `sdks/php/tests/JwksSingleFlightTest.php` - New test file: proves the single-flight guarantee via Guzzle async + Reflection-invoked `ensureFreshAsync`, non-vacuous by construction (a 2-response MockHandler queue that a missing guard would exhaust)

## Decisions Made

- TypeScript: no `inFlightFetch` guard added — `jose`'s own `RemoteJWKSet.reload()` (`this.#pendingFetch ||= fetchJwks(...).then(...)`) already provides the exact lazy-promise-singleton shape D-08 asks for. Verified by direct source read of `jose`'s `dist/webapi/jwks/remote.js` and confirmed empirically by the burst test passing with zero implementation changes.
- PHP: the OIDC discovery request was ALSO converted to async (not just the JWKS leg) so the entire `ensureFresh` chain shares one guard — a partial guard (JWKS-only) would still let concurrent callers each independently re-run discovery.
- PHP test uses Reflection to invoke the private `ensureFreshAsync` directly rather than looping over the public synchronous `verify()`, because `verify()`'s own `->wait()` call would block until the first fetch resolves before any second call could even reach `ensureFreshAsync` — that would not exercise genuine concurrency (this is precisely RESEARCH Pitfall 6's warning against a sequential-loop antipattern). Firing all 8 calls without waiting individually, then draining via `Promise\Utils::settle(...)->wait()`, is the pattern that actually proves the guard.

## Deviations from Plan

None - plan executed exactly as written. Task 1's "if jose already coalesces, document it" contingency and Task 2's "wrap ensureFresh in a Guzzle-promise-based in-flight guard" were both explicitly anticipated outcomes in the plan text, not deviations.

## TDD Gate Compliance

- **Task 1 (tdd="true"):** The plan explicitly anticipates that the burst test may pass immediately if `jose` already coalesces ("If jose already coalesces, the test passes as-is and you document that in a code comment"). This is what happened: the test was written, run, and passed against the pre-existing implementation with no fetch-logic changes needed. A single `test(27-04): ...` commit captures the test + the accompanying documentation comment. There is no separate RED-failing commit for this task because there was nothing to make GREEN — the "RED" step (writing the test) directly confirmed the already-correct behavior. This is a sanctioned exception per the plan's own task design, not a gate skip.
- **Task 2 (tdd="true"):** Full RED→GREEN cycle followed. RED was confirmed by `git stash`-ing the `JwksVerifier.php` change and re-running `JwksSingleFlightTest.php`, which failed with `ReflectionException: Method ... ensureFreshAsync() does not exist` (3 errors, as expected — the guard didn't exist yet). The stash was then popped to restore the implementation, and all 3 new tests passed (GREEN). Both the test and implementation landed in the single `feat(27-04): ...` commit (`16f0242`) rather than split into separate `test`+`feat` commits, since the guard's private internal seam (`ensureFreshAsync`) is only reachable by a test written against its exact signature — writing the test against a not-yet-existing private method and committing it standalone would not compile/parse meaningfully as an isolated commit. The RED/GREEN cycle was still rigorously executed and verified before committing; only the commit granularity differs from the idealized two-commit shape.

## Issues Encountered

- `sdks/php/vendor/` was not installed. `composer install` repeatedly failed with `Could not authenticate against github.com` when trying to download `phpstan/phpstan` (a dev-only static-analysis tool, irrelevant to running `phpunit`) — GitHub's dist zipball endpoint returned `403` through the sandbox's egress proxy, and phpstan has no viable git-source fallback cached locally. Worked around this by temporarily removing `phpstan/phpstan` from `composer.json`'s `require-dev` (all other dependencies, including `guzzlehttp/guzzle`, `phpunit/phpunit`, and `firebase/php-jwt`, resolved successfully from the local git cache at `/root/.cache/composer/vcs/`), running `composer update` to install everything else, then restoring `composer.json` to its original tracked content via `git checkout -- composer.json` before any task commit. `vendor/` and `composer.lock` are both gitignored (`sdks/php/.gitignore`), so this workaround touches no tracked file and required no code change — it only enabled local test execution in this sandbox. This is a local-environment issue, not a functional gap in the plan's deliverables.
- `sdks/typescript/node_modules/` was also not installed; `npm install` completed cleanly with no equivalent GitHub-egress issue.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- PERF-03 is now fully closed across all 7 code SDKs (rust/python: 27-02, go/java/csharp: 27-03, typescript/php: this plan).
- This was the last plan of Phase 27 (performance-load-hardening) per the 7-plan structure implied by ROADMAP; verify remaining phase-level `<success_criteria>` (criterion benches, HIBP breaker, batch authz concurrency, DB reconnect resilience) were covered in earlier 27-0x plans before marking the phase itself complete.
- No blockers for subsequent phases.

---

## Self-Check: PASSED

All created/modified files found on disk; all 3 commit hashes (`08fbee9`, `16f0242`, `80f65d2`) found in git log.

---

*Phase: 27-performance-load-hardening*
*Completed: 2026-07-05*
