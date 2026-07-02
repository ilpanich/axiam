---
phase: 20-java-sdk
plan: 04
subsystem: auth
tags: [java, jwt, eddsa, nimbus-jose-jwt, concurrency, retry, jwks, single-flight]

# Dependency graph
requires:
  - phase: 20-java-sdk (20-01)
    provides: sdks/java scaffold — pom.xml with pinned deps (nimbus-jose-jwt 10.7, tink 1.15.0, okhttp 4.12.0/mockwebserver, junit 5), Java 21 baseline, @NullMarked package convention, error taxonomy (AuthError/AuthzError/NetworkError)
provides:
  - "RefreshGuard: ReentrantLock + CompletableFuture-in-AtomicReference single-flight refresh guard (D-07/§9), proven by a 5-thread SC#2 test"
  - "TokenPair: immutable access/refresh/expiry value record"
  - "JwksVerifier: RemoteJWKSet + DefaultJWKSetCache-backed EdDSA-pinned local JWT verification (D-19) with cross-tenant assertTenant() control"
  - "Retry: dependency-free bounded exponential-backoff-with-jitter helper for idempotent ops, honoring Retry-After (D-26)"
affects: [20-05-rest-client, 20-06-spring-security, 20-08-grpc-client]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ReentrantLock (not synchronized) held only around bookkeeping, never around the actual refresh HTTP call — double-check-after-lock, lock-release-before-join, no-retry-on-failure (§9.3)"
    - "Non-blocking volatile-field cachedAccessToken()/cached() accessor for interceptor hot paths — never acquire RefreshGuard's lock synchronously on a request path"
    - "JWKMatcher-based direct key lookup against RemoteJWKSet, bypassing JWSVerificationKeySelector/DefaultJWTProcessor for OKP/EdDSA keys (nimbus 10.7 library limitation — see Deviations)"
    - "RuntimeException-implements-marker-interface (RetryAfterHint) for optional Retry-After propagation without changing Retry's core Predicate<RuntimeException> signature"

key-files:
  created:
    - sdks/java/src/main/java/io/axiam/sdk/internal/package-info.java
    - sdks/java/src/main/java/io/axiam/sdk/internal/TokenPair.java
    - sdks/java/src/main/java/io/axiam/sdk/internal/RefreshGuard.java
    - sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java
    - sdks/java/src/main/java/io/axiam/sdk/internal/Retry.java
    - sdks/java/src/test/java/io/axiam/sdk/internal/RefreshGuardSingleFlightTest.java
    - sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java
    - sdks/java/src/test/java/io/axiam/sdk/internal/RetryTest.java
  modified: []

key-decisions:
  - "nimbus-jose-jwt 10.7's DefaultJWTProcessor + JWSVerificationKeySelector(EdDSA, jwkSource) pipeline does not work for OKP/Ed25519 keys (OctetKeyPair.toKeyPair() unconditionally throws, silently swallowed by KeyConverter.toJavaKeys, and DefaultJWSVerifierFactory has no EdDSA branch) — replaced with a direct JWKMatcher-based lookup against the same RemoteJWKSet/DefaultJWKSetCache paired with Ed25519Verifier(OctetKeyPair), confirmed working via a throwaway debug harness before committing"
  - "Algorithm pinning implemented as an explicit pre-lookup header.getAlgorithm()==EdDSA check (mirrors the Go/Rust/Python hand-check idiom) rather than relying on JWSVerificationKeySelector, since that class cannot drive OKP verification in this nimbus release"
  - "RefreshGuard's join()-path unwraps CompletionException so waiters receive the SAME exception instance the refreshing thread caught (not a wrapped CompletionException), matching the plan's 'same exception' requirement"
  - "Retry-After propagation via a RuntimeException-implemented RetryAfterHint marker interface rather than a passed-in extractor function, keeping the public withRetry(int, Supplier, Predicate) signature simple"

patterns-established:
  - "Internal transport-independent primitives (RefreshGuard, JwksVerifier, Retry) live in io.axiam.sdk.internal, never imported by SDK consumers directly — one RefreshGuard/JwksVerifier instance per AxiamClient, shared by every transport"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "RefreshGuard single-flight refresh: 5 concurrent threads on an expired token trigger exactly 1 refresh call (SC#2)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/RefreshGuardSingleFlightTest.java#fiveConcurrentThreadsOnExpiredTokenTriggerExactlyOneRefresh"
        status: pass
    human_judgment: false
  - id: D2
    description: "RefreshGuard: a failing refresh propagates the same exception to every waiter with no retry loop (§9.3)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/RefreshGuardSingleFlightTest.java#failingRefreshPropagatesToAllWaitersWithoutRetry"
        status: pass
    human_judgment: false
  - id: D3
    description: "JwksVerifier: valid EdDSA token verifies against the cached JWKS and returns claims; non-EdDSA alg token rejected before key lookup"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java#validEdDsaTokenVerifiesAndReturnsClaims"
        status: pass
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java#nonEdDsaAlgTokenIsRejected"
        status: pass
    human_judgment: false
  - id: D4
    description: "JwksVerifier.assertTenant enforces the cross-tenant claim control (T-20-07)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java#assertTenantThrowsOnMismatchAndPassesOnMatch"
        status: pass
    human_judgment: false
  - id: D5
    description: "Retry: bounded backoff for idempotent ops, honors Retry-After, no external retry framework dependency (D-26)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/RetryTest.java#transientFailureThenSuccessSucceedsWithinMaxAttempts"
        status: pass
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/RetryTest.java#retryAfterHintIsHonoredAsAMinimumWait"
        status: pass
    human_judgment: false

duration: 16min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 04: RefreshGuard / JwksVerifier / Retry Summary

**Single-flight refresh guard (ReentrantLock + CompletableFuture-in-AtomicReference, SC#2-proven), EdDSA-pinned JWKS verifier with cross-tenant enforcement, and a hand-rolled idempotent-only retry helper — the shared verification/concurrency core for REST, gRPC, and Spring Security.**

## Performance

- **Duration:** ~16 min
- **Started:** 2026-07-02T07:24:10Z (session start per STATE.md)
- **Completed:** 2026-07-02T07:38:00Z
- **Tasks:** 3
- **Files modified:** 8 (all new)

## Accomplishments
- `RefreshGuard` collapses any number of concurrent callers observing the same expired token into exactly 1 refresh call (SC#2, 5-thread test), with double-check-after-lock, lock-release-before-join, and no retry loop on failure (§9.3) — every waiter receives the SAME exception instance on failure
- Non-blocking `cachedAccessToken()`/`cached()` volatile-field reads for the future REST interceptor/gRPC client interceptor hot paths (never acquire the guard's lock synchronously on a request path)
- `JwksVerifier` sources EdDSA keys from `{baseUrl}/oauth2/jwks` via `RemoteJWKSet` + `DefaultJWKSetCache(300, 60, SECONDS)`, pins `alg=EdDSA` before any key lookup, and provides `assertTenant()` — the mandatory cross-tenant claim control since the JWKS is organization-wide, not tenant-scoped
- `Retry` provides a ~130-line dependency-free bounded exponential-backoff-with-jitter helper for idempotent operations, honoring a `Retry-After` hint as a minimum wait, with no Resilience4j/Failsafe dependency

## Task Commits

Each task was committed atomically:

1. **Task 1: RefreshGuard single-flight (D-07/§9) + TokenPair + SC#2 5-thread test** - `4d5e134` (feat)
2. **Task 2: JwksVerifier — RemoteJWKSet + EdDSA pinning + cross-tenant helper (D-19)** - `905c7b5` (feat)
3. **Task 3: Retry — hand-rolled bounded backoff + jitter for idempotent ops (D-26)** - `0088e78` (feat)

**Plan metadata:** (this commit, docs: complete plan)

## Files Created/Modified
- `sdks/java/src/main/java/io/axiam/sdk/internal/package-info.java` - `@NullMarked` package declaration for the internal package tree
- `sdks/java/src/main/java/io/axiam/sdk/internal/TokenPair.java` - immutable access/refresh/expiry record
- `sdks/java/src/main/java/io/axiam/sdk/internal/RefreshGuard.java` - §9 single-flight refresh guard
- `sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java` - EdDSA-pinned local JWT verification + cross-tenant helper
- `sdks/java/src/main/java/io/axiam/sdk/internal/Retry.java` - bounded backoff+jitter retry helper
- `sdks/java/src/test/java/io/axiam/sdk/internal/RefreshGuardSingleFlightTest.java` - 4 tests: SC#2 5-thread exactly-1-refresh, failure propagation, double-check cached-token path, lock-free read
- `sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java` - 5 tests: valid EdDSA verify, non-EdDSA rejection, assertTenant match/mismatch/absent, Tink-presence smoke test
- `sdks/java/src/test/java/io/axiam/sdk/internal/RetryTest.java` - 5 tests: transient-then-success, non-retryable short-circuit, max-attempts exhaustion, Retry-After honored, default maxAttempts

## Decisions Made
- **nimbus-jose-jwt 10.7 EdDSA verification pipeline substitution** (see Deviations below for full detail) — the researched `DefaultJWTProcessor` + `JWSVerificationKeySelector(EdDSA, jwkSource)` combination does not work for OKP/Ed25519 keys in the pinned nimbus version; verification uses a direct `JWKMatcher`-based lookup against the same `RemoteJWKSet` instead, still preserving D-19's "use RemoteJWKSet+DefaultJWKSetCache for fetch/cache/rotation" mandate
- Algorithm pinning implemented as an explicit `header.getAlgorithm().equals(EdDSA)` check before any JWKS lookup, mirroring the hand-rolled idiom the Go/Rust/Python sibling SDKs already use, since nimbus's own algorithm-pinning key-selector class cannot drive OKP verification here
- `RefreshGuard`'s waiter path unwraps `CompletionException` from `CompletableFuture.join()` so every waiter receives the identical exception instance the refreshing thread threw, matching the plan's "same exception to every waiter" requirement more precisely than the research pattern's unmodified `join()` call
- `Retry`'s Retry-After hint is carried via a `RuntimeException`-implemented marker interface (`Retry.RetryAfterHint`) rather than a separate extractor-function parameter, keeping the primary `withRetry(int, Supplier, Predicate)` overload simple; a package-private, test-injectable overload accepts a `Sleeper` + `Random` for deterministic, non-blocking tests

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] nimbus-jose-jwt 10.7's researched EdDSA verification pipeline silently rejects valid tokens**
- **Found during:** Task 2 (JwksVerifier implementation)
- **Issue:** RESEARCH.md Pattern 4 (and the plan's `<action>` text) specified `DefaultJWTProcessor` + `JWSVerificationKeySelector(JWSAlgorithm.EdDSA, jwkSource)`. Implementing this exactly and testing against a real Ed25519-signed token against a `MockWebServer`-served JWKS produced `BadJOSEException("Signed JWT rejected: Another algorithm expected, or no matching key(s) found")` even though the JWKS fetch succeeded and the key otherwise matched. Root cause (confirmed via a throwaway debug harness, not committed): `JWSVerificationKeySelector.selectJWSKeys` converts every matched `JWK` to a raw `java.security.Key` via `KeyConverter.toJavaKeys`, which for an `OctetKeyPair` calls `OctetKeyPair.toKeyPair()` — a method that **unconditionally** throws `JOSEException("Export to java.security.KeyPair not supported")` in nimbus-jose-jwt 10.7. `KeyConverter.toJavaKeys` silently swallows that exception ("Key conversion exceptions are silently ignored"), so the selector always returns zero candidate keys for EdDSA. Separately, `DefaultJWSVerifierFactory.createJWSVerifier` has no EdDSA/OKP branch at all (only HMAC/RSA/EC), so even a successful key conversion would not have produced a working verifier.
- **Fix:** Replaced the `DefaultJWTProcessor`/`JWSVerificationKeySelector` pipeline with a direct `JWKMatcher`-based key lookup against the same `RemoteJWKSet` + `DefaultJWKSetCache` (preserving fetch/cache/rotation-on-unknown-`kid`, satisfying D-19's "Don't Hand-Roll" mandate for that part), paired with `Ed25519Verifier(OctetKeyPair)` constructed directly from the matched key — a combination nimbus supports natively. Algorithm pinning is now an explicit pre-lookup `header.getAlgorithm() == EdDSA` check, matching the hand-rolled idiom already used in the Go/Rust/Python sibling SDKs.
- **Files modified:** `sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java`
- **Verification:** `JwksVerifierTest` (5 tests, all passing) — valid EdDSA verify, non-EdDSA alg rejected pre-lookup, `assertTenant` match/mismatch/absent-claim, Tink-presence smoke test (no `NoClassDefFoundError`)
- **Committed in:** `905c7b5` (Task 2 commit, with full deviation detail in the commit message and class-level javadoc)

---

**Total deviations:** 1 auto-fixed (1 bug fix — library API incompatibility discovered and resolved at implementation time)
**Impact on plan:** Necessary for correctness; the plan's `<action>` text specified an approach that does not compile-and-work against the actual pinned nimbus-jose-jwt 10.7 release for EdDSA keys (confirmed empirically, not by inspection alone). The `<artifacts_this_phase_produces>` public API surface (`JwksVerifier(String baseUrl)`, `verify(String)`, `assertTenant(...)`) and all acceptance criteria are unchanged. No scope creep — RESEARCH.md's own Open Question #1 / Assumption A5 explicitly flagged this API as needing implementation-time verification.

## Issues Encountered
None beyond the deviation documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `RefreshGuard`, `JwksVerifier`, and `Retry` are ready to be wired into the REST client (20-05: OkHttp `Interceptor`/`Authenticator` both funneling into this same `RefreshGuard` instance), the Spring Security filter (20-06: `JwksVerifier.verify()` + `assertTenant()`), and the gRPC client (20-08: same `RefreshGuard` instance, `UNAUTHENTICATED`-triggered retry-once via the guard)
- No blockers. All 30 tests in the `sdks/java` module pass (`mvn -f sdks/java/pom.xml test`).
- Downstream plans should reuse the JwksVerifier deviation note (class-level javadoc in `JwksVerifier.java`) rather than re-discovering the nimbus OKP limitation.

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 8 created files verified present on disk; all 3 task commit hashes (`4d5e134`, `905c7b5`, `0088e78`) verified present in `git log --oneline --all`.
