---
phase: 20-java-sdk
plan: 06
subsystem: auth
tags: [spring-security, oncePerRequestFilter, jwt, eddsa, cross-tenant, auto-configuration, java]

# Dependency graph
requires:
  - phase: 20-java-sdk (20-04)
    provides: JwksVerifier (EdDSA-pinned local JWT verify + assertTenant cross-tenant check)
  - phase: 20-java-sdk (20-03)
    provides: AuthError/AuthzError error taxonomy
provides:
  - AxiamAuthenticationFilter (OncePerRequestFilter) — local verify, cross-tenant enforcement, SecurityContext population
  - AxiamAutoConfiguration — optional zero-config Spring Boot registration (@ConditionalOnMissingBean)
  - AutoConfiguration.imports registration at the Spring Boot 3.x mechanism path
affects: [20-09 (Spring Boot example app wires AxiamAuthenticationFilter explicitly in SecurityConfig)]

# Tech tracking
tech-stack:
  added: [spring-test (test scope, MockHttpServletRequest/Response for AxiamAuthenticationFilterIT)]
  patterns:
    - "OncePerRequestFilter: extract (Bearer header then axiam_access cookie) -> JwksVerifier.verify (EdDSA) -> exp check -> JwksVerifier.assertTenant (cross-tenant) -> SecurityContextHolder.setAuthentication -> chain.doFilter; AuthError->401/AuthzError->403 via Jackson-encoded JSON body"
    - "@AutoConfiguration @ConditionalOnClass(SecurityFilterChain.class) with @ConditionalOnMissingBean beans so an explicit consumer SecurityConfig always takes precedence over the zero-config default"

key-files:
  created:
    - sdks/java/src/main/java/io/axiam/sdk/spring/package-info.java
    - sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java
    - sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAutoConfiguration.java
    - sdks/java/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
    - sdks/java/src/test/java/io/axiam/sdk/spring/AxiamAuthenticationFilterIT.java
  modified:
    - sdks/java/pom.xml

key-decisions:
  - "Used Jackson ObjectMapper (already a dependency) to write the standardized JSON error body instead of manual string concatenation — closes a JSON-injection risk in the RESEARCH.md reference pattern where an exception message containing a quote would produce malformed/injected JSON"
  - "AxiamAutoConfiguration provides real @ConditionalOnMissingBean AxiamAuthenticationFilter and SecurityFilterChain beans (reading axiam.base-url/axiam.tenant-id properties), not an empty marker class, to satisfy the plan's acceptance criterion that it 'yields to a consumer @Bean (@ConditionalOnMissingBean)'"
  - "Default auto-configured SecurityFilterChain disables Spring's own CSRF protection, matching RESEARCH.md Pattern 8's explicit-wiring example comment: AXIAM's own X-CSRF-Token/cookie double-submit (CONTRACT.md §3) supersedes Spring's default token, avoiding double-protection"
  - "Added org.springframework:spring-test 6.2.11 (test scope) pinned to spring-security-web's transitive spring-core version (confirmed via mvn dependency:tree) rather than pulling in spring-boot-starter-test — AxiamAuthenticationFilterIT is a MockFilterChain-level integration test, not a full ApplicationContext test"

patterns-established:
  - "Spring middleware error responses use Jackson ObjectMapper.writeValueAsString for JSON bodies, never manual string interpolation of exception messages"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "AxiamAuthenticationFilter locally verifies a Bearer/cookie token via JwksVerifier, enforces the cross-tenant claim check, and sets SecurityContextHolder on success"
    requirement: "JAVA-01"
    verification:
      - kind: integration
        ref: "sdks/java/src/test/java/io/axiam/sdk/spring/AxiamAuthenticationFilterIT.java#matchingTenantValidTokenAuthenticatesAndReachesProtectedEndpoint"
        status: pass
    human_judgment: false
  - id: D2
    description: "A validly-signed token whose tenant_id differs from the configured tenant is rejected 401 even though the signature is valid (cross-tenant replay defense, non-vacuous)"
    requirement: "JAVA-01"
    verification:
      - kind: integration
        ref: "sdks/java/src/test/java/io/axiam/sdk/spring/AxiamAuthenticationFilterIT.java#validSignatureWrongTenantTokenIsRejectedEvenThoughSignatureIsValid"
        status: pass
    human_judgment: false
  - id: D3
    description: "An expired but signature-valid token is rejected 401 (resource-server trust boundary explicit exp check)"
    verification:
      - kind: integration
        ref: "sdks/java/src/test/java/io/axiam/sdk/spring/AxiamAuthenticationFilterIT.java#expiredTokenIsRejected"
        status: pass
    human_judgment: false
  - id: D4
    description: "A request with no token passes through unauthenticated so Spring Security's own access-control rules can 401/403 it"
    verification:
      - kind: integration
        ref: "sdks/java/src/test/java/io/axiam/sdk/spring/AxiamAuthenticationFilterIT.java#noTokenPassesThroughUnauthenticated"
        status: pass
    human_judgment: false
  - id: D5
    description: "Optional AxiamAutoConfiguration (@ConditionalOnClass(SecurityFilterChain.class)) registers AxiamAuthenticationFilter and a default SecurityFilterChain, both @ConditionalOnMissingBean so an explicit consumer SecurityConfig takes precedence; AutoConfiguration.imports registers it at the exact Spring Boot 3.x path"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "mvn -f sdks/java/pom.xml -q test-compile (Spring types resolve via provided/optional scope; imports file contains exactly io.axiam.sdk.spring.AxiamAutoConfiguration)"
        status: pass
    human_judgment: false

duration: 10min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 06: Spring Security Integration Summary

**`AxiamAuthenticationFilter` (OncePerRequestFilter) with local EdDSA verification, cross-tenant claim enforcement, and SecurityContext population, plus an optional `@ConditionalOnMissingBean`-gated `@AutoConfiguration`**

## Performance

- **Duration:** 10 min
- **Completed:** 2026-07-02
- **Tasks:** 2
- **Files modified:** 6 (5 created, 1 modified)

## Accomplishments
- `AxiamAuthenticationFilter extends OncePerRequestFilter` — extracts Bearer/cookie token, verifies locally via `JwksVerifier` (EdDSA-pinned), explicitly rejects expired tokens, enforces the MUST-carry-forward cross-tenant claim check (`JwksVerifier.assertTenant`), and populates `SecurityContextHolder` with scope-derived `GrantedAuthority` instances
- `AxiamAuthenticationFilterIT` proves all four required behaviors: matching-tenant auth succeeds and reaches the protected endpoint; a validly-signed wrong-tenant token is rejected 401 (non-vacuous cross-tenant defense — same signing key, different `tenant_id`); an expired token is rejected 401; a request with no token passes through unauthenticated
- `AxiamAutoConfiguration` — `@AutoConfiguration @ConditionalOnClass(SecurityFilterChain.class)` providing a default `AxiamAuthenticationFilter` and `SecurityFilterChain` bean, both `@ConditionalOnMissingBean` so an explicit consumer `SecurityConfig` (20-09) always takes precedence
- `AutoConfiguration.imports` registers `io.axiam.sdk.spring.AxiamAutoConfiguration` at the exact Spring Boot 3.x path (`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`), not the legacy `spring.factories` mechanism
- All Spring dependencies remain `provided`/`optional` scope; `mvn test-compile` confirms Spring types resolve without affecting a non-Spring consumer's classpath

## Task Commits

Each task was committed atomically:

1. **Task 1: AxiamAuthenticationFilter — local verify + cross-tenant check + SecurityContext (D-14, §10)** - `c95148c` (feat)
2. **Task 2: Optional @AutoConfiguration + AutoConfiguration.imports (D-15)** - `aac90ee` (feat)

## Files Created/Modified
- `sdks/java/src/main/java/io/axiam/sdk/spring/package-info.java` - `@NullMarked` package documentation
- `sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java` - the OncePerRequestFilter (extract/verify/cross-tenant/SecurityContext/JSON errors)
- `sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAutoConfiguration.java` - `@AutoConfiguration` with `@ConditionalOnMissingBean` filter + SecurityFilterChain beans
- `sdks/java/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` - single-line Spring Boot 3.x registration
- `sdks/java/src/test/java/io/axiam/sdk/spring/AxiamAuthenticationFilterIT.java` - 4-case integration test (happy path, cross-tenant rejection, expiry rejection, no-token pass-through)
- `sdks/java/pom.xml` - added test-scoped `org.springframework:spring-test:6.2.11`

## Decisions Made
- Jackson `ObjectMapper` for the JSON error body instead of manual string concatenation (see Deviations)
- `AxiamAutoConfiguration` ships real `@ConditionalOnMissingBean` beans (`axiam.base-url`/`axiam.tenant-id` properties), not an empty marker class, to literally satisfy the plan's acceptance criterion of "yields to a consumer `@Bean`"
- Default auto-configured `SecurityFilterChain` disables Spring's own CSRF protection (AXIAM's `X-CSRF-Token` supersedes it — avoids double-protection, matches the RESEARCH.md Pattern 8 explicit-wiring example)
- `spring-test` (not `spring-boot-starter-test`) added at test scope, version-pinned to the transitive `spring-core` version already resolved by `spring-security-web` (6.2.11) — keeps the IT test a lightweight `MockFilterChain`-level test rather than pulling in a full Spring `ApplicationContext`/`@WebMvcTest` dependency footprint

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Replaced manual JSON string concatenation with Jackson `ObjectMapper` in `writeJsonError`**
- **Found during:** Task 1 (writing `AxiamAuthenticationFilter.doFilterInternal`)
- **Issue:** RESEARCH.md Pattern 8's reference implementation builds the error JSON body via raw string interpolation (`"{\"error\":\"...\",\"message\":\"" + message + "\"}"`), which produces malformed or injectable JSON if `e.getMessage()` ever contains a `"` or control character (e.g. a malformed-claims parse error echoing raw input)
- **Fix:** Used the already-available `com.fasterxml.jackson.databind.ObjectMapper`/`ObjectNode` (same library `AxiamClient` already depends on) to construct and serialize the error body safely
- **Files modified:** `sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java`
- **Verification:** `AxiamAuthenticationFilterIT` asserts the 401 response body deserializes/contains `authentication_failed` correctly
- **Committed in:** `c95148c` (Task 1 commit)

**2. [Rule 3 - Blocking] Added test-scoped `spring-test` dependency**
- **Found during:** Task 1 (writing `AxiamAuthenticationFilterIT`)
- **Issue:** `pom.xml` had no `MockHttpServletRequest`/`MockHttpServletResponse` test utility available — required to exercise the filter without a live servlet container or a full `ApplicationContext`
- **Fix:** Added `org.springframework:spring-test:6.2.11` (test scope only), version confirmed via `mvn dependency:tree` against `spring-security-web`'s transitive `spring-core`
- **Files modified:** `sdks/java/pom.xml`
- **Verification:** `mvn test` green, including all 4 `AxiamAuthenticationFilterIT` cases
- **Committed in:** `c95148c` (Task 1 commit)

**3. [Rule 2 - Missing Critical] `AxiamAutoConfiguration` implemented with real `@ConditionalOnMissingBean` beans, not an empty class**
- **Found during:** Task 2 (writing `AxiamAutoConfiguration`)
- **Issue:** RESEARCH.md Pattern 9's code example is an empty class with only a doc comment describing the intended `@ConditionalOnMissingBean` yielding behavior; the plan's own acceptance criteria explicitly requires "`AxiamAutoConfiguration` is `@ConditionalOnClass(SecurityFilterChain.class)` and yields to a consumer `@Bean` (`@ConditionalOnMissingBean`)" — an empty class has no bean to yield with, so the criterion would be unsatisfiable
- **Fix:** Added a `@ConditionalOnMissingBean(AxiamAuthenticationFilter.class)` filter bean (reading `axiam.base-url`/`axiam.tenant-id` properties) and a `@ConditionalOnMissingBean(SecurityFilterChain.class)` default chain wiring it in, both yielding entirely when a consumer defines their own
- **Files modified:** `sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAutoConfiguration.java`
- **Verification:** `mvn -f sdks/java/pom.xml -q test-compile` green
- **Committed in:** `aac90ee` (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (1 bug, 1 blocking, 1 missing-critical)
**Impact on plan:** All three are correctness/security fixes or acceptance-criterion-literal implementations within the plan's stated scope. No architectural changes, no scope creep beyond what the plan's own text and acceptance criteria required.

## Issues Encountered
None beyond the deviations documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `AxiamAuthenticationFilter` + `AxiamAutoConfiguration` + `AutoConfiguration.imports` are complete and tested; ready for 20-09's Spring Boot example app to wire `AxiamAuthenticationFilter` explicitly in a `SecurityConfig` `@Bean` (satisfying SC#3's "complete working application context") and demonstrate the auto-configuration's zero-config path
- No blockers

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All created files verified present on disk; all task/plan-metadata commit hashes (`c95148c`, `aac90ee`, `fdd253c`) verified present in `git log`.
