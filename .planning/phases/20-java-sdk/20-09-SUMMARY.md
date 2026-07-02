---
phase: 20-java-sdk
plan: 09
subsystem: sdk
tags: [java, maven, spring-boot, spring-security, github-actions, maven-central, gpg, ci-cd]

# Dependency graph
requires:
  - phase: 20-java-sdk (05-08)
    provides: AxiamClient (REST), GrpcAuthzClient/AuthClientInterceptor (gRPC), AmqpConsumer/ErrDrop (AMQP), AxiamAuthenticationFilter/AxiamAutoConfiguration (Spring), JwksVerifier, Sensitive, error taxonomy
provides:
  - Four runnable capability examples (login-mfa, rest-authz, grpc-checkaccess, amqp-consumer) importing only public SDK entry points
  - Complete, bootable Spring Boot 3.x example app with explicit SecurityFilterChain wiring of AxiamAuthenticationFilter (SC#3)
  - README getting-started (Maven + Gradle, tenantId requirement, try-with-resources, BOM coordinate)
  - io.axiam:axiam-bom coordinate (packaging=pom, dependencyManagement pinning axiam-sdk, GPG-signable/publishable)
  - Full Java SDK CI/CD pipeline: mvn test, TLS-bypass gate, mvn verify -Dgpg.skip=false (ephemeral key) with javadoc/sources jars, dependency:tree re-verification, gRPC codegen drift-check, BOM validate, Spring Boot example verify, tag-triggered dual-coordinate Central Portal publish job
affects: [21-csharp-sdk, 22-php-sdk, milestone-v1.1-completion]

# Tech tracking
tech-stack:
  added: [spring-boot-starter-parent 3.5.6, spring-boot-starter-web, maven-failsafe-plugin]
  patterns:
    - "Standalone example .java files (no pom, no CI compile step) referencing only public SDK entry points, matching sibling SDKs' examples/ convention"
    - "GPG signing gated behind gpg.skip property: ephemeral throwaway key proves mvn verify -Dgpg.skip=false in PR CI; real CI-secret key confined to the tag-triggered publish job (Pitfall 4)"
    - "maven-failsafe-plugin bound to integration-test/verify for *IT.java classes, since default maven-surefire-plugin does not match that naming pattern"

key-files:
  created:
    - sdks/java/examples/login-mfa/LoginMfaExample.java
    - sdks/java/examples/rest-authz/RestAuthzExample.java
    - sdks/java/examples/grpc-checkaccess/GrpcCheckAccessExample.java
    - sdks/java/examples/amqp-consumer/AmqpConsumerExample.java
    - sdks/java/examples/spring-boot-app/pom.xml
    - sdks/java/examples/spring-boot-app/src/main/java/io/axiam/example/springboot/SpringBootExampleApplication.java
    - sdks/java/examples/spring-boot-app/src/main/java/io/axiam/example/springboot/SecurityConfig.java
    - sdks/java/examples/spring-boot-app/src/main/java/io/axiam/example/springboot/HelloController.java
    - sdks/java/examples/spring-boot-app/src/main/resources/application.properties
    - sdks/java/examples/spring-boot-app/src/test/java/io/axiam/example/springboot/SpringBootExampleIT.java
    - sdks/java-bom/pom.xml
  modified:
    - sdks/java/README.md
    - sdks/java/src/main/java/io/axiam/sdk/AxiamClient.java
    - .github/workflows/sdk-ci-java.yml

key-decisions:
  - "Added a session() accessor to AxiamClient — it was missing entirely, making it structurally impossible to construct a GrpcAuthzClient (whose public constructor requires SessionState) that shares the same guard/session pair from any AxiamClient instance (D-07/D-08 'one guard')"
  - "Added exceptionHandling(...HttpStatusEntryPoint(UNAUTHORIZED)) to the example's SecurityFilterChain — without it, Spring Security's default fallback (Http403ForbiddenEntryPoint, since no formLogin/httpBasic is configured) returns 403 for an unauthenticated request instead of the required 401"
  - "Added maven-failsafe-plugin to the example app's pom — SpringBootExampleIT follows the *IT.java Failsafe naming convention but the default maven-surefire-plugin (bound to `test`) doesn't match that pattern, so a plain `mvn verify` was silently running zero tests"
  - "CI workflow split into one job per concern (test/tls-bypass-gate/verify-signed/grpc-drift-check/bom-validate/spring-boot-example/publish) rather than one monolithic job, so the real GPG/Central secrets can be scoped to exactly the tag-triggered publish job and nowhere else"

patterns-established:
  - "Java SDK examples/ directory: standalone runnable .java files with a main() method, env-var configuration with sane defaults, importing only public io.axiam.sdk.* entry points — no pom.xml, no CI compile step, matching sibling SDKs (Python/Go) precedent"
  - "BOM module (io.axiam:axiam-bom) mirrors the SDK POM's full metadata + gpg/central-publishing plugin chain so it is independently signable/publishable alongside the SDK jar"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "Four capability examples (login+MFA, REST authz, gRPC CheckAccess, AMQP consumer) compile against the SDK's public API only"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "javac compilation of all four example files against sdks/java/target/classes + resolved dependency classpath"
        status: pass
      - kind: other
        ref: "grep for io.axiam.sdk.internal import statements in sdks/java/examples/ (none found)"
        status: pass
    human_judgment: false
  - id: D2
    description: "README states CONTRACT.md §1-§10 conformance and documents io.axiam:axiam-sdk, required tenantId, and io.axiam:axiam-bom"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "grep -c 'This SDK conforms to CONTRACT.md' sdks/java/README.md (>=1)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Complete Spring Boot 3.x example app boots a full application context; SecurityConfig wires AxiamAuthenticationFilter via an explicit SecurityFilterChain @Bean; /hello is protected (401 no token, 200 valid matching-tenant token, 401 valid-signature wrong-tenant token)"
    requirement: "JAVA-01"
    verification:
      - kind: integration
        ref: "mvn -f sdks/java/examples/spring-boot-app/pom.xml clean verify -- SpringBootExampleIT (4 tests: contextBootsWithACompleteApplicationContext, protectedEndpointRejectsRequestWithoutToken, protectedEndpointAcceptsValidMatchingTenantToken, protectedEndpointRejectsValidSignatureWrongTenantToken)"
        status: pass
    human_judgment: false
  - id: D4
    description: "io.axiam:axiam-bom validates, packaging=pom, dependencyManagement pins io.axiam:axiam-sdk"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "mvn -f sdks/java-bom/pom.xml validate"
        status: pass
    human_judgment: false
  - id: D5
    description: "sdk-ci-java.yml is valid YAML; PR-gate runs mvn test + TLS-bypass gate + mvn verify -Dgpg.skip=false (ephemeral key, javadoc/sources jars) + dependency:tree + gRPC codegen drift-check; a separate tag-triggered job publishes both io.axiam:axiam-sdk and io.axiam:axiam-bom; GPG_PRIVATE_KEY/GPG_PASSPHRASE/CENTRAL_TOKEN_* appear only in that tag job"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "python3 -c \"import yaml; yaml.safe_load(open('.github/workflows/sdk-ci-java.yml'))\""
        status: pass
      - kind: other
        ref: "awk-based scan confirming GPG_PRIVATE_KEY/GPG_PASSPHRASE/CENTRAL_TOKEN_* lines all fall under the publish: job"
        status: pass
      - kind: other
        ref: "mvn -f sdks/java/pom.xml verify -Dgpg.skip=false -Dgpg.passphrase='' (ephemeral key generated via gpg --quick-generate-key) -- 55 tests pass, sources+javadoc jars attached, GPG signs 4 files"
        status: pass
      - kind: other
        ref: "bash sdks/java/scripts/tls-bypass-gate.sh"
        status: pass
    human_judgment: false
  - id: D6
    description: "First live Maven Central publish (namespace verification + real GPG/Central credentials) is a maintainer action"
    verification: []
    human_judgment: true
    rationale: "Requires the verified io.axiam namespace + Central Portal credentials + real GPG key, none of which are available in this environment; the publish job is fully wired and structurally proven (ephemeral-key mvn verify) but the first real tag-triggered deploy must be confirmed by a maintainer per 20-VALIDATION.md's Manual-Only Verifications row"

# Metrics
duration: 14min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 09: Examples, Spring Boot App, BOM, CI/Publish Pipeline Summary

**Four public-API-only capability examples, a complete bootable Spring Boot 3.x app with explicit SecurityFilterChain wiring (SC#3), the io.axiam:axiam-bom coordinate, and a full mvn-test/TLS-gate/GPG-signed-verify/drift-check/tag-publish CI pipeline (SC#4/SC#5) — completing the Java SDK.**

## Performance

- **Duration:** ~14 min
- **Started:** 2026-07-02T08:47:04Z
- **Completed:** 2026-07-02T09:00:46Z
- **Tasks:** 3
- **Files modified:** 15 (11 created, 4 modified)

## Accomplishments
- Four runnable examples (login+MFA two-phase flow, REST `can`/`checkAccess`/`batchCheck`, gRPC `checkAccess`/`batchCheck` sharing the REST client's guard/session, AMQP consumer with an `ErrDrop` poison-message demonstration) — all compile against the SDK's public API only (verified via `javac` against the built SDK classpath)
- Complete, bootable Spring Boot 3.x example app (`SpringBootExampleApplication` + `SecurityConfig` + `HelloController`) proving SC#3's "complete working application context": `SecurityConfig` builds `JwksVerifier`/`AxiamAuthenticationFilter` beans and wires an explicit `SecurityFilterChain @Bean` that disables Spring's own CSRF (AXIAM's §3 supersedes it) and inserts the AXIAM filter before `UsernamePasswordAuthenticationFilter`
- `SpringBootExampleIT` boots the full `@SpringBootTest(webEnvironment = RANDOM_PORT)` context against a real `MockWebServer`-backed JWKS endpoint (`@DynamicPropertySource`) and proves `/hello`: 401 without a token, 200 with a valid matching-tenant token, 401 with a valid-signature wrong-tenant token (cross-tenant defense proven end-to-end, not just unit-tested)
- README adds Maven + Gradle getting-started snippets, the `tenantId`-required/try-with-resources quick-start, and the `io.axiam:axiam-bom` coordinate, alongside the pre-existing `CONTRACT.md §1-§10` conformance line
- `sdks/java-bom/pom.xml`: `io.axiam:axiam-bom`, `packaging=pom`, full POM metadata mirroring the SDK, `dependencyManagement` pinning `io.axiam:axiam-sdk`, and the same GPG + Central Portal publish plugin chain
- `sdk-ci-java.yml` rewritten into one job per concern: `test`, `tls-bypass-gate`, `verify-signed` (ephemeral GPG key + `mvn verify -Dgpg.skip=false` incl. javadoc/sources jars + `dependency:tree`), `grpc-drift-check`, `bom-validate`, `spring-boot-example`, and a separate tag-triggered (`sdks/java/v*`) `publish` job that imports the real `GPG_PRIVATE_KEY`/`GPG_PASSPHRASE` and deploys both `io.axiam:axiam-sdk` and `io.axiam:axiam-bom` via `CENTRAL_TOKEN_*` credentials — those three secret names appear only in `publish`, confirmed via automated scan

## Task Commits

Each task was committed atomically:

1. **Task 1: Four capability examples + README conformance statement (D-13, §1-§10)** - `9983554` (feat)
2. **Task 2: Complete Spring Boot 3.x example app + boot integration test (SC#3)** - `cbc8f2e` (feat)
3. **Task 3: BOM coordinate + full CI/publish pipeline (D-22/D-23, SC#4/SC#5, Pitfall 4)** - `f3f9f69` (feat)

_No separate plan-metadata commit yet — SUMMARY.md/STATE.md/ROADMAP.md/REQUIREMENTS.md land in the final docs commit below._

## Files Created/Modified

- `sdks/java/examples/login-mfa/LoginMfaExample.java` — two-phase login/verifyMfa flow demo
- `sdks/java/examples/rest-authz/RestAuthzExample.java` — `can`/`checkAccess`/`batchCheck` demo
- `sdks/java/examples/grpc-checkaccess/GrpcCheckAccessExample.java` — gRPC `checkAccess`/`batchCheck` sharing the REST client's guard/session
- `sdks/java/examples/amqp-consumer/AmqpConsumerExample.java` — `AmqpConsumer.consume` with an `ErrDrop` poison-message branch
- `sdks/java/examples/spring-boot-app/pom.xml` — Spring Boot 3.5.6 example app POM (depends on the locally-installed `io.axiam:axiam-sdk`)
- `sdks/java/examples/spring-boot-app/src/main/java/io/axiam/example/springboot/SpringBootExampleApplication.java` — `@SpringBootApplication` entry point
- `sdks/java/examples/spring-boot-app/src/main/java/io/axiam/example/springboot/SecurityConfig.java` — explicit `SecurityFilterChain @Bean` wiring `AxiamAuthenticationFilter` + `HttpStatusEntryPoint(UNAUTHORIZED)`
- `sdks/java/examples/spring-boot-app/src/main/java/io/axiam/example/springboot/HelloController.java` — protected `GET /hello`
- `sdks/java/examples/spring-boot-app/src/main/resources/application.properties` — `axiam.base-url`/`axiam.tenant-id` defaults
- `sdks/java/examples/spring-boot-app/src/test/java/io/axiam/example/springboot/SpringBootExampleIT.java` — full-context boot + protected-endpoint integration test
- `sdks/java-bom/pom.xml` — `io.axiam:axiam-bom` coordinate
- `sdks/java/README.md` — getting-started (Maven+Gradle), tenantId/try-with-resources quick-start, BOM mention
- `sdks/java/src/main/java/io/axiam/sdk/AxiamClient.java` — added the missing `session()` accessor
- `.github/workflows/sdk-ci-java.yml` — full CI/publish pipeline rewrite

## Decisions Made

- Added `AxiamClient.session()` — 20-08's gRPC transport comment block promised the accessors needed to construct a `GrpcAuthzClient` sharing the "one guard," but the actual `session()` accessor was never added, making it impossible for any caller (including this plan's own example) to construct one from an `AxiamClient` instance
- Added `HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)` to the example's `SecurityFilterChain` — Spring Security's default `Http403ForbiddenEntryPoint` fallback (no `formLogin`/`httpBasic` configured) returns 403 for missing credentials, but SC#3's literal acceptance criterion requires 401
- Added `maven-failsafe-plugin` to the example app's POM — `SpringBootExampleIT`'s `*IT.java` suffix is the Failsafe convention, but the default `maven-surefire-plugin` (bound to `test`) silently ignores it, so a plain `mvn verify` (as both the plan's acceptance criteria and the CI workflow invoke it) was running zero tests before this fix
- Split the CI workflow into one job per concern so the real GPG/Central secrets are provably confined to the tag-triggered `publish` job (verified via an automated `awk` scan, not just visual review)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `AxiamClient` was missing the `session()` accessor entirely**
- **Found during:** Task 1 (writing `GrpcCheckAccessExample.java`)
- **Issue:** `GrpcAuthzClient`'s public constructor requires `(target, RefreshGuard, SessionState, customCaPem)` to share the "one guard" (D-07/D-08) with the REST transport, but `AxiamClient` (added in 20-08) only exposed `refreshGuard()`/`tenantId()`/`baseUrl()`/`okHttpClient()`/`customCa()` — no `session()`. Without it, no caller could construct a `GrpcAuthzClient` that shares an `AxiamClient`'s session, blocking the gRPC example (and any real-world Spring/other integration wanting both transports).
- **Fix:** Added `public SessionState session()` to `AxiamClient`, mirroring the existing accessor pattern and Javadoc block.
- **Files modified:** `sdks/java/src/main/java/io/axiam/sdk/AxiamClient.java`
- **Verification:** `GrpcCheckAccessExample.java` compiles cleanly against the SDK's public API (`javac` against `sdks/java/target/classes`); existing SDK test suite (55 tests) still passes unchanged.
- **Committed in:** `9983554` (Task 1 commit)

**2. [Rule 1 - Bug] No-token request to `/hello` returned 403 instead of the required 401**
- **Found during:** Task 2 (`SpringBootExampleIT`)
- **Issue:** With `AxiamAuthenticationFilter` letting an unauthenticated request pass through (per its documented design — "let Spring Security's own access-control rules 401/403 it") and no `formLogin`/`httpBasic` configured, Spring Security 6's `ExceptionTranslationFilter` falls back to `Http403ForbiddenEntryPoint`, returning 403 Forbidden rather than 401 Unauthorized. The plan's literal acceptance criteria require "401 without a token, 200 with a matching-tenant token."
- **Fix:** Added `.exceptionHandling(handling -> handling.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))` to `SecurityConfig`'s `SecurityFilterChain` bean.
- **Files modified:** `sdks/java/examples/spring-boot-app/src/main/java/io/axiam/example/springboot/SecurityConfig.java`
- **Verification:** `SpringBootExampleIT.protectedEndpointRejectsRequestWithoutToken` asserts `HttpStatus.UNAUTHORIZED`; full 4-test suite passes.
- **Committed in:** `cbc8f2e` (Task 2 commit)

**3. [Rule 1 - Bug] `mvn verify` on the example app silently ran zero integration tests**
- **Found during:** Task 3 (validating the CI workflow's `spring-boot-example` job)
- **Issue:** `SpringBootExampleIT` follows the classic Failsafe `*IT.java` naming convention, but the example POM only had the default `maven-surefire-plugin` (bound to the `test` phase, matching `**/Test*.java`/`**/*Test.java`/`**/*Tests.java`/`**/*TestCase.java` — NOT `**/*IT.java`). A plain `mvn verify` (exactly the command the plan's acceptance criteria and this task's CI workflow both invoke, without `-Dtest=`) compiled the class but executed zero tests, silently "passing" without ever booting the app or exercising `/hello`.
- **Fix:** Added `maven-failsafe-plugin` (version managed by `spring-boot-starter-parent`'s `pluginManagement`) bound to the `integration-test`/`verify` goals, whose default include pattern matches `**/*IT.java`.
- **Files modified:** `sdks/java/examples/spring-boot-app/pom.xml`
- **Verification:** `mvn -f sdks/java/examples/spring-boot-app/pom.xml clean verify` now shows `failsafe:integration-test` running and passing all 4 `SpringBootExampleIT` tests, followed by `failsafe:verify`.
- **Committed in:** `f3f9f69` (Task 3 commit)

---

**Total deviations:** 3 auto-fixed (1 blocking, 2 bugs)
**Impact on plan:** All three were necessary for the plan's own literal acceptance criteria to actually hold (a real `session()` seam for the gRPC example; the SC#3-mandated 401 status; `mvn verify` actually running the integration test it names). No scope creep — no new features beyond what the plan already specified.

## Issues Encountered

None beyond the three deviations above, each caught by actually running the plan's own `<verify>` commands (not just writing code that looked correct).

## User Setup Required

**External services require manual configuration for the live first Maven Central publish.** The `sdks/java-bom/pom.xml` -> `.github/workflows/sdk-ci-java.yml publish` job pipeline is fully wired and structurally proven (ephemeral-key `mvn verify -Dgpg.skip=false` passes locally, including javadoc/sources jar attachment), but the first real tag-triggered deploy requires, per this plan's frontmatter `user_setup`:
- `CENTRAL_TOKEN_USERNAME`/`CENTRAL_TOKEN_PASSWORD` (Sonatype Central Portal user token) as repo secrets
- `GPG_PRIVATE_KEY` (base64-encoded ASCII-armored real signing key) and `GPG_PASSPHRASE` as repo secrets, scoped to the tag-publish job only
- Verification of the `io.axiam` Maven Central namespace (DNS TXT or GitHub-repo ownership proof) in the Sonatype Central Portal dashboard

No `{phase}-USER-SETUP.md` file was generated separately — this section documents the same `user_setup` block already present in `20-09-PLAN.md`'s frontmatter.

## Next Phase Readiness

- The Java SDK (Phase 20) is now feature-complete against JAVA-01: REST/gRPC/AMQP transports, Spring Security integration, examples, a complete Spring Boot app proving SC#3, and an operational (structurally-proven) CI/publish pipeline proving SC#4/SC#5.
- No blockers for closing Phase 20. The only remaining open item is the live first Maven Central publish, which is explicitly a maintainer action pending the `io.axiam` namespace verification and CI secrets (tracked above, not a code gap).

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*
