---
phase: 20-java-sdk
plan: 03
subsystem: auth
tags: [java, jackson, okhttp, grpc, sensitive-data, error-handling, tdd]

requires:
  - phase: 20-java-sdk (20-01)
    provides: pom.xml scaffold (OkHttp, Jackson, grpc-stub, jspecify), root package-info @NullMarked
provides:
  - "io.axiam.sdk.Sensitive — hardened final class redacting on toString/Jackson/reflective-serialization"
  - "io.axiam.sdk.LoginResult / AxiamUser — immutable DTO records (D-04)"
  - "io.axiam.sdk.errors.{AuthError,AuthzError,NetworkError} — unchecked error taxonomy (D-03)"
  - "io.axiam.sdk.errors.ErrorMapper — central status->error mapper with redact-before-wrap (D-18/CR-04)"
affects: [20-java-sdk (all subsequent REST/gRPC/AMQP/Spring plans that construct errors or carry tokens)]

tech-stack:
  added: []
  patterns:
    - "Sensitive: final class + Jackson StdSerializer Redactor + non-Serializable + package-private expose()"
    - "ErrorMapper.sanitize(Response) as the single choke point from a live okhttp3.Response into NetworkError"

key-files:
  created:
    - sdks/java/src/main/java/io/axiam/sdk/Sensitive.java
    - sdks/java/src/main/java/io/axiam/sdk/LoginResult.java
    - sdks/java/src/main/java/io/axiam/sdk/AxiamUser.java
    - sdks/java/src/main/java/io/axiam/sdk/errors/package-info.java
    - sdks/java/src/main/java/io/axiam/sdk/errors/AuthError.java
    - sdks/java/src/main/java/io/axiam/sdk/errors/AuthzError.java
    - sdks/java/src/main/java/io/axiam/sdk/errors/NetworkError.java
    - sdks/java/src/main/java/io/axiam/sdk/errors/ErrorMapper.java
    - sdks/java/src/test/java/io/axiam/sdk/SensitiveTest.java
    - sdks/java/src/test/java/io/axiam/sdk/errors/ErrorRedactionTest.java
  modified: []

key-decisions:
  - "LoginResult.challengeToken typed as Sensitive (not raw String) — it is a token-carrying field per §7's blanket requirement, mirrors sdks/go's MFAToken Sensitive field"
  - "NetworkError exposes a single (String message, String sanitizedSummary) constructor — no overload accepts okhttp3.Response, structurally preventing a raw response from ever entering the exception chain"
  - "AuthzError.action()/resourceId() nullable accessors populated only via the 3-arg constructor; ErrorMapper's HTTP-table path uses the message-only 403/409 branch since the response body is not parsed in this plan's scope"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "Sensitive redacts raw token on toString() and Jackson serialization, and fails closed (not Serializable)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/SensitiveTest.java#toStringReturnsRedactedPlaceholder,jacksonSerializationEmitsRedactedPlaceholder,sensitiveIsNotSerializable"
        status: pass
    human_judgment: false
  - id: D2
    description: "LoginResult/AxiamUser immutable records with mfaRequired flag (MFA-required never thrown as exception)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/SensitiveTest.java (compiles LoginResult/AxiamUser records used indirectly); javap -p confirms record accessor mfaRequired()"
        status: pass
    human_judgment: false
  - id: D3
    description: "ErrorMapper implements CONTRACT.md §2 HTTP + gRPC status tables exactly (401->Auth, 403/409->Authz, else->Network; UNAUTHENTICATED->Auth, PERMISSION_DENIED->Authz, else->Network)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/errors/ErrorRedactionTest.java#httpStatusMappingMatchesContract,grpcStatusMappingMatchesContract"
        status: pass
    human_judgment: false
  - id: D4
    description: "NetworkError redact-before-wrap: raw Set-Cookie token never leaks into toString/getMessage/cause chain, while a non-sensitive control header survives (non-vacuous CR-04 regression)"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/errors/ErrorRedactionTest.java#networkErrorNeverLeaksRawSetCookieToken,networkErrorSanitizedSummaryRetainsNonSensitiveControlHeader"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 03: Sensitive + Error Taxonomy Summary

**Hardened `Sensitive` token wrapper (Jackson-redacting, non-`Serializable`) and a central `ErrorMapper` that redacts `Set-Cookie`/`Authorization`/`Cookie` before any header reaches a thrown `NetworkError`, proven by non-vacuous regression tests.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-02T07:16:03Z
- **Completed:** 2026-07-02T07:22:37Z
- **Tasks:** 2
- **Files modified:** 10 (8 created main, 2 created test)

## Accomplishments
- `io.axiam.sdk.Sensitive`: final class, `toString()` → `[SENSITIVE]`, Jackson `Redactor` serializer, NOT `Serializable` (fails closed via `NotSerializableException` on any attempted Java serialization), raw value reachable only via package-private `expose()`
- `LoginResult`/`AxiamUser` immutable records (D-04) — MFA-required represented as a boolean flag, never thrown as an exception (D-03)
- `AuthError`/`AuthzError`/`NetworkError` unchecked exception taxonomy (D-03), English-only messages (D-29)
- `ErrorMapper` — single central status→error mapper transcribing CONTRACT.md §2's HTTP and gRPC tables exactly; `sanitize(Response)` is the sole choke point converting a live `okhttp3.Response` into a `NetworkError`, always redacting before wrap
- Two non-vacuous regression tests (`SensitiveTest`, `ErrorRedactionTest`) proving raw tokens/cookies never leak while benign data survives redaction

## Task Commits

Each task followed RED → GREEN TDD:

1. **Task 1: Sensitive + LoginResult/AxiamUser**
   - `e7a1f15` test(20-03): add failing test for Sensitive redaction (D-17)
   - `a8c5123` feat(20-03): implement Sensitive hardened final class + LoginResult/AxiamUser records (D-17, D-04)
2. **Task 2: Error taxonomy + ErrorMapper**
   - `2d59c2f` test(20-03): add failing test for ErrorMapper redact-before-wrap (D-18, CR-04)
   - `19754af` feat(20-03): implement error taxonomy + central ErrorMapper with redact-before-wrap (D-18, CR-04)

**Plan metadata:** (this commit)

## Files Created/Modified
- `sdks/java/src/main/java/io/axiam/sdk/Sensitive.java` - hardened token wrapper (D-17)
- `sdks/java/src/main/java/io/axiam/sdk/LoginResult.java` - immutable login-outcome record (D-04)
- `sdks/java/src/main/java/io/axiam/sdk/AxiamUser.java` - immutable user-identity record (D-04)
- `sdks/java/src/main/java/io/axiam/sdk/errors/package-info.java` - `@NullMarked` for the errors package
- `sdks/java/src/main/java/io/axiam/sdk/errors/AuthError.java` - unchecked auth-failure exception
- `sdks/java/src/main/java/io/axiam/sdk/errors/AuthzError.java` - unchecked authz-failure exception with optional action/resourceId
- `sdks/java/src/main/java/io/axiam/sdk/errors/NetworkError.java` - unchecked transport-failure exception, redact-before-wrap only
- `sdks/java/src/main/java/io/axiam/sdk/errors/ErrorMapper.java` - central status->error mapper + single Response sanitize choke point
- `sdks/java/src/test/java/io/axiam/sdk/SensitiveTest.java` - CR-04-class regression test for Sensitive
- `sdks/java/src/test/java/io/axiam/sdk/errors/ErrorRedactionTest.java` - CR-04 regression test for ErrorMapper/NetworkError

## Decisions Made
- `LoginResult.challengeToken` typed as `Sensitive` (not raw `String`) — it is a token-carrying field per CONTRACT.md §7's blanket "all token-carrying fields MUST use this type" requirement; mirrors `sdks/go`'s `MFAToken Sensitive` field.
- `NetworkError` exposes a single `(String message, String sanitizedSummary)` constructor with no overload accepting `okhttp3.Response` — this is a structural (compile-time) guarantee that a raw response can never enter the exception chain, not just a convention.
- `AuthzError` carries optional `action`/`resourceId` via a 3-arg constructor (nullable accessors); `ErrorMapper`'s status-table path uses the message-only 2-arg form since response-body parsing for `action`/`resourceId` is out of this plan's scope (a later transport plan will populate them when available).

## Deviations from Plan

None - plan executed exactly as written. Both tasks matched RESEARCH.md Pattern 6 (Sensitive) and Pattern 7 (ErrorMapper) closely, adapted only for the plan's explicit constructor/field shape (`LoginResult`/`AxiamUser` minimal fields, `NetworkError`'s single sanitized-summary constructor).

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `Sensitive` and the `errors` package are ready for reuse by every subsequent Java SDK plan (REST/gRPC/AMQP transports, Spring Security integration) — they are the CR-04 leak-class control every sibling SDK carries forward.
- `ErrorMapper.fromHttpStatus`/`fromHttpResponse`/`fromGrpcStatus` are the only sanctioned entry points for transport code to construct `AuthError`/`AuthzError`/`NetworkError`; future plans MUST route through them rather than constructing these exceptions ad hoc, to preserve the single-choke-point redact-before-wrap invariant.
- No blockers.

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*
