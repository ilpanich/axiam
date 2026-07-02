---
phase: 20-java-sdk
plan: 08
subsystem: api
tags: [grpc, java, netty, tls, refresh-guard, authz]

# Dependency graph
requires:
  - phase: 20-java-sdk (20-01)
    provides: protobuf-maven-plugin codegen producing axiam.v1.AuthorizationServiceGrpc/Authorization stubs
  - phase: 20-java-sdk (20-05)
    provides: AxiamClient's package-internal RefreshGuard/SessionState seam (refreshGuard(), tenantId(), baseUrl(), okHttpClient(), customCa() accessors)
  - phase: 20-java-sdk (20-03)
    provides: central ErrorMapper.fromGrpcStatus (§2 gRPC status table) and the Auth/Authz/NetworkError taxonomy
provides:
  - io.axiam.sdk.grpc.AuthClientInterceptor — non-blocking authorization/x-tenant-id metadata injection + strict-TLS NettyChannelBuilder construction seam + default per-call deadlines
  - io.axiam.sdk.grpc.GrpcAuthzClient — checkAccess/checkAccessAsync/batchCheck/batchCheckAsync over one shared ManagedChannel, UNAUTHENTICATED->shared-guard-refresh->retry-once, §2 error mapping
affects: [20-09 (packaging/publishing), any future plan wiring GrpcAuthzClient onto AxiamClient's public surface]

# Tech tracking
tech-stack:
  added: [grpc-inprocess:1.82.0 (test scope only)]
  patterns:
    - "gRPC ClientInterceptor wraps ForwardingClientCall.SimpleForwardingClientCall, attaching Metadata in start() from a non-blocking Supplier<String> token accessor"
    - "Token source falls back RefreshGuard.cachedAccessToken() -> SessionState.cachedAccessToken() so the very first gRPC call after login() (before any refresh has ever run) still carries a Bearer token"
    - "gRPC request-body tenant_id/subject_id resolved from the CURRENT access token's unverified-decoded claims, not the raw configured tenant string, to satisfy the real server's JWT-claim cross-validation"
    - "ListenableFuture -> CompletableFuture adaptation via Futures.addCallback(..., MoreExecutors.directExecutor()), with async refresh-retry composed via handle().thenCompose(Function.identity())"

key-files:
  created:
    - sdks/java/src/main/java/io/axiam/sdk/grpc/package-info.java
    - sdks/java/src/main/java/io/axiam/sdk/grpc/AuthClientInterceptor.java
    - sdks/java/src/main/java/io/axiam/sdk/grpc/GrpcAuthzClient.java
    - sdks/java/src/test/java/io/axiam/sdk/grpc/GrpcAuthzClientTest.java
  modified:
    - sdks/java/pom.xml (added io.grpc:grpc-inprocess:1.82.0, test scope)

key-decisions:
  - "AuthClientInterceptor takes a Supplier<String> token accessor (not RefreshGuard directly) so GrpcAuthzClient can wire a guard-then-session fallback without the interceptor needing to know about SessionState"
  - "gRPC wire tenant_id/subject_id resolve from access-token claims (RefreshGuard cache, falling back to SessionState's cookie-jar token), not the client's configured tenantId string — the real axiam-api-grpc authorization.rs handler cross-validates both body fields against verified JWT claims and rejects (PERMISSION_DENIED) on mismatch; a human-readable tenantSlug would never satisfy that check"
  - "GrpcAuthzClient exposes a package-private ManagedChannel-accepting constructor (test-only seam) alongside the public target-string constructor, so GrpcAuthzClientTest can attach an in-process channel + AuthClientInterceptor without a live network dependency"
  - "grpc-inprocess added as a test-scope-only Maven dependency — grpc-java 1.62+ moved InProcessServerBuilder/InProcessChannelBuilder out of grpc-core into a separate module"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "AuthClientInterceptor injects authorization Bearer + x-tenant-id metadata via a non-blocking accessor, never refreshIfNeeded on the hot path"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "io.axiam.sdk.grpc.GrpcAuthzClientTest#outgoingMetadataCarriesAuthorizationAndTenantId"
        status: pass
    human_judgment: false
  - id: D2
    description: "Strict-TLS ManagedChannel construction (system trust store + optional customCa, no bypass) via NettyChannelBuilder/GrpcSslContexts"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "bash sdks/java/scripts/tls-bypass-gate.sh"
        status: pass
    human_judgment: false
  - id: D3
    description: "checkAccess/batchCheck allow/deny mapping and default per-call deadlines"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "io.axiam.sdk.grpc.GrpcAuthzClientTest#checkAccessAllowedMapsToAllowedTrue"
        status: pass
      - kind: unit
        ref: "io.axiam.sdk.grpc.GrpcAuthzClientTest#checkAccessDeniedYieldsReason"
        status: pass
    human_judgment: false
  - id: D4
    description: "UNAUTHENTICATED triggers exactly one shared-guard refresh then exactly one retry (§9.3), guard shared with REST"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "io.axiam.sdk.grpc.GrpcAuthzClientTest#unauthenticatedThenSuccessTriggersExactlyOneSharedGuardRefreshAndOneRetry"
        status: pass
    human_judgment: false
  - id: D5
    description: "§2 gRPC error mapping — PERMISSION_DENIED->AuthzError, UNAVAILABLE->NetworkError"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "io.axiam.sdk.grpc.GrpcAuthzClientTest#permissionDeniedMapsToAuthzErrorAndUnavailableMapsToNetworkError"
        status: pass
    human_judgment: false
  - id: D6
    description: "batchCheck preserves input order"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "io.axiam.sdk.grpc.GrpcAuthzClientTest#batchCheckReturnsResultsInInputOrder"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 08: gRPC Transport (GrpcAuthzClient + AuthClientInterceptor) Summary

**gRPC `CheckAccess`/`BatchCheckAccess` over one long-lived strict-TLS `ManagedChannel`, sharing the exact `RefreshGuard` instance REST uses, with claim-derived tenant/subject fields matching the server's JWT cross-validation**

## Performance

- **Duration:** 25 min
- **Completed:** 2026-07-02
- **Tasks:** 2
- **Files modified:** 5 (4 created + 1 modified)

## Accomplishments

- `AuthClientInterceptor` non-blocking metadata injection (`authorization: Bearer <token>` + `x-tenant-id`) plus the strict-TLS `NettyChannelBuilder` construction seam (system trust store + optional `customCa` composite trust manager) and the two default per-call deadlines (`CheckAccess` 3000ms / `BatchCheckAccess` 10000ms, D-12)
- `GrpcAuthzClient` wraps one shared `ManagedChannel` with both blocking and `ListenableFuture`-adapted `CompletableFuture` async surfaces for `checkAccess`/`batchCheck`; `UNAUTHENTICATED` drives exactly one call into the SAME `RefreshGuard` REST uses, retries exactly once, and terminal errors route through the central `ErrorMapper.fromGrpcStatus`
- `GrpcAuthzClientTest` proves all of the above over a real in-process gRPC server (allow/deny mapping, single-refresh-and-retry, §2 error mapping, metadata injection, batch order) with no live network dependency

## Task Commits

Each task was committed atomically:

1. **Task 1: AuthClientInterceptor (metadata + deadline) + ManagedChannel construction** - `7b2710c` (feat)
2. **Task 2: GrpcAuthzClient checkAccess/batchCheck with shared-guard refresh-retry + error mapping** - `8def6dd` (feat)

_Note: Task 2's commit also includes the `grpc-inprocess` test dependency addition to `pom.xml`, required by `GrpcAuthzClientTest`._

## Files Created/Modified

- `sdks/java/src/main/java/io/axiam/sdk/grpc/package-info.java` - `@NullMarked` package doc for the gRPC transport
- `sdks/java/src/main/java/io/axiam/sdk/grpc/AuthClientInterceptor.java` - metadata-injecting `ClientInterceptor` + strict-TLS channel construction seam + deadline constants
- `sdks/java/src/main/java/io/axiam/sdk/grpc/GrpcAuthzClient.java` - the gRPC authz client (blocking + async, shared-guard refresh-retry, wire mapping, error mapping)
- `sdks/java/src/test/java/io/axiam/sdk/grpc/GrpcAuthzClientTest.java` - in-process-server test suite covering all must-haves
- `sdks/java/pom.xml` - added `io.grpc:grpc-inprocess:1.82.0` (test scope)

## Decisions Made

- **Token source fallback (RefreshGuard -> SessionState):** `RefreshGuard`'s cache is only ever populated by an actual refresh call — `AxiamClient.login()` sets cookies but never touches the guard. Reading only `RefreshGuard.cachedAccessToken()` (as a literal reading of the plan's action text and RESEARCH.md/PATTERNS.md examples might suggest) would leave every gRPC call unauthenticated immediately after `login()`, before any refresh has ever happened. `GrpcAuthzClient.currentAccessToken()` reads the guard first, falling back to `SessionState.cachedAccessToken()` (the cookie-jar-backed token REST already relies on) — both reads are non-blocking, preserving the interceptor's hot-path discipline.
- **Wire tenant_id/subject_id from JWT claims, not the configured tenant string:** verified directly against `crates/axiam-api-grpc/src/services/authorization.rs` — the real `check_access`/`batch_check_access` handlers derive authoritative `tenant_id`/`subject_id` from the VALIDATED JWT claims and reject the RPC (`PERMISSION_DENIED`) if the request body's `tenant_id`/`subject_id` don't match those claims exactly. `session.tenantId()` (the client's configured, possibly-human-readable tenant slug) is used only for the `x-tenant-id` metadata header (matching REST's `X-Tenant-Id` header behavior); the wire request body's `tenant_id` is resolved from `SessionState.decodeUnverifiedClaims(...).tenantId()` instead.
- **Package-private test constructor on `GrpcAuthzClient`:** the public constructor hard-builds a strict-TLS `NettyChannelBuilder`-backed channel from a `target` string; a same-package, package-private `GrpcAuthzClient(ManagedChannel, RefreshGuard, SessionState)` constructor lets `GrpcAuthzClientTest` substitute a pre-built in-process channel (with its own `AuthClientInterceptor` attached) — exercising the real production code path end-to-end without a live network dependency.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Token source must fall back to the cookie-jar token, not rely solely on RefreshGuard's cache**
- **Found during:** Task 1/2 design — reasoning through the actual call sequence `AxiamClient.login()` -> first `GrpcAuthzClient.checkAccess()` (before any refresh)
- **Issue:** `RefreshGuard.current` starts `null` and is only ever set inside `refreshIfNeeded()`. `AxiamClient.login()`/`verifyMfa()` never call the guard — they only rely on `Set-Cookie` response headers. Wiring `AuthClientInterceptor` to read `RefreshGuard.cachedAccessToken()` exclusively (a literal reading of the plan text/RESEARCH.md pattern sketch) would mean every gRPC call made before the first-ever refresh silently goes out with no `Authorization` header.
- **Fix:** `GrpcAuthzClient.currentAccessToken(guard, session)` reads the guard first, falling back to `SessionState.cachedAccessToken()` (the same cookie-jar-backed source REST's `AuthInterceptor` reads). Both reads remain non-blocking (no lock acquisition), preserving the interceptor hot-path discipline. Used consistently for the interceptor's token accessor, claims resolution (`resolveClaims()`), and the refresh-retry's "observed" token.
- **Files modified:** `sdks/java/src/main/java/io/axiam/sdk/grpc/GrpcAuthzClient.java`, `sdks/java/src/main/java/io/axiam/sdk/grpc/AuthClientInterceptor.java`
- **Verification:** `GrpcAuthzClientTest#outgoingMetadataCarriesAuthorizationAndTenantId` seeds only the guard (simulating post-refresh state); `#unauthenticatedThenSuccessTriggersExactlyOneSharedGuardRefreshAndOneRetry` seeds only the session cookie jar via a real HTTP response (simulating post-login, pre-refresh state) — both pass.
- **Commit:** `8def6dd` (part of Task 2)

**2. [Rule 1 - Bug] gRPC request-body tenant_id/subject_id must come from JWT claims, not the configured tenant identifier**
- **Found during:** Task 2 — cross-referencing `crates/axiam-api-grpc/src/services/authorization.rs`'s `check_access` handler per the plan's own `<read_first>` instruction
- **Issue:** The plan's action text says "map to `CheckAccessRequest` (tenant_id from the client's tenant...)", which read literally suggests using `session.tenantId()` (the client's configured, possibly human-readable tenant slug/string) as the wire `tenant_id`. The actual server handler `parse_uuid(&req.tenant_id, "tenant_id")`s the body field and cross-validates it against the VERIFIED JWT claim's `tenant_id`, returning `PERMISSION_DENIED` on any mismatch (and would return `invalid_argument` if the configured value isn't even a valid UUID, e.g. a tenant slug).
- **Fix:** `GrpcAuthzClient.toWire()` resolves `tenant_id`/`subject_id` from `SessionState.decodeUnverifiedClaims(currentAccessToken(...))` — the exact same UUIDs the server's JWT-claim cross-validation expects — rather than from `session.tenantId()`. The configured tenant identifier is still used for the `x-tenant-id` metadata header (matching REST's `X-Tenant-Id` header semantics), just not for the request body.
- **Files modified:** `sdks/java/src/main/java/io/axiam/sdk/grpc/GrpcAuthzClient.java`
- **Verification:** `GrpcAuthzClientTest#outgoingMetadataCarriesAuthorizationAndTenantId`/`#batchCheckReturnsResultsInInputOrder` seed a well-formed fake JWT and assert the client builds successfully against a real (in-process) server contract; `mvn -f sdks/java/pom.xml test -Dtest=GrpcAuthzClientTest` green (6/6).
- **Commit:** `8def6dd` (part of Task 2)

---

**Total deviations:** 2 auto-fixed (2 Rule 1 — both were genuine correctness bugs that would have broken every real gRPC call against the actual AXIAM server; discovered by reading the plan's own cited `<read_first>` source files, not scope creep).
**Impact on plan:** Both fixes are necessary for the client to actually work against the real server; no architectural changes, no new files beyond what the plan specified.

## Issues Encountered

**`java.net.CookieManager` stale-cookie replacement in tests:** `GrpcAuthzClientTest`'s refresh-retry test initially manually inserted a "stale" cookie via `CookieStore.add(uri, cookie)` directly, then asserted the guard's cache reflected a "new" token after the simulated refresh response. This intermittently retrieved the STALE cookie instead of the fresh one — traced (via a standalone JDK reproduction) to `java.net.CookieManager`'s internal replace-on-add logic keying on the exact request `URI` object identity used for `.add()`/`.put()`; a manually-added `CookieStore` entry and a later real `CookieManager.put()`-driven `Set-Cookie` response end up as two coexisting entries (not a replacement) when their originating request URIs differ syntactically (e.g. trailing slash), and `SessionState.cookieValue()`'s "return the first match" loop non-deterministically preferred the stale one. Fixed by seeding the stale token via an actual HTTP response round-trip (consuming an extra enqueued `MockResponse`) instead of a manual `CookieStore.add()` call, exactly mirroring how `AxiamClient.login()` seeds cookies in production. This is a test-fixture-only concern — the SDK's own production code path (`AxiamClient.login()` -> `Set-Cookie` -> `SessionState.doHttpRefresh()` -> `Set-Cookie`) was never affected, since it always goes through real HTTP responses.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

`GrpcAuthzClient`/`AuthClientInterceptor` are ready to be wired onto `AxiamClient`'s public surface (or exposed as a standalone constructible transport) by a future plan if desired — this plan intentionally kept them as independently-testable, package-private-seam-friendly units per the plan's file scope (`AxiamClient.java` was not in this plan's `files_modified` list). The transport trio (REST/gRPC/AMQP) is now complete for the Java SDK; no blockers for 20-09 (packaging/publishing).

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All created files verified present on disk; all task/summary commits verified present in `git log`.
