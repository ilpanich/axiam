---
phase: 27-performance-load-hardening
plan: 03
subsystem: sdk
tags: [jwks, jwt, single-flight, concurrency, go, java, csharp, mutex, reentrantlock, semaphoreslim]

# Dependency graph
requires:
  - phase: 21-c-sdk
    provides: "C# SDK's CS-01 token-refresh single-flight guard (SemaphoreSlim(1,1) precedent reused here)"
  - phase: 18-go-sdk
    provides: "Go SDK's internal/jwks.Verifier wrapping lestrrat-go/jwx/v3 jwk.Cache"
  - phase: 20-java-sdk
    provides: "Java SDK's JwksVerifier wrapping Nimbus RemoteJWKSet + DefaultJWKSetCache"
provides:
  - "Go SDK: sync.Mutex-guarded double-checked JWKS refetch in internal/jwks/verifier.go"
  - "Java SDK: ReentrantLock-guarded double-checked JWKS refetch in JwksVerifier.java"
  - "C# SDK: SemaphoreSlim(1,1)-guarded double-checked JWKS fetch/cache-mutation in JwksVerifier.cs (fixes a pre-existing unsynchronized Dictionary/DateTimeOffset data race)"
  - "Per-SDK burst tests proving exactly one JWKS fetch under a concurrent invalid-kid burst"
affects: [28-func-completeness, 30-cmpl-docs]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Uniform hand-rolled JWKS single-flight (D-08): fast-path freshness check outside the lock, acquire lock, re-check freshness once more (double-checked locking), only then perform the actual network fetch"
    - "Lock/semaphore wraps ONLY the fetch/refresh decision, never the cryptographic verification step (jwx EdDSA verify / Ed25519Verifier / BouncyCastle Ed25519Signer)"

key-files:
  created: []
  modified:
    - sdks/go/internal/jwks/verifier.go
    - sdks/go/internal/jwks/verifier_test.go
    - sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java
    - sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java
    - sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs
    - sdks/csharp/Axiam.Sdk/Axiam.Sdk.csproj
    - sdks/csharp/tests/Axiam.Sdk.Tests/JwksVerifierTests.cs

key-decisions:
  - "Go: added sync.Mutex field; unknown-kid branch acquires it, re-checks v.cache.CachedSet() (no network call) before falling back to v.cache.Refresh() — does not rely on jwx/httprc's own internal coalescing"
  - "Java: added ReentrantLock; selectKey() checks RemoteJWKSet#getCachedJWKSet() (no network call) as a fast path, re-checks under the lock, and only calls RemoteJWKSet#get() (the call that may fetch) if still missing — does not rely on Nimbus's own thread-safety"
  - "C#: added SemaphoreSlim(1,1) reusing CS-01's exact primitive for in-codebase consistency; EnsureFreshAsync now double-checks IsFresh() before AND after acquiring the lock, which also fixes the pre-existing zero-synchronization Dictionary/DateTimeOffset data race"
  - "[Deviation] Fixed Axiam.Sdk.csproj's Google.Protobuf version pin from a nonexistent 2.80.0 to 3.25.8 (matching sdks/java/pom.xml's protobuf.version) — this was blocking the ENTIRE C# SDK build, including JwksVerifier.cs itself, before any test could run"

patterns-established:
  - "Double-checked lock shape for cache coalescing: cheap unlocked read -> lock -> re-read under lock -> do the expensive/networked thing only if still needed -> release. Applied identically across Go/Java/C# in this plan; matches the shape already used for sdks/rust/src/token/jwks.rs (RwLock) per 27-PATTERNS.md."

requirements-completed: [PERF-03]

coverage:
  - id: D1
    description: "Go SDK: concurrent invalid-kid burst (8 goroutines) collapses to exactly one JWKS fetch via sync.Mutex-guarded double-checked refresh; jwx EdDSA verify untouched"
    requirement: "PERF-03"
    verification:
      - kind: unit
        ref: "sdks/go/internal/jwks/verifier_test.go#TestJWKS_ConcurrentUnknownKidSingleFlight"
        status: pass
      - kind: unit
        ref: "cd sdks/go && go vet ./..."
        status: pass
    human_judgment: false
  - id: D2
    description: "Java SDK: concurrent invalid-kid burst (8 threads via ExecutorService+CountDownLatch) collapses to exactly one Nimbus RemoteJWKSet fetch via ReentrantLock-guarded double-checked selectKey(); Ed25519Verifier untouched"
    requirement: "PERF-03"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java#concurrentVerifyBurstTriggersExactlyOneJwksFetch"
        status: pass
    human_judgment: false
  - id: D3
    description: "C# SDK: concurrent invalid-kid burst (8 Tasks via Task.WhenAll) collapses to exactly one HTTP fetch via SemaphoreSlim(1,1)-guarded EnsureFreshAsync, also fixing the pre-existing unsynchronized Dictionary/DateTimeOffset cache; BouncyCastle Ed25519Signer verify untouched"
    requirement: "PERF-03"
    verification:
      - kind: unit
        ref: "sdks/csharp/tests/Axiam.Sdk.Tests/JwksVerifierTests.cs#ConcurrentUnknownKidBurst_TriggersExactlyOneFetch"
        status: pass
    human_judgment: true
    rationale: "The literal plan verification command (`cd sdks/csharp && dotnet test --filter JwksVerifier`) cannot succeed as-is because three pre-existing, unrelated files in the same test assembly (GrpcAuthzClientTests.cs, AmqpConsumerTests.cs, SensitiveRedactionTests.cs) and a fourth in the sibling Axiam.Sdk.AspNetCore project fail to compile for reasons unconnected to JWKS/PERF-03 (documented in deferred-items.md). The JwksVerifier-specific work was proven correct by scoping the dotnet test invocation to the test project with those three files transiently excluded (never committed) — a human should confirm this scoping is acceptable given the plan's literal acceptance criterion could not be run verbatim."

# Metrics
duration: 20min
completed: 2026-07-05
status: complete
---

# Phase 27 Plan 03: JWKS SDK Single-Flight (Go/Java/C#) Summary

**Uniform hand-rolled single-flight guards (Go sync.Mutex, Java ReentrantLock, C# SemaphoreSlim) collapse a concurrent invalid-kid JWKS fetch storm to exactly one network call per SDK, verification logic untouched.**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-05T13:37:19Z
- **Completed:** 2026-07-05T13:53:35Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments
- Go SDK's `internal/jwks.Verifier` gained a `sync.Mutex`-guarded double-checked refresh path around `v.cache.Refresh` — an 8-goroutine unknown-kid burst now produces exactly 1 JWKS fetch (proven by a new burst test, `go vet` clean)
- Java SDK's `JwksVerifier` gained a `ReentrantLock`-guarded double-checked `selectKey()` — an 8-thread unknown-kid burst against a cold cache now produces exactly 1 Nimbus `RemoteJWKSet` fetch (proven by an `ExecutorService`+`CountDownLatch` burst test)
- C# SDK's `JwksVerifier` gained a `SemaphoreSlim(1,1)`-guarded double-checked `EnsureFreshAsync` — reusing CS-01's exact primitive — an 8-task unknown-kid burst now produces exactly 1 HTTP fetch, and the previously **zero-synchronization** `Dictionary`/`DateTimeOffset` cache fields are now race-free
- All three SDKs' cryptographic verification (jwx EdDSA / Nimbus `Ed25519Verifier` / BouncyCastle `Ed25519Signer`) is provably unchanged — existing regression tests (alg-pinning, tampered-signature, cross-tenant) still pass alongside the new burst tests

## Task Commits

Each task was committed atomically:

1. **Task 1: Go SDK JWKS single-flight** - `6428d3c` (feat)
2. **Task 2: Java SDK JWKS single-flight** - `9bb83d4` (feat)
3. **Task 3: C# SDK JWKS single-flight** - `e256f88` (feat, includes the Google.Protobuf version-pin fix as an in-commit deviation)

**Plan metadata:** (this commit)

## Files Created/Modified
- `sdks/go/internal/jwks/verifier.go` - `refreshMu sync.Mutex` field; unknown-kid branch does fast CachedSet re-check under the lock before calling `cache.Refresh`
- `sdks/go/internal/jwks/verifier_test.go` - `TestJWKS_ConcurrentUnknownKidSingleFlight`: 8 concurrent goroutines, asserts exactly 1 fetch + cache reuse on a follow-up call
- `sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java` - `ReentrantLock refreshLock`; `selectKey()` split into a lock-free `selectFromCache` fast path + locked double-check + `RemoteJWKSet#get` fallback
- `sdks/java/src/test/java/io/axiam/sdk/internal/JwksVerifierTest.java` - `concurrentVerifyBurstTriggersExactlyOneJwksFetch`: 8 threads via `ExecutorService`+`CountDownLatch`, asserts exactly 1 fetch via a counting `MockWebServer` dispatcher
- `sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs` - `SemaphoreSlim(1,1) _fetchLock`; `EnsureFreshAsync` now double-checks `IsFresh()` before/after acquiring the lock; extracted `IsFresh(kid)` helper
- `sdks/csharp/Axiam.Sdk/Axiam.Sdk.csproj` - **deviation**: `Google.Protobuf` version corrected `2.80.0` -> `3.25.8` (see Deviations)
- `sdks/csharp/tests/Axiam.Sdk.Tests/JwksVerifierTests.cs` - `ConcurrentUnknownKidBurst_TriggersExactlyOneFetch`: 8 `Task`s via `Task.WhenAll` against a cold cache, asserts exactly 1 fetch, all 8 results valid, and cache reuse on a follow-up call; `FakeJwksHandler.RequestCount` made thread-safe via `Interlocked.Increment`

## Decisions Made
- Go: mutex wraps only the fetch/refresh decision (`CachedSet` re-check + `Refresh` call); `jws.Verify` calls happen outside the lock both before and after, per D-08's "never wrap crypto verification" constraint
- Java: chose `RemoteJWKSet#getCachedJWKSet()` (a genuinely non-network-calling accessor confirmed via `javap` bytecode inspection of the installed `nimbus-jose-jwt-10.7.jar`, no sources jar available) as the lock-free fast path, rather than assuming Nimbus's internal cache is safe to read/write concurrently
- C#: reused CS-01's `SemaphoreSlim(1,1)` primitive verbatim (not a new lock type) per the plan's explicit in-codebase-consistency instruction

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed Google.Protobuf version pin in Axiam.Sdk.csproj**
- **Found during:** Task 3 (C# JWKS single-flight verification)
- **Issue:** `Axiam.Sdk.csproj` pinned `<PackageReference Include="Google.Protobuf" Version="2.80.0" />` — a version that does not exist for that package (2.80.0 is `Grpc.Net.Client`/`Grpc.Tools`' own release numbering, not protobuf's, which is on the 3.x line). NuGet silently floor-resolved it to the ancient `3.0.0`, which is missing `IBufferMessage`/`WriteContext`/`ParseContext`/`UnknownFieldSet` used by the already-generated `axiam.v1` gRPC stubs — this broke the build of the ENTIRE `Axiam.Sdk` project (which `JwksVerifier.cs` is part of), so no test in the SDK — JWKS or otherwise — could run at all.
- **Fix:** Pinned to `3.25.8`, matching the exact protobuf-java runtime version this repo already uses (`sdks/java/pom.xml`'s `protobuf.version` property) for cross-SDK consistency.
- **Files modified:** `sdks/csharp/Axiam.Sdk/Axiam.Sdk.csproj`
- **Verification:** `Axiam.Sdk.csproj` now builds cleanly (`Axiam.Sdk -> .../Axiam.Sdk.dll`); confirmed via `dotnet build`.
- **Committed in:** `e256f88` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking build fix)
**Impact on plan:** Necessary for any C# verification to run at all; scoped to a single version-string correction, no other code changed. No scope creep — the plan's `files_modified` didn't list the `.csproj`, but leaving it broken would have made Task 3 unverifiable end-to-end.

## Issues Encountered

- **`dotnet` was not installed in this sandbox at all** (confirmed no `/usr/bin/dotnet`, no cached NuGet packages, no `~/.m2`-equivalent). Installed `dotnet-sdk-8.0` via `apt-get` (matches the SDK's `net8.0` `TargetFramework`) to make Task 3's verification runnable at all — a one-time sandbox environment setup, not a code change, and not something reverted (future plans in this sandbox will find `dotnet` already present).
- **Three pre-existing, unrelated compile failures were discovered in the C# test assembly** while proving Task 3's build: `GrpcAuthzClientTests.cs` (references a server-side gRPC stub that doesn't exist because the SDK's codegen is intentionally client-only), `AmqpConsumerTests.cs` (RabbitMQ.Client API version mismatch), and `SensitiveRedactionTests.cs` (a C# namespace-shadowing bug against the sibling `Axiam.Sdk.Grpc` namespace). A fourth, unrelated failure exists in the separate `Axiam.Sdk.AspNetCore` project (`IAuthorizationMiddlewareResultHandler` namespace typo). None of these are touched by this plan (scope: `JwksVerifier.cs`/`JwksVerifierTests.cs` only) — logged to [deferred-items.md](./deferred-items.md) rather than fixed, per the scope-boundary rule. Task 3's own work was verified correct by temporarily excluding the three unrelated broken files from compilation for the verification run only (via an uncommitted, reverted `<Compile Remove>` edit to `Axiam.Sdk.Tests.csproj`) — all 13 `JwksVerifierTests` tests pass (8 pre-existing test methods, including the 5-case `Theory`, plus the 1 new burst test = 13 total), and the new burst test specifically was re-run 5x standalone with no flakiness observed.
- This means the plan's literal Task 3 verification command (`cd sdks/csharp && dotnet test --filter JwksVerifier`, run from the SDK root against the full `.sln`) does **not** exit 0 as written, due to the four pre-existing unrelated failures above — not due to anything in this plan's diff. This is called out explicitly in the `coverage` D3 entry's `human_judgment: true` + `rationale` above so a human can confirm the narrower scoped verification is an acceptable substitute.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- PERF-03 is now closed for 3 of the 7 SDKs (Go, Java, C#) — Rust, Python, TypeScript, and PHP were out of this plan's scope (per the phase's wave breakdown) and remain to close PERF-03 fully.
- The C# SDK test suite has real, pre-existing gaps (documented in `deferred-items.md`) that should be remediated before the C# SDK's next release-readiness pass — recommend a small follow-up plan/task in a later phase (e.g. 28 or 30) to fix `GrpcAuthzClientTests.cs`'s missing server codegen, `AmqpConsumerTests.cs`'s `RabbitMQ.Client` 7.2.1 API drift, `SensitiveRedactionTests.cs`'s namespace shadowing, and `Axiam.Sdk.AspNetCore`'s `IAuthorizationMiddlewareResultHandler` namespace typo.
- `dotnet-sdk-8.0` is now installed in this sandbox — subsequent phases/plans touching the C# SDK will not need to repeat that setup step.

---
*Phase: 27-performance-load-hardening*
*Completed: 2026-07-05*

## Self-Check: PASSED

All 7 modified source files, both new planning docs, and all 4 commit hashes (`6428d3c`, `9bb83d4`, `e256f88`, `8068e61`) confirmed present on disk / in git history.
