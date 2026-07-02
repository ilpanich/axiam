---
phase: 21-c-sdk
plan: 01
subsystem: sdk
tags: [csharp, dotnet8, grpc, bouncycastle, sensitive, error-taxonomy, xunit, nuget]

# Dependency graph
requires:
  - phase: 15-sdk-foundation
    provides: "sdks/CONTRACT.md (§1-§10 binding cross-language contract), proto/axiam/v1/*.proto, sdks/csharp scaffold (csproj/README/LICENSE)"
  - phase: 20-java-sdk
    provides: "closest analog — single-jar+optional-framework packaging, redact-before-wrap NetworkError, generate-on-build+bundle-compiled codegen pattern"
provides:
  - "sdks/csharp/ two-package solution scaffold (Axiam.Sdk + Axiam.Sdk.AspNetCore) with Grpc.Tools build-time codegen wired to proto/axiam/v1/*.proto"
  - "Core token-safety vocabulary: Sensitive<T> (redacts on ToString + JSON) and TokenPair"
  - "Central error taxonomy: ErrorMapper/AuthError/AuthzError/NetworkError with a single redact-before-wrap construction path (CR-04 closed)"
  - "Wave 0 xUnit test harness + committed cross-SDK HMAC fixture + Ed25519/JWKS/JWT fixture helper, unblocking all Wave 2+ plans"
affects: [21-02, 21-03, 21-04, 21-05, 21-06, 21-07]

# Tech tracking
tech-stack:
  added: [Grpc.Net.Client 2.80.0, Grpc.Tools 2.80.0, Google.Protobuf 2.80.0, RabbitMQ.Client 7.2.1, BouncyCastle.Cryptography 2.6.2, Microsoft.Extensions.Http 8.0.1, Microsoft.Extensions.Logging.Abstractions 8.0.3, xunit 2.9.3, xunit.runner.visualstudio, Microsoft.NET.Test.Sdk, Moq 4.20.72]
  patterns: ["redact-before-wrap single-choke-point NetworkError (CR-04 carry-forward)", "open-generic JsonConverter attribute for Sensitive<T>", "Grpc.Tools MSBuild build-time codegen (the documented buf exception)"]

key-files:
  created:
    - sdks/csharp/Axiam.Sdk.AspNetCore/Axiam.Sdk.AspNetCore.csproj
    - sdks/csharp/Axiam.Sdk.sln
    - sdks/csharp/.gitignore
    - sdks/csharp/Axiam.Sdk/Core/Sensitive.cs
    - sdks/csharp/Axiam.Sdk/Core/ErrorMapper.cs
    - sdks/csharp/Axiam.Sdk/Core/NetworkError.cs
    - sdks/csharp/Axiam.Sdk/Core/AuthError.cs
    - sdks/csharp/Axiam.Sdk/Core/AuthzError.cs
    - sdks/csharp/Axiam.Sdk/Auth/TokenPair.cs
    - sdks/csharp/tests/Axiam.Sdk.Tests/Axiam.Sdk.Tests.csproj
    - sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/amqp_hmac_vectors.json
    - sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/JwksFixture.cs
    - sdks/csharp/tests/Axiam.Sdk.Tests/SensitiveRedactionTests.cs
  modified:
    - sdks/csharp/Axiam.Sdk/Axiam.Sdk.csproj

key-decisions:
  - "Google.Protobuf pinned to 2.80.0 (matching Grpc.Net.Client/Grpc.Tools' 2.80.x line per 21-RESEARCH.md's Standard Stack guidance) since `dotnet restore` is unavailable in this execution environment to resolve-then-lock the exact compatible patch per Open Question 2's literal instruction; CI's `dotnet restore` will surface a clear conflict if a different patch is required."
  - "Sensitive<T> uses the open-generic JsonConverter attribute form (`typeof(SensitiveJsonConverter<>)`) rather than RESEARCH.md's draft closed-to-string form, so redaction works for any T (not just string) without changing the documented behavior."
  - "Added [assembly: InternalsVisibleTo(\"Axiam.Sdk.Tests\")] to Sensitive.cs so SensitiveRedactionTests can exercise the internal Sensitive.Of<T> factory/Reveal() directly, without widening any public API surface."

requirements-completed: [CS-01]

coverage:
  - id: D1
    description: "Two-package net8.0 solution (Axiam.Sdk + Axiam.Sdk.AspNetCore) with Grpc.Tools build-time gRPC codegen wired to proto/axiam/v1/*.proto (D-01, D-03, D-05)"
    requirement: "CS-01"
    verification:
      - kind: other
        ref: "manual static review — dotnet unavailable locally; dotnet build sdks/csharp/Axiam.Sdk -c Release && dotnet build sdks/csharp/Axiam.Sdk.AspNetCore -c Release deferred to CI (.github/workflows/sdk-ci-csharp.yml, plan 21-07)"
        status: unknown
    human_judgment: true
    rationale: "dotnet SDK/CLI is not installed in this execution environment (documented constraint); build/test/pack validation runs in the per-SDK CI workflow built in plan 21-07. Source-level assertions (proto glob, GrpcServices=Client, pinned versions, obj/ gitignored, buf.gen.yaml untouched) were manually verified via grep/git check-ignore."
  - id: D2
    description: "Sensitive<T> redacts on ToString + System.Text.Json (write-only converter); ErrorMapper/NetworkError/AuthError/AuthzError implement a single redact-before-wrap construction path closing the CR-04 leak class"
    requirement: "CS-01"
    verification:
      - kind: unit
        ref: "sdks/csharp/tests/Axiam.Sdk.Tests/SensitiveRedactionTests.cs#NetworkErrorNeverLeaksRawSetCookieToken, #NetworkErrorRetainsNonSensitiveControlHeader, #HttpStatusMappingMatchesContract, #GrpcStatusMappingMatchesContract, #SensitiveToStringAlwaysRedacts, #SensitiveJsonSerializationAlwaysRedacts, #SensitiveJsonDeserializationIsUnsupported"
        status: unknown
    human_judgment: true
    rationale: "dotnet test cannot run locally (documented constraint). Test logic was manually traced line-by-line against ErrorMapper/NetworkError/Sensitive<T> source to confirm expected behavior; execution and pass/fail confirmation deferred to CI (plan 21-07)."
  - id: D3
    description: "xUnit test project scaffold + Rust-signed HMAC fixture (byte-identical to the Java sibling SDK) + BouncyCastle Ed25519/JWKS/JWT fixture helper committed for Wave 0"
    requirement: "CS-01"
    verification:
      - kind: other
        ref: "git diff --no-index sdks/java/src/test/resources/amqp_hmac_vectors.json sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/amqp_hmac_vectors.json (empty — confirmed byte-identical)"
        status: pass
      - kind: other
        ref: "manual static review of JwksFixture.cs — confirmed it calls Ed25519Signer.Init(forSigning: true, ...) directly (BouncyCastle signing path), independent of any SDK verifier (none exists yet)"
        status: pass
    human_judgment: false

# Metrics
duration: 35min
completed: 2026-07-02
status: complete
---

# Phase 21 Plan 01: C# SDK Foundation Summary

**Two-package net8.0 C# SDK solution (`Axiam.Sdk` + `Axiam.Sdk.AspNetCore`) with Grpc.Tools build-time codegen, a redact-before-wrap error taxonomy closing the CR-04 leak class, and the Wave 0 xUnit harness + cross-SDK HMAC/JWKS fixtures.**

## Performance

- **Duration:** 35 min
- **Started:** 2026-07-02T12:10:00Z
- **Completed:** 2026-07-02T12:45:00Z
- **Tasks:** 3
- **Files modified:** 14 (13 created, 1 modified)

## Accomplishments
- Extended the existing `Axiam.Sdk.csproj` scaffold with all pinned CS-01 dependencies and `Grpc.Tools` MSBuild build-time gRPC codegen against `proto/axiam/v1/*.proto` (client-only) — the documented C# exception to the repo-wide `buf` pipeline
- Added the `Axiam.Sdk.AspNetCore` companion package (ASP.NET Core `FrameworkReference` + `ProjectReference` to core), the two-package `Axiam.Sdk.sln`, and `sdks/csharp/.gitignore` (verified `obj/` is git-ignored)
- Implemented `Sensitive<T>` (internal-only construction/read, `ToString()`/JSON always emit `[SENSITIVE]`) and `TokenPair`
- Implemented the central `ErrorMapper`/`NetworkError`/`AuthError`/`AuthzError` taxonomy with a single redact-before-wrap construction path — no code path can build a `NetworkError` from a raw, unredacted `HttpResponseMessage`
- Stood up the `Axiam.Sdk.Tests` xUnit project, copied the Java sibling SDK's Rust-signed HMAC fixture byte-for-byte, built a real BouncyCastle Ed25519/JWKS/JWT fixture helper, and wrote the non-vacuous `SensitiveRedactionTests` CR-04 regression suite

## Task Commits

Each task was committed atomically:

1. **Task 1: Two-package solution scaffold + Grpc.Tools MSBuild codegen (D-01, D-03, D-05)** - `2b4edf0` (feat)
2. **Task 2: Core primitives — Sensitive<T> + central error taxonomy (D-12, §2, §7, CR-04)** - `94315e8` (feat)
3. **Task 3: xUnit test project + cross-SDK fixtures + SensitiveRedactionTests (Wave 0, CR-04)** - `620e89c` (test)

**Plan metadata:** pending (docs: complete plan, this commit)

## Files Created/Modified
- `sdks/csharp/Axiam.Sdk/Axiam.Sdk.csproj` - extended with pinned deps, Grpc.Tools codegen, Deterministic/doc-gen build flags, D-02 divergence comment
- `sdks/csharp/Axiam.Sdk.AspNetCore/Axiam.Sdk.AspNetCore.csproj` - new companion package (ASP.NET Core FrameworkReference + core ProjectReference)
- `sdks/csharp/Axiam.Sdk.sln` - two packages + test project
- `sdks/csharp/.gitignore` - bin/, obj/, *.nupkg/*.snupkg, IDE files
- `sdks/csharp/Axiam.Sdk/Core/Sensitive.cs` - `Sensitive<T>`, `Sensitive.Of<T>`, `SensitiveJsonConverter<T>`, `InternalsVisibleTo("Axiam.Sdk.Tests")`
- `sdks/csharp/Axiam.Sdk/Core/ErrorMapper.cs` - HTTP + gRPC status → error class single source of truth
- `sdks/csharp/Axiam.Sdk/Core/NetworkError.cs` - single redact-before-wrap construction path (`FromResponse`/`FromException`)
- `sdks/csharp/Axiam.Sdk/Core/AuthError.cs` / `AuthzError.cs` - typed error classes
- `sdks/csharp/Axiam.Sdk/Auth/TokenPair.cs` - `record TokenPair(Sensitive<string>, Sensitive<string>, DateTimeOffset)`
- `sdks/csharp/tests/Axiam.Sdk.Tests/Axiam.Sdk.Tests.csproj` - xUnit + Moq test project, Fixtures/** glob
- `sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/amqp_hmac_vectors.json` - byte-identical copy of the Java sibling's Rust-signed fixture
- `sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/JwksFixture.cs` - BouncyCastle Ed25519 keypair + JWKS doc + JWT signer helper
- `sdks/csharp/tests/Axiam.Sdk.Tests/SensitiveRedactionTests.cs` - CR-04 regression + HTTP/gRPC status mapping + `Sensitive<T>` round-trip tests

## Decisions Made
- **Google.Protobuf pinned to 2.80.0** (matching the `Grpc.Net.Client`/`Grpc.Tools` 2.80.x line per 21-RESEARCH.md's Standard Stack table) rather than running `dotnet add package` to resolve-then-lock (Open Question 2's literal instruction) — `dotnet` is unavailable in this execution environment. CI's `dotnet restore` will surface a clear version conflict if a different patch is actually required; low risk per the plan's own environment-availability note.
- **`Sensitive<T>` uses the open-generic `[JsonConverter(typeof(SensitiveJsonConverter<>))]` attribute form**, not RESEARCH.md's draft (which hardcoded `SensitiveJsonConverter<string>` on the generic `Sensitive<T>` declaration — a mismatch that would only work correctly for `T=string`). The open-generic form is the officially documented System.Text.Json pattern for a generic converter matching a generic type, and generalizes correctly for any `T` the SDK later wraps.
- **`AuthError`/`AuthzError`/`NetworkError` follow the Java/Go sibling "unchecked, no live-response overload" shape**: `NetworkError`'s constructor is private; the only two public factories (`FromResponse`, `FromException`) never store a live `HttpResponseMessage` — only a pre-sanitized string survives.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `InternalsVisibleTo` so the test assembly can exercise `Sensitive<T>`'s internal surface**
- **Found during:** Task 3 (writing `SensitiveRedactionTests.cs`)
- **Issue:** The plan's Task 2 action explicitly specifies `Sensitive.Of<T>(T)` as an *internal* factory and the constructor as internal-only (CONTRACT.md §7 invariant: never a public getter/constructor). The Wave 0 test project (`Axiam.Sdk.Tests`) is a separate assembly, so it cannot call an internal member without an explicit grant — without this, `SensitiveRedactionTests.cs` would fail to compile.
- **Fix:** Added `[assembly: InternalsVisibleTo("Axiam.Sdk.Tests")]` to `Core/Sensitive.cs` (the file that already declares the internal members it grants access to).
- **Files modified:** `sdks/csharp/Axiam.Sdk/Core/Sensitive.cs`
- **Verification:** Manually traced the attribute against the test assembly name declared in `Axiam.Sdk.Tests.csproj` (defaults to the project file name, `Axiam.Sdk.Tests`) — matches exactly. No public API surface was widened; `Reveal()` and the constructor remain internal to everything except this one named test assembly.
- **Committed in:** `620e89c` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary for the Wave 0 test project to compile against the plan's explicitly-internal `Sensitive<T>` surface. No scope creep — no new public API was added.

## Issues Encountered

**`dotnet` SDK/CLI is not installed in this execution environment** (documented constraint in the executor's task prompt). All three tasks' `<automated>` verify commands (`dotnet build`, `dotnet test`) could not be executed locally. Per the documented protocol:
- All source code, test code, and fixtures were written exactly as specified and committed — they are real deliverables that will run in the per-SDK CI workflow (`.github/workflows/sdk-ci-csharp.yml`, built in plan 21-07).
- Every task's acceptance criteria that could be verified via static inspection (grep for exact version strings/glob patterns, `git check-ignore` for `obj/`, `git diff --no-index` for byte-identical fixture parity, manual line-by-line trace of test assertions against source) was verified and is recorded in the `coverage:` block above.
- Build/test/pack execution and pass/fail confirmation are deferred to CI and flagged `human_judgment: true` in the coverage block where automated status is `unknown` — this is NOT a Self-Check failure; it reflects the documented environment constraint, not an authoring gap.

## Known Stubs

None. No hardcoded empty values, placeholder text, or unwired data sources were introduced — every file in this plan is either a real, complete implementation (`Sensitive<T>`, `ErrorMapper`, `NetworkError`, `AuthError`, `AuthzError`, `TokenPair`) or a genuine test/fixture artifact.

## Threat Flags

None. All new surface (csproj package references, `NetworkError`'s header-redaction choke point, the xUnit test project) matches the plan's own `<threat_model>` register (T-21-01, T-21-SC, T-21-02) exactly — no new trust boundary or attack surface was introduced beyond what the plan already threat-modeled.

## User Setup Required

None - no external service configuration required. (NuGet publish credentials are out of scope for this Wave 0 plan; see plan 21-07/D-04.)

## Next Phase Readiness

- The two-package solution, `Sensitive<T>`/error-taxonomy vocabulary, and Wave 0 test harness + fixtures are all in place — Wave 2+ plans (REST/gRPC/AMQP/JWKS/ASP.NET Core middleware) can now build directly on this foundation without re-deriving any of it.
- `sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/amqp_hmac_vectors.json` is ready for 21-02's HMAC verify-before-handler tests; `Fixtures/JwksFixture.cs` is ready for the JWKS/JWT verification plan's tests.
- **Blocker/concern for the maintainer:** `dotnet build`/`dotnet test`/`dotnet pack` have not been executed against this code in any environment yet (no `dotnet` CLI was available during Phase 21's Wave 0 authoring). The first CI run in plan 21-07 (or an earlier ad hoc `dotnet restore` by a maintainer with local tooling) should be treated as the first real compile/test signal for this phase and may surface a small number of fixes (e.g. the `Google.Protobuf` version pin, exact `Grpc.Tools`-generated stub namespace/type names referenced by later plans).

---
*Phase: 21-c-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 14 created/modified files confirmed present on disk; all 4 task/summary commit hashes (2b4edf0, 94315e8, 620e89c, 014289d) confirmed in git log.
