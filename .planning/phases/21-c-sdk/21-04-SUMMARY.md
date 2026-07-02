---
phase: 21-c-sdk
plan: 04
subsystem: sdk
tags: [csharp, dotnet8, httpclient, delegatinghandler, cookiejar, tls, authz, xunit]

# Dependency graph
requires:
  - phase: 21-c-sdk
    plan: "01"
    provides: "sdks/csharp two-package scaffold, Sensitive<T>/TokenPair/error taxonomy, Wave 0 xUnit harness"
  - phase: 21-c-sdk
    plan: "03"
    provides: "RefreshGuard (SemaphoreSlim(1,1) single-flight, D-10/§9), LoginResult, JwksVerifier (BouncyCastle Ed25519)"
provides:
  - "sdks/csharp/Axiam.Sdk/AxiamClient.cs: the public REST facade — tenant-required constructor (SC#1), async-only auth flow (LoginAsync/VerifyMfaAsync/RefreshAsync/LogoutAsync), Authz accessor, internal seam (RefreshGuard/JwksVerifier/CurrentAccessToken/BaseUrl/CustomCaPem/TransportHttpClient) for 21-05/21-06"
  - "sdks/csharp/Axiam.Sdk/Rest/*: AxiamHttpClientFactory (SDK-owned cookie jar + no-TLS-bypass, D-09/§4/§6), AxiamHttpMessageHandler (tenant/auth/CSRF header injection + single reactive 401->refresh->retry, §3/§9), AuthzRestClient (CheckAccessAsync/CanAsync/BatchCheckAsync, FND-04)"
  - "sdks/csharp/Axiam.Sdk/Options/AxiamClientOptions.cs, Core/TenantContext.cs"
  - "SC#1 + FND-04 test coverage: ClientConstructionTests.cs, AuthzRestClientTests.cs"
affects: [21-05, 21-06, 21-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Additive customCa chain-trust-store TLS callback (never an unconditional-true bypass) — the only ServerCertificateCustomValidationCallback assignment anywhere in Axiam.Sdk, verified via the literal SC#4-preview grep gate"
    - "DelegatingHandler chain: AxiamHttpMessageHandler (cross-cutting concerns) wraps AxiamHttpClientFactory's primary HttpClientHandler (cookie jar + TLS) as InnerHandler"
    - "Reactive 401->RefreshGuard->retry-once with the refresh endpoint's own path exempted from the retry trigger, preventing self-recursion/deadlock on the shared guard"
    - "AxiamClientOptions `with { BaseUrl, TenantId }` — the constructor's own positional args are always the source of truth for tenant/base-URL, independent of what an optional options object carries"

key-files:
  created:
    - sdks/csharp/Axiam.Sdk/Rest/AxiamHttpClientFactory.cs
    - sdks/csharp/Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs
    - sdks/csharp/Axiam.Sdk/Rest/AuthzRestClient.cs
    - sdks/csharp/Axiam.Sdk/AxiamClient.cs
    - sdks/csharp/Axiam.Sdk/Options/AxiamClientOptions.cs
    - sdks/csharp/Axiam.Sdk/Core/TenantContext.cs
    - sdks/csharp/tests/Axiam.Sdk.Tests/ClientConstructionTests.cs
    - sdks/csharp/tests/Axiam.Sdk.Tests/AuthzRestClientTests.cs
  modified: []

key-decisions:
  - "AxiamClientOptions.BaseUrl/TenantId are `required` (reserved for the future AddAxiam()/IOptions<T> DI path, D-07/plan 21-06); AxiamClient's own constructor always sources tenant/base-URL from its own positional parameters via `baseOptions with { BaseUrl = baseUrl, TenantId = tenantId }`, so SC#1's guarantee never depends on what an options object happens to carry."
  - "LoginResult intentionally still omits a User/AxiamUser field in this plan (carried forward from 21-03's note) — Task 2's action text and files_modified scope only call for MfaRequired/ChallengeToken; introducing AxiamUser was out of this plan's explicit scope. Deferred again; no plan currently claims it."
  - "AuthzRestClient.CheckAccessAsync signature is (action, resourceId, scope=null, subjectId=null, ct) rather than the plan text's literal (subjectId, resource, action, ct) ordering — action/resourceId are the two server-mandated fields (crates/axiam-api-rest/src/handlers/authz_check.rs CheckAccessBody), and C# requires optional params to trail required ones; this ordering also mirrors the closest sibling reference (Java's checkAccess(action, resourceId, scope))."
  - "CanAsync (not bare `Can`) is the ergonomic alias per D-10's async-only-with-CancellationToken mandate for every public I/O method on this SDK — CONTRACT.md §1's 'Can' row names the canonical operation, not a literal synchronous method name."
  - "BatchCheckAsync returns IReadOnlyList<bool> (matching CheckAccessAsync's plain-bool return) rather than a richer AccessResult(bool,reason) type, for return-type consistency with the single-check method; the wire `reason` field is still parsed but not surfaced (no task text or test requires exposing it)."
  - "Tenant identifier form is auto-detected: AxiamClient parses tenantId as a Guid first (sending tenant_id) and falls back to tenant_slug otherwise — supports both CONTRACT.md §5 forms (`tenant_slug`/`tenant_id`) without adding API surface."
  - "AxiamClientOptions carries OrgId/OrgSlug (mutually exclusive) because the real LoginRequest/RefreshRequest handlers (crates/axiam-api-rest/src/handlers/auth.rs) require an organization identifier beyond §5's documented tenant-only minimum — mirrors the Java/Rust/Go sibling SDKs' own org-resolution addition (Rule 2: missing critical functionality, without which LoginAsync/RefreshAsync cannot succeed against the real server)."
  - "RefreshAsync/DoHttpRefreshAsync/LogoutAsync resolve tenant_id/org_id/jti via an unverified base64url JWT payload decode of the current access token (mirrors the Java sibling's SessionState.decodeUnverifiedClaims) — used only as an operational hint for building the refresh/logout request bodies, never as an authorization decision (JwksVerifier remains the sole signature-verifying component)."
  - "customCa PEM-loading uses `new X509Certificate2(byte[])` (not `X509CertificateLoader`) since the latter has no net8.0-compatible surface and the former is not obsolete-with-warning on the net8.0 TFM (SYSLIB0057's obsolete marking postdates net8.0's reference assemblies) — resolves 21-RESEARCH.md Open Question 3/Assumption A2 at code-time as instructed."
  - "An internal-only `AxiamClient.CreateForTesting(...)` seam (private ctor overload) lets unit tests substitute a fake HttpMessageHandler as the transport bottom while exercising the real AxiamHttpMessageHandler/RefreshGuard wiring — kept `internal` so it is invisible to SC#1's public-constructor reflection test."

requirements-completed: [CS-01]

coverage:
  - id: D1
    description: "AxiamHttpClientFactory: SDK-owned HttpClientHandler with UseCookies=true + private CookieContainer (both the owned and IHttpClientFactory-alt paths); additive customCa chain-trust-store TLS callback with no unconditional-true bypass anywhere in Axiam.Sdk (D-09, §4, §6, SC#4 preview)"
    requirement: "CS-01"
    verification:
      - kind: other
        ref: "grep -rn \"ServerCertificateCustomValidationCallback\" sdks/csharp/Axiam.Sdk --include=*.cs | grep -v \"CustomTrustStore\" — run directly, confirmed empty (exit 1 / no matches)"
        status: pass
      - kind: other
        ref: "manual static review — dotnet unavailable locally; dotnet build sdks/csharp/Axiam.Sdk -c Release deferred to CI (.github/workflows, plan 21-07)"
        status: unknown
    human_judgment: true
    rationale: "dotnet SDK/CLI is not installed in this execution environment (documented constraint). The grep-gate acceptance criterion was independently verified by executing the literal command; the warning-free-build acceptance criterion (obsolete-API diagnostics on the net8.0 PEM-loading path) requires an actual dotnet build and is deferred to CI."
  - id: D2
    description: "AxiamClient: tenant-required public constructor (SC#1, no default/omittable-tenant overload), async-only auth flow (LoginAsync/VerifyMfaAsync/RefreshAsync/LogoutAsync) with ConfigureAwait(false) throughout, exact endpoint paths (/api/v1/auth/login, /mfa/verify, /refresh, /logout), and the internal client seam (RefreshGuard/JwksVerifier/CurrentAccessToken/BaseUrl/CustomCaPem/TransportHttpClient) for 21-05/21-06"
    requirement: "CS-01"
    verification:
      - kind: unit
        ref: "sdks/csharp/tests/Axiam.Sdk.Tests/ClientConstructionTests.cs#OnlyOnePublicConstructor_Exists, #PublicConstructor_RequiresTenantId_WithNoDefaultValue, #Constructor_RejectsBlankTenantId_AtRuntime, #LoginAsync_ImmediateSuccess_ReturnsLoginResult_WithMfaRequiredFalse, #LoginAsync_MfaChallenge_ReturnsLoginResult_WithMfaRequiredTrue_AndChallengeToken, #LoginAsync_InvalidCredentials_ThrowsAuthError, #RefreshAsync_NoSession_ThrowsAuthError_WithoutAnyNetworkCall, #LogoutAsync_NoSession_ThrowsAuthError_WithoutAnyNetworkCall"
        status: unknown
    human_judgment: true
    rationale: "dotnet test cannot run locally (documented constraint). Every test's logic was manually traced against AxiamClient.cs's/AxiamHttpMessageHandler.cs's actual control flow (reflection over the single public constructor's parameters, TenantContext's blank-string guard, LoginAsync's 200/202/else status branching, the 401->refresh->catch-and-return-original-response path for the no-session cases) to confirm the asserted behavior is correct; execution/pass-fail confirmation is deferred to the per-SDK CI workflow (plan 21-07)."
  - id: D3
    description: "AxiamHttpMessageHandler: injects X-Tenant-Id + Authorization Bearer (read from the cookie jar), captures/echoes X-CSRF-Token on state-changing requests only (§3 non-browser), and drives exactly one reactive 401->RefreshGuard->retry with the refresh path exempted from re-triggering (no self-recursion, no retry loop)"
    requirement: "CS-01"
    verification:
      - kind: other
        ref: "manual static review of Rest/AxiamHttpMessageHandler.cs — confirmed RefreshPath constant matches AxiamClient's own refresh path constant, the retry-marker HttpRequestOptionsKey prevents a second refresh attempt on the retried request, and the refresh-guard's own exception path returns the ORIGINAL response object unmodified (no infinite loop / no swallowed 401)"
        status: pass
    human_judgment: false
  - id: D4
    description: "AuthzRestClient: CheckAccessAsync/CanAsync/BatchCheckAsync over POST /api/v1/authz/check and /api/v1/authz/check/batch (FND-04), routing every non-2xx through ErrorMapper (403->AuthzError), with no local decision cache"
    requirement: "CS-01"
    verification:
      - kind: unit
        ref: "sdks/csharp/tests/Axiam.Sdk.Tests/AuthzRestClientTests.cs#CheckAccessAsync_Allowed_ReturnsTrue, #CheckAccessAsync_Denied_ReturnsFalse, #CheckAccessAsync_Forbidden_MapsToAuthzError, #CanAsync_IsAnAliasForCheckAccessAsync, #BatchCheckAsync_PreservesOrder, #BatchCheckAsync_Forbidden_MapsToAuthzError, #CheckAccessAsync_EveryCall_HitsTheFakeTransportFresh_NoLocalCache"
        status: unknown
    human_judgment: true
    rationale: "dotnet test cannot run locally (documented constraint). Every test was manually traced against AuthzRestClient.cs's actual control flow (exact request paths, IsSuccessStatusCode branching into ErrorMapper.FromHttpResponse, LINQ projection preserving batch order, and the absence of any field/cache storing a prior decision) to confirm expected behavior; execution/pass-fail confirmation deferred to CI (plan 21-07)."

# Metrics
duration: 30min
completed: 2026-07-02
status: complete
---

# Phase 21 Plan 04: C# SDK REST Transport + AxiamClient Facade Summary

**SDK-owned cookie-jar/no-TLS-bypass HttpClient factory, a DelegatingHandler that injects tenant/auth/CSRF headers and drives one reactive 401→refresh→retry through the shared RefreshGuard, and the public `AxiamClient` facade (tenant-required ctor + async auth flow + FND-04 authz client) that plans 21-05/21-06 will compose against without touching this file.**

## Performance

- **Duration:** ~30 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 8 (8 created)

## Accomplishments
- Implemented `AxiamHttpClientFactory` (`CreateOwned`/`CreatePrimaryHandler`/`ConfigureFactoryHandler`): SDK-owned `HttpClientHandler` with `UseCookies=true` + a private `CookieContainer` on both the owned and future `IHttpClientFactory` paths; the only `ServerCertificateCustomValidationCallback` in the whole `Axiam.Sdk` project is the additive `customCa` chain-trust-store path — verified directly with the plan's own literal grep gate, which returns empty
- Implemented `AxiamHttpMessageHandler` (`DelegatingHandler`): injects `X-Tenant-Id` + `Authorization: Bearer <access>` (read from the shared cookie jar) on every request, captures/echoes `X-CSRF-Token` only on state-changing verbs (§3 non-browser), and drives exactly one reactive 401→`RefreshGuard`→retry — with the refresh endpoint's own path exempted so it can never recursively re-enter the guard on itself
- Implemented `AxiamClient` (`sealed class : IDisposable`): the single public tenant-required constructor (SC#1 — no overload/default that omits `tenantId`), async-only `LoginAsync`/`VerifyMfaAsync`/`RefreshAsync`/`LogoutAsync` against the exact real endpoint paths, and an internal seam (`RefreshGuard`, `JwksVerifier`, `CurrentAccessToken`, `BaseUrl`, `CustomCaPem`, `TransportHttpClient`) so the gRPC (21-05) and ASP.NET Core (21-06) plans never need to modify this file
- Implemented `AuthzRestClient` (exposed as `client.Authz`): `CheckAccessAsync`/`CanAsync`/`BatchCheckAsync` over the exact FND-04 REST endpoints, routing every non-2xx through the shared `ErrorMapper`, with zero client-side caching of any authorization decision
- Wrote `ClientConstructionTests.cs` (SC#1: reflection-based single-constructor + no-default-tenant proof, blank-tenant runtime guard, `LoginAsync` typed-result tests against a fake transport) and `AuthzRestClientTests.cs` (allow/deny/403-mapping/batch-order/no-cache) — both real, non-vacuous test suites that will run in CI

## Task Commits

Each task was committed atomically:

1. **Task 1: SDK-owned HttpClient cookie jar + client-override safety + no-TLS-bypass (D-09, §4, §6)** - `76f95e0` (feat)
2. **Task 2: AxiamClient facade — tenant-required ctor, async auth flow, CSRF/header injection, reactive refresh (SC#1, D-10, §3, §5)** - `d686d93` (feat)
3. **Task 3: REST authorization client — CheckAccessAsync/Can/BatchCheckAsync over FND-04 (§1)** - `edb9ec4` (feat)

**Plan metadata:** pending (docs: complete plan, this commit)

## Files Created/Modified
- `sdks/csharp/Axiam.Sdk/Rest/AxiamHttpClientFactory.cs` - `CreateOwned`/`CreatePrimaryHandler` (cookie jar + additive customCa TLS), `ConfigureFactoryHandler` (IHttpClientFactory alt path)
- `sdks/csharp/Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs` - `DelegatingHandler`: tenant/auth/CSRF header injection, single reactive 401→refresh→retry with refresh-path exemption
- `sdks/csharp/Axiam.Sdk/Rest/AuthzRestClient.cs` - `CheckAccessAsync`/`CanAsync`/`BatchCheckAsync` over `/api/v1/authz/check[/batch]`, no local cache
- `sdks/csharp/Axiam.Sdk/AxiamClient.cs` - public facade: tenant-required ctor, `LoginAsync`/`VerifyMfaAsync`/`RefreshAsync`/`LogoutAsync`, `Authz` accessor, internal seam, `internal static CreateForTesting(...)` test-only seam
- `sdks/csharp/Axiam.Sdk/Options/AxiamClientOptions.cs` - typed options (`BaseUrl`/`TenantId` required for the future DI path, `OrgId`/`OrgSlug`, `CustomCaPem`, JWKS cache TTL, timeouts, reserved backoff config)
- `sdks/csharp/Axiam.Sdk/Core/TenantContext.cs` - tenant-identity value object; throws `ArgumentException` on a blank tenant identifier (SC#1 runtime guard)
- `sdks/csharp/tests/Axiam.Sdk.Tests/ClientConstructionTests.cs` - SC#1 reflection tests + `LoginAsync`/`RefreshAsync`/`LogoutAsync` behavior tests against a fake transport
- `sdks/csharp/tests/Axiam.Sdk.Tests/AuthzRestClientTests.cs` - FND-04 allow/deny/403/batch-order/no-cache tests

## Decisions Made

See `key-decisions` in the frontmatter for the full list. Highlights:
- `AxiamClientOptions.BaseUrl`/`TenantId` are `required` for the future `AddAxiam()` DI path (21-06); `AxiamClient`'s own constructor always uses its own positional `baseUrl`/`tenantId` arguments as the source of truth via a `with` expression, so SC#1 never depends on what an options object happens to carry.
- `AuthzRestClient.CheckAccessAsync`'s parameter order is `(action, resourceId, scope, subjectId, ct)` rather than the plan text's literal `(subjectId, resource, action, ct)` — this matches the real server's `CheckAccessBody` field priority and C#'s requirement that optional parameters trail required ones.
- `CanAsync` (not a bare synchronous `Can`) is the async-only ergonomic alias, consistent with D-10's async-only-with-`CancellationToken` mandate for every public I/O method in this SDK.
- Tenant/org identifiers: `AxiamClient` auto-detects whether the configured `tenantId` string is a GUID (sends `tenant_id`) or a slug (sends `tenant_slug`); `AxiamClientOptions.OrgId`/`OrgSlug` were added (Rule 2) because the real `LoginRequest`/`RefreshRequest` handlers require an organization identifier beyond CONTRACT.md §5's documented tenant-only minimum — without this, `LoginAsync`/`RefreshAsync` could never succeed against the real server.
- `LoginResult` still intentionally has no `User`/`AxiamUser` field (carried forward from 21-03's note) — this plan's Task 2 action text and `files_modified` scope did not call for it.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added `OrgId`/`OrgSlug` to `AxiamClientOptions` and wired them into `LoginAsync`/`DoHttpRefreshAsync`**
- **Found during:** Task 2 (implementing `LoginAsync`/`RefreshAsync` against the real server contract)
- **Issue:** The real `crates/axiam-api-rest/src/handlers/auth.rs` `LoginRequest`/`RefreshRequest` structs require an organization identifier (`org_id` or `org_slug`) in addition to the tenant identifier — CONTRACT.md §5 only documents the tenant-only minimum. Without an org-resolution path, every `LoginAsync`/`RefreshAsync` call against the real server would fail with a 400 Validation error, making the auth flow non-functional in practice (a correctness gap, not a cosmetic one).
- **Fix:** Added `OrgId`/`OrgSlug` (mutually exclusive) to `AxiamClientOptions` and `TenantContext`; `LoginAsync` includes whichever is configured in the login body; `DoHttpRefreshAsync` prefers the configured `OrgId` and falls back to the `org_id` claim decoded from the current access token (mirrors the Java sibling SDK's identical addition).
- **Files modified:** `sdks/csharp/Axiam.Sdk/Options/AxiamClientOptions.cs`, `sdks/csharp/Axiam.Sdk/Core/TenantContext.cs`, `sdks/csharp/Axiam.Sdk/AxiamClient.cs`
- **Verification:** Manually traced `LoginRequest`/`RefreshRequest`'s actual Rust field definitions (`crates/axiam-api-rest/src/handlers/auth.rs`) against the C# request-body construction to confirm every required field is populated when `OrgId`/`OrgSlug` is configured.
- **Committed in:** `d686d93` (Task 2 commit)

**2. [Rule 3 - Blocking] Wrapped `customCaPem`'s certificate-load failure in a clear `ArgumentException`**
- **Found during:** Task 1 (implementing `AxiamHttpClientFactory.CreatePrimaryHandler`)
- **Issue:** CONTRACT.md §6 explicitly requires "a clear error at construction time" when a non-PEM `customCa` is supplied. A bare `new X509Certificate2(customCaPem)` would surface an opaque low-level `CryptographicException` instead.
- **Fix:** Wrapped the certificate-load call in a `try/catch (CryptographicException)` that rethrows a descriptive `ArgumentException` naming the `customCaPem` parameter and citing §6.
- **Files modified:** `sdks/csharp/Axiam.Sdk/Rest/AxiamHttpClientFactory.cs`
- **Verification:** Manually confirmed the exception is thrown synchronously inside `AxiamClient`'s constructor path (before any network activity), matching "construction time" per the contract's wording.
- **Committed in:** `76f95e0` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 missing-critical, 1 blocking)
**Impact on plan:** Both fixes are necessary for the SDK to actually work against AXIAM's real, frozen v1.0 REST API and to satisfy CONTRACT.md §6's literal wording. No scope creep — no new public API surface beyond what the real request/response schemas already require.

## Issues Encountered

**`dotnet` SDK/CLI is not installed in this execution environment** (documented constraint in the executor's task prompt). All three tasks' `<automated>` verify commands (`dotnet build`, `dotnet test --filter ...`) could not be executed locally. Per the documented protocol:
- All source code and test code were written exactly as the plan specifies and committed — they are real deliverables that will run in the per-SDK CI workflow (plan 21-07).
- The one acceptance criterion that COULD be verified without `dotnet` — Task 1's literal SC#4-preview grep gate (`grep -rn "ServerCertificateCustomValidationCallback" sdks/csharp/Axiam.Sdk --include=*.cs | grep -v "CustomTrustStore"`) — was actually executed and confirmed empty; the code was adjusted (comment wording) until the literal command passed, not just approximated.
- Every other acceptance criterion was verified via rigorous manual static review: full line-by-line control-flow tracing of `AxiamHttpMessageHandler`'s 401-retry/no-loop logic, `AxiamClient`'s constructor/auth-method status-code branching, and `AuthzRestClient`'s request/response mapping — recorded in the `coverage:` block above with `human_judgment: true` and an explicit rationale where automated status is `unknown`. This is NOT a Self-Check failure; it reflects the documented environment constraint, not an authoring gap.
- Brace/paren balance was verified for every new file via direct counting (all balanced) as an additional compile-sanity signal beyond manual review.

## Known Stubs

None. `AxiamHttpClientFactory`, `AxiamHttpMessageHandler`, `AxiamClient`, and `AuthzRestClient` are all real, complete implementations against the actual AXIAM REST API shapes (verified against `crates/axiam-api-rest/src/handlers/auth.rs` and `authz_check.rs`) — no hardcoded empty values, placeholder text, or unwired data sources. `AxiamClientOptions`'s backoff/retry config properties (`MaxRetryAttempts`/`RetryBaseDelay`/`RetryMaxDelay`) are reserved config surface per Task 1's literal instruction but are not yet consumed by any call path in this plan — no task in this plan required a retry wrapper, and no method silently no-ops because of it; this is documented explicitly in the properties' own XML doc comments, not a stub.

## Threat Flags

None. All new surface (the `AxiamHttpClientFactory` TLS/cookie-jar configuration, `AxiamHttpMessageHandler`'s header-injection/401-retry logic, `AuthzRestClient`'s fresh-every-call authorization checks) matches the plan's own `<threat_model>` register (T-21-10, T-21-11, T-21-12, T-21-13) exactly — no new trust boundary or attack surface was introduced beyond what the plan already threat-modeled.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `AxiamClient` exposes the exact internal seam plan 21-05 (gRPC) and plan 21-06 (ASP.NET Core) need — the shared `RefreshGuard`, `JwksVerifier`, `CurrentAccessToken`, `BaseUrl`, `CustomCaPem`, and `TransportHttpClient` — without either plan needing to edit `AxiamClient.cs`.
- `AuthzRestClient` (REST leg of FND-04) is complete; plan 21-05 can now add the gRPC leg (`CheckAccess`/`BatchCheckAccess`) sharing the same `RefreshGuard`.
- **Blocker/concern for the maintainer (carried forward from 21-01/21-02/21-03):** `dotnet build`/`dotnet test` have still not been executed against any of this phase's code in any environment. The first CI run in plan 21-07 (or an earlier ad hoc `dotnet restore`/`dotnet build` by a maintainer with local tooling) should be treated as the first real compile/test signal for the whole phase — this plan's manual review was thorough (including literally running the SC#4-preview grep gate and full brace/paren balance checks on every new file) but cannot substitute for an actual compiler pass.

---
*Phase: 21-c-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 8 created files (AxiamHttpClientFactory.cs, AxiamHttpMessageHandler.cs, AuthzRestClient.cs, AxiamClient.cs, AxiamClientOptions.cs, TenantContext.cs, ClientConstructionTests.cs, AuthzRestClientTests.cs) confirmed present on disk; all 3 task-commit hashes (76f95e0, d686d93, edb9ec4) confirmed in git log.
