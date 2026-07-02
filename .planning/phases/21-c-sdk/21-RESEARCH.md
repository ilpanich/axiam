# Phase 21: C# SDK - Research

**Researched:** 2026-07-02
**Domain:** .NET 8 client SDK (REST + gRPC + AMQP), ASP.NET Core framework integration, NuGet packaging
**Confidence:** HIGH (both gating research flags resolved with source-verified findings; packaging/middleware patterns HIGH via direct source/registry checks; a few numeric defaults MEDIUM/LOW and logged in Assumptions)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 [LOCKED]:** net8.0-only baseline. Single TFM, matches scaffold's `<TargetFramework>net8.0</TargetFramework>`. Native EdDSA path, native gRPC (HTTP/2), and `RabbitMQ.Client` 7.2 async API all work cleanly. netstandard2.0 + BouncyCastle multi-target is deferred.
- **D-02:** EdDSA (Ed25519) local JWKS verification — native-preferred, minimal verify-only crypto dep as the researched fallback. Prefer `System.Security.Cryptography` on net8.0. Researcher MUST confirm native net8.0 Ed25519 verification is viable; if not, permit **one** well-vetted crypto library (e.g. NSec/libsodium or BouncyCastle) scoped **only** to signature verification. No hand-rolled crypto. Reactive 401-driven refresh remains as fallback either way.
- **D-03 [LOCKED]:** Two NuGet packages. `Axiam.Sdk` = REST + gRPC + AMQP + `Sensitive` + JWKS; `Axiam.Sdk.AspNetCore` = middleware + DI + authorization (depends on core). `Grpc.Net.Client` + `RabbitMQ.Client` are always-on deps of core (not split).
- **D-04 [LOCKED]:** NuGet publish = API key + SourceLink + snupkg symbols. `dotnet pack` → `dotnet nuget push` with NuGet API key from CI secrets; tag-triggered (`sdks/csharp/vX.Y.Z`). Deterministic build + SourceLink (GitHub) + `.snupkg`. Author signing deferred/optional. Trusted Publishing (OIDC) preferred future path, not provisioned in-phase. Live first publish may be a maintainer action.
- **D-05 [LOCKED]:** gRPC codegen = `Grpc.Tools` MSBuild, generate-on-build, bundled compiled. `<Protobuf Include="../../proto/**/*.proto" GrpcServices="Client" />` into `obj/` (gitignored); compiled stubs ship inside the package. The documented C# exception to `buf generate`. Generated sources NOT committed. Optional CI drift-check.
- **D-06 [LOCKED]:** Full-idiom ASP.NET Core integration (authentication). `Axiam.Sdk.AspNetCore` provides `app.UseMiddleware<AxiamAuthMiddleware>()` AND sets `HttpContext.User` to a `ClaimsPrincipal` (claims: `user_id`, `tenant_id`, `roles`) so standard `[Authorize]`/policy-based auth works. Reads `X-Tenant-ID` (or configured tenant); surfaces `AuthError` → 401 with standardized JSON body; never caches verification beyond token's remaining TTL.
- **D-07 [LOCKED]:** DI extensions + Options pattern. Ship `AddAxiam()` / `AddAxiamAspNetCore()` `IServiceCollection` extension methods + a typed Options class. Raw `UseMiddleware` form remains available.
- **D-08 [LOCKED]:** Policy-based authorization integration (authz half / 403). `IAuthorizationHandler` + policy provider so `[Authorize(Policy="resource:action")]` calls `client.CheckAccessAsync` under the hood. `[Authorize]` → 401 (unauthenticated); failed AXIAM authz → 403 (`AuthzError`) with standardized JSON body. Runnable example MUST demonstrate it.
- **D-09 [LOCKED]:** SDK-owned handler by default + optional `IHttpClientFactory` path. SDK owns its `HttpClient`+`HttpClientHandler` by default (guarantees §4 cookie jar, §6 strict TLS, `IDisposable` lifecycle). Also offer DI/typed-client path where `AddAxiam()` registers via `IHttpClientFactory` using `SocketsHttpHandler` with `UseCookies` + `PooledConnectionLifetime`. Client-override safety: SDK always re-applies its own cookie container + strict TLS over any supplied handler — an override can never silently drop the cookie jar or weaken TLS. No `ServerCertificateCustomValidationCallback` bypass anywhere; only a `customCa` escape hatch.
- **D-10 [LOCKED]:** Async-only public API + `CancellationToken`. All I/O methods Task-returning `*Async` with `CancellationToken`; no sync wrappers. `ConfigureAwait(false)` throughout. §9 single-flight guard = `SemaphoreSlim(1,1)` + shared `Task<TokenPair>` field, one guard across REST+gRPC on one client. SC#2: 5 concurrent tasks on expired token ⇒ exactly 1 refresh (xUnit test). ValueTask micro-optimization rejected.
- **D-11 [LOCKED]:** AMQP consumer = `AsyncEventingBasicConsumer` + callback, verify-before-handler. Register `RabbitMQ.Client` 7.x `AsyncEventingBasicConsumer`; on each delivery verify HMAC-SHA256 (constant-time compare) BEFORE invoking a consumer-supplied async handler. Handler success → `BasicAckAsync`; retryable failure → `BasicNackAsync` WITH requeue; HMAC-fail/parse-fail/drop-sentinel → `BasicNackAsync` WITHOUT requeue + security log. Handler never sees an unverified message. Enable built-in automatic recovery.
- **D-12:** `Sensitive` — struct with `ToString()` → `"[SENSITIVE]"` + redact-before-wrap on `NetworkError`. Harden `System.Text.Json` serialization to emit `[SENSITIVE]`. `AuthError`/`AuthzError`/`NetworkError` from one central status→error mapper. `NetworkError` MUST redact `Set-Cookie`/`Authorization`/`Cookie` from any wrapped `HttpResponseMessage`/exception before storing it. Add a regression test analogous to sibling error-redaction tests.

### Claude's Discretion

- Internal namespace/folder/file layout under `sdks/csharp/`.
- Exact numeric timeout/deadline/backoff/retry values, gRPC per-call deadline, AMQP prefetch/QoS. (Idempotent-only bounded exponential backoff + jitter, honor `Retry-After`; state-changing requests never auto-retry.)
- gRPC channel construction, interceptor ordering, and metadata injection (`Authorization`/`X-Tenant-Id`/`X-CSRF-Token`); one long-lived channel reused across authz RPCs, disposed with the client.
- `LoginResult` optional-field set beyond `MfaRequired`; DTO style (records + nullable reference types).
- csproj/CI plugin + package versions; SourceLink/deterministic-build config specifics; `Grpc.Tools` version; JWKS cache-TTL and rotation-on-unknown-`kid` specifics.
- Logging facade choice (`Microsoft.Extensions.Logging.Abstractions`, silent by default, redaction-aware).

### Deferred Ideas (OUT OF SCOPE)

- netstandard2.0 + BouncyCastle multi-target (revisit if broad-reach support becomes a requirement).
- NuGet Trusted Publishing (OIDC) — ship API-key publish now, migrate later.
- Author package signing (code-signing cert) — nuget.org repo-signs on ingest.
- ValueTask hot-path variants — rejected as over-engineering for v1.1.
- Live NuGet first publish may be a maintainer action if namespace/API-key creds are absent in CI.
- Automated cross-language conformance harness — Phase 21 verifies conformance via its own §1–§10 checklist.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CS-01 | C# SDK — `sdks/csharp/` (`Axiam.Sdk` + `Axiam.Sdk.AspNetCore`): REST+gRPC+AMQP full baseline, `SemaphoreSlim(1,1)` single-flight, `HttpClientHandler.CookieContainer`, native/near-native EdDSA verification, `Grpc.Tools` MSBuild codegen, ASP.NET Core middleware sub-package, NuGet publish pipeline | This document resolves both CS-01 pinned-dep viability flags (Ed25519 native support — confirmed NOT viable, BouncyCastle.Cryptography selected; RabbitMQ.Client 7.2 API surface — confirmed exact signatures from source) and provides concrete code patterns for every SC#1–#5 acceptance criterion (see Architecture Patterns, Code Examples, Package Legitimacy Audit, Validation Architecture) |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Language/stack:** Rust workspace + SurrealDB backend; this phase is a pure external client (C#/.NET) — MUST NOT depend on server crates (`axiam-*`). All server behavior referenced here (JWKS format, HMAC protocol, error taxonomy) is *reimplemented*, not imported.
- **Security standards:** JWT = EdDSA (Ed25519), short-lived access tokens (15 min); TLS 1.3 minimum for external communication; webhook/AMQP signatures = HMAC-SHA256 — all directly relevant to this phase's JWKS verification and AMQP consumer work.
- **RBAC engine is additive-only (allow-wins, default-deny)** — the ASP.NET Core policy-authz handler (D-08) must not attempt to implement a deny-override or any client-side authz caching that could diverge from server-side additive semantics; every `[Authorize(Policy=...)]` call must go to `CheckAccessAsync` (or trust only a short-TTL local cache within the token's own remaining lifetime), never a longer-lived client cache.
- **License:** Apache-2.0 repo-wide — `sdks/csharp/LICENSE` and csproj `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>` already match; keep them.
- **PR/commit process:** Each roadmap task requires a signed commit; feature branches; `claude_dev/` holds planning docs (not touched by this phase).
- **No project-specific `.claude/skills/` or `rules/*.md` were found** for this repository — no additional project skill conventions apply beyond CLAUDE.md itself.

## Summary

The C# SDK (`sdks/csharp/`) is the sixth of seven planned client SDKs and the first to hit a **hard native-crypto gap**: .NET (through .NET 10, the latest GA release as of this research) has **no built-in Ed25519/EdDSA support** anywhere in `System.Security.Cryptography` or `Microsoft.IdentityModel.Tokens`. The `dotnet/runtime` API proposals for Ed25519 (#14741, opened 2016; #63174, opened 2022) remain unimplemented; .NET 10's cryptography additions were exclusively post-quantum (ML-KEM/ML-DSA/SLH-DSA), not EdDSA. **CS-01's assertion of "native EdDSA on .NET 8+" is FALSE and must be corrected in the plan.** The recommended fix is **`BouncyCastle.Cryptography`** (pure-managed, MIT-licensed, no native binary dependency, already the exact library CS-01 names for the deferred netstandard2.0 leg — using it now on net8.0 too means **zero code-path divergence** when netstandard2.0 is eventually added) via its `Ed25519Signer`/`Ed25519PublicKeyParameters` primitives, wrapped in a small hand-written JWT/JWKS envelope (header/payload split, base64url decode, `kid` lookup, `exp`/`tenant_id` claim checks) — this is plumbing, not crypto, and keeps the SDK to a single verify-only cryptographic dependency as D-02 requires.

The second gating flag — `RabbitMQ.Client` 7.2's async API surface — is **confirmed viable and documented** directly from the library's own GitHub source (`main` branch, matching the 7.2.1 published package): `ConnectionFactory.CreateConnectionAsync()` → `IConnection.CreateChannelAsync()` → `AsyncEventingBasicConsumer` with a `ReceivedAsync` event (not `Received` — renamed in 7.x) → `IChannel.BasicAckAsync(deliveryTag, multiple, ct)` / `BasicNackAsync(deliveryTag, multiple, requeue, ct)`. `AutomaticRecoveryEnabled` and `TopologyRecoveryEnabled` both default to `true`; `NetworkRecoveryInterval` defaults to 5s; `ConsumerDispatchConcurrency` defaults to `1` (sequential dispatch — the safe default matching the "verify-before-handler, no out-of-order surprises" requirement).

A third, non-obvious finding carries forward directly from Phase 19/20's hard-won lesson (logged in `.planning/STATE.md`): the AMQP HMAC "canonical JSON" is **NOT** alphabetically-sorted or RFC-8785-canonical JSON — it is the **exact wire/insertion key order** the server's Rust `serde_json` struct serialization produced. `System.Text.Json.Nodes.JsonObject` is (confirmed directly from `dotnet/runtime` source) backed by an `OrderedDictionary<string, JsonNode?>`, making the parse-into-`JsonObject` → `Remove("hmac_signature")` → `ToJsonString()` pattern the correct, zero-extra-effort C# equivalent of Java's `ObjectNode` / Rust's `serde_json::Value::Object` approach used by every prior sibling SDK.

**Primary recommendation:** Build `Axiam.Sdk` on net8.0 with `HttpClient`+`HttpClientHandler{UseCookies=true}` for REST, `Grpc.Net.Client` 2.80.0 + `Grpc.Tools` 2.80.0 (build-time codegen) for gRPC, `RabbitMQ.Client` 7.2.1 for AMQP, and `BouncyCastle.Cryptography` 2.6.2 as the sole crypto dependency for Ed25519 JWKS verification. Ship `Axiam.Sdk.AspNetCore` as a companion package with `AddAxiamAspNetCore()`, a `ClaimsPrincipal`-populating middleware, and an `IAuthorizationHandler`+policy provider for `[Authorize(Policy="resource:action")]`. Package with SourceLink + Deterministic builds + `.snupkg`, publish via tag-triggered `dotnet nuget push` with an API key.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| REST auth flow (`LoginAsync`/`VerifyMfaAsync`/`RefreshAsync`/`LogoutAsync`) | API / Backend (AXIAM server) | Consuming app's own tier (holds `AxiamClient` + cookie jar) | The SDK is a faithful, thin client — credential verification, MFA, and session issuance are exclusively server-side responsibilities; the SDK never re-implements auth logic. |
| Authorization decisions (`CheckAccessAsync`/`Can`/`BatchCheckAsync`, gRPC `CheckAccess`/`BatchCheckAccess`) | API / Backend (AXIAM server's additive-only RBAC engine) | — | RBAC engine is server-side, allow-wins/default-deny, additive-only (SEC-040); the SDK/ASP.NET policy handler MUST NOT cache or short-circuit an authz decision beyond the current request — no client-side deny-override logic is permitted. |
| Local JWKS / Ed25519 signature verification (proactive refresh + `Axiam.Sdk.AspNetCore` middleware fast-path) | SDK Client (runs inside whatever process hosts the consuming app) | API / Backend (AXIAM server remains the JWKS issuer of record; reactive 401 fallback is the ground truth) | Local verification is a **performance optimization** to avoid a server round trip on every request — it does not create a new trust boundary. Signature validity alone does not imply tenant authorization (JWKS is org-wide, not tenant-scoped) — the `tenant_id` claim MUST additionally be checked against the configured tenant. |
| AMQP event consumption + HMAC verify (`axiam.audit.events`, `axiam.authz.request` if consumed) | SDK Client (message consumer) | Message Broker / Storage (RabbitMQ delivers; does not verify) | The SDK is a consumer of a server-published/signed stream; HMAC verification is a client-side trust-boundary check performed before any user-supplied handler ever sees the message. |
| ASP.NET Core middleware (`AxiamAuthMiddleware`, identity injection, policy-based authz) | API / Backend (protects the consuming app's own endpoints) | Frontend Server / SSR (same middleware pattern equally protects Razor Pages/MVC SSR routes) | Contract-mandated per-framework integration (§10): the SDK supplies the mechanism, but *where* it's registered (API-only app vs. SSR app) is the consuming app's own architectural decision — the middleware itself must stay framework-integration-only, never embedding business logic. |
| NuGet packaging / publish CI | Build & Distribution (not a runtime tier) | — | Not part of the request/response path; included here only for completeness — no tier ownership question applies. |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|---------------|
| `HttpClient` + `HttpClientHandler` | built into net8.0 (BCL) | REST transport, cookie jar (§4) | Contract-mandated (`sdks/CONTRACT.md` §4 C# row); no alternative under consideration — `HttpClientHandler{UseCookies=true, CookieContainer=new()}` is the canonical .NET cookie-persisting HTTP client. `[CITED: sdks/CONTRACT.md §4]` |
| `Grpc.Net.Client` | **2.80.0** | gRPC transport (HTTP/2) for `CheckAccess`/`BatchCheckAccess` | CS-01 pinned dep; confirmed to exist on NuGet at exactly this version. `[VERIFIED: nuget.org registry — api.nuget.org/v3-flatcontainer/grpc.net.client/index.json queried directly, 2026-07-02]` |
| `Grpc.Tools` | **2.80.0** (align major.minor with `Grpc.Net.Client`; latest stable overall is 2.81.1) | Build-time MSBuild codegen for gRPC client stubs (D-05, the buf exception) | `Grpc.Tools` is the official gRPC-for-.NET codegen package; version-aligning with `Grpc.Net.Client` avoids stub/runtime API skew. `[VERIFIED: nuget.org registry, both 2.80.0 and 2.81.1 confirmed present]` |
| `Google.Protobuf` | matches `Grpc.Tools`/`Grpc.Net.Client` major (2.80.x line) | Protobuf message runtime required alongside `Grpc.Net.Client` | Standard companion package for any `Grpc.Net.Client` project; without it, generated message classes will not compile. `[ASSUMED — well-known package pairing, not independently version-checked this session]` |
| `RabbitMQ.Client` | **7.2.1** | AMQP transport, async consumer (D-11) | CS-01 pinned dep (7.2 line); 7.2.1 is the latest published patch. Confirmed directly from the official `rabbitmq/rabbitmq-dotnet-client` GitHub source (`main` branch matches the 7.x async API described here). `[VERIFIED: nuget.org registry + github.com/rabbitmq/rabbitmq-dotnet-client source, 2026-07-02]` |
| `BouncyCastle.Cryptography` | **2.6.2** | Ed25519 signature verification for local JWKS validation (D-02) | **Required because .NET has no native Ed25519 support** (see Pitfall 1 / research flag resolution below). Pure-managed (no native binaries — unlike NSec/libsodium), MIT-style license, exact library CS-01 already names for the deferred netstandard2.0 leg, so adopting it now avoids a future migration. `[VERIFIED: nuget.org registry version list + github.com/bcgit/bc-csharp source for exact `Ed25519PublicKeyParameters`/`Ed25519Signer` API, 2026-07-02]` |
| `System.Text.Json` | built into net8.0 (BCL) | JSON (de)serialization everywhere, incl. `JsonObject` for order-preserving AMQP HMAC canonicalization | Framework-provided; `System.Text.Json.Nodes.JsonObject` is confirmed (directly from `dotnet/runtime` source) to be backed by `OrderedDictionary<string, JsonNode?>`, giving wire-order preservation for free. `[VERIFIED: github.com/dotnet/runtime src/libraries/System.Text.Json/.../Nodes/JsonObject.cs, 2026-07-02]` |
| `Microsoft.Extensions.Http` | **8.0.1** | `IHttpClientFactory` typed-client registration path (D-09 alt path) | Official Microsoft package aligned to the net8.0 TFM baseline (avoids forcing a jump to .NET 10-line BCL-extension packages for a net8.0-targeted library). `[VERIFIED: nuget.org registry 8.x version list, 2026-07-02]` |
| `Microsoft.Extensions.Logging.Abstractions` | **8.0.3** | Logging facade (silent by default, redaction-aware) | Official Microsoft abstractions-only package — no concrete logging provider forced on consumers. `[VERIFIED: nuget.org registry 8.x version list, 2026-07-02]` |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `Microsoft.AspNetCore.App` (shared framework ref, `Axiam.Sdk.AspNetCore` only) | net8.0 shared framework | Middleware, `IAuthorizationHandler`, DI extensions | `Axiam.Sdk.AspNetCore` project references the ASP.NET Core shared framework (`<FrameworkReference Include="Microsoft.AspNetCore.App" />`), keeping the core `Axiam.Sdk` package framework-free (D-03). `[CITED: standard ASP.NET Core library authoring pattern]` |
| `Microsoft.SourceLink.GitHub` | latest 8.x (dev dependency) | SourceLink debugging support in published `.nupkg` (D-04) | `PrivateAssets="All"` dev dependency, added once at pack-config time. `[ASSUMED]` |
| `xunit` + `xunit.runner.visualstudio` + `Microsoft.NET.Test.Sdk` | **xunit 2.9.3** (latest stable) | Test framework — SC#2 single-flight test, HMAC fixture tests, redaction regression test | Confirmed current stable version directly from NuGet registry. `[VERIFIED: nuget.org registry, 2026-07-02]` |
| `Moq` | **4.20.72** | Mocking `HttpMessageHandler`/`ILogger` in unit tests where a fake handler is insufficient | Optional — a hand-written fake `HttpMessageHandler` is often simpler for HTTP-call tests and avoids one more dependency; use `Moq` only where interface mocking (e.g. `ILogger<T>` assertions) is materially simpler. `[VERIFIED: nuget.org registry, 2026-07-02]` |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `BouncyCastle.Cryptography` (direct `Ed25519Signer`) | `NSec.Cryptography` (libsodium-backed) | NSec is a clean, modern Span-based API and MIT-licensed, but ships **native libsodium binaries per-RID** (and on Windows requires the VC++ 2015-2022 Redistributable) — meaningfully more complex NuGet packaging/distribution story for a starter SDK than a pure-managed library, with no functional benefit for a verify-only, low-QPS use case. `[VERIFIED: nuget.org NSec.Cryptography package + community docs, 2026-07-02]` |
| `BouncyCastle.Cryptography` (direct primitive, hand-written JWT envelope) | `ScottBrady.IdentityModel` (v4.1.0, wraps BouncyCastle's EdDSA behind a `Microsoft.IdentityModel.Tokens`-compatible `EdDsaSecurityKey`, enabling full `JwtSecurityTokenHandler`/`TokenValidationParameters` pipeline reuse — clock-skew handling, `exp`/`iss`/`aud` validation, alg-pinning via `ValidAlgorithms`) | Genuinely attractive for parity with Java's `nimbus-jose-jwt` + alg-pinning pattern, and removes the need to hand-write JWT segment splitting/claim checks. **However** it is a single-maintainer community package (not Microsoft, not BouncyCastle project itself) layered on top of BouncyCastle — adds a second dependency for marginal benefit, since the claim-validation logic needed here (check `exp` with clock skew, check `tenant_id` against configured tenant) is only a handful of lines. **Recommendation: use direct BouncyCastle primitives as the primary path; if the planner prefers full `Microsoft.IdentityModel.Tokens` pipeline reuse, `ScottBrady.IdentityModel` is a documented, valid alternative but MUST be gated behind a `checkpoint:human-verify` task given its niche/solo-maintainer profile (see Package Legitimacy Audit).** `[ASSUMED — package discovered via WebSearch/community blog posts, not an authoritative source]` |
| SDK-owned `HttpClientHandler` (default, D-09) | `IHttpClientFactory`-only design | Contract explicitly requires the SDK to guarantee its own cookie jar + TLS policy even when a handler is supplied/injected (client-override safety) — a pure DI-factory-only design without an SDK-owned fallback risks callers accidentally dropping the cookie jar or TLS strictness. D-09 already resolves this by requiring both paths. |
| Hand-rolled base64url + JWT segment parsing (used regardless, see above) | A general-purpose JWT library (e.g. `jose-jwt`/`Jose.Jwt` NuGet package) | General JWT libraries add signature-algorithm surface area (RS256/HS256/etc.) the SDK never needs and historically have inconsistent/absent EdDSA support (same underlying gap as `Microsoft.IdentityModel.Tokens`) — not investigated further since BouncyCastle-direct is simpler and matches "one verify-only crypto dep" exactly. |

**Installation:**
```bash
# Axiam.Sdk (core)
dotnet add package Grpc.Net.Client --version 2.80.0
dotnet add package Google.Protobuf --version 2.80.0
dotnet add package RabbitMQ.Client --version 7.2.1
dotnet add package BouncyCastle.Cryptography --version 2.6.2
dotnet add package Microsoft.Extensions.Http --version 8.0.1
dotnet add package Microsoft.Extensions.Logging.Abstractions --version 8.0.3

# build-time only (codegen)
dotnet add package Grpc.Tools --version 2.80.0
# (mark PrivateAssets="all"; IncludeAssets="runtime; build; native; contentfiles; analyzers; buildtransitive")

# Axiam.Sdk.AspNetCore (references Axiam.Sdk + ASP.NET Core shared framework)

# test project
dotnet add package xunit --version 2.9.3
dotnet add package xunit.runner.visualstudio
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package Moq --version 4.20.72
```

**Version verification:** All Core-table versions above were checked directly against the NuGet v3 flat-container registry (`api.nuget.org/v3-flatcontainer/<id>/index.json`) on 2026-07-02, and `RabbitMQ.Client`/`Grpc.Tools`/`System.Text.Json.Nodes.JsonObject`/BouncyCastle's `Ed25519PublicKeyParameters` API were additionally cross-checked directly against each project's GitHub source (`main` branch for RabbitMQ.Client/dotnet-runtime, `master` for bc-csharp). `BouncyCastle.Cryptography` and `ScottBrady.IdentityModel` package *names* were discovered via WebSearch/community docs (not an authoritative source) and are tagged `[ASSUMED]` per the package-name provenance rule even though registry existence was independently confirmed.

## Package Legitimacy Audit

> gsd-tools (`package-legitimacy check` seam) was not available in this environment (no `gsd-core/bin/gsd-tools.cjs` found on the runtime and `gsd-tools` is not on `PATH`). The checks below were performed manually: direct NuGet v3 registry queries (existence + full version history/catalog-page count as an age/maturity proxy) plus GitHub source-repository confirmation for API surface. No downloads-per-week figures were independently retrieved this session — flagged as a gap below.

| Package | Registry | Age (proxy: version-history depth) | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `RabbitMQ.Client` | NuGet | Many major versions (1.x→7.x over 15+ years); official RabbitMQ team package | Not independently queried this session — widely known to be extremely high (core RabbitMQ .NET client) | github.com/rabbitmq/rabbitmq-dotnet-client (confirmed, fetched source directly) | OK | Approved |
| `Grpc.Net.Client` / `Grpc.Tools` | NuGet | Long version history (2.2x → 2.8x line spans years); official gRPC/grpc-dotnet project | Not independently queried — well-known, extremely high (official gRPC .NET packages) | github.com/grpc/grpc-dotnet, github.com/grpc/grpc | OK | Approved |
| `BouncyCastle.Cryptography` | NuGet | Multiple major versions (2.0.0 → 2.7.0-beta); bc-csharp itself is a 20+ year old cryptography project (Legion of the Bouncy Castle) | Not independently queried — extremely well-known, one of the most-used .NET crypto libraries | github.com/bcgit/bc-csharp (confirmed, fetched `Ed25519PublicKeyParameters` source directly) | OK | Approved |
| `Microsoft.Extensions.Http` / `Microsoft.Extensions.Logging.Abstractions` | NuGet | Official Microsoft BCL-extensions packages, versioned alongside every .NET release since .NET Core 2.x | Not independently queried — official first-party Microsoft package, effectively universal in .NET apps | github.com/dotnet/runtime (Microsoft.Extensions.* live here) | OK | Approved |
| `xunit` / `Moq` | NuGet | Long-established test tooling (xunit 2.x line for many years; Moq similarly long-lived) | Not independently queried — both are among the most-downloaded .NET test packages | github.com/xunit/xunit, github.com/devlooped/moq | OK | Approved |
| `ScottBrady.IdentityModel` (alternative, NOT the primary recommendation) | NuGet | v4.1.0 published ~Nov 2024 (per search results); rename of the older `ScottBrady91.IdentityModel` | Not independently queried; community sentiment (blog citations from damienbod.com, scottbrady.io) suggests real but modest adoption, single maintainer | github.com/scottbrady91/IdentityModel | SUS | Flagged — only relevant if the planner chooses the `ScottBrady.IdentityModel` alternative over the primary direct-BouncyCastle recommendation; if so, planner MUST add a `checkpoint:human-verify` task before adding this dependency (single-maintainer, comparatively low profile relative to BouncyCastle/Microsoft/RabbitMQ packages, sits in the security-critical JWT-verification path) |
| `NSec.Cryptography` (alternative, NOT the primary recommendation) | NuGet | Long-running project (v18.2.0-preview1 → v26.4.0), MIT license | Not independently queried | github.com/ektrah/nsec | OK (not chosen — see Alternatives Considered for the native-binary/packaging tradeoff, not a legitimacy concern) | Not used |

**Packages removed due to `[SLOP]` verdict:** none.
**Packages flagged as suspicious `[SUS]`:** `ScottBrady.IdentityModel` — only applicable if this alternative path is chosen instead of the primary direct-BouncyCastle recommendation; gate behind `checkpoint:human-verify`.

*Download-count figures were not independently retrieved this session (no public NuGet downloads-count endpoint was queried) — treat the "Downloads" column above as directional community knowledge, not a verified metric. All package **names** in this table were discovered via WebSearch/training and are `[ASSUMED]` per the provenance rule regardless of the registry-existence confirmation performed above.*

## Architecture Patterns

### System Architecture Diagram

```
 Consuming .NET app (any tier: API service, ASP.NET Core MVC/Razor SSR app, worker service, console)
 ┌──────────────────────────────────────────────────────────────────────────┐
 │  new AxiamClient(baseUrl, tenantId, ...)      [ Axiam.Sdk (core) ]        │
 │                                                                            │
 │  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────────────┐  │
 │  │  REST path  │   │  gRPC path   │   │        AMQP path              │  │
 │  │ HttpClient  │   │Grpc.Net.Client│  │  RabbitMQ.Client 7.2 (async)  │  │
 │  │ +Handler    │   │ CheckAccess/ │   │  AsyncEventingBasicConsumer   │  │
 │  │ CookieJar   │   │ BatchCheck   │   │                               │  │
 │  └──────┬──────┘   └──────┬───────┘   └───────────────┬───────────────┘  │
 │         │  every call: inject Authorization + X-Tenant-Id (+X-CSRF-Token │  │
 │         │  on state-changing REST calls) via the SAME RefreshGuard       │  │
 │         ▼                 ▼                            ▼                 │
 │  ┌─────────────────────────────────────────┐  ┌────────────────────────┐│
 │  │   RefreshGuard (SemaphoreSlim(1,1) +    │  │  HMAC verify-before-   ││
 │  │   shared Task<TokenPair> field)          │  │  handler (BouncyCastle-││
 │  │   — proactive: JwksVerifier says "near   │  │  free; native HMACSHA256│
 │  │     expiry" → refresh once, share result │  │  + FixedTimeEquals)    ││
 │  │   — reactive: 401/UNAUTHENTICATED → same │  │  ack/nack decision     ││
 │  │     guard, retry once, no loop           │  │  (never invoke handler ││
 │  └───────────────────┬───────────────────────┘  │  on unverified msg)   ││
 │                       │                          └───────────┬────────┘│
 │                       ▼                                       │         │
 │  ┌─────────────────────────────────┐                          │         │
 │  │  JwksVerifier (BouncyCastle      │                          │         │
 │  │  Ed25519Signer, cached by `kid`) │                          │         │
 │  │  — decodes header.payload only   │                          │         │
 │  │    when a local check is needed  │                          │         │
 │  └───────────────────┬─────────────┘                          │         │
 └──────────────────────┼──────────────────────────────────────────────────┘
                         │ GET /oauth2/jwks (cache, refetch on unknown kid)    │ consume: exchange declared
                         │ POST /auth/login, /auth/mfa/verify, /auth/refresh, │  by ops config; queue bound
                         │  /auth/logout, /api/v1/authz/check[/batch]         │  by ops config
                         ▼                                                     ▼
        ┌────────────────────────────────────────────┐      ┌───────────────────────────────┐
        │      AXIAM Server (frozen v1.0 API)         │      │        RabbitMQ Broker         │
        │  REST (Actix-Web) · gRPC (Tonic) · AMQP     │◄─────┤  axiam.audit.events, etc.      │
        │  additive-only RBAC engine (source of truth)│      │  (HMAC-signed by server before │
        └──────────────────────────────────────────────┘      │  publish)                      │
                                                                └───────────────────────────────┘

 ── Axiam.Sdk.AspNetCore (companion package, references core) ──────────────────────────────
 Incoming HTTP request
   → AxiamAuthMiddleware (reads X-Tenant-ID or configured tenant; extracts bearer/cookie token;
       verifies via core's JwksVerifier + RefreshGuard fallback)
   → on success: sets HttpContext.User = ClaimsPrincipal(user_id, tenant_id, roles)
   → downstream: standard [Authorize] → 401 on failure (AuthError → standardized JSON body)
   → downstream: [Authorize(Policy="resource:action")] → AxiamPolicyHandler → client.CheckAccessAsync
       → 403 on failure (AuthzError → standardized JSON body)
```

### Recommended Project Structure

```
sdks/csharp/
├── Axiam.Sdk/
│   ├── Axiam.Sdk.csproj              # net8.0, PackageId=Axiam.Sdk (existing scaffold)
│   ├── AxiamClient.cs                # public entry point; tenant required ctor param
│   ├── Auth/
│   │   ├── RefreshGuard.cs           # SemaphoreSlim(1,1) + Task<TokenPair> (D-10, §9)
│   │   ├── JwksVerifier.cs           # BouncyCastle Ed25519 verify, kid-keyed cache (D-02)
│   │   └── LoginResult.cs            # record; MfaRequired + discretion fields
│   ├── Rest/
│   │   ├── AxiamHttpMessageHandler.cs # cookie-jar + header-injection + client-override safety (D-09)
│   │   └── AuthzRestClient.cs        # CheckAccessAsync/Can/BatchCheckAsync (REST leg)
│   ├── Grpc/
│   │   ├── AxiamGrpcChannel.cs       # one long-lived channel + interceptor (metadata injection)
│   │   └── (generated stubs land in obj/, not committed — D-05)
│   ├── Amqp/
│   │   ├── AxiamAmqpConsumer.cs      # AsyncEventingBasicConsumer registration (D-11)
│   │   └── Hmac.cs                   # verify-before-handler, JsonObject wire-order preserving
│   ├── Core/
│   │   ├── Sensitive.cs              # struct, ToString() → "[SENSITIVE]" (D-12)
│   │   ├── ErrorMapper.cs            # AuthError/AuthzError/NetworkError, redact-before-wrap
│   │   └── TenantContext.cs
│   └── Options/
│       └── AxiamClientOptions.cs
├── Axiam.Sdk.AspNetCore/
│   ├── Axiam.Sdk.AspNetCore.csproj   # net8.0, FrameworkReference Microsoft.AspNetCore.App
│   ├── AxiamAuthMiddleware.cs        # D-06
│   ├── AxiamPolicyHandler.cs         # IAuthorizationHandler (D-08)
│   ├── AxiamPolicyProvider.cs        # IAuthorizationPolicyProvider (D-08)
│   └── ServiceCollectionExtensions.cs # AddAxiam() / AddAxiamAspNetCore() (D-07)
├── examples/
│   └── AspNetCoreSample/             # runnable app demonstrating middleware + [Authorize(Policy=...)]  (SC#3)
├── tests/
│   └── Axiam.Sdk.Tests/
│       ├── RefreshGuardSingleFlightTests.cs   # SC#2 xUnit test
│       ├── HmacVerifyTests.cs                 # fixture-based, Rust-signed vectors
│       ├── SensitiveRedactionTests.cs         # CR-04 carry-forward regression test
│       └── TlsBypassGrepGateTests.cs          # optional: assert no ServerCertificateCustomValidationCallback in source
├── README.md                         # states CONTRACT.md §1–§10 conformance + Grpc.Tools exception (existing scaffold)
└── LICENSE                           # Apache-2.0 (existing scaffold)
```

### Pattern 1: Native Ed25519 Gap — BouncyCastle-Backed JWKS Verifier (resolves D-02 research flag)

**What:** .NET has no native Ed25519 support (confirmed below). Fetch+cache `GET {baseUrl}/oauth2/jwks` (confirmed exact path and JWK shape from `crates/axiam-oauth2/src/oidc.rs` — `kty:"OKP"`, `crv:"Ed25519"`, `x`=base64url raw 32-byte public key, deterministic `kid`), keyed by `kid`; verify signature with BouncyCastle; pin `alg=="EdDSA"` before any key lookup (never trust the token's own alg to select a verifier); after signature verification, **additionally** check `tenant_id` claim against the configured tenant (JWKS is organization-wide, not tenant-scoped — same finding independently made by every sibling SDK).

**When to use:** Proactive pre-expiry refresh trigger (avoid a server round trip on every request) and the `Axiam.Sdk.AspNetCore` middleware's local-verification fast path. The reactive 401/`UNAUTHENTICATED`-driven refresh via `RefreshGuard` remains the fallback path regardless — local JWKS verification is an optimization, not a new trust boundary.

**Research flag resolution — confirmed facts:**
- `System.Security.Cryptography` has **no** `Ed25519`/`EdDSA` class as of .NET 10 (the current GA release). The relevant API proposals (`dotnet/runtime` #14741 opened 2016, #63174 opened 2022) remain open/unimplemented. `.NET 10`'s cryptography additions were exclusively post-quantum (ML-KEM/FIPS 203, ML-DSA/FIPS 204, SLH-DSA/FIPS 205) — Ed25519 was NOT among them. `[VERIFIED: WebSearch cross-checked against multiple sources — Microsoft Learn "What's new in .NET 10 libraries", dotnet/core release-notes preview docs, dotnet/runtime issue search — 2026-07-02; could not fetch the GitHub issues directly due to a 403 on unauthenticated `gh`/WebFetch access to github.com in this environment, so issue *state* (open/closed) is inferred from the absence of any "shipped in .NET X" announcement rather than a direct issue-status read]`
- `Microsoft.IdentityModel.Tokens` does **not** support EdDSA out of the box — this is explicitly documented by the .NET identity community (damienbod.com, scottbrady.io) as a known gap, worked around by the third-party `ScottBrady.IdentityModel` package. `[CITED: damienbod.com/2025/08/06/use-eddsa-signatures-to-validate-tokens-in-asp-net-core-using-openid-connect, scottbrady.io/c-sharp/eddsa-for-jwt-signing-in-dotnet-core]`
- **This exact same gap was independently hit by the Java sibling SDK** (Phase 20): `nimbus-jose-jwt`'s `DefaultJWTProcessor` + `JWSVerificationKeySelector(EdDSA)` pipeline could not verify OKP/Ed25519 keys either (`OctetKeyPair.toKeyPair()` unconditionally throws), forcing a direct `JWKMatcher`+`Ed25519Verifier(OctetKeyPair)` workaround instead of the "obvious" high-level API. `[VERIFIED: .planning/STATE.md Phase 20 decision log]` — this is a strong cross-language pattern: **every mainstream managed-runtime JWT library's "just works" EdDSA path is broken or absent; direct primitive-level verification is consistently the correct fallback.**
- `BouncyCastle.Cryptography`'s `Ed25519PublicKeyParameters(byte[] buf)` (32-byte raw key) and `Ed25519Signer.Init(false, publicKey)` / `BlockUpdate(...)` / `VerifySignature(sig)` are confirmed directly from the `bcgit/bc-csharp` source (`crypto/src/crypto/parameters/Ed25519PublicKeyParameters.cs`, `crypto/src/crypto/signers/Ed25519Signer.cs`). `[VERIFIED: github.com/bcgit/bc-csharp source, master branch, 2026-07-02]`

**Example:**
```csharp
// Source: JWK shape confirmed from crates/axiam-oauth2/src/oidc.rs (kty=OKP, crv=Ed25519,
// x=base64url raw pubkey, kid=first-16-hex(SHA256(rawkey))); JWKS path confirmed from
// crates/axiam-api-rest/src/handlers/oauth2.rs (`GET /oauth2/jwks`, org-wide, not
// tenant-scoped — same finding independently made by Rust/Go/Python/Java sibling SDKs).
// BouncyCastle API confirmed from github.com/bcgit/bc-csharp source (2026-07-02).
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Axiam.Sdk.Auth;

public sealed record Jwk(string Kty, string Crv, string X, string Kid, string Use, string Alg);
public sealed record JwksDocument(Jwk[] Keys);

public sealed class JwksVerifier
{
    private readonly HttpClient _http;
    private readonly Uri _jwksUri; // {baseUrl}/oauth2/jwks — NOT /.well-known/jwks.json (AXIAM doesn't serve that path)
    private Dictionary<string, byte[]> _keysByKid = new();
    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;
    private readonly TimeSpan _cacheTtl;

    public JwksVerifier(HttpClient http, Uri baseUrl, TimeSpan cacheTtl)
    {
        _http = http;
        _jwksUri = new Uri(baseUrl, "/oauth2/jwks");
        _cacheTtl = cacheTtl;
    }

    private async Task EnsureFreshAsync(string? unknownKid, CancellationToken ct)
    {
        bool expired = DateTimeOffset.UtcNow - _fetchedAt > _cacheTtl;
        bool unknown = unknownKid is not null && !_keysByKid.ContainsKey(unknownKid);
        if (!expired && !unknown) return;

        var doc = await _http.GetFromJsonAsync<JwksDocument>(_jwksUri, ct).ConfigureAwait(false)
                   ?? throw new InvalidOperationException("empty JWKS document");
        var map = new Dictionary<string, byte[]>();
        foreach (var jwk in doc.Keys)
        {
            if (jwk.Kty != "OKP" || jwk.Crv != "Ed25519") continue; // ignore non-EdDSA entries defensively
            map[jwk.Kid] = Base64UrlDecode(jwk.X); // raw 32-byte Ed25519 public key
        }
        _keysByKid = map;
        _fetchedAt = DateTimeOffset.UtcNow;
    }

    /// Verifies signature AND tenant_id claim. Returns claims on success, null on any failure.
    /// Never throws for malformed/untrusted input — verification failure is always a `false`/null
    /// result, matching the AMQP HMAC verifier's "never throw on attacker input" convention.
    public async Task<JsonElement?> VerifyAsync(string jwt, string expectedTenantId, CancellationToken ct)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return null;

        var headerJson = Base64UrlDecode(parts[0]);
        using var header = JsonDocument.Parse(headerJson);
        if (!header.RootElement.TryGetProperty("alg", out var algEl) || algEl.GetString() != "EdDSA")
            return null; // alg-pin BEFORE key lookup — never trust the token to select its own verifier
        string? kid = header.RootElement.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;
        if (kid is null) return null;

        await EnsureFreshAsync(kid, ct).ConfigureAwait(false);
        if (!_keysByKid.TryGetValue(kid, out var rawPubKey)) return null; // unknown kid even after refetch

        var signingInput = System.Text.Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var signature = Base64UrlDecode(parts[2]);

        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(rawPubKey));
        verifier.BlockUpdate(signingInput, 0, signingInput.Length);
        if (!verifier.VerifySignature(signature)) return null;

        var payloadJson = Base64UrlDecode(parts[1]);
        using var payload = JsonDocument.Parse(payloadJson);
        var root = payload.RootElement.Clone();

        // Multi-tenant carry-forward (mirrors every sibling SDK's mandatory control):
        // signature validity alone does NOT imply tenant authorization — JWKS is org-wide.
        if (!root.TryGetProperty("tenant_id", out var tid) || tid.GetString() != expectedTenantId)
            return null;

        if (root.TryGetProperty("exp", out var expEl) &&
            DateTimeOffset.FromUnixTimeSeconds(expEl.GetInt64()) < DateTimeOffset.UtcNow)
            return null; // expired — caller falls back to reactive refresh path

        return root;
    }

    private static byte[] Base64UrlDecode(string s)
    {
        string padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4) { case 2: padded += "=="; break; case 3: padded += "="; break; }
        return Convert.FromBase64String(padded);
    }
}
```

### Pattern 2: `SemaphoreSlim(1,1)` Single-Flight Refresh (D-10, §9, SC#2)

**What:** Exactly one in-flight refresh at a time, shared across REST and gRPC on one client instance. Concurrent callers await the *same* `Task<TokenPair>`; on success all retry with new tokens, on failure all fail with `AuthError`; no retry loop on a failed refresh call itself.

**Example:**
```csharp
// Source: sdks/CONTRACT.md §9 (locked C# mechanism: "SemaphoreSlim(1,1) + Task<TokenPair>
// stored in field") + standard .NET async double-checked-locking idiom.
namespace Axiam.Sdk.Auth;

public sealed record TokenPair(Sensitive<string> AccessToken, Sensitive<string> RefreshToken, DateTimeOffset ExpiresAt);

public sealed class RefreshGuard : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Task<TokenPair>? _inFlight;
    private readonly Func<CancellationToken, Task<TokenPair>> _doRefresh;

    public RefreshGuard(Func<CancellationToken, Task<TokenPair>> doRefresh) => _doRefresh = doRefresh;

    /// Called by both the reactive (401/UNAUTHENTICATED) and proactive (near-expiry) paths.
    /// Guarantees exactly one underlying HTTP refresh call regardless of concurrent callers.
    public async Task<TokenPair> RefreshIfNeededAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Double-checked: another waiter may have already completed a refresh while
            // this caller was blocked on the gate — do not just check _inFlight is null,
            // check whether the ALREADY-COMPLETED result is still fresh enough to reuse.
            if (_inFlight is { IsCompletedSuccessfully: true } done &&
                done.Result.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(5))
            {
                return done.Result;
            }
            _inFlight = _doRefresh(ct); // start exactly one refresh; do NOT await inside the gate scope narrowly —
                                        // awaiting here (while still holding the gate) is what makes concurrent
                                        // callers pile up on _gate.WaitAsync and then share the single Task result.
            return await _inFlight.ConfigureAwait(false);
        }
        catch
        {
            _inFlight = null; // failed refresh: do not cache a faulted task for the next caller
            throw; // surfaces as AuthError to every waiter — no retry loop (§9.3)
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();
}
```
**SC#2 test shape (xUnit):** spin up 5 concurrent `Task`s that all call `RefreshIfNeededAsync` against a client with an already-expired token pointed at a test double / `MockHttpMessageHandler` counting refresh calls; assert the counter equals exactly 1 after all 5 tasks complete. Mirrors the Java sibling's `CountDownLatch`/thread-pool/counting-dispatcher test shape adapted to `Task.WhenAll`.

### Pattern 3: RabbitMQ.Client 7.2 Async Consumer, HMAC Verify-Before-Handler (D-11, §8)

**What:** `AsyncEventingBasicConsumer` registered via `BasicConsumeAsync`; every delivery is HMAC-verified (using `System.Text.Json.Nodes.JsonObject`'s confirmed wire-order-preserving re-serialization) **before** the user handler runs. Built-in automatic recovery is on by default (`AutomaticRecoveryEnabled = true`).

**Critical correctness requirement (carried forward from the Python/Java sibling SDKs' proven fix, logged in `.planning/STATE.md`):** the "canonical JSON" for HMAC is the **exact wire/insertion key order**, NOT alphabetically sorted, NOT the order a strongly-typed C# record/POCO would declare. Deserializing into a POCO and re-serializing it would silently reorder fields to match the class's declared property order — computing the HMAC over a *different* byte sequence than the server signed, and failing 100% of verifications. `System.Text.Json.Nodes.JsonObject` (confirmed from `dotnet/runtime` source to be backed by `OrderedDictionary<string, JsonNode?>`) is the correct C# tool here — parse into `JsonObject`, `Remove("hmac_signature")`, `ToJsonString()`, exactly mirroring Java's `ObjectNode`/Rust's `serde_json::Value::Object` approach.

**Example:**
```csharp
// Source: HMAC protocol confirmed from crates/axiam-amqp/src/messages.rs (sign_payload/
// verify_payload: hex(HMAC-SHA256), hmac_signature field omitted before signing) +
// sdks/CONTRACT.md §8. RabbitMQ.Client 7.x API (CreateConnectionAsync, CreateChannelAsync,
// AsyncEventingBasicConsumer.ReceivedAsync, BasicAckAsync/BasicNackAsync signatures,
// AutomaticRecoveryEnabled/TopologyRecoveryEnabled/NetworkRecoveryInterval/
// ConsumerDispatchConcurrency defaults) confirmed directly from
// github.com/rabbitmq/rabbitmq-dotnet-client source (main branch), 2026-07-02.
// Key-order preservation for JsonObject confirmed from github.com/dotnet/runtime source.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Axiam.Sdk.Amqp;

public static class Hmac
{
    /// Returns true iff body's hmac_signature field matches
    /// HMAC-SHA256(key, canonical_json_of(body_without_hmac_signature)), constant-time
    /// compared. Never throws — malformed input verifies as false (strict-mode default, §8.3).
    public static bool Verify(byte[] signingKey, byte[] body)
    {
        try
        {
            var node = JsonNode.Parse(body)?.AsObject();
            if (node is null) return false;
            if (!node.TryGetPropertyValue("hmac_signature", out var sigNode) || sigNode is null)
                return false; // §8.3 strict mode: missing signature = reject

            string sigHex = sigNode.GetValue<string>();
            node.Remove("hmac_signature"); // OrderedDictionary-backed: preserves the relative
                                            // order of ALL remaining keys exactly as received —
                                            // the load-bearing property (do NOT alphabetize).
            byte[] canonical = Encoding.UTF8.GetBytes(node.ToJsonString());

            byte[] expected = Convert.FromHexString(sigHex);
            byte[] computed = HMACSHA256.HashData(signingKey, canonical);

            return computed.Length == expected.Length &&
                   CryptographicOperations.FixedTimeEquals(computed, expected);
        }
        catch
        {
            return false; // parse failure / bad hex / bad key -> reject, never throw
        }
    }
}

public sealed class AxiamAmqpConsumer : IAsyncDisposable
{
    private IConnection? _connection;
    private IChannel? _channel;

    public async Task StartAsync(string uri, string queue, byte[] signingKey,
        Func<byte[], CancellationToken, Task> handler, ILogger logger, CancellationToken ct)
    {
        var factory = new ConnectionFactory
        {
            Uri = new Uri(uri),
            AutomaticRecoveryEnabled = true,   // default true — kept explicit for clarity
            TopologyRecoveryEnabled = true,    // default true
            NetworkRecoveryInterval = TimeSpan.FromSeconds(5),
            ConsumerDispatchConcurrency = 1,   // default; sequential dispatch — safe default,
                                                // bump only if handler is proven concurrency-safe
        };
        _connection = await factory.CreateConnectionAsync(ct).ConfigureAwait(false);
        _channel = await _connection.CreateChannelAsync(cancellationToken: ct).ConfigureAwait(false);
        await _channel.BasicQosAsync(0, prefetchCount: 10, global: false, ct).ConfigureAwait(false);

        var consumer = new AsyncEventingBasicConsumer(_channel);
        consumer.ReceivedAsync += async (sender, ea) =>
        {
            var body = ea.Body.ToArray(); // MUST copy — library-owned memory is only valid
                                           // for the duration of this event (7.x migration note)
            var channel = ((AsyncEventingBasicConsumer)sender).Channel;

            if (!Hmac.Verify(signingKey, body))
            {
                logger.LogWarning("axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue");
                await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false, ct).ConfigureAwait(false);
                return;
            }
            try
            {
                await handler(body, ct).ConfigureAwait(false); // handler NEVER sees an unverified message
                await channel.BasicAckAsync(ea.DeliveryTag, multiple: false, ct).ConfigureAwait(false);
            }
            catch (PoisonMessageException) // consumer-supplied sentinel for "drop, don't requeue"
            {
                await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false, ct).ConfigureAwait(false);
            }
            catch (Exception)
            {
                await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: true, ct).ConfigureAwait(false); // transient -> requeue
            }
        };

        await _channel.BasicConsumeAsync(queue, autoAck: false, consumerTag: "", noLocal: false,
            exclusive: false, arguments: null, consumer, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_channel is not null) await _channel.CloseAsync().ConfigureAwait(false);
        if (_connection is not null) await _connection.CloseAsync().ConfigureAwait(false);
    }
}

public sealed class PoisonMessageException : Exception { }
```

### Pattern 4: `Grpc.Tools` MSBuild Build-Time Codegen (D-05, the buf exception)

**What:** `<Protobuf>` MSBuild item generates C# client stubs into `obj/` at build time — the one documented exception to the repo-wide `buf generate` pipeline (`sdks/buf.gen.yaml` is NOT touched for C#).

**Example:**
```xml
<!-- Source: official Grpc.Tools MSBuild integration pattern
     (grpc.io/blog/grpc-dotnet-build, learn.microsoft.com/aspnet/core/grpc/basics) applied
     to Phase 15 D-01's C# exception ("Grpc.Tools MSBuild" instead of buf) -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Grpc.Net.Client" Version="2.80.0" />
    <PackageReference Include="Google.Protobuf" Version="2.80.0" />
    <PackageReference Include="Grpc.Tools" Version="2.80.0">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
    </PackageReference>
  </ItemGroup>

  <ItemGroup>
    <!-- Client-only codegen (SDK never hosts a gRPC server) -->
    <Protobuf Include="../../../proto/axiam/v1/*.proto" GrpcServices="Client"
              ProtoRoot="../../../proto" />
  </ItemGroup>
</Project>
```
Generated `.cs` files land under `obj/Debug/net8.0/Protos/` (or similar, MSBuild-managed) — **gitignored**, and the compiled stub classes are bundled into the published `.nupkg` as ordinary compiled types (no source distribution, matching Rust/TS/Java's "ships a compiled artifact" model, unlike source-distributed Go/Python). Document this explicitly in `sdks/csharp/README.md` as required by the contract's closing "C# `Grpc.Tools` Exception" note — the existing scaffold's README already states this; Phase 21 fills in the actual proto wiring.

### Pattern 5: ASP.NET Core Middleware + DI Extensions + Policy-Based Authorization (D-06, D-07, D-08)

**What:** `Axiam.Sdk.AspNetCore` provides both the contract-literal `app.UseMiddleware<AxiamAuthMiddleware>()` form (§10) and idiomatic `AddAxiam()`/`AddAxiamAspNetCore()` DI extensions + Options pattern (D-07). The middleware sets `HttpContext.User` to a `ClaimsPrincipal` so standard `[Authorize]` works (401 on failure); a separate `IAuthorizationHandler` + policy provider lets `[Authorize(Policy="resource:action")]` call `CheckAccessAsync` under the hood (403 on failure, D-08).

**Example:**
```csharp
// Source: sdks/CONTRACT.md §10 (locked C# row: "app.UseMiddleware<AxiamAuthMiddleware>()
// in Program.cs") + standard ASP.NET Core middleware/IAuthorizationHandler authoring
// patterns (learn.microsoft.com/aspnet/core/fundamentals/middleware/write,
// learn.microsoft.com/aspnet/core/security/authorization/policies) + Java sibling's
// D-14 Spring SecurityContext-integration analog (mirrored here for parity).
namespace Axiam.Sdk.AspNetCore;

public sealed class AxiamAuthMiddleware
{
    private readonly RequestDelegate _next;
    public AxiamAuthMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, AxiamClient client, AxiamOptions options)
    {
        string tenantId = context.Request.Headers["X-Tenant-ID"].FirstOrDefault() ?? options.DefaultTenantId
            ?? throw new InvalidOperationException("no tenant available"); // never a silent default (§5)
        string? token = ExtractToken(context); // Authorization: Bearer, or cookie per §4

        if (token is null)
        {
            await WriteErrorAsync(context, 401, "AuthError", "missing credentials").ConfigureAwait(false);
            return;
        }

        var claims = await client.Auth.VerifyLocallyOrRemotelyAsync(token, tenantId, context.RequestAborted)
            .ConfigureAwait(false); // local JWKS fast-path (Pattern 1) with reactive fallback (Pattern 2)
        if (claims is null)
        {
            await WriteErrorAsync(context, 401, "AuthError", "invalid or expired token").ConfigureAwait(false);
            return;
        }

        var identity = new ClaimsIdentity("Axiam");
        identity.AddClaim(new Claim("user_id", claims.Value.GetProperty("sub").GetString()!));
        identity.AddClaim(new Claim("tenant_id", tenantId));
        foreach (var role in claims.Value.GetProperty("roles").EnumerateArray())
            identity.AddClaim(new Claim(ClaimTypes.Role, role.GetString()!));
        context.User = new ClaimsPrincipal(identity); // never cached beyond this request — §10

        await _next(context).ConfigureAwait(false);
    }

    private static async Task WriteErrorAsync(HttpContext ctx, int status, string type, string message)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsJsonAsync(new { error = type, message }).ConfigureAwait(false);
    }

    private static string? ExtractToken(HttpContext ctx) =>
        ctx.Request.Headers.Authorization.FirstOrDefault()?.Replace("Bearer ", "")
        ?? ctx.Request.Cookies["axiam_access"];
}

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAxiam(this IServiceCollection services, Action<AxiamOptions> configure)
    {
        services.Configure(configure);
        services.AddHttpClient<AxiamClient>(); // IHttpClientFactory path (D-09 alt);
                                                 // AxiamClient's own DelegatingHandler re-applies
                                                 // cookie-jar + strict-TLS regardless (client-override safety)
        return services;
    }

    public static IServiceCollection AddAxiamAspNetCore(this IServiceCollection services, Action<AxiamOptions> configure)
    {
        services.AddAxiam(configure);
        services.AddSingleton<IAuthorizationHandler, AxiamPolicyHandler>();
        services.AddSingleton<IAuthorizationPolicyProvider, AxiamPolicyProvider>();
        return services;
    }
}

/// resource:action policy names (e.g. "documents:read") route through CheckAccessAsync.
public sealed class AxiamPolicyHandler : AuthorizationHandler<AxiamRequirement>
{
    private readonly AxiamClient _client;
    public AxiamPolicyHandler(AxiamClient client) => _client = client;

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, AxiamRequirement requirement)
    {
        var userId = context.User.FindFirst("user_id")?.Value;
        if (userId is null) return; // no identity — [Authorize] already yields 401 upstream

        bool allowed = await _client.Authz.CheckAccessAsync(userId, requirement.Resource, requirement.Action, CancellationToken.None)
            .ConfigureAwait(false); // server-side additive-only RBAC is the sole source of truth — no
                                     // client-side caching beyond this single request (project constraint)
        if (allowed) context.Succeed(requirement);
        // else: falls through unsatisfied -> ASP.NET Core's authorization middleware returns 403
        // (AuthzError, standardized JSON body via a custom IAuthorizationMiddlewareResultHandler)
    }
}
```

### Pattern 6: HttpClient Cookie Jar, Client-Override Safety, No TLS Bypass (D-09, §4, §6)

**What:** SDK owns its `HttpClient`+`HttpClientHandler` by default; also offers an `IHttpClientFactory`-registered path. Either way the SDK **re-applies** its own cookie container and strict TLS policy — a caller-supplied handler can never silently drop the cookie jar or weaken TLS.

**Example:**
```csharp
// Source: sdks/CONTRACT.md §4 (locked mechanism: "HttpClient with HttpClientHandler
// { UseCookies = true, CookieContainer = new() }") + §6 (absolute prohibition on any
// TLS-bypass surface) + D-09's client-override-safety requirement (Java D-27 analog).
public sealed class AxiamHttpClientFactory
{
    public static HttpClient CreateOwned(byte[]? customCaPem)
    {
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = new CookieContainer(),
        };
        if (customCaPem is not null)
        {
            var ca = X509CertificateLoader.LoadCertificate(customCaPem); // .NET 9+ API name may
                                                                          // differ on net8.0 — see
                                                                          // Assumptions Log A2
            handler.ServerCertificateCustomValidationCallback = (_, cert, chain, errors) =>
            {
                // Adds ONE trusted CA to the chain — this is NOT a bypass: unknown/mismatched
                // certs still fail. There is no branch here that returns `true` unconditionally
                // (the §6-prohibited pattern). CI's grep gate scans for the bare
                // `ServerCertificateCustomValidationCallback = (.*) => true` shape and equivalents.
                chain!.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                return chain.Build(cert);
            };
        }
        // No `else` branch that sets ServerCertificateCustomValidationCallback to anything
        // permissive — default system trust store verification applies untouched.
        return new HttpClient(handler) { BaseAddress = /* configured base URL */ null };
    }

    /// IHttpClientFactory-compatible registration (D-09 alt path). SocketsHttpHandler +
    /// PooledConnectionLifetime dodges the classic long-lived-HttpClient DNS-staleness/socket-
    /// exhaustion tradeoff that IHttpClientFactory exists to solve.
    public static void ConfigureFactoryHandler(SocketsHttpHandler handler)
    {
        handler.UseCookies = true; // re-applied even if caller supplied their own SocketsHttpHandler
        handler.CookieContainer = new CookieContainer();
        handler.PooledConnectionLifetime = TimeSpan.FromMinutes(15);
        // Same rule: never set an unconditional-true ServerCertificateCustomValidationCallback here.
    }
}
```

### Pattern 7: `Sensitive` Struct + Redact-Before-Wrap `NetworkError` (D-12, CR-04 carry-forward)

**What:** `struct Sensitive<T> { ToString() => "[SENSITIVE]" }`; harden `System.Text.Json` serialization with a custom converter; `NetworkError` MUST strip `Set-Cookie`/`Authorization`/`Cookie` headers from any wrapped `HttpResponseMessage`/exception before it's ever stored — mirrors the TypeScript `sanitizeAxiosError` fix from Phase 17 CR-04 (a real token-leak-via-error finding).

**Example:**
```csharp
// Source: sdks/CONTRACT.md §7 (locked C# mechanism: "Struct with ToString() override
// returning \"[SENSITIVE]\"") + Phase 17 CR-04 (sdks/typescript/src/core/errorMapper.ts
// sanitizeAxiosError) — the exact token-leak-via-error class of bug this pattern prevents.
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Axiam.Sdk.Core;

[JsonConverter(typeof(SensitiveJsonConverter<string>))]
public readonly struct Sensitive<T>
{
    private readonly T _value;
    internal Sensitive(T value) => _value = value; // internal ctor: only SDK-internal code can wrap a value
    internal T Reveal() => _value;                 // internal accessor: never a public getter (§7)
    public override string ToString() => "[SENSITIVE]";
}

public sealed class SensitiveJsonConverter<T> : JsonConverter<Sensitive<T>>
{
    public override Sensitive<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => throw new NotSupportedException("Sensitive<T> is write-only for serialization");
    public override void Write(Utf8JsonWriter writer, Sensitive<T> value, JsonSerializerOptions options)
        => writer.WriteStringValue("[SENSITIVE]"); // never emits the real value, even under System.Text.Json
}

public sealed class NetworkError : Exception
{
    private NetworkError(string message, Exception? inner) : base(message, inner) { }

    /// Wraps an HttpResponseMessage-derived failure. MUST be the ONLY construction path —
    /// never `throw new NetworkError(rawResponse.ToString())` anywhere else in the codebase.
    public static NetworkError FromResponse(HttpResponseMessage response, string context)
    {
        var sanitizedHeaders = response.Headers
            .Where(h => h.Key is not ("Set-Cookie" or "Authorization" or "Cookie"))
            .Select(h => $"{h.Key}: {string.Join(",", h.Value)}");
        var message = $"{context}: HTTP {(int)response.StatusCode} — headers: [{string.Join("; ", sanitizedHeaders)}]";
        return new NetworkError(message, inner: null); // note: raw `response` object itself is
                                                        // NEVER stored as InnerException/Data —
                                                        // only the pre-sanitized string survives
    }

    public static NetworkError FromException(Exception ex, string context) =>
        new($"{context}: {ex.GetType().Name} — {SanitizeMessage(ex.Message)}", inner: null);

    private static string SanitizeMessage(string raw)
    {
        // Defense in depth: strip anything that looks like a Set-Cookie/Authorization
        // fragment that may have leaked into an inner exception's .Message (e.g. from a
        // lower-level socket/TLS exception that echoed request headers verbatim).
        return System.Text.RegularExpressions.Regex.Replace(raw,
            @"(?i)(set-cookie|authorization|cookie)\s*:\s*[^\r\n]+", "$1: [SENSITIVE]");
    }
}
```
**Regression test (mirrors sibling SDKs' CR-04 test):** construct a `NetworkError` from a fixture `HttpResponseMessage` carrying a real-looking `Set-Cookie: axiam_access=abc123...` header; assert `"abc123"` never appears in `ToString()`, `Message`, or a `JsonSerializer.Serialize(error)` call. Include a **non-vacuous control case**: assert a *different*, non-secret header value (e.g. `Content-Type`) DOES still appear, proving the test isn't trivially passing because nothing survives at all.

### Anti-Patterns to Avoid

- **Claiming native .NET EdDSA support without verification:** CS-01's "native EdDSA on .NET 8+" phrasing is incorrect as of .NET 10 (the latest GA release) — do not let a plan silently assume `System.Security.Cryptography.Ed25519` exists; it does not.
- **Alphabetizing JSON keys before computing the AMQP HMAC:** this is the single highest-risk correctness bug in this phase (100% verification-failure rate, indistinguishable from a connectivity issue in testing) — use `JsonObject`'s insertion-order-preserving `Remove`+`ToJsonString`, never a POCO round-trip or a manually-sorted dictionary.
- **`ServerCertificateCustomValidationCallback` returning an unconditional `true`:** even for "just get it working" dev convenience — this is the exact §6/SC#4-prohibited pattern the CI grep gate exists to catch; use the `customCa` chain-trust-store pattern shown in Pattern 6 instead.
- **A general-purpose JWT library as a shortcut:** general JWT libraries (`Microsoft.IdentityModel.Tokens`, most third-party alternatives) either lack EdDSA support entirely or wrap it awkwardly — direct primitive-level BouncyCastle verification (Pattern 1) is simpler and has fewer moving parts for this specific verify-only use case.
- **Awaiting the refresh `Task` while still holding `_gate` in a fire-and-forget style that doesn't release on exception:** always release the semaphore in a `finally`, and clear a faulted `_inFlight` so a failed refresh doesn't get "stuck" cached for subsequent callers (Pattern 2).
- **Treating `AutomaticRecoveryEnabled`/`TopologyRecoveryEnabled` as needing explicit opt-in:** both already default to `true` in `RabbitMQ.Client` 7.x — don't add unnecessary ceremony, but DO set them explicitly in code for readability/documentation purposes per the project's own convention of explicit configuration.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Ed25519 signature verification primitive | A hand-rolled Edwards-curve implementation | `BouncyCastle.Cryptography`'s `Ed25519Signer`/`Ed25519PublicKeyParameters` | D-02's explicit "no hand-rolled crypto" — Ed25519 has subtle timing/malleability pitfalls that a 20+ year old, widely-audited library already solves correctly. |
| HMAC-SHA256 + constant-time comparison | A hand-rolled `==` byte comparison or a manual HMAC construction | `System.Security.Cryptography.HMACSHA256.HashData(...)` + `CryptographicOperations.FixedTimeEquals(...)` — both native, no extra dependency | Both are framework-provided, side-channel-resistant primitives confirmed present in net8.0; hand-rolling either reintroduces the exact timing-side-channel class of bug `FixedTimeEquals` exists to prevent. |
| Cookie jar / session persistence | A custom cookie parser/store | `HttpClientHandler{ UseCookies = true, CookieContainer = new() }` (or `SocketsHttpHandler` equivalent for the `IHttpClientFactory` path) | Cookie attribute parsing (domain/path/secure/`SameSite`) is exactly the kind of "looks simple, isn't" problem the BCL already solves correctly; contract-mandated (§4) regardless. |
| JWT/JWKS full-spec parsing (multiple algorithms, `x5c` chains, etc.) | A general-purpose JWT validation library pulled in "just in case" | The minimal hand-written header/payload/signature split shown in Pattern 1, scoped ONLY to the one algorithm (`EdDSA`) and one claim set (`exp`, `tenant_id`) the SDK actually needs | The SDK only ever needs to verify AXIAM's own EdDSA-signed tokens against AXIAM's own JWKS — a general-purpose multi-algorithm JWT library adds substantial unused surface area (and, per research, still lacks working EdDSA support in the most common option). |
| Async consumer dispatch / connection recovery for AMQP | A hand-rolled reconnect-and-redeliver loop around a synchronous consumer | `RabbitMQ.Client` 7.x's built-in `AutomaticRecoveryEnabled`/`TopologyRecoveryEnabled` + `AsyncEventingBasicConsumer` | The official client's automatic recovery already handles connection-loss/reconnect/topology-redeclare correctly and is on by default — reimplementing it is both unnecessary and a common source of subtle bugs (double-acks, lost consumer tags after reconnect). |
| gRPC/protobuf code generation | Hand-written protobuf message classes or a custom protoc invocation script | `Grpc.Tools` MSBuild integration (Pattern 4) | The one-line `<Protobuf>` MSBuild item is the officially documented, zero-maintenance approach; a custom build step would have to reinvent dependency tracking, incremental rebuilds, and multi-platform `protoc` binary resolution that `Grpc.Tools` already provides. |

**Key insight:** every "don't hand-roll" item in this phase maps to a place where .NET's own answer (native crypto, a general JWT library) is either **missing** (Ed25519) or **overkill** (full JWT spec support) — the correct response in both cases is a single, narrowly-scoped, well-vetted dependency, not a custom implementation and not a maximal general-purpose library.

## Common Pitfalls

### Pitfall 1: Assuming CS-01's "native EdDSA on .NET 8+" claim is accurate

**What goes wrong:** A plan that budgets zero effort for JWKS/JWT verification because the requirement doc says "native," then discovers mid-implementation that `System.Security.Cryptography.Ed25519` doesn't exist, forcing an unplanned dependency addition and rework of `JwksVerifier`.

**Why it happens:** CS-01 (and D-02) were written aspirationally based on the pattern of every other .NET cryptographic primitive being native (RSA, ECDsa, AES are all native) — but Ed25519 is the one prominent exception, and this has been an open `dotnet/runtime` proposal since 2016/2022 with no shipped implementation through .NET 10.

**How to avoid:** Treat this RESEARCH.md's finding as authoritative for planning purposes: budget `BouncyCastle.Cryptography` as a Wave-0/foundational dependency from the start, not a contingency.

**Warning signs:** Any task description that says "use native Ed25519" without a fallback library named is under-specified per this research.

### Pitfall 2: Alphabetizing (or POCO-round-tripping) JSON keys before computing the AMQP HMAC

**What goes wrong:** 100% HMAC verification failure rate in integration testing, easily misdiagnosed as a connectivity/config issue rather than a serialization-order bug (this exact failure mode was hit and diagnosed by the Python sibling SDK in Phase 19, then documented as a MUST-avoid pattern for every later SDK — see `.planning/STATE.md`).

**Why it happens:** The server's Rust `serde_json` struct serialization preserves **declaration order** (not alphabetical); .NET's default POCO serialization order is also not guaranteed to match, and a naive canonicalizer that alphabetizes keys (mirroring, e.g., Go's `encoding/json` map behavior, which DOES always sort) computes the HMAC over a different byte sequence entirely.

**How to avoid:** Use `System.Text.Json.Nodes.JsonObject` (backed by `OrderedDictionary`, confirmed from source) to parse, `Remove("hmac_signature")`, and re-serialize — never deserialize into a strongly-typed record for the purpose of computing the canonical bytes.

**Warning signs:** Any HMAC-verification code path that uses `JsonSerializer.Deserialize<SomeRecord>(...)` followed by `JsonSerializer.Serialize(...)` (record round-trip) instead of the `JsonNode`/`JsonObject` DOM approach.

### Pitfall 3: JWKS is organization-wide, not tenant-scoped — signature validity ≠ tenant authorization

**What goes wrong:** A token signed with a valid, currently-active key verifies successfully even if it was issued for a *different tenant* under the same AXIAM organization — if the SDK/middleware stops at "signature valid" without also checking the `tenant_id` claim against the configured tenant, cross-tenant token replay becomes possible.

**Why it happens:** `GET /oauth2/jwks` is registered at the top server scope (`crates/axiam-api-rest/src/server.rs`), outside any tenant path segment — the same JWKS document serves every tenant in the organization. Every sibling SDK (Rust/Go/Python/Java) independently confirmed and mitigated this.

**How to avoid:** Always check `tenant_id` claim == configured tenant AFTER signature verification succeeds, as shown in Pattern 1 and the ASP.NET Core middleware (Pattern 5).

**Warning signs:** Any `JwksVerifier.VerifyAsync`-equivalent method that returns claims without the caller (or the method itself) checking `tenant_id`.

### Pitfall 4: `HttpClientHandler`/`SocketsHttpHandler` override silently dropping the cookie jar or TLS strictness

**What goes wrong:** A caller supplies their own handler (e.g. via a custom `IHttpClientFactory` registration or a test double) that doesn't set `UseCookies=true`/`CookieContainer`, silently breaking the post-login session (every subsequent request looks unauthenticated) — or, worse, a caller-supplied handler with a permissive `ServerCertificateCustomValidationCallback` silently weakens TLS for the whole client.

**Why it happens:** .NET's `HttpClient`/handler composition model makes it easy to construct a "mostly correct" handler that's missing one critical property, and there's no compiler-level guarantee the SDK's required settings survive an override.

**How to avoid:** The SDK MUST always re-apply its own cookie container and TLS policy over any supplied handler (D-09's client-override safety requirement) — never trust a caller-supplied handler's settings for these two properties specifically.

**Warning signs:** Any code path that accepts an externally-constructed `HttpClient` (not just a `HttpMessageHandler`) directly without the SDK wrapping/re-configuring it.

### Pitfall 5: `RabbitMQ.Client` 6.x-era patterns copy-pasted into 7.x code

**What goes wrong:** Code that references `IModel` (renamed to `IChannel` in 7.x), calls synchronous `BasicAck`/`BasicNack`/`BasicConsume`, or checks a `DispatchConsumersAsync` flag (removed — all consumers are async in 7.x) fails to compile or silently misbehaves.

**Why it happens:** The overwhelming majority of existing RabbitMQ .NET tutorials and StackOverflow answers predate the 7.x async rewrite (a major breaking change); training-data-era knowledge is very likely to default to 6.x shapes.

**How to avoid:** Use only the confirmed-from-source 7.x signatures documented in Pattern 3 (`IChannel`, `*Async` suffix everywhere, `AsyncEventingBasicConsumer.ReceivedAsync` not `.Received`, `ConsumerDispatchConcurrency` not `DispatchConsumersAsync`).

**Warning signs:** Any reference to `IModel`, `EventingBasicConsumer.Received` (non-async), or `DispatchConsumersAsync` in new C# SDK code is a signal the wrong API generation was used.

## Code Examples

See **Architecture Patterns** above (Patterns 1–7) — all seven include complete, source-verified code with inline provenance comments. No additional standalone examples beyond what's already embedded there.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `RabbitMQ.Client` 6.x synchronous `IModel`/`BasicAck`/`EventingBasicConsumer.Received` | `RabbitMQ.Client` 7.x fully-async `IChannel`/`BasicAckAsync`/`AsyncEventingBasicConsumer.ReceivedAsync`, `DispatchConsumersAsync` flag replaced by `ConsumerDispatchConcurrency` | 7.0 (major async rewrite) | Any training-data-era or tutorial-derived RabbitMQ .NET code needs a full rewrite, not a patch, to target 7.x — this is why the CS-01 flag explicitly called this out for research verification. |
| Hoped-for native .NET Ed25519 (`dotnet/runtime` #14741/#63174) | Still unimplemented through .NET 10 GA; .NET 10's cryptography focus was post-quantum (ML-KEM/ML-DSA/SLH-DSA), not EdDSA | Ongoing — no shipped date as of this research | Every .NET SDK author needing EdDSA JWT verification (not just this project — same gap independently hit by the Java sibling SDK's `nimbus-jose-jwt`) must add a third-party crypto dependency; this is not expected to change soon given the multi-year-old open proposal. |
| `Microsoft.Extensions.Http`/`Logging.Abstractions` versioned to match the newest .NET (10.x preview lines showed up first in a naive registry query) | For a **net8.0-targeted library**, pin to the matching 8.x stable line (`8.0.1`/`8.0.3`) rather than forcing a dependency on 10.x-line BCL-extension packages | N/A — an authoring-convention point, not a library API change | Prevents unnecessarily widening the minimum runtime/SDK requirements for consumers who are still on .NET 8. |

**Deprecated/outdated:**
- `RabbitMQ.Client` 6.x API shapes (`IModel`, synchronous Basic* methods) — superseded by the 7.x async rewrite; do not reference in new code.
- Any assumption that `ScottBrady91.IdentityModel` is the current package name — it has been renamed to `ScottBrady.IdentityModel` (v4.1.0+).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `BouncyCastle.Cryptography` package name/version (`2.6.2`) and `ScottBrady.IdentityModel` package name/version (`4.1.0`) were discovered via WebSearch/community sources, not an authoritative first-party source; registry existence was independently confirmed via direct NuGet queries, but per the package-name provenance rule this remains `[ASSUMED]` | Standard Stack, Alternatives Considered, Package Legitimacy Audit | Low — both are extremely well-established, long-history packages confirmed on the registry directly; risk is limited to a possible version-number staleness, not a slopsquat/hallucination risk. |
| A2 | The exact .NET 8-compatible API for loading a custom CA certificate from PEM bytes (used in Pattern 6's `customCa` escape hatch) — shown as `X509CertificateLoader.LoadCertificate(...)`, which is confirmed to exist starting in .NET 9; on net8.0 the equivalent may instead be `new X509Certificate2(bytes)` (the pre-.NET-9 constructor, which is obsolete-with-warning starting .NET 9 but present and functional on net8.0) | Pattern 6 (HttpClient cookie jar / no-TLS-bypass) | Low-Medium — purely an API-surface detail; either API achieves the same PEM-to-certificate-object result on net8.0, but the plan/implementation should verify which constructor/loader is actually available and non-obsolete for the net8.0 TFM before finalizing this code. |
| A3 | `Google.Protobuf` companion package version alignment (recommended: match the `2.80.x` line used for `Grpc.Net.Client`/`Grpc.Tools`) was not independently version-checked against the NuGet registry this session (time-boxed) | Standard Stack (Core table) | Low — this is a very standard, well-known package pairing; if the exact patch version differs slightly from `Grpc.Net.Client`'s, NuGet's own dependency resolution will surface a clear conflict at restore time rather than a silent failure. |
| A4 | `dotnet/runtime` GitHub issues #14741 and #63174's precise open/closed *status* could not be read directly (WebFetch/`gh` both returned 403/not-found in this sandboxed environment) — the "still unimplemented" conclusion is inferred from the absence of any "Ed25519 shipped in .NET X" announcement across multiple independent searches (Microsoft Learn "what's new" docs, dotnet/core release notes, community blog posts current through mid-2026), not from a direct read of the issue tracker | Summary, Pattern 1 (research flag resolution) | Low — multiple independent corroborating sources (official .NET 10 release-notes pages, multiple 2025/2026-dated community blog posts explicitly stating "EdDSA is not yet supported out of the box in .NET") converge on the same conclusion; if wrong, the impact is that `BouncyCastle.Cryptography` becomes an unnecessary (but harmless) dependency rather than a required one — low downside. |
| A5 | Downloads-per-week figures in the Package Legitimacy Audit table are qualitative/directional (based on general knowledge of package prominence), not independently queried from a NuGet downloads-count API this session | Package Legitimacy Audit | Low — all flagged-OK packages are unambiguously well-established (official first-party or 15-20+ year old projects); the only package where download volume genuinely matters for risk assessment (`ScottBrady.IdentityModel`) is already flagged `[SUS]` with a `checkpoint:human-verify` gate regardless of the exact number. |

**If this table is empty:** N/A — see rows above.

## Open Questions (RESOLVED)

> All three resolved during planning (Phase 21 plans, commit `41a882c`): Q1 → plan `21-03` Task 2 adopts direct BouncyCastle; Q2 → plan `21-01` Task 1 resolves-then-pins `Google.Protobuf`; Q3 → plan `21-04` Task 1 selects the warning-free net8.0 PEM-loading API at code-time. Recommendations below stand as authored.

1. **[RESOLVED → 21-03 Task 2: direct BouncyCastle] Should the planner adopt the direct-BouncyCastle path or the `ScottBrady.IdentityModel` wrapper for JWKS verification?**
   - What we know: Direct BouncyCastle (Pattern 1) is simpler (one dependency, no Microsoft.IdentityModel.Tokens pipeline dependency), fully sufficient for the SDK's narrow needs (one algorithm, two claims checked), and avoids adding a single-maintainer package to the security-critical path. `ScottBrady.IdentityModel` offers `Microsoft.IdentityModel.Tokens` pipeline reuse (clock-skew handling, structured `TokenValidationParameters`) at the cost of a second, lower-profile dependency.
   - What's unclear: Whether the planner/team has an existing organizational preference for staying within the `Microsoft.IdentityModel.Tokens` ecosystem for consistency with other .NET auth code they may already run.
   - Recommendation: Default to direct BouncyCastle (this is what this research document's code examples and package table assume as primary); note this as an explicit, easily-reversible choice in the plan rather than something requiring a `checkpoint:human-verify` — the SUS flag is only relevant if the ScottBrady path is chosen instead.

2. **[RESOLVED → 21-01 Task 1: resolve-then-pin] Exact `Google.Protobuf` version to pin (see Assumption A3).**
   - What we know: It must be compatible with `Grpc.Net.Client`/`Grpc.Tools` 2.80.0.
   - What's unclear: The precise latest patch version in the 2.80.x (or whether to track 2.81.x) line was not independently queried this session.
   - Recommendation: Planner/implementer should run `dotnet add package Google.Protobuf` without a version pin initially (letting NuGet resolve the compatible version against the already-pinned `Grpc.Net.Client`/`Grpc.Tools` 2.80.0), then lock the resolved version in the `.csproj`.

3. **[RESOLVED → 21-04 Task 1: warning-free net8.0 API chosen at code-time] Exact PEM-loading API for the `customCa` escape hatch on net8.0 (see Assumption A2).**
   - What we know: Some certificate-loading API exists and works on net8.0 either way.
   - What's unclear: Whether `X509CertificateLoader` (the newer, non-obsolete .NET 9+ API) has a net8.0-compatible path, or whether the implementation should use the classic `X509Certificate2` constructor (functional but obsolete-with-warning starting .NET 9) for a net8.0-only SDK.
   - Recommendation: Implementer verifies at code-time via `dotnet build` warnings (`CA` obsolete-API diagnostics) which constructor is warning-free on the net8.0 TFM baseline and uses that one; either choice is behaviorally correct.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| .NET SDK | Building/testing `sdks/csharp/` | Not verified in this research session (no `dotnet` CLI probe was run against the actual execution environment — this research focused on library/API research, not local toolchain verification) | — | Planner/executor MUST verify `dotnet --version` reports an SDK ≥ 8.0.x before Wave 0; if absent, install via the official .NET install scripts (out of scope for this research doc). |
| RabbitMQ broker (for integration testing the AMQP consumer) | SC#2-adjacent AMQP integration tests, HMAC fixture tests | Not verified — no live broker probe performed | — | Use `docker compose` (an ephemeral RabbitMQ container) or a fixture-based unit test (canned Rust-signed byte payloads, matching the Python/Java sibling SDKs' approach) instead of a live broker for CI; this avoids an external-service dependency in CI entirely. |
| A running/reachable AXIAM server instance (for live JWKS fetch / login integration tests) | End-to-end verification of SC#1 | Not verified — this phase's server-side APIs are frozen and pre-existing (Phases 1-14), but no live instance was probed this session | — | Use `MockWebServer`/`HttpMessageHandler` test doubles seeded with fixture JWKS documents and login responses (mirrors every sibling SDK's approach) rather than a live server dependency for automated tests. |
| NuGet API key + `nuget.org` package namespace reservation for `Axiam.Sdk`/`Axiam.Sdk.AspNetCore` | SC#5 (live publish) | Not verified — CI secrets and package namespace reservation are an operational/maintainer concern outside this research's scope | — | Per D-04/Deferred: the `dotnet pack` + CI pipeline must structurally pass in-phase; live first publish may be a maintainer action if credentials/namespace are absent. |

**Missing dependencies with no fallback:** none identified — every dependency above has a documented fallback (fixture/mock-based testing, deferred live-publish action) that does not block phase completion.

**Missing dependencies with fallback:** all four rows above use a fixture/mock/deferred-action fallback rather than requiring a live external dependency during automated CI.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | xUnit 2.9.3 (`Microsoft.NET.Test.Sdk` + `xunit.runner.visualstudio`) |
| Config file | none yet — `sdks/csharp/tests/Axiam.Sdk.Tests/Axiam.Sdk.Tests.csproj` to be created in Wave 0 |
| Quick run command | `dotnet test sdks/csharp/tests/Axiam.Sdk.Tests --filter Category=Fast` |
| Full suite command | `dotnet test sdks/csharp` (solution-wide, incl. the SC#2 single-flight test and HMAC fixture tests) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CS-01 (SC#1) | `dotnet add package Axiam.Sdk` installs; `LoginAsync` returns typed `LoginResult`; `tenant` required ctor param (no default) | unit + compile-time (ctor overload check) | `dotnet test --filter FullyQualifiedName~ClientConstructionTests` | ❌ Wave 0 |
| CS-01 (SC#2) | 5 concurrent tasks on expired token ⇒ exactly 1 refresh | unit (xUnit, `Task.WhenAll` + counting fake handler) | `dotnet test --filter FullyQualifiedName~RefreshGuardSingleFlightTests` | ❌ Wave 0 |
| CS-01 (SC#3) | `Axiam.Sdk.AspNetCore` middleware protects a sample endpoint; runnable example demonstrates `[Authorize(Policy=...)]` | integration (in-memory `WebApplicationFactory`) + manual run of `examples/AspNetCoreSample` | `dotnet test --filter FullyQualifiedName~AspNetCoreMiddlewareTests` | ❌ Wave 0 |
| CS-01 (SC#4) | `Grpc.Tools` build-time codegen documented; no `ServerCertificateCustomValidationCallback` bypass anywhere | build (codegen succeeds) + static grep gate | `dotnet build sdks/csharp/Axiam.Sdk` && `grep -rn "ServerCertificateCustomValidationCallback" sdks/csharp --include=*.cs \| grep -v "chain!.ChainPolicy"` (expect empty after excluding the one allowed `customCa` chain-trust pattern) | ❌ Wave 0 |
| CS-01 (SC#5) | `dotnet pack` succeeds, produces valid `.nupkg`; NuGet publish pipeline documented/operational | build + CI pipeline dry-run | `dotnet pack sdks/csharp/Axiam.Sdk -c Release` | ❌ Wave 0 |
| CS-01 (§8 AMQP HMAC) | HMAC verify-before-handler matches server byte-for-byte (wire-order preservation) | unit (fixture-based, using a real Rust-signed byte vector) | `dotnet test --filter FullyQualifiedName~HmacVerifyTests` | ❌ Wave 0 |
| CS-01 (CR-04 carry-forward) | Raw token never appears in `NetworkError`'s `ToString`/JSON/logs | unit (regression, non-vacuous control case) | `dotnet test --filter FullyQualifiedName~SensitiveRedactionTests` | ❌ Wave 0 |
| CS-01 (D-02) | JWKS Ed25519 verification round-trips against a real AXIAM-issued token/JWKS fixture | unit (fixture-based, mirrors the Java sibling's throwaway-harness-then-committed-test approach) | `dotnet test --filter FullyQualifiedName~JwksVerifierTests` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `dotnet test sdks/csharp/tests/Axiam.Sdk.Tests --filter Category=Fast` (unit tests only: `Sensitive<T>` redaction, HMAC sign/verify fixture vectors, JWKS `kid` lookup logic, refresh-guard single-flight)
- **Per wave merge:** `dotnet test sdks/csharp` (full solution, incl. `WebApplicationFactory`-based ASP.NET Core middleware integration tests)
- **Phase gate:** Full suite green + `dotnet build`/`dotnet pack` succeed + TLS-bypass grep gate empty, before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `sdks/csharp/tests/Axiam.Sdk.Tests/Axiam.Sdk.Tests.csproj` — test project scaffold (xUnit + Moq + Microsoft.NET.Test.Sdk references)
- [ ] `sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/` — a real Rust-signed HMAC byte-vector fixture (generate once via a throwaway call into `crates/axiam-amqp`'s `sign_payload`, or via a small standalone Rust binary, then commit the fixed byte array + expected hex signature as test data — do NOT depend on `axiam-amqp` at runtime, only to *generate* the fixture)
- [ ] `sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/` — a real Ed25519 keypair + AXIAM-shaped JWKS document + a matching signed JWT fixture (mirrors the Java sibling's "throwaway debug harness before committing" approach for empirically confirming the BouncyCastle verify path against a real signature, not just a self-signed round-trip)
- [ ] Framework install: `dotnet add package xunit xunit.runner.visualstudio Microsoft.NET.Test.Sdk Moq` (Wave 0, alongside the main `Axiam.Sdk`/`Axiam.Sdk.AspNetCore` project scaffolds)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | JWT (EdDSA/Ed25519) verification via `BouncyCastle.Cryptography` (Pattern 1); reactive 401-driven re-authentication fallback via `RefreshGuard` (Pattern 2); never a client-side credential store beyond the `HttpClientHandler` cookie jar. |
| V3 Session Management | yes | `HttpClientHandler{ UseCookies=true, CookieContainer=new() }` (§4); single-flight refresh with no retry-loop on refresh failure (§9); ASP.NET Core middleware never caches verification beyond the token's remaining TTL (§10). |
| V4 Access Control | yes | Server-side additive-only, allow-wins, default-deny RBAC is the sole source of truth (`CheckAccessAsync`/gRPC `CheckAccess`); ASP.NET Core `IAuthorizationHandler` (D-08) never implements client-side deny-override or long-lived authz caching; JWKS org-wide-not-tenant-scoped requires an explicit post-verification `tenant_id` claim check (Pitfall 3). |
| V5 Input Validation | yes | `System.Text.Json` for all request/response (de)serialization; JWT/JWKS parsing (Pattern 1) validates `alg` BEFORE key lookup (never trusts a token's self-declared algorithm to select a verifier — classic "alg confusion" JWT vulnerability class); AMQP HMAC verification (Pattern 3) never throws on malformed attacker-controlled input, always fails closed (`false`/nack-without-requeue). |
| V6 Cryptography | yes | `BouncyCastle.Cryptography` (Ed25519, verify-only, never hand-rolled) for JWT/JWKS; native `HMACSHA256`+`CryptographicOperations.FixedTimeEquals` (both framework-provided, side-channel-resistant) for AMQP HMAC — no cryptographic primitive in this SDK is hand-implemented. |

### Known Threat Patterns for .NET/ASP.NET Core SDK

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| JWT "alg confusion" (attacker crafts a token with a different/`none` algorithm to bypass verification) | Spoofing | Pin `alg=="EdDSA"` from the token header BEFORE any key lookup or verification attempt (Pattern 1) — never branch verifier selection on untrusted input beyond this single explicit check. |
| Cross-tenant token replay (valid signature, wrong tenant) | Elevation of Privilege | Mandatory post-signature `tenant_id` claim check against the configured tenant (Pitfall 3) — signature validity alone never implies tenant authorization given the org-wide JWKS. |
| AMQP message tampering / forged events | Tampering | HMAC-SHA256 verify-before-handler (Pattern 3), constant-time compare, fail-closed (nack without requeue) on any verification failure, security-event logging without leaking the HMAC value itself. |
| Token leakage via exception/log message (`NetworkError` wrapping a raw `HttpResponseMessage` carrying `Set-Cookie`) | Information Disclosure | Redact-before-wrap `NetworkError` (Pattern 7) — this is a **carried-forward, previously-confirmed real bug class** (Phase 17 CR-04), not a hypothetical. |
| TLS downgrade / certificate-validation bypass | Tampering / Information Disclosure | Absolute prohibition on any unconditional-`true` `ServerCertificateCustomValidationCallback` (§6/SC#4); CI grep gate; the only escape hatch is an additive `customCa` chain-trust-store addition (Pattern 6), which never weakens verification for certs outside the custom CA. |
| Thundering-herd token refresh (many concurrent 401s triggering many refresh calls, potentially exhausting the refresh-token's single-use budget or triggering rate-limiting) | Denial of Service (self-inflicted) | `SemaphoreSlim(1,1)` + shared `Task<TokenPair>` single-flight guard (Pattern 2), proven by the SC#2 concurrency test. |

## Sources

### Primary (HIGH confidence)

- `github.com/rabbitmq/rabbitmq-dotnet-client` (`main` branch source: `v7-MIGRATION.md`, `ConnectionFactory.cs`, `IChannel.cs`, `Constants.cs`, `Events/AsyncEventingBasicConsumer.cs`) — fetched directly, 2026-07-02.
- `github.com/bcgit/bc-csharp` (`master` branch source: `Ed25519PublicKeyParameters.cs`) — fetched directly, 2026-07-02.
- `github.com/dotnet/runtime` (`main` branch source: `System.Text.Json/.../Nodes/JsonObject.cs`, `HMACSHA256.cs`) — fetched directly, 2026-07-02.
- `api.nuget.org/v3-flatcontainer/*/index.json` — direct registry queries for `rabbitmq.client`, `grpc.net.client`, `grpc.tools`, `bouncycastle.cryptography`, `microsoft.extensions.http`, `microsoft.extensions.logging.abstractions`, `xunit`, `moq`, `nsec.cryptography` — queried directly, 2026-07-02.
- `sdks/CONTRACT.md` §1–§10 (this repository, binding) — read in full.
- `crates/axiam-oauth2/src/oidc.rs`, `crates/axiam-api-rest/src/handlers/oauth2.rs`, `crates/axiam-auth/src/token.rs`, `crates/axiam-amqp/src/messages.rs` (this repository) — read in full to confirm JWKS shape/path and AMQP HMAC protocol.
- `.planning/STATE.md`, `.planning/phases/{16,18,19,20}-*/{CONTEXT,RESEARCH}.md` (this repository) — sibling-phase precedent, especially Phase 19's proven wire-order HMAC fix and Phase 20's `nimbus-jose-jwt` EdDSA-gap finding.

### Secondary (MEDIUM confidence)

- Microsoft Learn: "What's new in .NET 10 libraries" / "Cross-platform cryptography" (WebSearch-surfaced, cross-checked against multiple independent queries).
- `damienbod.com/2025/08/06/use-eddsa-signatures-to-validate-tokens-in-asp-net-core-using-openid-connect` and `scottbrady.io/c-sharp/eddsa-for-jwt-signing-in-dotnet-core` — community-authoritative (recognized .NET identity/security practitioners), corroborating the "EdDSA not natively supported" finding.
- `nsec.rocks` / NSec.Cryptography NuGet page — for the native-libsodium-binary packaging tradeoff.

### Tertiary (LOW confidence)

- General WebSearch-aggregated summaries (not independently re-verified against a primary source) regarding `ScottBrady.IdentityModel`'s exact adoption/download profile — flagged `[SUS]` in the Package Legitimacy Audit accordingly.
- The precise open/closed status of `dotnet/runtime` issues #14741/#63174 (WebFetch/`gh` access to github.com issue pages returned 403 in this environment) — conclusion inferred from absence of a "shipped" announcement, not a direct issue-tracker read (see Assumption A4).

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every pinned/recommended package version was checked directly against the NuGet v3 registry this session; RabbitMQ.Client and BouncyCastle API surfaces confirmed directly from GitHub source, not from memory or secondary docs.
- Architecture: HIGH — every pattern (cookie jar, JWKS verify, HMAC verify, single-flight refresh, middleware, DI extensions) is either a direct mirror of proven code/patterns already in this repository's sibling SDKs (Rust/Go/Python/Java) or confirmed directly from official/source-level references.
- Pitfalls: HIGH — Pitfalls 1, 2, 3, and 5 are all empirically-confirmed, previously-encountered issues (logged in `.planning/STATE.md` or independently rediscovered via direct source verification this session), not speculative.

**Research date:** 2026-07-02
**Valid until:** 2026-08-01 (30 days) — shorten to ~14 days specifically for the "no native .NET Ed25519 support" finding if a .NET 10 servicing release or .NET 11 preview is announced in the interim, since this is the single most likely fact in this document to change upstream.
