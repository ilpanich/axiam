# Phase 21: C# SDK - Context

**Gathered:** 2026-07-02
**Status:** Ready for planning

> **Discussion note:** Interactive discuss session. The user selected all four
> originally-presented C#-specific gray areas (Target frameworks, Package split,
> ASP.NET Core depth, HttpClient lifecycle), then chose "explore more" once to
> cover async surface, the RabbitMQ.Client 7.2 consumer shape, and NuGet
> publishing — **11 C#-specific decisions across 3 rounds**. Every choice is
> grounded in the binding `sdks/CONTRACT.md` §1–§10, the `CS-01` pinned deps, and
> the five sibling reference SDKs (Rust 16, TypeScript 17, Go 18, Python 19,
> Java 20). All decisions below are **user-confirmed**. Low-level items (exact
> timeout/deadline/backoff/prefetch numbers, gRPC channel/interceptor specifics,
> internal namespace/file layout, csproj plugin versions) are explicitly
> delegated to research/planner.

<domain>
## Phase Boundary

Phase 21 delivers `sdks/csharp/` — the NuGet package **`Axiam.Sdk`** and its
web-framework companion **`Axiam.Sdk.AspNetCore`** — the **sixth SDK** (after
Rust ref Phase 16, TypeScript Phase 17, Go Phase 18, Python Phase 19, Java
Phase 20). It implements the full client capability baseline against the frozen
v1.0 APIs in idiomatic .NET on a **net8.0** baseline:

- **REST** (`HttpClient` + `HttpClientHandler { UseCookies = true, CookieContainer }`)
  — auth flow (`LoginAsync` → `VerifyMfaAsync`), `RefreshAsync`, `LogoutAsync`,
  `CheckAccessAsync`/`Can`, `BatchCheckAsync`. JSON via `System.Text.Json`.
- **gRPC** (`Grpc.Net.Client` 2.80 over HTTP/2) — `CheckAccess`, `BatchCheckAccess`.
  Stubs generated at build time by **`Grpc.Tools` MSBuild** (`<Protobuf Include=
  "../../proto/**/*.proto" GrpcServices="Client" />`) — the **one documented
  exception** to the repo-wide `buf` pipeline (Phase 15 D-01).
- **AMQP** (`RabbitMQ.Client` 7.2, fully-async API) — event consumer with
  HMAC-SHA256 verify-before-handler and automatic recovery.
- Local JWKS verification (EdDSA/Ed25519) for proactive refresh; a first-class
  **ASP.NET Core** integration (`Axiam.Sdk.AspNetCore`) providing middleware +
  `ClaimsPrincipal` + policy-based authorization.

Public API is **async-only** (Task-returning `*Async` + `CancellationToken`). It
conforms to `sdks/CONTRACT.md` §1–§10 in full and **inherits the
Rust/TS/Go/Python/Java reference patterns** wherever a .NET analog exists. C# is a
**non-browser** SDK, so §3 CSRF = capture `X-CSRF-Token` from the response header
(not the browser cookie double-submit the TS browser persona uses). The novel
work this phase resolves is everything .NET's ecosystem forces — `Grpc.Tools`
build-time codegen (the buf exception), the ASP.NET Core authentication +
authorization integration, `IHttpClientFactory`-compatible lifecycle, the
`RabbitMQ.Client` 7.x async consumer API, native/near-native EdDSA verification,
and NuGet publishing.

**In scope (CS-01):** the `sdks/csharp/` solution + all three transports +
`Axiam.Sdk.AspNetCore` middleware/DI + examples + NuGet publish CI, with
`SemaphoreSlim(1,1)` single-flight refresh, HMAC verify, and the no-TLS-bypass
gate proven by test.

**Out of scope:** any change to the AXIAM server (v1.0 APIs are frozen; the SDK
is a pure external client and MUST NOT depend on server crates); the remaining
PHP SDK (Phase 22); the shared foundation already delivered in Phase 15
(`buf.gen.yaml`, `CONTRACT.md`, FND-04 endpoint, scaffold); netstandard2.0 /
.NET Framework support (see Deferred).

</domain>

<decisions>
## Implementation Decisions

> **Note:** The SDK's *behavioral* surface is already locked by the binding
> `sdks/CONTRACT.md` §1–§10 and by `CS-01` (pinned deps: Grpc.Net.Client 2.80,
> RabbitMQ.Client 7.2; `SemaphoreSlim(1,1)` single-flight; `HttpClientHandler`
> `CookieContainer`; `tenant` required constructor param; `Grpc.Tools` codegen;
> `Axiam.Sdk.AspNetCore` sub-package; NuGet `Axiam.Sdk`). The decisions below are
> the **HOW choices** — all **user-confirmed** in the 2026-07-02 discuss session.
> They do not restate the contract — downstream agents MUST read CONTRACT.md.

### Target Framework & Cryptography
- **D-01 [LOCKED]:** **net8.0-only baseline.** Single TFM, matches the scaffold's
  `<TargetFramework>net8.0</TargetFramework>`. Native EdDSA path, native gRPC
  (HTTP/2), and the `RabbitMQ.Client` 7.2 async API all work cleanly. Covers the
  ASP.NET Core 8+ audience CS-01/SC#3 name. **netstandard2.0 + BouncyCastle
  multi-target is deferred** (see Deferred) — CS-01 mentions it, but it is out of
  scope for this v1.1 starter SDK.
- **D-02:** **EdDSA (Ed25519) local JWKS verification — native-preferred, minimal
  verify-only crypto dep as the researched fallback.** Prefer
  `System.Security.Cryptography` on net8.0 (CS-01 intent). **`.NET` Ed25519 JWT
  verification is a known gap** — `System.Security.Cryptography`'s Ed25519 support
  is thin/absent depending on runtime, and `Microsoft.IdentityModel` JWT handlers
  historically don't verify EdDSA. **Researcher MUST confirm** native net8.0
  Ed25519 verification is viable; if not, permit **one** well-vetted crypto
  library (e.g. NSec/libsodium or BouncyCastle) scoped **only** to signature
  verification. **No hand-rolled crypto.** Reactive 401-driven refresh remains as
  the fallback path either way. (See Canonical Refs research flag.)

### Packaging & Distribution
- **D-03 [LOCKED]:** **Two NuGet packages.** `Axiam.Sdk` = REST + gRPC + AMQP +
  `Sensitive` + JWKS (everything except the web framework); `Axiam.Sdk.AspNetCore`
  = middleware + DI + authorization (depends on core). Matches CS-01/SC#3 exactly,
  keeps core free of ASP.NET Core framework deps, mirrors Java's single-jar +
  optional-Spring model. **`Grpc.Net.Client` + `RabbitMQ.Client` are always-on
  deps of core** (transports are NOT split into separate packages — user accepted
  this footprint tradeoff).
- **D-04 [LOCKED]:** **NuGet publish = API key + SourceLink + snupkg symbols.**
  `dotnet pack` → `dotnet nuget push` with a NuGet API key from CI secrets;
  **tag-triggered** (`sdks/csharp/vX.Y.Z`, Phase 15 D-13). Enable Deterministic
  build + SourceLink (GitHub) + `.snupkg` symbol packages pushed to nuget.org.
  Author package **signing (cert) deferred/optional** — nuget.org repo-signs on
  ingest. Documented credential setup per CS-01/SC#5. **Trusted Publishing (OIDC)
  is the preferred future path** but not provisioned in-phase (see Deferred). Live
  first publish may be a maintainer action if namespace/creds are absent in CI;
  the pipeline + `dotnet pack` (SC#5) must still pass.
- **D-05 [LOCKED]:** **gRPC codegen = `Grpc.Tools` MSBuild, generate-on-build,
  bundled compiled.** Stubs generated at build via `<Protobuf Include=
  "../../proto/**/*.proto" GrpcServices="Client" />` into `obj/` (gitignored);
  compiled stub classes ship inside the published package. This is the **contract
  §-documented C# exception** to `buf generate` (Phase 15 D-01). Generated sources
  are NOT committed. Optional CI drift-check.

### ASP.NET Core Integration
- **D-06 [LOCKED]:** **Full-idiom integration (authentication).** `Axiam.Sdk.AspNetCore`
  provides the contract-§10 `app.UseMiddleware<AxiamAuthMiddleware>()` form **and**
  sets `HttpContext.User` to a `ClaimsPrincipal` (claims: `user_id`, `tenant_id`,
  `roles`) so standard `[Authorize]` / policy-based auth works. Reads `X-Tenant-ID`
  (or configured tenant) per §10; surfaces `AuthError` → 401 with the standardized
  JSON body; never caches verification beyond the token's remaining TTL. Direct
  analog of Java D-14's Spring `SecurityContext` integration.
- **D-07 [LOCKED]:** **DI extensions + Options pattern.** Ship `AddAxiam()` /
  `AddAxiamAspNetCore()` `IServiceCollection` extension methods + a typed Options
  class for configuration. What enterprise ASP.NET Core devs expect; keeps the raw
  `UseMiddleware` form available for the contract-literal path.
- **D-08 [LOCKED]:** **Policy-based authorization integration (authz half / 403).**
  Include an `IAuthorizationHandler` + policy provider so
  `[Authorize(Policy="resource:action")]` calls `client.CheckAccessAsync` under the
  hood — `[Authorize]` yields 401 (unauthenticated), failed AXIAM authz yields 403
  (`AuthzError`) with the standardized JSON body (§10). The idiomatic .NET authz
  surface; the runnable example (SC#3) MUST demonstrate it. Within the ASP.NET
  integration domain (framework integration helper), not a new capability.

### HttpClient Lifecycle & Transports
- **D-09 [LOCKED]:** **SDK-owned handler by default + optional `IHttpClientFactory`
  path.** By default the SDK owns its `HttpClient` + `HttpClientHandler` —
  guaranteeing the §4 persistent `CookieContainer`, the §6 strict-TLS/no-bypass
  config, and `IDisposable` lifecycle. **Also** offer a DI/typed-client path where
  `AddAxiam()` registers via `IHttpClientFactory` using `SocketsHttpHandler` with
  `UseCookies` + `PooledConnectionLifetime` (dodges socket exhaustion). **Client-
  override safety (Java D-27 analog):** the SDK **always re-applies its own cookie
  container (§4) + strict TLS/no-bypass (§6) over any supplied handler** — an
  override can never silently drop the cookie jar (breaks post-login) or weaken TLS
  (SC#4). **No `ServerCertificateCustomValidationCallback` bypass anywhere**
  (SC#4); only a `customCa` escape hatch.
- **D-10 [LOCKED]:** **Async-only public API + `CancellationToken`.** All I/O
  methods are Task-returning `*Async` with a `CancellationToken` parameter; **no
  sync wrappers** (avoids sync-over-async deadlocks, halves the API surface).
  `ConfigureAwait(false)` throughout the library. §9 single-flight guard =
  `SemaphoreSlim(1,1)` + a shared `Task<TokenPair>` field, **one guard across REST
  + gRPC** on one client. SC#2: 5 concurrent tasks on an expired token ⇒ exactly 1
  refresh (xUnit test). ValueTask micro-optimization rejected as over-engineering.
- **D-11 [LOCKED]:** **AMQP consumer = `AsyncEventingBasicConsumer` + callback,
  verify-before-handler.** Register a `RabbitMQ.Client` 7.x
  `AsyncEventingBasicConsumer`; on each delivery verify HMAC-SHA256 (constant-time
  compare) **before** invoking a consumer-supplied async handler. Handler success →
  `BasicAckAsync`; retryable failure → `BasicNackAsync` **WITH** requeue;
  HMAC-fail / parse-fail / drop-sentinel → `BasicNackAsync` **WITHOUT** requeue +
  security log. Handler never sees an unverified message. Enable the client's
  built-in automatic recovery. Direct Java D-13 / Go analog.

### Token Safety & Verification (carried forward from siblings)
- **D-12:** **`Sensitive` — struct with `ToString()` → `"[SENSITIVE]"` (§7 floor)
  + redact-before-wrap on `NetworkError` (CR-04 carry-forward).** Per CONTRACT §7
  C# row. Additionally harden `System.Text.Json` serialization to emit
  `[SENSITIVE]`. `AuthError`/`AuthzError`/`NetworkError` from one central
  status→error mapper (HTTP §2 table + gRPC status codes). **`NetworkError` MUST
  redact `Set-Cookie`/`Authorization`/`Cookie` from any wrapped
  `HttpResponseMessage`/exception before storing it** — never let a raw token enter
  the exception chain, `ToString`, or logs. Add a regression test analogous to the
  sibling error-redaction tests (assert the raw `axiam_access`/`axiam_refresh`
  value never appears in `ToString`/JSON/log of a thrown error, with a non-vacuous
  control case). Direct TS Phase 17 CR-04 carry-forward.

### Claude's Discretion (delegated to research/planner)
- Internal namespace/folder/file layout under `sdks/csharp/`.
- Exact numeric timeout/deadline/backoff/retry values, gRPC per-call deadline,
  AMQP prefetch/QoS. (Sane defaults, builder/options-overridable; idempotent-only
  bounded exponential backoff + jitter, honor `Retry-After`; state-changing
  requests never auto-retry — Java D-26 / Go analog.)
- gRPC channel construction, interceptor ordering, and metadata injection
  (`Authorization`/`X-Tenant-Id`/`X-CSRF-Token`); one long-lived channel reused
  across authz RPCs, disposed with the client.
- `LoginResult` optional-field set beyond `MfaRequired`; DTO style (records +
  nullable reference types — scaffold already has `<Nullable>enable`).
- csproj/CI plugin + package versions; SourceLink/deterministic-build config
  specifics; `Grpc.Tools` version; JWKS cache-TTL and rotation-on-unknown-`kid`
  specifics.
- Logging facade choice (`Microsoft.Extensions.Logging.Abstractions`, silent by
  default, redaction-aware — never logs `Sensitive` values).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Binding contract & phase definition (read FIRST)
- `sdks/CONTRACT.md` §1–§10 — **normative/binding** cross-language behavioral
  contract. The C# SDK *implements* this. Relevant §: §1 PascalCase method map
  (row: C#), §2 error taxonomy + status mapping (D-12), §3 CSRF (**C# =
  non-browser → `X-CSRF-Token` response header**), §4 cookie jar
  (**"`HttpClient` with `HttpClientHandler { UseCookies = true, CookieContainer =
  new() }`"** → D-09), §5 tenant (required constructor param, SC#1), §6 TLS
  no-bypass (D-09; SC#4 gate — no `ServerCertificateCustomValidationCallback`), §7
  `Sensitive` (**"Struct with `ToString()` override returning `\"[SENSITIVE]\"`"**
  → D-12), §8 AMQP HMAC protocol (D-11), §9 single-flight (**"`SemaphoreSlim(1,1)`
  + `Task<TokenPair>` stored in field"** → D-10), §10 ASP.NET Core middleware
  (**"`app.UseMiddleware<AxiamAuthMiddleware>()` in `Program.cs`"** → D-06). The
  **"C# `Grpc.Tools` Exception"** closing note is the direct source for D-05.
- `.planning/ROADMAP.md` — Phase 21 goal + 5 success criteria; the
  `sdks/<lang>/vX.Y.Z` tag convention (Phase 15 D-13) the publish CI follows.
- `.planning/REQUIREMENTS.md` §CS-01 — acceptance criteria + pinned deps (HttpClient
  + Grpc.Net.Client 2.80 + RabbitMQ.Client 7.2; native EdDSA on .NET 8+ /
  BouncyCastle for netstandard2.0; `SemaphoreSlim(1,1)`; `HttpClientHandler.CookieContainer`;
  `Grpc.Tools` MSBuild codegen; `Axiam.Sdk.AspNetCore` middleware sub-package;
  NuGet `Axiam.Sdk` + credential setup).

### ⚠ Research flags (must resolve before planning)
- **Native .NET Ed25519 JWT verification viability (D-02).** Confirm whether
  net8.0 `System.Security.Cryptography` / `Microsoft.IdentityModel.Tokens` can
  verify EdDSA (Ed25519) JWTs locally. If not, select the single verify-only crypto
  dependency (NSec/libsodium vs BouncyCastle). This gates the proactive-refresh +
  middleware local-verification path. CS-01 asserts "native EdDSA on .NET 8+" —
  verify this claim against reality.
- **`RabbitMQ.Client` 7.2 async consumer API surface (D-11).** 7.x is a breaking
  async rewrite of 6.x — confirm `AsyncEventingBasicConsumer` + `BasicAckAsync`/
  `BasicNackAsync` names/signatures and automatic-recovery config.

### Prior-phase decisions this phase inherits
- `.planning/phases/20-java-sdk/20-CONTEXT.md` — **closest analog** (compiled
  static-typed enterprise SDK). Framework SecurityContext integration (→ D-06),
  single-jar + optional-framework packaging (→ D-03), generate-on-build + bundle
  compiled (→ D-05), client-override safety (→ D-09), single `LoginResult` + flag
  (→ D-10), redact-before-wrap (→ D-12), bounded-backoff/timeouts/logging discretion.
- `.planning/phases/19-python-sdk/19-CONTEXT.md` — sync+async dual-surface framing
  (C# resolves to async-only, D-10), `Sensitive` multi-surface redaction (→ D-12),
  publish/signing framing (→ D-04).
- `.planning/phases/18-go-sdk/18-CONTEXT.md` — non-browser reference. Typed error +
  redact-before-wrap (→ D-12), closure/callback AMQP consumer (→ D-11),
  identity-injection middleware (→ D-06), client override safety (→ D-09).
- `.planning/phases/17-typescript-sdk/17-CONTEXT.md` + `17-REVIEW.md` §CR-04 +
  `17-VERIFICATION.md` — the **token-leak-via-error** finding + `sanitizeAxiosError()`
  fix; **D-12's redact-before-wrap is the direct C# carry-forward.** Read CR-04
  before implementing `NetworkError`.
- `.planning/phases/16-rust-sdk/16-CONTEXT.md` — first reference (local JWKS + OIDC
  discovery/rotation → D-02, shared-session single-flight → D-10, closure-handler
  AMQP → D-11, regenerate-and-bundle publish → D-05).
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — D-01 (**`Grpc.Tools` C#
  exception → D-05**), D-05 (FND-04 `/authz/check` + `/batch`), D-09/D-10 (binding
  contract + locked vocabulary), D-11/D-12/D-13 (package identities + monorepo tag
  scheme `sdks/csharp/vX.Y.Z`).

### SDK domain research (read for rationale)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth, monorepo +
  path-filtered CI.
- `.planning/research/STACK.md` — toolchain + plugin set.
- `.planning/research/PITFALLS.md` — cross-language divergence trap + the
  **TLS-bypass pitfall** (→ SC#4 gate; C# =
  `ServerCertificateCustomValidationCallback` bypass).
- `.planning/research/FEATURES.md` — per-SDK feature matrix.
- `.planning/research/SUMMARY.md` — consolidated research synthesis
  (TLS-disabled anti-pattern).

### Code the SDK consumes / mirrors (reuse semantics; do NOT depend on server crates)
- `crates/axiam-amqp/src/messages.rs` — **AMQP HMAC reference impl** (§8):
  canonical-JSON + hex-HMAC-SHA256 protocol the C# verify (D-11) must match
  byte-for-byte (use `System.Security.Cryptography.HMACSHA256` +
  `CryptographicOperations.FixedTimeEquals` for constant-time compare).
- `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`), the
  Go/Python/Java error + sensitive modules — the redaction implementations D-12
  mirrors in C#.
- `sdks/rust/src/`, `sdks/go/`, `sdks/python/src/axiam_sdk/`, `sdks/java/src/` —
  reference trees (session/single-flight, grpc interceptor, amqp consumer,
  middleware, sensitive) — structural analogs for the C# namespaces.
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface
  the C# stubs cover; `CheckAccess`/`BatchCheckAccess` request/response shapes for
  the gRPC client.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC
  `check_access`/`batch_check_access` semantics the C# gRPC client targets.
- REST `POST /api/v1/authz/check` + `/api/v1/authz/check/batch` (Phase 15 FND-04,
  `crates/axiam-api-rest/src/handlers/authz_check.rs`) — the endpoints
  `CheckAccessAsync`/`Can`/`BatchCheckAsync` call.
- `sdks/buf.gen.yaml` — buf codegen config for the OTHER SDKs; C# is the documented
  exception (D-05) and does NOT add a plugin entry here — it uses `Grpc.Tools` in
  the `.csproj`.
- `sdks/csharp/{Axiam.Sdk/Axiam.Sdk.csproj,README.md,LICENSE}` — existing scaffold
  (`net8.0`, `PackageId=Axiam.Sdk`, `<Nullable>enable`, Apache-2.0, README states
  CONTRACT.md conformance + the `Grpc.Tools` exception) — Phase 21 fills it in.
- OIDC `/.well-known/jwks.json` (exact path to confirm in research) — JWKS source
  for D-02.

### Project-wide constraints
- License is **Apache-2.0** repo-wide — `sdks/csharp/LICENSE` + csproj
  `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>` already match;
  keep them. See project memory `project_license_apache.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `sdks/rust/`, `sdks/typescript/`, `sdks/go/`, `sdks/python/`, `sdks/java/` —
  **five** complete reference implementations of the same contract; the C# SDK
  ports their structure (shared session + single-flight guard, gRPC interceptor/
  metadata, callback AMQP consumer, JWKS cache, middleware) into idiomatic .NET 8.
- The sibling error-redaction + `Sensitive` implementations — the exact behavior
  C#'s `NetworkError` (D-12) and `Sensitive` struct mirror (CR-04 carry-forward).
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify; the C# consumer
  reimplements *verification* (cannot depend on the crate) but the canonical-JSON +
  hex-HMAC-SHA256 protocol must be byte-identical (§8 / D-11); use `HMACSHA256` +
  `CryptographicOperations.FixedTimeEquals`.
- `proto/axiam/v1/*.proto` — the proto surface; D-05 generates C# stubs at build
  via `Grpc.Tools` (NOT buf), gitignored, bundled compiled into the package.
- `sdks/csharp/` scaffold (`Axiam.Sdk.csproj` with `Axiam.Sdk` + Apache-2.0,
  LICENSE, README documenting the `Grpc.Tools` exception) — Phase 21 fills it in;
  `net8.0` + `<Nullable>enable` already set (D-01).

### Established Patterns
- **CONTRACT.md is binding (Phase 15 D-09):** "CONTRACT.md §1–§10 conformance
  verified" is a required acceptance checklist item for this phase.
- **No TLS bypass (§6 / SC#4):** no `ServerCertificateCustomValidationCallback`
  override; a CI grep gate over `sdks/csharp/` (source + examples + tests) MUST
  return empty. Only a `customCa` escape hatch.
- **C# is the codegen exception (§ / Phase 15 D-01):** `Grpc.Tools` MSBuild, NOT
  `buf generate`. This is intentional and documented — do not "fix" it to buf.
- **Additive-only / allow-wins / default-deny RBAC** constrains how the SDK
  surfaces authz `reason` semantics (mirrors gRPC), and how the ASP.NET policy
  handler maps authz results to 403 (D-08).
- **Monorepo tag release** (`sdks/csharp/vX.Y.Z`, Phase 15 D-13) — the publish CI
  follows it.
- **Codegen distribution differs by ecosystem:** C# (like Rust/TS/Java) ships a
  compiled artifact, so D-05 generates-on-build + bundles compiled stubs — unlike
  source-distributed Go/Python which commit stubs.

### Integration Points
- New `sdks/csharp/` solution: `Axiam.Sdk/` (REST core + gRPC + AMQP + auth/JWKS +
  `Sensitive`), `Axiam.Sdk.AspNetCore/` (middleware + DI + policy authz), plus
  `examples/` including a runnable ASP.NET Core 8+ app that demonstrates the
  middleware, `ClaimsPrincipal`, and `[Authorize(Policy=...)]` (SC#3).
- New per-SDK GitHub Actions workflow under `.github/workflows/` with
  `paths: sdks/csharp/**` filter: `dotnet build`/`dotnet test` (incl. the xUnit
  `SemaphoreSlim` single-flight test SC#2) + the TLS-bypass grep gate + `dotnet
  pack` + tag-triggered `dotnet nuget push` (`sdks/csharp/vX.Y.Z`, SC#5).
- gRPC stubs generated from `proto/axiam/v1/` via `Grpc.Tools` into `obj/`
  (gitignored) at build time.

</code_context>

<specifics>
## Specific Ideas

- The C# SDK is the **ASP.NET Core / enterprise .NET SDK** — decisions favor what
  .NET developers expect (async-all-the-way + `CancellationToken`, DI extensions +
  Options pattern, `ClaimsPrincipal` + policy-based `[Authorize]`,
  `IHttpClientFactory` compatibility, SourceLink/symbols, NuGet) while staying
  byte-faithful to the shared contract.
- Success-criterion proof points to preserve as concrete tests: (#1) `dotnet add
  package Axiam.Sdk` + `tenant` required constructor param (no default) +
  `await client.LoginAsync(...)` returns typed `LoginResult`; (#2) 5 concurrent
  tasks on an expired token ⇒ **exactly 1 refresh** (xUnit `SemaphoreSlim(1,1)`
  single-flight test); (#3) `Axiam.Sdk.AspNetCore` middleware protects a sample
  ASP.NET Core 8+ endpoint in a runnable example (demonstrating `[Authorize]`/policy
  per D-08); (#4) `Grpc.Tools` build-time codegen documented as the buf exception +
  **no `ServerCertificateCustomValidationCallback` bypass anywhere** (grep gate);
  (#5) `dotnet pack` produces a valid `.nupkg` + NuGet publish pipeline operational.
- **CR-04 must not recur in C#:** never wrap a raw `HttpResponseMessage`/exception
  carrying `Set-Cookie`/`Authorization` into `NetworkError` without redacting first
  (D-12). Add a C# regression test analogous to the sibling error-redaction tests
  (assert the raw `axiam_access`/`axiam_refresh` value never appears in
  `ToString`/JSON/log of a thrown error, with a non-vacuous control case).

</specifics>

<deferred>
## Deferred Ideas

- **netstandard2.0 + BouncyCastle multi-target** — CS-01 names "BouncyCastle for
  netstandard2.0", but D-01 scopes this phase to net8.0-only. .NET Framework / Unity
  / older-runtime reach via a netstandard2.0 leg (with BouncyCastle EdDSA + polyfills
  and the awkward pre-.NET-Core gRPC/RabbitMQ story) is **deferred to a future
  phase**. **Do not lose** — if broad-reach support becomes a requirement, revisit.
  Planner may note this divergence from CS-01's literal wording.
- **NuGet Trusted Publishing (OIDC)** — considered (D-04); the preferred future
  auth path (no long-lived API key), but newer/less-documented and needs nuget.org
  policy config on the reserved `Axiam.Sdk` package. Ship API-key publish now,
  migrate to OIDC later.
- **Author package signing (code-signing cert)** — deferred (D-04); nuget.org
  repo-signs on ingest, so author signing is optional for a starter SDK. Revisit if
  supply-chain requirements demand it.
- **ValueTask hot-path variants** — considered (D-10); rejected as over-engineering
  for a v1.1 starter SDK. Revisit only if allocation profiling shows a real hot path.
- **Live NuGet first publish** — the pipeline + `dotnet pack` must pass in-phase, but
  the first real publish may be a maintainer action if namespace/API-key creds are
  absent in CI (D-04).
- **Automated cross-language conformance harness** — inherited from Phase 15–20
  deferred list; Phase 21 verifies conformance via its own §1–§10 checklist, not a
  mechanical suite.

### Reviewed Todos (not folded)
None — no pending todos matched this phase.

</deferred>

---

*Phase: 21-c-sdk*
*Context gathered: 2026-07-02*
