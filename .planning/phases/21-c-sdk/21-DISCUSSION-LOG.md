# Phase 21: C# SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-02
**Phase:** 21-c-sdk
**Areas discussed:** Target frameworks (TFM), Package split, ASP.NET Core depth, HttpClient lifecycle, Async surface, AMQP consumer, NuGet publishing

---

## Gray-area selection

Presented 4 C#-specific gray areas (multiSelect). User selected **all four**:
Target frameworks (TFM), Package split, ASP.NET Core depth, HttpClient lifecycle.
After those, user chose "Explore more gray areas" once, adding Async surface, AMQP
consumer, and NuGet publishing.

---

## Target Frameworks (TFM)

| Option | Description | Selected |
|--------|-------------|----------|
| net8.0 only | Single TFM, native EdDSA/gRPC/RabbitMQ 7.2; simplest; BouncyCastle path deferred | ✓ |
| net8.0 + net9.0 | Multi-target both LTS+STS, both native EdDSA | |
| net8.0 + netstandard2.0 | Broadest reach (.NET Framework/Unity) but BouncyCastle + awkward gRPC/AMQP | |

**User's choice:** net8.0 only
**Notes:** Locks native-EdDSA path; netstandard2.0/BouncyCastle deferred (D-01).

### EdDSA fallback (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| Allow minimal crypto dep | Native-preferred; if net8.0 Ed25519 verify unviable, one vetted verify-only lib (NSec/BouncyCastle) | ✓ |
| Native-only, hard requirement | System.Security.Cryptography only; risk of no viable Ed25519 JWT verify | |
| Reactive-only, skip local verify | Rely on server 401s, no local JWKS pre-verify | |

**User's choice:** Allow minimal crypto dep (verify-only), researcher confirms native viability
**Notes:** Known .NET Ed25519 JWT gap flagged as a research must-verify (D-02).

---

## Package Split

| Option | Description | Selected |
|--------|-------------|----------|
| Two packages | Axiam.Sdk (all transports) + Axiam.Sdk.AspNetCore; matches CS-01/SC#3 | ✓ |
| Split transports too | + Axiam.Sdk.Grpc + Axiam.Sdk.Amqp; leaner footprint, 4 coordinates | |
| Single package | Everything incl. ASP.NET; forces framework ref on all consumers (violates SC#3) | |

**User's choice:** Two packages
**Notes:** gRPC + RabbitMQ are always-on deps of core; transports not split (D-03).

---

## ASP.NET Core Depth

| Option | Description | Selected |
|--------|-------------|----------|
| Full idiom | ClaimsPrincipal on HttpContext.User + [Authorize]/policies + AddAxiam() DI + Options | ✓ |
| Contract-minimum only | UseMiddleware + HttpContext.Items only; no [Authorize] wiring | |
| AuthenticationHandler scheme | Full auth scheme instead of raw middleware; diverges from §10 UseMiddleware | |

**User's choice:** Full idiom (D-06, D-07)

### Authorization half (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| Ship policy integration | IAuthorizationHandler so [Authorize(Policy="resource:action")] → CheckAccessAsync → 403 | ✓ |
| Authentication only | Middleware + 401 only; authz left to app calling CheckAccessAsync manually | |

**User's choice:** Ship policy integration (D-08)
**Notes:** Example must demonstrate `[Authorize(Policy=...)]`. Within ASP.NET integration domain.

---

## HttpClient Lifecycle

| Option | Description | Selected |
|--------|-------------|----------|
| SDK-owned + optional factory | SDK owns handler by default (§4 cookie + §6 TLS + IDisposable); optional IHttpClientFactory path; re-applies cookie+TLS over supplied handler | ✓ |
| SDK-owned only | Single long-lived HttpClient; no factory path | |
| IHttpClientFactory-first | Require DI/typed client; complicates standalone constructor + cookie guarantee | |

**User's choice:** SDK-owned + optional factory (D-09)
**Notes:** Client-override safety (Java D-27 analog); no ServerCertificateCustomValidationCallback bypass (SC#4).

---

## Async Surface

| Option | Description | Selected |
|--------|-------------|----------|
| Async-only + CancellationToken | Task-returning *Async, no sync wrappers, ConfigureAwait(false) | ✓ |
| Async + sync wrappers | *Async plus blocking wrappers; sync-over-async deadlock risk | |
| ValueTask variants | ValueTask on hot paths; micro-optimization | |

**User's choice:** Async-only + CancellationToken (D-10)

---

## AMQP Consumer

| Option | Description | Selected |
|--------|-------------|----------|
| AsyncEventingBasicConsumer + callback | 7.x async consumer; HMAC verify-before-handler; ack/nack-requeue/nack-no-requeue | ✓ |
| IAsyncEnumerable stream | foreach-await verified messages; murkier ack/nack semantics | |
| Raw channel, verify helper only | Expose HMAC helper + DTOs only; weaker §8 guarantee | |

**User's choice:** AsyncEventingBasicConsumer + callback (D-11)
**Notes:** Direct Java D-13 / Go analog; enable automatic recovery.

---

## NuGet Publishing

| Option | Description | Selected |
|--------|-------------|----------|
| API key + SourceLink + snupkg | dotnet nuget push w/ CI API key; tag-triggered; deterministic + SourceLink + symbols; author signing deferred | ✓ |
| Trusted Publishing (OIDC) | OIDC no-key publish; newer/less-documented, needs nuget.org policy config | |
| API key, minimal | Push only; skip SourceLink/symbols/deterministic | |

**User's choice:** API key + SourceLink + snupkg (D-04)
**Notes:** OIDC trusted publishing + author signing noted as preferred future paths (Deferred).

---

## Claude's Discretion

- Internal namespace/folder/file layout under `sdks/csharp/`.
- Exact numeric timeout/deadline/backoff/retry values, gRPC per-call deadline, AMQP prefetch/QoS.
- gRPC channel construction, interceptor ordering, metadata injection.
- `LoginResult` optional-field set beyond `MfaRequired`; DTO record style.
- csproj/CI plugin + package versions; SourceLink/deterministic-build specifics; JWKS cache-TTL/rotation.
- Logging facade choice (Microsoft.Extensions.Logging.Abstractions, silent, redaction-aware).

## Deferred Ideas

- netstandard2.0 + BouncyCastle multi-target (CS-01 names it; out of scope this phase).
- NuGet Trusted Publishing (OIDC) — preferred future auth path.
- Author package signing (code-signing cert) — nuget.org repo-signs on ingest.
- ValueTask hot-path variants — over-engineering for a starter SDK.
- Live NuGet first publish — may be a maintainer action if creds absent.
- Automated cross-language conformance harness — inherited deferral.
