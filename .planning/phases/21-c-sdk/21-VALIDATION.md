---
phase: 21
slug: c-sdk
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-07-02
---

# Phase 21 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `21-RESEARCH.md` § Validation Architecture. Task IDs are bound
> to plans during planning/execution; the SC-level behaviors below are the
> fixed acceptance targets.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | xUnit 2.9.3 (`Microsoft.NET.Test.Sdk` + `xunit.runner.visualstudio` + `Moq` 4.20.72) |
| **Config file** | none yet — `sdks/csharp/tests/Axiam.Sdk.Tests/Axiam.Sdk.Tests.csproj` created in Wave 0 |
| **Quick run command** | `dotnet test sdks/csharp/tests/Axiam.Sdk.Tests --filter Category=Fast` |
| **Full suite command** | `dotnet test sdks/csharp` |
| **Estimated runtime** | ~30 seconds (quick), ~90 seconds (full incl. WebApplicationFactory integration) |

---

## Sampling Rate

- **After every task commit:** Run `dotnet test sdks/csharp/tests/Axiam.Sdk.Tests --filter Category=Fast` (unit only: `Sensitive<T>` redaction, HMAC sign/verify fixture vectors, JWKS `kid` lookup, refresh-guard single-flight)
- **After every plan wave:** Run `dotnet test sdks/csharp` (full solution, incl. `WebApplicationFactory` ASP.NET Core middleware integration tests)
- **Before `/gsd-verify-work`:** Full suite green + `dotnet build`/`dotnet pack` succeed + TLS-bypass grep gate empty
- **Max feedback latency:** ~30 seconds

---

## Per-Requirement Verification Map

| Behavior (SC / contract §) | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|----------------------------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| SC#1 — `LoginAsync` returns typed `LoginResult`; `tenant` required ctor param (no default) | CS-01 | — | tenant context mandatory (no cross-tenant default) | unit + compile-time ctor overload check | `dotnet test --filter FullyQualifiedName~ClientConstructionTests` | ❌ W0 | ⬜ pending |
| SC#2 — 5 concurrent tasks on expired token ⇒ exactly 1 refresh | CS-01 | — | single-flight refresh, no token stampede | unit (`Task.WhenAll` + counting fake handler) | `dotnet test --filter FullyQualifiedName~RefreshGuardSingleFlightTests` | ❌ W0 | ⬜ pending |
| SC#3 — `Axiam.Sdk.AspNetCore` middleware protects a sample endpoint | CS-01 | — | identity injection; unauthenticated → 401 | integration (`WebApplicationFactory`) + manual `examples/AspNetCoreSample` run | `dotnet test --filter FullyQualifiedName~AspNetCoreMiddlewareTests` | ❌ W0 | ⬜ pending |
| SC#4 — no `ServerCertificateCustomValidationCallback` bypass anywhere | CS-01 | TLS-bypass | TLS validation never disabled in SDK source | static grep gate + build | `dotnet build sdks/csharp/Axiam.Sdk` && grep gate empty (excluding allowed `customCa` chain-trust pattern) | ❌ W0 | ⬜ pending |
| SC#4 — `Grpc.Tools` build-time codegen documented & working | CS-01 | — | codegen at build time (buf exception) | build | `dotnet build sdks/csharp/Axiam.Sdk` | ❌ W0 | ⬜ pending |
| SC#5 — `dotnet pack` produces valid `.nupkg`; publish pipeline documented | CS-01 | — | reproducible package + credential setup | build + CI dry-run | `dotnet pack sdks/csharp/Axiam.Sdk -c Release` | ❌ W0 | ⬜ pending |
| §8 AMQP HMAC verify-before-handler matches server byte-for-byte (wire-order preserved) | CS-01 | HMAC forgery | constant-time compare; wire key order | unit (real Rust-signed byte vector fixture) | `dotnet test --filter FullyQualifiedName~HmacVerifyTests` | ❌ W0 | ⬜ pending |
| CR-04 carry-forward — raw token never in `NetworkError` `ToString`/JSON/logs | CS-01 | token leak | redact-before-wrap | unit (regression, non-vacuous control) | `dotnet test --filter FullyQualifiedName~SensitiveRedactionTests` | ❌ W0 | ⬜ pending |
| D-02 — JWKS Ed25519 verification round-trips against real AXIAM token/JWKS | CS-01 | forged/replayed JWT | BouncyCastle Ed25519 verify + `tenant_id` claim check | unit (real keypair + JWKS + signed JWT fixture) | `dotnet test --filter FullyQualifiedName~JwksVerifierTests` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `sdks/csharp/tests/Axiam.Sdk.Tests/Axiam.Sdk.Tests.csproj` — test project scaffold (xUnit + Moq + `Microsoft.NET.Test.Sdk` references)
- [ ] `sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/` — real Rust-signed HMAC byte-vector fixture (generate once via `crates/axiam-amqp` `sign_payload`, then commit fixed bytes + expected hex signature; do NOT depend on `axiam-amqp` at runtime)
- [ ] `sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/` — real Ed25519 keypair + AXIAM-shaped JWKS document + matching signed JWT fixture (throwaway harness to confirm the BouncyCastle verify path against a real signature, not a self-signed round-trip)
- [ ] Framework install: `dotnet add package xunit xunit.runner.visualstudio Microsoft.NET.Test.Sdk Moq`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| NuGet publish pipeline is operational (real registry push) | CS-01 (SC#5) | Requires real NuGet credentials + registry; not run in unit CI | Configure `NUGET_API_KEY`, run the documented publish workflow against a pre-release channel following the `sdks/csharp/vX.Y.Z` tag scheme |
| `examples/AspNetCoreSample` runs against a live AXIAM server | CS-01 (SC#3) | End-to-end needs a running server + issued token | Follow the example README; hit the protected endpoint with/without a valid token |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (test project + HMAC/JWKS fixtures)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-02 (via gsd-plan-checker verification — every task carries an automated verify; Wave 0 in plan 21-01 scaffolds test project + HMAC/JWKS fixtures)
