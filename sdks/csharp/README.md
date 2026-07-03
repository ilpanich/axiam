# Axiam.Sdk (C#)

Official C# client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **NuGet package:** `Axiam.Sdk`
- **Registry:** [nuget.org/packages/Axiam.Sdk](https://www.nuget.org/packages/Axiam.Sdk) _(reserved, not yet published)_
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

### §1–§10 conformance checklist

| § | Requirement | Where implemented |
|---|---|---|
| §1 | PascalCase method map (`Login`/`VerifyMfa`/`Refresh`/`Logout`/`CheckAccess`/`Can`/`BatchCheck`) | `AxiamClient.LoginAsync`/`VerifyMfaAsync`/`RefreshAsync`/`LogoutAsync`; `AuthzRestClient.CheckAccessAsync`/`CanAsync`/`BatchCheckAsync`; `Grpc/AxiamGrpcAuthzClient.CheckAccessAsync`/`BatchCheckAsync` |
| §2 | `AuthError`/`AuthzError`/`NetworkError` taxonomy + HTTP/gRPC status mapping | `Core/ErrorMapper.cs`, `Core/AuthError.cs`, `Core/AuthzError.cs`, `Core/NetworkError.cs` |
| §3 | Non-browser CSRF: capture `X-CSRF-Token` response header, echo on state-changing requests | `Rest/AxiamHttpMessageHandler.cs` |
| §4 | Persistent cookie jar (`HttpClientHandler { UseCookies = true, CookieContainer = new() }`) | `Rest/AxiamHttpClientFactory.cs` |
| §5 | Tenant is a required, non-optional constructor parameter | `AxiamClient`'s single public constructor (SC#1) |
| §6 | Strict TLS always on; only escape hatch is a `customCa` chain-trust callback — no bypass surface | `Rest/AxiamHttpClientFactory.CreatePrimaryHandler` (verified by the `TlsBypassGrepGateTests` xUnit test + a CI grep gate, SC#4) |
| §7 | `Sensitive<T>` struct redacting `ToString()`/JSON to `"[SENSITIVE]"` | `Core/Sensitive.cs` |
| §8 | AMQP HMAC-SHA256 verify-before-handler, constant-time compare | `Amqp/Hmac.cs`, `Amqp/AxiamAmqpConsumer.cs` |
| §9 | `SemaphoreSlim(1,1)` single-flight refresh, one guard across REST + gRPC | `Auth/RefreshGuard.cs` (shared by `AxiamClient` and `Grpc/AuthInterceptor.cs`) |
| §10 | `app.UseMiddleware<AxiamAuthMiddleware>()` + `ClaimsPrincipal` injection + policy-based `[Authorize]` | `Axiam.Sdk.AspNetCore/AxiamAuthMiddleware.cs`, `AxiamPolicyHandler.cs`/`AxiamPolicyProvider.cs` |

## Quickstart

```bash
dotnet add package Axiam.Sdk
dotnet add package Axiam.Sdk.AspNetCore   # optional — ASP.NET Core middleware + DI
```

```csharp
using Axiam.Sdk;

// tenantId is a required, positional constructor argument (SC#1) — there is no
// overload or default that omits it (CONTRACT.md §5).
using var client = new AxiamClient(new Uri("https://your-axiam-instance"), "your-tenant-slug");

var login = await client.LoginAsync("alice@example.com", "correct horse battery staple");
if (login.MfaRequired)
{
    login = await client.VerifyMfaAsync(login.ChallengeToken!.Value, totpCode: "123456");
}

bool canRead = await client.Authz.CanAsync("documents:read", documentId);
```

See [`examples/`](examples/) for a full runnable ASP.NET Core sample (middleware +
policy authorization, SC#3) and a console quickstart covering REST, gRPC, and
AMQP.

## Grpc.Tools exception

The C# SDK is the **one documented exception** to the repository-wide `buf` codegen pipeline.
All other language SDKs (Rust, TypeScript, Python, Java, PHP, Go) use `buf generate` to produce
gRPC stubs from `proto/axiam/v1/`. The C# SDK uses **`Grpc.Tools` MSBuild codegen** instead:
`.proto` files are included via `<Protobuf Include="..." />` in the `.csproj` and stubs are
generated at build time by the `Grpc.Tools` package, not by buf.

This exception is intentional and approved (D-01, Phase 15 context). The C# SDK still
references the same `proto/axiam/v1/` definitions as the buf pipeline; only the codegen
toolchain differs.

## Status

Phase 21 (C# SDK) is complete: `Axiam.Sdk` (REST + gRPC + AMQP + `Sensitive` +
JWKS) and `Axiam.Sdk.AspNetCore` (middleware + DI + policy authorization) are
both fully implemented and tested. See the Quickstart above and
[`examples/`](examples/) for runnable code.
