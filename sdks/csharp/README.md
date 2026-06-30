# Axiam.Sdk (C#)

Official C# client SDK for [AXIAM](https://github.com/axiam/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **NuGet package:** `Axiam.Sdk`
- **Registry:** [nuget.org/packages/Axiam.Sdk](https://www.nuget.org/packages/Axiam.Sdk) _(reserved, not yet published)_
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

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

Scaffold placeholder. Full implementation follows in Phase 21 (C# SDK).

## Usage

```bash
dotnet add package Axiam.Sdk
```

```csharp
using Axiam.Sdk;

var client = new AximClient(new AximClientOptions { BaseUrl = "https://your-axiam-instance" });
```
