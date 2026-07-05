# Deferred Items — Phase 27 (Performance & Load Hardening)

Out-of-scope discoveries logged during execution, per the executor's scope-boundary rule
(only auto-fix issues directly caused by the current task's changes).

## 27-03 (JWKS single-flight — Go/Java/C# SDKs)

While verifying Task 3 (C# JWKS single-flight guard) with a real `dotnet test` run (the
sandbox previously had no .NET SDK installed at all, so these appear to have never been
build-verified against a real toolchain), the C# test project (`sdks/csharp/tests/Axiam.Sdk.Tests`)
was found to have THREE pre-existing compile failures, all unrelated to JWKS/PERF-03:

1. **`GrpcAuthzClientTests.cs`** — `FakeAuthorizationService : AuthorizationService.AuthorizationServiceBase`
   does not compile. `Axiam.Sdk.csproj`'s `<Protobuf>` item generates `GrpcServices="Client"`
   only (D-05, intentional — the SDK never hosts a gRPC server), and no `<Protobuf>` item
   exists anywhere in the test project to generate server-side stubs for the in-process fake
   server the test relies on. Needs either a test-project-local Protobuf codegen item
   (`GrpcServices="Server"` or `"Both"`, scoped to tests only) or a different fake-server
   strategy.
2. **`AmqpConsumerTests.cs`** — `RabbitMQ.Client` API mismatch: `BasicDeliverEventArgs` now
   requires an additional `consumerTag` constructor argument, and several previously-mutable
   properties are now read-only (`CS0191`). The installed `RabbitMQ.Client` 7.2.1 (pinned in
   `Axiam.Sdk.csproj`) has evidently diverged from the API shape this test file was written
   against.
3. **`SensitiveRedactionTests.cs`** — `Grpc.Core.StatusCode` fails to resolve
   (`CS0234: 'Core' does not exist in the namespace 'Axiam.Sdk.Grpc'`). This is a C# namespace
   shadowing issue: the file's enclosing `Axiam.Sdk` scope also contains a real
   `Axiam.Sdk.Grpc` namespace, so unqualified `Grpc.Core...` resolves against that sibling
   namespace instead of the global `Grpc.Core` (needs `global::Grpc.Core.StatusCode` or an
   explicit `using Grpc.Core;` + unqualified `StatusCode`).

None of these three files were touched by 27-03 (scoped to `JwksVerifier.cs` /
`JwksVerifierTests.cs` only). They were excluded from compilation ONLY transiently, in-memory,
during 27-03's own verification run (via a temporary `<Compile Remove>` in
`Axiam.Sdk.Tests.csproj` that was reverted before committing) so the JWKS burst test could be
proven in isolation. The working tree carries none of that transient exclusion.

Additionally, `Axiam.Sdk.AspNetCore/ServiceCollectionExtensions.cs` (a separate project, not
part of `Axiam.Sdk.Tests`, referenced only by the `.sln`) fails with
`CS0234: 'IAuthorizationMiddlewareResultHandler' does not exist in the namespace
'Microsoft.AspNetCore.Authorization.Policy'`. The real ASP.NET Core type lives in
`Microsoft.AspNetCore.Authorization` (no `.Policy` segment) — a namespace typo, pre-existing,
unrelated to JWKS. This means the literal plan verification command run at the solution root
(`cd sdks/csharp && dotnet test --filter JwksVerifier`) cannot succeed as written until this
and the three test-file issues above are fixed, since `dotnet test` without an explicit project
path builds every project the `.sln` references. 27-03's SUMMARY.md documents the narrower
verification actually performed (`dotnet test tests/Axiam.Sdk.Tests/Axiam.Sdk.Tests.csproj
--filter JwksVerifier`, with the three broken sibling test files transiently excluded during
verification only, never committed).

**Follow-up recommended:** a dedicated remediation plan/task to fix all four issues above (and
confirm the rest of the C# solution is green now that `dotnet` is actually runnable in this
sandbox — previously the `Google.Protobuf` version bug documented in 27-03's SUMMARY.md blocked
the build before any of this could even be reached).
