---
status: testing
phase: 21-c-sdk
source: [21-VERIFICATION.md]
started: 2026-07-02T14:24:25Z
updated: 2026-07-02T14:24:25Z
---

## Current Test

number: 1
name: First real compiler/test-runner pass against the C# SDK
expected: |
  Solution restores/builds warning-free; the full xUnit suite
  (RefreshGuardSingleFlightTests, JwksVerifierTests, ClientConstructionTests,
  AuthzRestClientTests, GrpcAuthzClientTests, HmacVerifyTests, AmqpConsumerTests,
  SensitiveRedactionTests, TlsBypassGrepGateTests, AspNetCoreMiddlewareTests)
  passes green — in particular SC#2's 5-concurrent-callers-exactly-1-refresh
  assertion and SC#3's WebApplicationFactory 401/403/200 assertions.
awaiting: user response

## Tests

### 1. First real compiler/test-runner pass (dotnet build + test)
expected: |
  Run `dotnet restore sdks/csharp && dotnet build sdks/csharp -c Release --no-restore
  && dotnet test sdks/csharp -c Release --no-build` (or trigger
  .github/workflows/sdk-ci-csharp.yml on a PR touching sdks/csharp/**).
  Solution restores/builds warning-free; full test suite passes green, including
  SC#2's single-flight refresh assertion and SC#3's WebApplicationFactory 401/403/200
  assertions.
why_human: |
  The dotnet SDK/CLI is not installed in the execution environment (documented
  constraint for the entire phase). Every task's automated verify across all 7 plans
  was manually traced instead of executed; no compiler or test runner has ever run
  against this code. Source-level structural checks were independently confirmed
  during verification, but a real build/test has not happened yet.
result: [pending]

### 2. dotnet pack produces valid .nupkg + .snupkg
expected: |
  Run `dotnet pack sdks/csharp/Axiam.Sdk -c Release` and
  `dotnet pack sdks/csharp/Axiam.Sdk.AspNetCore -c Release`; inspect output.
  Both produce a valid, SourceLink-enabled, deterministic .nupkg + matching .snupkg
  under bin/Release.
why_human: |
  dotnet pack cannot be executed in this environment; the csproj packaging
  properties (SourceLink, Deterministic, SymbolPackageFormat=snupkg) were confirmed
  present via static review, but a real pack has never been run.
result: [pending]

### 3. NuGet publish pipeline operational (live push)
expected: |
  Maintainer configures the NUGET_API_KEY repository secret and either lets the
  tag-triggered publish job push sdks/csharp/vX.Y.Z or performs the first live push
  manually. Axiam.Sdk and Axiam.Sdk.AspNetCore appear on nuget.org.
why_human: |
  Requires real NuGet credentials + registry access — explicitly out of scope for an
  automated/local check, and flagged in ROADMAP.md CS-01 acceptance criteria as a
  maintainer action pending NUGET_API_KEY secret configuration.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
