# Csharp SDK benchmark — now wired

The C# SDK bench glue is wired to `Axiam.Sdk` (`ilpanich/axiam-csharp-sdk`,
1.0.0-alpha2). `Program.cs` times the four canonical ops (`login`, `refresh`,
`check_access`, `batch_check`) and emits one `axiam.sdk-bench/v1` JSON record to
stdout; `run.sh` runs it with `dotnet run -c Release`.

## SDK dependency
`axiam-sdk-bench.csproj` uses a `ProjectReference` to the sibling checkout at
`../../../../axiam-csharp-sdk/Axiam.Sdk/Axiam.Sdk.csproj` (the alpha may not be on
NuGet yet). Once `Axiam.Sdk` 1.0.0-alpha2 is published, swap that for the
commented-out `<PackageReference Include="Axiam.Sdk" Version="1.0.0-alpha2" />`.

## Run
`cd benchmarks && just sdk=csharp sdk-bench`

## H8 status: honest `pending` — dotnet is not installed in this environment

This sandbox has no `dotnet` on `PATH`. `run.sh` preflights for it and, when
missing, prints the exact install commands below to stderr and emits a
spec-conformant `status: "pending"` record (via `../_pending.sh`) instead of
failing the whole `sdk-bench-all` run. The bench code itself
(`Program.cs`/`axiam-sdk-bench.csproj`) is otherwise complete and wired to the
sibling `axiam-csharp-sdk` checkout via the `ProjectReference` above — it has
not been compiled or run here because the toolchain isn't present, not
because of a code defect.

### Installing the .NET SDK (net8.0)

Option A — Microsoft's install script (no root, no apt repo needed):
```
curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
bash /tmp/dotnet-install.sh --channel 8.0
export PATH="$HOME/.dotnet:$PATH"   # add to your shell profile to persist
```

Option B — apt (Ubuntu/Debian; 24.04's default repos dropped the standalone
`dotnet-sdk-*` packages, so add Microsoft's package feed first):
```
wget https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
sudo dpkg -i /tmp/packages-microsoft-prod.deb
sudo apt-get update && sudo apt-get install -y dotnet-sdk-8.0
```

After either option, re-run `cd benchmarks && just sdk=csharp sdk-bench` — it
should build the sibling `axiam-csharp-sdk` via the `ProjectReference` and
emit a `status: "ok"` (or `"error"` if no seeded target is reachable) record.

## p3-mtls (CONTRACT.md §6.1) — wired and verified

The "dotnet is not installed" status above is stale: with the .NET SDK present
this bench builds and runs, and it now carries the full TLS configuration.

A new `NewOptions()` factory backs both client construction sites (the shared
client and the fresh one `login` builds per iteration) and adds:

- **`BENCH_CA_CERT` -> `CustomCaPem`.** This bench never read it, so like the
  Kotlin one it could not have completed a run under *any* TLS profile.
- **`BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` -> `ClientCertificatePem`/`ClientKeyPem`**
  for p3-mtls.

All three are file PATHS (HARNESS-SPEC.md) read into the `byte[]?` PEM that
`AxiamClientOptions` expects. Reading happens inside the existing setup
try/catch, so an unreadable path becomes the contractual `status:"error"`
record instead of an unhandled exception. The cert/key pair is all-or-nothing
(§6.1 rule 1). `run.sh` absolutises the three paths before `dotnet run
--project` launches the app with the project directory as its cwd.

No stale-artifact hazard: `axiam-sdk-bench.csproj` uses a `ProjectReference` to
the sibling checkout, so the SDK is always built from source.

```
cd benchmarks && just target=axiam profile=p3-mtls sdk=csharp sdk-bench
just sdk-bench-test csharp  # proves the cert reaches the wire, no stack needed
```

Verified: phase A (half-configured pair -> `status:"error"` naming both vars)
and phase B (stub mTLS server observes `CN=bench-client`) both pass.
