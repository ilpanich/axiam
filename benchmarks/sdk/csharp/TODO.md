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
