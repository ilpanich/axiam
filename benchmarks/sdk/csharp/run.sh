#!/usr/bin/env bash
# Run the Csharp SDK bench. Wired to Axiam.Sdk (ilpanich/axiam-csharp-sdk) via a
# ProjectReference in axiam-sdk-bench.csproj; the bench entrypoint (Program.cs)
# emits an axiam.sdk-bench/v1 record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
command -v dotnet >/dev/null || { source "$HERE/../_pending.sh"; emit_pending csharp; exit 0; }
exec dotnet run -c Release --project "$HERE"
