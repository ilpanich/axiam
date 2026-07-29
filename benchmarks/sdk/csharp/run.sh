#!/usr/bin/env bash
# Run the Csharp SDK bench. Wired to Axiam.Sdk (ilpanich/axiam-csharp-sdk) via a
# ProjectReference in axiam-sdk-bench.csproj; the bench entrypoint (Program.cs)
# emits an axiam.sdk-bench/v1 record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# H8: dotnet is not installed on this host. Print the exact install commands
# (see csharp/TODO.md "Installing the .NET SDK") to stderr so a maintainer
# copy-pastes them, then degrade to an honest `pending` record rather than
# fail the whole sdk-bench-all run.
if ! command -v dotnet >/dev/null 2>&1; then
  cat >&2 <<'EOF'
[csharp] dotnet SDK not found on PATH — this bench needs .NET SDK 8.0 (net8.0
target) to build/run. Install it with ONE of:

  # Option A — Microsoft's install script (no root, no apt repo needed):
  curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --channel 8.0
  export PATH="$HOME/.dotnet:$PATH"   # add to your shell profile to persist

  # Option B — apt (Ubuntu/Debian, requires the dotnet-install feed or the
  # Microsoft package repo, since 24.04's default repo dropped the older
  # dotnet-sdk packages):
  wget https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
  sudo dpkg -i /tmp/packages-microsoft-prod.deb
  sudo apt-get update && sudo apt-get install -y dotnet-sdk-8.0

After installing, re-run: cd benchmarks && just sdk=csharp sdk-bench
EOF
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending csharp
  exit 0
fi
exec dotnet run -c Release --project "$HERE"
