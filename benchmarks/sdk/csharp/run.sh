#!/usr/bin/env bash
# Run the Csharp SDK bench. The Csharp SDK is still under development
# (feature/phase-17, T17.5); until it is wired this emits a 'pending'
# record. Replace the body below with: dotnet run -c Release
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# When the SDK lands, implement bench in this directory and exec it here, e.g.:
#   exec dotnet run -c Release
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending csharp
