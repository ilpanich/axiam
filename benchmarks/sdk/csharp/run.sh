#!/usr/bin/env bash
# Run the Csharp SDK bench. The C# SDK (sdks/csharp) is implemented; the
# bench glue in this directory is not yet wired, so this emits a 'pending'
# record. Replace the body below with: dotnet run -c Release
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   exec dotnet run -c Release
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending csharp
