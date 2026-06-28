#!/usr/bin/env bash
# Run the TypeScript SDK bench. Falls back to a pending record if node is absent.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if command -v node >/dev/null 2>&1; then
  exec node "$HERE/bench.mjs"
else
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending typescript
fi
