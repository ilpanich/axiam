#!/usr/bin/env bash
# Run the Python SDK bench. Falls back to a pending record if python3 is absent.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
  exec python3 "$HERE/bench.py"
else
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending python
fi
