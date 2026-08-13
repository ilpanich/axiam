#!/usr/bin/env bash
# Assert that `tools/surreal-race-probe` measures the storage engine the server
# actually runs (ilpanich/axiam#302, X6).
#
# The probe is excluded from the workspace and carries its own lockfile, which
# is deliberate — it pulls three storage engines, one of which builds RocksDB
# from C++, and CI should not pay for that on every commit. The cost of that
# independence is that the two lockfiles can drift, and a probe measuring
# `surrealkv` 0.21.3 tells you nothing useful about a server running 0.22.0.
#
# So the gate checks this first. If it fails, the fix is to re-pin the probe to
# the workspace's versions, re-run it, and update `RESULTS.md` — not to relax
# the check.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSIONS="$REPO_ROOT/scripts/surreal-engine-versions.sh"

workspace="$("$VERSIONS" "$REPO_ROOT/Cargo.lock")"
probe="$("$VERSIONS" "$REPO_ROOT/tools/surreal-race-probe/Cargo.lock")"

if [[ "$workspace" == "$probe" ]]; then
    echo "probe pin matches the workspace:"
    echo "$workspace" | sed 's/^/  /'
    exit 0
fi

cat >&2 <<EOF
error: tools/surreal-race-probe is pinned to different SurrealDB versions than
       the workspace, so the race gate would measure an engine the server does
       not run (ilpanich/axiam#302).

workspace Cargo.lock:
$(echo "$workspace" | sed 's/^/  /')

tools/surreal-race-probe/Cargo.lock:
$(echo "$probe" | sed 's/^/  /')

To fix:
  1. Edit tools/surreal-race-probe/Cargo.toml so its \`surrealdb\` pin matches
     the workspace's resolved version.
  2. cd tools/surreal-race-probe && cargo update -p surrealdb --precise <version>
  3. Re-run the probe and record the new numbers in
     tools/surreal-race-probe/RESULTS.md.
EOF
exit 1
