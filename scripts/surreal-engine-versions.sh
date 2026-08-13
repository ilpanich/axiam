#!/usr/bin/env bash
# Print the pinned versions of the three crates that decide whether AXIAM's
# single-use credentials are actually single-use (ilpanich/axiam#302, X6).
#
# `surrealdb` / `surrealdb-core` / `surrealkv` between them own the write-write
# conflict detection that `permission_ticket.consume`, `device_grant.redeem`
# and `pushed_auth_request.consume` rely on for their first layer of
# arbitration. SurrealDB documents no guarantee about that behaviour, so a
# version bump can change it in either direction, silently — which is exactly
# what `.github/workflows/surreal-race-probe.yml` uses this script to notice.
#
# Usage:
#   scripts/surreal-engine-versions.sh [lockfile]     # default: ./Cargo.lock
#
# Output is one `name=version` line per crate, sorted, so two invocations can
# be diffed directly. A crate absent from the lockfile is omitted rather than
# reported as empty — `surrealkv` legitimately disappears from a lockfile that
# does not enable the `kv-surrealkv` feature.

set -euo pipefail

LOCKFILE="${1:-Cargo.lock}"

if [[ ! -f "$LOCKFILE" ]]; then
    echo "error: no lockfile at $LOCKFILE" >&2
    exit 1
fi

# `[[package]]` stanzas are `name = "x"` followed by `version = "y"`. Matching
# the pair in one pass beats grepping for the name and taking the next line,
# which silently produces nonsense if the field order ever changes.
awk '
    /^name = "/ {
        name = $0
        sub(/^name = "/, "", name)
        sub(/"$/, "", name)
        next
    }
    /^version = "/ {
        if (name == "surrealdb" || name == "surrealdb-core" || name == "surrealkv") {
            version = $0
            sub(/^version = "/, "", version)
            sub(/"$/, "", version)
            print name "=" version
        }
        name = ""
    }
' "$LOCKFILE" | sort -u
