#!/usr/bin/env bash
# Run the Java SDK bench. The Java SDK is still under development
# (feature/phase-17, T17.4); until it is wired this emits a 'pending'
# record. Replace the body below with: mvn -q exec:java
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# When the SDK lands, implement bench in this directory and exec it here, e.g.:
#   exec mvn -q exec:java
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending java
