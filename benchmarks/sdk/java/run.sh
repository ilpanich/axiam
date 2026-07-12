#!/usr/bin/env bash
# Run the Java SDK bench. The Java SDK (ilpanich/axiam-java-sdk) is implemented; the bench
# glue in this directory is not yet wired, so this emits a 'pending' record.
# Replace the body below with: mvn -q exec:java
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   exec mvn -q exec:java
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending java
