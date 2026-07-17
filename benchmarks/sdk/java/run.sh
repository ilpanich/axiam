#!/usr/bin/env bash
# Run the Java SDK bench. The Java SDK (ilpanich/axiam-java-sdk) is implemented and
# this bench glue is now wired: exec:java runs io.axiam.bench.Bench, which prints one
# axiam.sdk-bench/v1 JSON record to stdout. If the SDK is not yet on Maven Central,
# run `mvn install` in ../../../../axiam-java-sdk first to populate the local ~/.m2.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
command -v mvn >/dev/null || { source "$HERE/../_pending.sh"; emit_pending java; exit 0; }
exec mvn -q -e exec:java
