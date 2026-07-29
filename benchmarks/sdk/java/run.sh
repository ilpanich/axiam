#!/usr/bin/env bash
# Run the Java SDK bench. The Java SDK (ilpanich/axiam-java-sdk) is implemented and
# this bench glue is now wired: exec:java runs io.axiam.bench.Bench, which prints one
# axiam.sdk-bench/v1 JSON record to stdout. If the SDK is not yet on Maven Central,
# run `mvn install` in ../../../../axiam-java-sdk first to populate the local ~/.m2.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# H8: resolve BENCH_CA_CERT to an absolute path before `cd "$HERE"` below —
# profiles/*.env sets it relative to benchmarks/ (the caller's cwd), which
# no longer resolves once this script cds into sdk/java/.
if [ -n "${BENCH_CA_CERT:-}" ] && [ -f "$BENCH_CA_CERT" ]; then
  export BENCH_CA_CERT="$(cd "$(dirname "$BENCH_CA_CERT")" && pwd)/$(basename "$BENCH_CA_CERT")"
fi
cd "$HERE"
command -v mvn >/dev/null || { source "$HERE/../_pending.sh"; emit_pending java; exit 0; }

# H8 fix: `mvn exec:java` alone never triggers the `compile` phase (exec:java
# is not bound to a lifecycle phase here), so target/classes/io/axiam/bench/
# was empty and the JVM raised ClassNotFoundException: io.axiam.bench.Bench.
# Bind compile before exec:java in the same invocation. If the SDK dependency
# itself can't be resolved (not yet on Maven Central / not yet installed to
# the local ~/.m2), install it from the sibling checkout first.
SIBLING_SDK="${AXIAM_JAVA_SDK_DIR:-$HERE/../../../../axiam-java-sdk}"
if ! mvn -q -e dependency:resolve >/dev/null 2>&1; then
  if [ -f "$SIBLING_SDK/pom.xml" ]; then
    echo "[java] axiam-sdk dependency not resolvable — installing from $SIBLING_SDK" >&2
    mvn -q -f "$SIBLING_SDK/pom.xml" install -DskipTests >&2
  fi
fi

exec mvn -q -e compile exec:java
