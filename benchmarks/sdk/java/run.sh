#!/usr/bin/env bash
# Run the Java SDK bench. The Java SDK (ilpanich/axiam-java-sdk) is implemented and
# this bench glue is now wired: exec:java runs io.axiam.bench.Bench, which prints one
# axiam.sdk-bench/v1 JSON record to stdout. If the SDK is not yet on Maven Central,
# run `mvn install` in ../../../../axiam-java-sdk first to populate the local ~/.m2.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# H8: resolve the TLS input paths (BENCH_CA_CERT and, for p3-mtls,
# BENCH_CLIENT_CERT/BENCH_CLIENT_KEY) to absolute paths before `cd "$HERE"`
# below — profiles/*.env sets them relative to benchmarks/ (the caller's cwd),
# which no longer resolves once this script cds into sdk/java/.
# shellcheck disable=SC1091
source "$HERE/../_tlspaths.sh"; absolutize_tls_paths
cd "$HERE"
command -v mvn >/dev/null || { source "$HERE/../_pending.sh"; emit_pending java; exit 0; }

# H8 fix: `mvn exec:java` alone never triggers the `compile` phase (exec:java
# is not bound to a lifecycle phase here), so target/classes/io/axiam/bench/
# was empty and the JVM raised ClassNotFoundException: io.axiam.bench.Bench.
# Bind compile before exec:java in the same invocation. If the SDK dependency
# itself can't be resolved (not yet on Maven Central / not yet installed to
# the local ~/.m2), install it from the sibling checkout first.
SIBLING_SDK="${AXIAM_JAVA_SDK_DIR:-$HERE/../../../../axiam-java-sdk}"

# Build against the version the SIBLING CHECKOUT actually declares, not a
# version literal frozen in pom.xml. The old code only installed the sibling
# when the dependency failed to RESOLVE — but a stale jar in ~/.m2 always
# resolves, so the bench kept compiling against whatever ancient SDK had been
# installed once (observed: pom pinned 1.0.0-alpha2 while the checkout was at
# 1.0.0-alpha21, hiding CONTRACT.md §6.1's clientCertificate() entirely).
# Reading the version straight out of the sibling pom means a checkout bump is
# picked up automatically, with no pom.xml edit here.
MVN_ARGS=()
if [ -f "$SIBLING_SDK/pom.xml" ]; then
  # First <version> under <project> (the sibling's own), not a dependency's:
  # stop at the first match, which in a standard pom is the project version.
  SDK_VERSION="$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' "$SIBLING_SDK/pom.xml" | head -1)"
  if [ -n "$SDK_VERSION" ]; then
    MVN_ARGS+=("-Daxiam.sdk.version=$SDK_VERSION")
    # Install that exact version into ~/.m2 if it isn't there yet. Cheap when
    # it already is (a single directory test), and it is what makes a fresh
    # laptop work with no manual `mvn install` step.
    M2_JAR="$HOME/.m2/repository/io/github/ilpanich/axiam-sdk/$SDK_VERSION"
    if [ ! -d "$M2_JAR" ]; then
      echo "[java] axiam-sdk $SDK_VERSION not in ~/.m2 — installing from $SIBLING_SDK" >&2
      mvn -q -f "$SIBLING_SDK/pom.xml" install -DskipTests -Djacoco.skip=true >&2
    fi
  fi
fi

if ! mvn -q -e "${MVN_ARGS[@]}" dependency:resolve >/dev/null 2>&1; then
  if [ -f "$SIBLING_SDK/pom.xml" ]; then
    echo "[java] axiam-sdk dependency not resolvable — installing from $SIBLING_SDK" >&2
    mvn -q -f "$SIBLING_SDK/pom.xml" install -DskipTests -Djacoco.skip=true >&2
  fi
fi

exec mvn -q -e "${MVN_ARGS[@]}" compile exec:java
