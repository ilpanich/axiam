#!/usr/bin/env bash
# Run the Kotlin SDK bench. The Kotlin SDK (ilpanich/axiam-kotlin-sdk) is implemented and
# this bench glue is now wired: `gradle run` builds src/main/kotlin/Bench.kt against the SDK
# (via the includeBuild composite in settings.gradle.kts, pointing at the sibling
# axiam-kotlin-sdk checkout) and prints one axiam.sdk-bench/v1 JSON record to stdout.
#
# Prefer the pinned `./gradlew` wrapper (reproducible Gradle version) but fall back to a
# system `gradle` install if the wrapper can't fetch its distribution zip (e.g. GitHub
# release-asset egress blocked in a sandboxed environment — services.gradle.org redirects
# there for the actual binary). Only stdout is captured as the JSON record; Gradle/JVM
# diagnostics on stderr (including the JVM's "Picked up JAVA_TOOL_OPTIONS" banner) pass
# through live and never pollute the single-JSON-object stdout contract.
#
# If neither Gradle path works, or the build itself fails (most likely: Maven Central /
# Gradle Plugin Portal dependency resolution blocked — see TODO.md), this degrades to a
# 'pending' record instead of crashing, per HARNESS-SPEC.md.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

command -v java >/dev/null || { source "$HERE/../_pending.sh"; emit_pending kotlin; exit 0; }

OUT=""
OK=0
if [ -x "$HERE/gradlew" ] && OUT="$("$HERE/gradlew" -q --console=plain run)"; then
  OK=1
elif command -v gradle >/dev/null && OUT="$(gradle -q --console=plain run)"; then
  OK=1
fi

if [ "$OK" -ne 1 ]; then
  source "$HERE/../_pending.sh"
  emit_pending kotlin
  exit 0
fi

echo "$OUT"
