#!/usr/bin/env bash
# Regression guard for `_sdkversion.sh` — the record field that says WHICH SDK
# was measured.
#
# Eight of the eleven benches carried `sdk_version` as a literal compiled into
# the harness, and by the time the SDKs reached 1.0.0-beta12 every one of those
# literals was stale (alpha2, alpha7, alpha12, alpha13, 1.0.0a2). Nothing went
# red, because a literal cannot: a whole matrix would have been published
# attributing beta12 measurements to alphas that no longer exist.
#
# `_sdkversion.sh` replaced them by READING the sibling checkout each bench
# builds against. This test pins that reading against synthetic checkouts — one
# per manifest shape, plus the CHANGELOG fallback the five tag-published SDKs
# rely on — so the next manifest rename fails here in seconds instead of
# silently reappearing as a wrong number in a published table.
#
# Hermetic: no SDK checkouts, no toolchains, no AXIAM stack. The fixtures are
# written into a temp dir and passed in explicitly.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# shellcheck source=/dev/null
source "$HERE/_sdkversion.sh"

fail=0
check() {  # check <label> <got> <want>
  if [ "$2" != "$3" ]; then
    echo "[sdkversion-selftest] $1: got '$2', want '$3'" >&2
    fail=1
  fi
}

changelog() {  # changelog <dir> <released-version>
  mkdir -p "$1"
  cat > "$1/CHANGELOG.md" <<EOF
# Changelog

## [Unreleased]
### Added
- something not yet released

## [$2] - 2026-09-11
### Added
- the release this test asserts is the one reported
EOF
}

# --- manifest-shaped SDKs -------------------------------------------------
# Each fixture ALSO carries a CHANGELOG naming a different version, so a test
# that passed only because of the fallback would be caught.

mkdir -p "$TMP/rust"
printf '[package]\nname = "axiam-sdk"\nversion = "9.9.9-rust"\n\n[dependencies]\nserde = { version = "1.2.3" }\n' > "$TMP/rust/Cargo.toml"
changelog "$TMP/rust" "0.0.0-changelog"
check "rust reads Cargo.toml's [package] version" "$(resolve_sdk_version rust "$TMP/rust")" "9.9.9-rust"

mkdir -p "$TMP/typescript"
printf '{\n  "name": "axiam-sdk",\n  "version": "9.9.9-ts",\n  "dependencies": {}\n}\n' > "$TMP/typescript/package.json"
changelog "$TMP/typescript" "0.0.0-changelog"
check "typescript reads package.json" "$(resolve_sdk_version typescript "$TMP/typescript")" "9.9.9-ts"

mkdir -p "$TMP/python"
printf '[project]\nname = "axiam-sdk"\nversion = "9.9.9b1"\n' > "$TMP/python/pyproject.toml"
changelog "$TMP/python" "0.0.0-changelog"
# PEP 440 spelling is preserved verbatim: a Python record must say what pip says.
check "python reads pyproject.toml in PEP 440 spelling" "$(resolve_sdk_version python "$TMP/python")" "9.9.9b1"

mkdir -p "$TMP/java"
printf '<project>\n  <artifactId>axiam-sdk</artifactId>\n  <version>9.9.9-java</version>\n  <dependencies><dependency><version>1.2.3</version></dependency></dependencies>\n</project>\n' > "$TMP/java/pom.xml"
changelog "$TMP/java" "0.0.0-changelog"
check "java reads the project version, not a dependency's" "$(resolve_sdk_version java "$TMP/java")" "9.9.9-java"

mkdir -p "$TMP/kotlin"
printf 'group=io.github.ilpanich\nversion=9.9.9-kotlin\n' > "$TMP/kotlin/gradle.properties"
changelog "$TMP/kotlin" "0.0.0-changelog"
check "kotlin reads gradle.properties" "$(resolve_sdk_version kotlin "$TMP/kotlin")" "9.9.9-kotlin"

mkdir -p "$TMP/csharp/Axiam.Sdk"
printf '<Project>\n  <PropertyGroup>\n    <Version>9.9.9-csharp</Version>\n  </PropertyGroup>\n</Project>\n' > "$TMP/csharp/Axiam.Sdk/Axiam.Sdk.csproj"
changelog "$TMP/csharp" "0.0.0-changelog"
check "csharp reads Axiam.Sdk.csproj" "$(resolve_sdk_version csharp "$TMP/csharp")" "9.9.9-csharp"

# --- tag-published SDKs: CHANGELOG is the only source ---------------------
# Go, PHP, Swift, C and C++ publish from a git tag and carry no version in any
# manifest — and a fresh clone of a tagged release does not necessarily have
# the tag fetched, which is why the CHANGELOG rather than `git describe`.
for lang in go php swift c cpp; do
  changelog "$TMP/$lang" "9.9.9-$lang"
  check "$lang falls back to the newest released CHANGELOG heading" \
    "$(resolve_sdk_version "$lang" "$TMP/$lang")" "9.9.9-$lang"
done

# `## [Unreleased]` must never be reported as a version.
changelog "$TMP/unreleased-only" "1.2.3"
check "an Unreleased heading is skipped" "$(resolve_sdk_version go "$TMP/unreleased-only")" "1.2.3"

# --- absence is empty, never an error ------------------------------------
check "a missing checkout resolves to nothing" "$(resolve_sdk_version rust "$TMP/does-not-exist")" ""
mkdir -p "$TMP/empty"
check "a checkout with no manifest and no changelog resolves to nothing" \
  "$(resolve_sdk_version rust "$TMP/empty")" ""

# `set -e` must survive an unresolvable lookup — a bench whose SDK checkout is
# absent has to keep running and fall back to its own literal, not die here.
( set -e; source "$HERE/_sdkversion.sh"; export_sdk_version rust "$TMP/does-not-exist"; ) \
  || { echo "[sdkversion-selftest] export_sdk_version must not fail on an absent checkout" >&2; fail=1; }

# An operator-supplied AXIAM_SDK_VERSION is never overwritten.
got="$(AXIAM_SDK_VERSION=pinned-by-operator bash -c \
  'source "$0"; export_sdk_version rust "$1"; printf %s "$AXIAM_SDK_VERSION"' \
  "$HERE/_sdkversion.sh" "$TMP/rust")"
check "an explicit AXIAM_SDK_VERSION wins" "$got" "pinned-by-operator"

# --- the real checkouts, when they are beside this repo ------------------
# Not a hard requirement (CI checks out `axiam` alone), but when the siblings
# ARE present every one of the eleven must resolve — that is the condition the
# operator actually runs under.
SIBLINGS="$HERE/../../.."
resolved=0
for lang in rust typescript python go java kotlin csharp php swift c cpp; do
  repo="$SIBLINGS/$(_sdk_repo_dir "$lang")"
  [ -d "$repo" ] || continue
  v="$(resolve_sdk_version "$lang")"
  if [ -z "$v" ]; then
    echo "[sdkversion-selftest] $lang: sibling checkout at $repo resolved to nothing" >&2
    fail=1
  else
    resolved=$((resolved + 1))
  fi
done
if [ "$resolved" -gt 0 ]; then
  echo "[sdkversion-selftest] resolved $resolved sibling SDK checkout(s) found beside this repo"
fi

# --- every bench must still honour the env var ---------------------------
# The literal each bench keeps is a fallback; AXIAM_SDK_VERSION is what run.sh
# exports. A bench that stops reading it silently reverts to a literal, which is
# exactly the failure this whole change exists to remove — so grep for it.
for f in rust/src/main.rs typescript/bench.mjs python/bench.py go/main.go \
         java/src/main/java/io/axiam/bench/Bench.java \
         kotlin/src/main/kotlin/Bench.kt csharp/Program.cs php/bench.php \
         swift/Sources/axiam-bench/main.swift c/bench.c cpp/bench.cpp; do
  grep -q 'AXIAM_SDK_VERSION' "$HERE/$f" || {
    echo "[sdkversion-selftest] $f no longer reads AXIAM_SDK_VERSION" >&2; fail=1; }
done

# …and every run.sh must still export it.
for lang in rust typescript python go java kotlin csharp php swift c cpp; do
  grep -q 'export_sdk_version' "$HERE/$lang/run.sh" || {
    echo "[sdkversion-selftest] $lang/run.sh no longer exports AXIAM_SDK_VERSION" >&2; fail=1; }
done

[ "$fail" -eq 0 ] || { echo "[sdkversion-selftest] FAILED" >&2; exit 1; }
echo "[sdkversion-selftest] OK — every bench reports the SDK checkout it was built against."
