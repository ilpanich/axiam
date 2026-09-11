#!/usr/bin/env bash
# _sdkversion.sh — resolve the version of the SDK a bench is about to measure,
# from the sibling `axiam-<lang>-sdk` checkout it actually builds against.
#
# Why this exists. `sdk_version` is not decoration: it is the field that says
# WHICH SDK produced a record. `sdk/_dryrun_verdict.py` prints it on every
# PASS/WARN line, `collect.py` folds the records into the published report, and
# a reader takes the number at face value. Eight of the eleven benches carried
# it as a literal compiled into the harness — `"1.0.0-alpha2"` in the Go, Java,
# C# and TypeScript benches, `"1.0.0a2"` in Python, `"1.0.0-alpha7"` in Rust,
# `"1.0.0-alpha12"` in Swift, `"1.0.0-alpha13"` in Kotlin — and every one of
# them was stale: the SDKs had moved to `1.0.0-beta12` without a single bench
# literal following. A whole SDK matrix would have been published attributing
# beta12 measurements to an alpha that no longer existed, and nothing in the
# harness would have complained, because a literal cannot go red.
#
# So the version is now READ rather than declared, from the checkout each
# `run.sh` already resolves its dependency against (`../../../../axiam-<lang>-sdk`
# — the same path the path/replace/project references use). A bench compiled
# against a checkout reports that checkout's version by construction, and the
# next release bump needs no edit here at all. The literal each bench still
# carries is now only a fallback for the case where the sibling checkout is
# absent (a bench run against a published package with no source tree beside it).
#
# Resolution order, per language:
#   1. the package manifest the SDK publishes from — the authoritative version
#      for the artefact actually built, and the one spelled in that ecosystem's
#      own convention (Python's `1.0.0b12` is PEP 440 for `1.0.0-beta12`, and a
#      Python record should say `1.0.0b12`);
#   2. the newest released `## [x.y.z]` heading in the checkout's CHANGELOG.md,
#      for the five SDKs that publish from a git tag and therefore carry no
#      version in any manifest (Go, PHP, Swift, C, C++);
#   3. nothing — the caller keeps its own fallback literal.
#
# Usage, from a language run.sh (before any `cd`, like _tlspaths.sh):
#
#     source "$HERE/../_sdkversion.sh"
#     export_sdk_version rust      # sets AXIAM_SDK_VERSION when resolvable
#
# and in the bench itself: prefer $AXIAM_SDK_VERSION, fall back to the literal.

# Map a bench directory name to its sibling SDK repository name. Identity for
# every language except C++, whose repo is spelled out (`axiam-cplusplus-sdk`)
# while its bench directory is not (`cpp/`).
_sdk_repo_dir() {
  case "${1:?lang}" in
    cpp) echo "axiam-cplusplus-sdk" ;;
    *)   echo "axiam-$1-sdk" ;;
  esac
}

# First capture group of the first line matching a sed expression, or nothing.
_sdk_first_match() {
  local file="$1" expr="$2"
  [ -f "$file" ] || return 0
  sed -n "$expr" "$file" 2>/dev/null | head -1
}

# The newest RELEASED version in a Keep-a-Changelog file: the first `## [x.y.z]`
# heading whose bracket starts with a digit, which skips `## [Unreleased]`
# without having to name it.
_sdk_changelog_version() {
  _sdk_first_match "$1/CHANGELOG.md" 's/^## \[\([0-9][^]]*\)\].*/\1/p'
}

# Echo the version of the SDK in <dir> (default: the sibling checkout for
# <lang>), or nothing if it cannot be established. Never fails the caller:
# an unresolvable version is a fallback, not an error.
resolve_sdk_version() {
  local lang="${1:?lang}" dir="${2:-}"
  if [ -z "$dir" ]; then
    # Relative to THIS file, so it resolves the same whether a run.sh sources
    # it before or after its own `cd` (benchmarks/sdk -> repo root's parent).
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    dir="$here/../../../$(_sdk_repo_dir "$lang")"
  fi
  [ -d "$dir" ] || return 0

  local v=""
  case "$lang" in
    rust)
      # The FIRST `version = "…"` in Cargo.toml is the `[package]` one; a
      # dependency's version, if any, comes later.
      v="$(_sdk_first_match "$dir/Cargo.toml" 's/^version *= *"\([^"]*\)".*/\1/p')" ;;
    typescript)
      v="$(_sdk_first_match "$dir/package.json" 's/.*"version" *: *"\([^"]*\)".*/\1/p')" ;;
    python)
      # PEP 440 spelling (`1.0.0b12`), deliberately — a Python record should
      # carry the version `pip` would report, not the CHANGELOG's `1.0.0-beta12`.
      v="$(_sdk_first_match "$dir/pyproject.toml" 's/^version *= *"\([^"]*\)".*/\1/p')" ;;
    java)
      # First <version> under <project> is the project's own.
      v="$(_sdk_first_match "$dir/pom.xml" 's:.*<version>\(.*\)</version>.*:\1:p')" ;;
    kotlin)
      v="$(_sdk_first_match "$dir/gradle.properties" 's/^version *= *\(.*\)$/\1/p')" ;;
    csharp)
      v="$(_sdk_first_match "$dir/Axiam.Sdk/Axiam.Sdk.csproj" 's:.*<Version>\(.*\)</Version>.*:\1:p')" ;;
    go|php|swift|c|cpp)
      # No manifest carries a version: all five publish from a git tag, and a
      # fresh clone of a tagged release does not necessarily have the tag
      # fetched. The CHANGELOG is the one file that always does.
      : ;;
    *) : ;;
  esac

  [ -n "$v" ] || v="$(_sdk_changelog_version "$dir")"
  # Trim whitespace a manifest may have carried along.
  v="$(printf '%s' "$v" | tr -d '[:space:]')"
  [ -n "$v" ] && printf '%s\n' "$v"
  return 0
}

# Export AXIAM_SDK_VERSION for the bench process, unless the caller already set
# one (an operator benching a published package can pin the label by hand).
export_sdk_version() {
  local lang="${1:?lang}" v
  if [ -n "${AXIAM_SDK_VERSION:-}" ]; then
    return 0
  fi
  v="$(resolve_sdk_version "$lang" "${2:-}")"
  [ -n "$v" ] && export AXIAM_SDK_VERSION="$v"
  return 0
}

# Allow direct invocation for the self-test and for debugging:
#   sdk/_sdkversion.sh rust  ->  1.0.0-beta12
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  resolve_sdk_version "${1:?usage: _sdkversion.sh <lang> [sdk-checkout-dir]}" "${2:-}"
fi
