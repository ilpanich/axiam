#!/usr/bin/env bash
# mass-tag.sh — Cut and push a signed release across many AXIAM repos.
#
# AXIAM ships as one platform repo plus seven per-language SDK repos, each in
# its own clone. Cutting a release means, in every selected repo: writing the
# release version into every file that must carry it, committing that bump, and
# putting the SAME signed tag on that commit so the per-repo release pipelines
# fire. Doing that by hand, across eight repos and their many manifests, is
# tedious and error-prone — this script does it in one pass.
#
# THE VERSION IS TAKEN FROM THE TAG. `--tag v1.4.0` means "release 1.4.0":
# the script strips a leading `v` (and, defensively, any `prefix/` segment),
# then writes 1.4.0 into every version-bearing file of each selected repo
# before committing and tagging. So preparing a release is just running this
# script — no manual version edits first.
#
# For each selected repo it will, in order:
#   1. check out the requested branch,
#   2. optionally pull it fast-forward from origin (--pull),
#   3. rewrite the release version everywhere the repo declares it (unless
#      --no-bump), and commit the change (signed) — skipped when nothing
#      changed (e.g. Go/PHP derive their version from the tag alone, or the
#      repo is already at this version),
#   4. create a SIGNED annotated tag on the resulting HEAD, whose message is
#      the repo name prepended to your message ("<repo> - <message>"),
#   5. push the branch and then the tag to origin.
#
# What "everywhere the version is declared" means, per repo (see bump_versions):
#   axiam (platform)   Cargo.toml [workspace.package] version; all axiam-*
#                      entries in Cargo.lock; sdks/openapi.json info.version
#                      (the OpenAPI drift gate — the spec is byte-for-byte
#                      identical apart from this field, so a targeted rewrite
#                      keeps the gate green with no rebuild; docs/api/openapi.json
#                      is a symlink to it); the frontend Sidebar version string
#                      and its test; the two k8s deployment image tags.
#   axiam-rust-sdk     Cargo.toml package version and the `=`-pinned
#                      axiam-sdk-macros dependency; axiam-sdk-macros/Cargo.toml.
#   axiam-python-sdk   pyproject.toml [project].version and the package
#                      __version__, both in PEP 440 spelling (1.4.0-rc1 -> 1.4.0rc1).
#   axiam-typescript-sdk  package.json and package-lock.json versions.
#   axiam-java-sdk     pom.xml project version, bom/pom.xml (project + managed
#                      axiam-sdk dep), the example's dependency on axiam-sdk,
#                      and the README install snippets.
#   axiam-csharp-sdk   the <Version> in both .csproj files.
#   axiam-php-sdk,     nothing to edit — Composer/Go derive the release version
#   axiam-go-sdk       from the git tag, so these are tagged as-is.
#   axiam-kotlin-sdk   gradle.properties version and the README install coords.
#   axiam-swift-sdk    the CocoaPods AxiamSDK.podspec s.version and README (SwiftPM
#                      itself is tag-derived, like Go).
#   axiam-c-sdk,       the CMake project() version, vcpkg.json version, conanfile.py
#   axiam-cplusplus-sdk version, and the README install coords — kept in lockstep.
# Each SDK's release workflow asserts the pushed tag equals the manifest
# version; the bump above is what makes that assertion pass.
#
# A pre-flight pass validates EVERY selected repo (exists, is a git repo, the
# branch exists, the tag is not already present locally or on origin, and the
# current version is discoverable) BEFORE anything is tagged, so a bad argument
# fails fast instead of half-releasing the fleet.
#
# Signing: tags are created with `git tag -s` and version-bump commits with
# `git commit -S`, using whatever signing backend your git is configured with
# (OpenPGP or SSH — the same one that signs your commits). If signing is not
# configured, tag/commit creation fails and the script stops; it never pushes
# an unsigned tag.
#
# TAG NAMES: every repo — the platform included — now releases on a plain
# `v*` tag (the platform's release workflow was reconciled from the old
# namespaced `axiam-server/v*` to `v*`). Tags are per-repo, so the same
# `v1.0.0-alpha` in each repo is unambiguous. A single run can therefore cut
# the whole fleet:
#     scripts/mass-tag.sh -r all -b main -t v1.0.0-alpha -m "first alpha release" -p
# (Use --repos to release a subset — e.g. -r axiam or -r all-sdks — when the
# platform and SDKs are versioned on different cadences.)
#
# Usage:
#   scripts/mass-tag.sh --repos <all|all-sdks|name[,name...]> \
#                       --branch <branch> \
#                       --tag <tag-name> \
#                       --message <message> \
#                       [--pull] [--no-bump] [--root <dir>] [--dry-run]
#
#   -r, --repos    (required) 'all' (platform + 7 SDKs), 'all-sdks' (the 7
#                  SDKs only), or a comma-separated subset of the known repo
#                  names below.
#   -b, --branch   (required) branch to tag; must exist in every selected repo.
#   -t, --tag      (required) tag name to create (identical across the run). The
#                  release version is derived from it (strip 'prefix/' and 'v').
#   -m, --message  (required) tag message; the final annotation for each repo
#                  is "<repo-name> - <message>".
#   -p, --pull     (optional) fast-forward pull each branch from origin before
#                  tagging, so the release lands on the freshest HEAD.
#       --no-bump  (optional) do NOT edit or commit version strings; just tag
#                  HEAD as-is (the historical behaviour of this script).
#       --root DIR (optional) directory that CONTAINS the repo clones as
#                  siblings. Defaults to the parent of this repository, which
#                  is correct when all clones sit side by side.
#   -n, --dry-run  (optional) print every mutating action (version edits,
#                  checkout/pull/commit/tag/push) instead of running it.
#                  Validation still runs.
#   -h, --help     show this help and exit.
#
# Exit status: 0 if every selected repo was released and pushed; non-zero if
# pre-flight validation failed (nothing tagged) or any repo's operations failed.

set -euo pipefail

# ---------------------------------------------------------------------------
# Known repos. `all` = the platform repo first, then the seven SDKs.
# ---------------------------------------------------------------------------
PLATFORM_REPO="axiam"
SDK_REPOS=(
  axiam-rust-sdk
  axiam-typescript-sdk
  axiam-python-sdk
  axiam-java-sdk
  axiam-csharp-sdk
  axiam-php-sdk
  axiam-go-sdk
  axiam-kotlin-sdk
  axiam-swift-sdk
  axiam-c-sdk
  axiam-cplusplus-sdk
)
ALL_REPOS=("$PLATFORM_REPO" "${SDK_REPOS[@]}")

# ---------------------------------------------------------------------------
# Defaults / arg storage
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This script lives at <root>/axiam/scripts/mass-tag.sh, so <root> — the
# directory holding all sibling clones — is two levels up.
DEFAULT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPOS_ARG=""
BRANCH=""
TAG=""
MESSAGE=""
PULL=false
DRY_RUN=false
BUMP=true
ROOT="$DEFAULT_ROOT"

usage() {
  cat <<'EOF'
mass-tag.sh — cut and push a signed release across many AXIAM repos.

It derives the release version from the tag (strips a leading 'prefix/' and
'v'), writes that version into every version-bearing file of each selected
repo, commits the bump (signed), then tags that commit and pushes.

Usage:
  scripts/mass-tag.sh --repos <all|all-sdks|name[,name...]> \
                      --branch <branch> --tag <tag-name> --message <message> \
                      [--pull] [--no-bump] [--root <dir>] [--dry-run]

  -r, --repos    (required) 'all', 'all-sdks', or a comma-separated subset.
  -b, --branch   (required) branch to tag; must exist in every selected repo.
  -t, --tag      (required) tag name to create (plain v* for every repo); the
                 release version is derived from it (v1.4.0 means 1.4.0).
  -m, --message  (required) tag message; each tag's annotation is
                 "<repo-name> - <message>".
  -p, --pull     (optional) fast-forward pull each branch before releasing.
      --no-bump  (optional) skip version edits/commit; tag HEAD as-is.
      --root DIR (optional) directory containing the repo clones as siblings
                 (default: the parent of this repository).
  -n, --dry-run  (optional) print the mutating actions instead of running them.
                 Pre-flight validation still runs.
  -h, --help     show this help and exit.

Known repos: axiam (platform) + the seven axiam-<lang>-sdk repos.
Every repo releases on a plain v* tag, so one run (e.g. -r all -t v1.0.0) can
cut the whole fleet; use --repos to release a subset on its own cadence.
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--repos)   REPOS_ARG="${2:-}"; shift 2 ;;
    -b|--branch)  BRANCH="${2:-}";    shift 2 ;;
    -t|--tag)     TAG="${2:-}";       shift 2 ;;
    -m|--message) MESSAGE="${2:-}";   shift 2 ;;
    -p|--pull)    PULL=true;          shift ;;
    --no-bump)    BUMP=false;         shift ;;
    --root)       ROOT="${2:-}";      shift 2 ;;
    -n|--dry-run) DRY_RUN=true;       shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "unknown argument: $1 (try --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# Validate required arguments
# ---------------------------------------------------------------------------
[[ -n "$REPOS_ARG" ]] || die "--repos is required (all | all-sdks | name[,name...])"
[[ -n "$BRANCH"    ]] || die "--branch is required"
[[ -n "$TAG"       ]] || die "--tag is required"
[[ -n "$MESSAGE"   ]] || die "--message is required"
[[ -d "$ROOT"      ]] || die "--root '$ROOT' is not a directory"

# ---------------------------------------------------------------------------
# Derive the release version from the tag: drop a leading "v" (and, defensively,
# any legacy "prefix/" segment such as the old axiam-server/ namespace).
#   v1.4.0 -> 1.4.0 ;  axiam-server/v1.4.0 -> 1.4.0
# ---------------------------------------------------------------------------
version_from_tag() {
  local t="${1##*/}"    # drop everything up to and including the last '/'
  printf '%s' "${t#v}"  # drop a leading 'v'
}

# PEP 440 spelling for Python packaging: 1.4.0-alpha1 -> 1.4.0a1,
# -beta -> b, -rc -> rc (separator collapsed). Leaves stable versions untouched.
pep440() {
  printf '%s' "$1" | sed -E 's/[-_.]?alpha[-_.]?/a/; s/[-_.]?beta[-_.]?/b/; s/[-_.]?rc[-_.]?/rc/'
}

RELEASE_VERSION="$(version_from_tag "$TAG")"
if $BUMP; then
  # SemVer-ish (matches the check the SDK release workflows apply to the tag).
  if ! printf '%s' "$RELEASE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
    die "tag '$TAG' yields version '$RELEASE_VERSION', which is not a valid release version (expected MAJOR.MINOR.PATCH[-prerelease]). Use --no-bump to tag without editing versions."
  fi
fi

# ---------------------------------------------------------------------------
# Resolve the selected repo list
# ---------------------------------------------------------------------------
declare -a REPOS
case "$REPOS_ARG" in
  all)      REPOS=("${ALL_REPOS[@]}") ;;
  all-sdks) REPOS=("${SDK_REPOS[@]}") ;;
  *)
    IFS=',' read -r -a REQUESTED <<< "$REPOS_ARG"
    for name in "${REQUESTED[@]}"; do
      name="$(echo "$name" | xargs)"   # trim surrounding whitespace
      [[ -n "$name" ]] || continue
      known=false
      for k in "${ALL_REPOS[@]}"; do [[ "$k" == "$name" ]] && known=true && break; done
      $known || die "unknown repo '$name'. Known: ${ALL_REPOS[*]}"
      REPOS+=("$name")
    done
    ;;
esac
[[ ${#REPOS[@]} -gt 0 ]] || die "no repos selected"

# ---------------------------------------------------------------------------
# Version discovery + rewriting
# ---------------------------------------------------------------------------
# Files edited by the current repo's bump (staged for the release commit).
# Set by bump_versions and read by the action loop; declared here for clarity.
BUMP_FILES=()

# Echo a repo's CURRENT declared version, run from inside the repo's dir.
# Empty when the repo derives its version purely from the git tag (php, go) or
# when it cannot be found (so callers can report a clean failure). Always
# returns 0 — a missing match must not abort the caller under `set -e`.
current_version() {
  { case "$1" in
    axiam)
      # The [workspace.package] version — the source all crates inherit.
      sed -n '/^\[workspace\.package\]/,/^\[/{s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p}' Cargo.toml | head -n1
      ;;
    axiam-rust-sdk)
      grep -m1 -oP '^version[[:space:]]*=[[:space:]]*"\K[^"]+' Cargo.toml
      ;;
    axiam-typescript-sdk)
      grep -m1 -oP '"version"[[:space:]]*:[[:space:]]*"\K[^"]+' package.json
      ;;
    axiam-java-sdk)
      # First <version> in the root pom is the project's own version.
      grep -m1 -oP '(?<=<version>)[^<]+' pom.xml
      ;;
    axiam-csharp-sdk)
      grep -m1 -oP '(?<=<Version>)[^<]+' Axiam.Sdk/Axiam.Sdk.csproj
      ;;
    axiam-python-sdk)
      grep -m1 -oP '^version[[:space:]]*=[[:space:]]*"\K[^"]+' pyproject.toml
      ;;
    axiam-php-sdk|axiam-go-sdk)
      printf ''   # version comes from the git tag; nothing declared in-repo
      ;;
    axiam-kotlin-sdk)
      grep -m1 -oP '^version[[:space:]]*=[[:space:]]*\K.*' gradle.properties
      ;;
    axiam-swift-sdk)
      # SwiftPM derives its version from the git tag; the CocoaPods podspec is the
      # one in-repo declaration, so bump/discover from there.
      grep -m1 -oP "s\.version\s*=\s*['\"]\K[^'\"]+" AxiamSDK.podspec
      ;;
    axiam-c-sdk|axiam-cplusplus-sdk)
      grep -m1 -oP '"version"[[:space:]]*:[[:space:]]*"\K[^"]+' vcpkg.json
      ;;
  esac ; } || true
}

# Replace every literal occurrence of $2 with $3 in file $1, recording the file
# for staging. No-op (silently) when the file is absent, when old == new, or
# when the old literal is not present. Honours --dry-run.
sub_literal() {
  local file="$1" old="$2" new="$3"
  [[ -n "$old" ]] || return 0            # empty old would match everywhere — refuse
  [[ -f "$file" ]] || return 0
  [[ "$old" == "$new" ]] && return 0
  grep -qF -- "$old" "$file" || return 0
  if $DRY_RUN; then
    printf '      [dry-run] %s: "%s" -> "%s"\n' "$file" "$old" "$new"
  else
    OLD="$old" NEW="$new" perl -pi -e 's/\Q$ENV{OLD}\E/$ENV{NEW}/g' "$file"
    printf '      %s: "%s" -> "%s"\n' "$file" "$old" "$new"
  fi
  BUMP_FILES+=("$file")
}

# Set the first `<prefix>"<value>"` occurrence in file $1 to $3, where $2 is a
# perl regex matching the prefix (e.g. 'version[[:space:]]*=[[:space:]]*').
# Used for version fields whose current value we don't rely on (Python, whose
# __version__ is a drifted placeholder and whose spelling differs from the tag).
set_quoted_field() {
  local file="$1" prefix="$2" val="$3" label="$4"
  [[ -f "$file" ]] || { printf '      [skip] %s (absent)\n' "$file"; return 0; }
  if $DRY_RUN; then
    printf '      [dry-run] %s: %s -> "%s"\n' "$file" "$label" "$val"
  else
    PRE="$prefix" VAL="$val" perl -0pi -e 's/($ENV{PRE})"[^"]*"/$1 . "\"" . $ENV{VAL} . "\""/e' "$file"
    printf '      %s: %s -> "%s"\n' "$file" "$label" "$val"
  fi
  BUMP_FILES+=("$file")
}

# Bump every axiam-* crate entry in ./Cargo.lock from $1 to $2. The workspace
# crates all share one version, so a `cargo build` would rewrite these anyway;
# doing it here keeps the committed lockfile consistent without a build.
bump_cargo_lock_axiam() {
  local old="$1" new="$2"
  [[ -f Cargo.lock ]] || return 0
  [[ "$old" == "$new" ]] && return 0
  grep -q '^name = "axiam-' Cargo.lock || return 0
  if $DRY_RUN; then
    printf '      [dry-run] Cargo.lock: axiam-* crate versions "%s" -> "%s"\n' "$old" "$new"
  else
    OLD="$old" NEW="$new" perl -0pi -e 's/(name = "axiam-[^"]*"\nversion = )"\Q$ENV{OLD}\E"/$1 . "\"" . $ENV{NEW} . "\""/ge' Cargo.lock
    printf '      Cargo.lock: axiam-* crate versions "%s" -> "%s"\n' "$old" "$new"
  fi
  BUMP_FILES+=("Cargo.lock")
}

# Rewrite the release version everywhere repo $1 declares it, to version $2.
# Runs from inside the repo's directory. Populates BUMP_FILES.
bump_versions() {
  local repo="$1" version="$2" old
  BUMP_FILES=()
  old="$(current_version "$repo")"
  case "$repo" in
    axiam)
      sub_literal Cargo.toml                                       "$old" "$version"
      sub_literal sdks/openapi.json                                "$old" "$version"
      sub_literal frontend/src/components/layout/Sidebar.tsx       "$old" "$version"
      sub_literal frontend/src/components/layout/Sidebar.test.tsx  "$old" "$version"
      sub_literal k8s/server/deployment.yml                        "$old" "$version"
      sub_literal k8s/frontend/deployment.yml                      "$old" "$version"
      bump_cargo_lock_axiam                                        "$old" "$version"
      ;;
    axiam-rust-sdk)
      # Replaces the package version AND the `=`-pinned axiam-sdk-macros dep
      # (the `=` prefix is preserved because only the literal changes).
      sub_literal Cargo.toml                    "$old" "$version"
      sub_literal axiam-sdk-macros/Cargo.toml   "$old" "$version"
      ;;
    axiam-typescript-sdk)
      sub_literal package.json       "$old" "$version"
      sub_literal package-lock.json  "$old" "$version"
      ;;
    axiam-java-sdk)
      # Every occurrence of the project version literal across the poms is the
      # project's own version or a managed/declared dependency on this repo's
      # own axiam-sdk; the example app's independent version (0.1.0) differs and
      # is left untouched.
      sub_literal pom.xml                              "$old" "$version"
      sub_literal bom/pom.xml                          "$old" "$version"
      sub_literal examples/spring-boot-app/pom.xml     "$old" "$version"
      sub_literal README.md                            "$old" "$version"
      ;;
    axiam-csharp-sdk)
      sub_literal Axiam.Sdk/Axiam.Sdk.csproj                        "$old" "$version"
      sub_literal Axiam.Sdk.AspNetCore/Axiam.Sdk.AspNetCore.csproj  "$old" "$version"
      ;;
    axiam-python-sdk)
      # PEP 440 spelling, and __version__ is a placeholder we overwrite outright.
      local pyver; pyver="$(pep440 "$version")"
      set_quoted_field pyproject.toml            'version[[:space:]]*=[[:space:]]*'      "$pyver" '[project].version'
      set_quoted_field src/axiam_sdk/__init__.py '__version__[[:space:]]*=[[:space:]]*' "$pyver" '__version__'
      ;;
    axiam-php-sdk|axiam-go-sdk)
      : # version is derived from the git tag; nothing to rewrite
      ;;
    axiam-kotlin-sdk)
      # Gradle project version lives in gradle.properties; README shows install coords.
      sub_literal gradle.properties  "$old" "$version"
      sub_literal README.md          "$old" "$version"
      ;;
    axiam-swift-sdk)
      # SwiftPM is tag-derived; the CocoaPods podspec carries the only in-repo version.
      sub_literal AxiamSDK.podspec   "$old" "$version"
      sub_literal README.md          "$old" "$version"
      ;;
    axiam-c-sdk|axiam-cplusplus-sdk)
      # C/C++ declare the version in the CMake project(), the vcpkg manifest and the
      # Conan recipe; keep all three (and the README install coords) in lockstep.
      sub_literal vcpkg.json         "$old" "$version"
      sub_literal CMakeLists.txt     "$old" "$version"
      sub_literal conanfile.py       "$old" "$version"
      sub_literal README.md          "$old" "$version"
      ;;
  esac
}

# Helper: run a mutating git command, honouring --dry-run. In dry-run mode the
# command is printed with shell quoting so it is unambiguous and copy-pasteable.
run() {
  if $DRY_RUN; then
    printf '    [dry-run]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

echo "==> Plan"
echo "    root:    $ROOT"
echo "    repos:   ${REPOS[*]}"
echo "    branch:  $BRANCH"
echo "    tag:     $TAG"
echo "    version: $RELEASE_VERSION"
echo "    message: <repo> - $MESSAGE"
echo "    pull:    $PULL"
echo "    bump:    $BUMP"
echo "    dry-run: $DRY_RUN"
echo ""

# ---------------------------------------------------------------------------
# Pre-flight: validate ALL selected repos before touching any of them.
# ---------------------------------------------------------------------------
echo "==> Pre-flight validation"
preflight_ok=true
for repo in "${REPOS[@]}"; do
  dir="$ROOT/$repo"
  if [[ ! -d "$dir/.git" ]]; then
    echo "    [FAIL] $repo — not a git repository at $dir"; preflight_ok=false; continue
  fi
  # Branch must exist locally or as a remote-tracking ref.
  if ! git -C "$dir" show-ref --verify --quiet "refs/heads/$BRANCH" \
     && ! git -C "$dir" show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
    echo "    [FAIL] $repo — branch '$BRANCH' not found (local or origin)"; preflight_ok=false; continue
  fi
  # Tag must not already exist locally...
  if git -C "$dir" rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "    [FAIL] $repo — tag '$TAG' already exists locally"; preflight_ok=false; continue
  fi
  # ...nor on origin (never silently clobber a published release tag).
  if [[ -n "$(git -C "$dir" ls-remote --tags origin "refs/tags/$TAG" 2>/dev/null)" ]]; then
    echo "    [FAIL] $repo — tag '$TAG' already exists on origin"; preflight_ok=false; continue
  fi
  # When bumping, the repo's current version must be discoverable (except for
  # the tag-derived repos), so the rewrite has a known starting point.
  if $BUMP; then
    cv="$(cd "$dir" && current_version "$repo")"
    if [[ "$repo" != axiam-php-sdk && "$repo" != axiam-go-sdk && -z "$cv" ]]; then
      echo "    [FAIL] $repo — could not determine current version to bump"; preflight_ok=false; continue
    fi
    echo "    [ ok ] $repo (${cv:-tag-derived} -> $RELEASE_VERSION)"
  else
    echo "    [ ok ] $repo"
  fi
done
$preflight_ok || die "pre-flight validation failed; nothing was tagged."
echo ""

# ---------------------------------------------------------------------------
# Action: bump + commit, then tag + push each repo.
# ---------------------------------------------------------------------------
echo "==> Releasing"
FAIL_COUNT=0
FAILED_REPOS=""
for repo in "${REPOS[@]}"; do
  dir="$ROOT/$repo"
  full_msg="$repo - $MESSAGE"
  echo "  --- $repo ---"
  (
    set -euo pipefail
    cd "$dir"

    echo "    checkout $BRANCH"
    run git checkout "$BRANCH"

    if $PULL; then
      echo "    pull --ff-only origin $BRANCH"
      run git pull --ff-only origin "$BRANCH"
    fi

    if $BUMP; then
      echo "    bump version -> $RELEASE_VERSION"
      bump_versions "$repo" "$RELEASE_VERSION"
      if $DRY_RUN; then
        echo "    [dry-run] git add <bumped files> && git commit -S (if anything changed)"
      elif [[ ${#BUMP_FILES[@]} -gt 0 ]]; then
        git add -- "${BUMP_FILES[@]}"
        if git diff --cached --quiet; then
          echo "    already at $RELEASE_VERSION — no version commit needed"
        else
          echo "    commit version bump"
          git commit -S -m "chore(release): prepare $repo $RELEASE_VERSION"
        fi
      else
        echo "    no in-repo version to bump (tag-derived) — tagging HEAD as-is"
      fi
    fi

    echo "    sign tag $TAG on HEAD ($(git rev-parse --short HEAD)) — \"$full_msg\""
    run git tag -s "$TAG" -m "$full_msg"

    echo "    push branch $BRANCH"
    run git push origin "$BRANCH"

    echo "    push tag $TAG"
    run git push origin "refs/tags/$TAG"
  ) || { echo "    [FAILED] $repo"; FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_REPOS="$FAILED_REPOS $repo"; continue; }
  echo "    [done] $repo"
done
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [[ $FAIL_COUNT -gt 0 ]]; then
  echo "==> Completed with failures:$FAILED_REPOS"
  exit 1
fi
echo "==> All ${#REPOS[@]} repo(s) released as '$TAG' (version $RELEASE_VERSION) and pushed."
