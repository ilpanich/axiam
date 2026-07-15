#!/usr/bin/env bash
# mass-tag.sh — Create and push a signed release tag across many AXIAM repos.
#
# AXIAM ships as one platform repo plus seven per-language SDK repos, each in
# its own clone. Cutting a release means putting the SAME tag on the HEAD of
# the SAME branch in every repo and pushing it so the per-repo release
# pipelines fire. Doing that by hand, eight times, is tedious and error-prone
# — this script does it in one pass.
#
# For each selected repo it will, in order:
#   1. check out the requested branch,
#   2. optionally pull it fast-forward from origin (--pull),
#   3. create a SIGNED annotated tag on HEAD, whose message is the repo name
#      prepended to your message ("<repo> - <message>"),
#   4. push the branch and then the tag to origin.
#
# A pre-flight pass validates EVERY selected repo (exists, is a git repo, the
# branch exists, the tag is not already present locally or on origin) BEFORE
# anything is tagged, so a bad argument fails fast instead of half-tagging the
# fleet.
#
# Signing: tags are created with `git tag -s`, which uses whatever signing
# backend your git is configured with (OpenPGP or SSH — the same one that
# signs your commits). If signing is not configured, tag creation fails and
# the script stops; it never pushes an unsigned tag.
#
# NOTE ON TAG NAMES: the platform repo's release workflow triggers on the
# namespaced tag `axiam-server/v*`, while every SDK triggers on `v*`. Because
# a single run applies ONE tag name to its selected repos, cut a release in
# two runs, e.g.:
#     scripts/mass-tag.sh -r axiam    -b main -t axiam-server/v1.0.0-alpha -m "first alpha release" -p
#     scripts/mass-tag.sh -r all-sdks -b main -t v1.0.0-alpha              -m "first alpha release" -p
#
# Usage:
#   scripts/mass-tag.sh --repos <all|all-sdks|name[,name...]> \
#                       --branch <branch> \
#                       --tag <tag-name> \
#                       --message <message> \
#                       [--pull] [--root <dir>] [--dry-run]
#
#   -r, --repos    (required) 'all' (platform + 7 SDKs), 'all-sdks' (the 7
#                  SDKs only), or a comma-separated subset of the known repo
#                  names below.
#   -b, --branch   (required) branch to tag; must exist in every selected repo.
#   -t, --tag      (required) tag name to create (identical across the run).
#   -m, --message  (required) tag message; the final annotation for each repo
#                  is "<repo-name> - <message>".
#   -p, --pull     (optional) fast-forward pull each branch from origin before
#                  tagging, so the tag lands on the freshest HEAD.
#       --root DIR (optional) directory that CONTAINS the repo clones as
#                  siblings. Defaults to the parent of this repository, which
#                  is correct when all clones sit side by side.
#   -n, --dry-run  (optional) print every git command instead of running the
#                  mutating ones (checkout/pull/tag/push). Validation still runs.
#   -h, --help     show this help and exit.
#
# Exit status: 0 if every selected repo was tagged and pushed; non-zero if
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
ROOT="$DEFAULT_ROOT"

usage() {
  cat <<'EOF'
mass-tag.sh — create and push a signed release tag across many AXIAM repos.

Usage:
  scripts/mass-tag.sh --repos <all|all-sdks|name[,name...]> \
                      --branch <branch> --tag <tag-name> --message <message> \
                      [--pull] [--root <dir>] [--dry-run]

  -r, --repos    (required) 'all', 'all-sdks', or a comma-separated subset.
  -b, --branch   (required) branch to tag; must exist in every selected repo.
  -t, --tag      (required) tag name to create (identical across the run).
  -m, --message  (required) tag message; each tag's annotation is
                 "<repo-name> - <message>".
  -p, --pull     (optional) fast-forward pull each branch before tagging.
      --root DIR (optional) directory containing the repo clones as siblings
                 (default: the parent of this repository).
  -n, --dry-run  (optional) print the git commands instead of running the
                 mutating ones. Pre-flight validation still runs.
  -h, --help     show this help and exit.

Known repos: axiam (platform) + the seven axiam-<lang>-sdk repos.
The platform repo's release tag is namespaced (axiam-server/v*); the SDKs use
v* — so cut a release in two runs (one per tag name) using --repos.
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
echo "    message: <repo> - $MESSAGE"
echo "    pull:    $PULL"
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
  echo "    [ ok ] $repo"
done
$preflight_ok || die "pre-flight validation failed; nothing was tagged."
echo ""

# ---------------------------------------------------------------------------
# Action: tag + push each repo.
# ---------------------------------------------------------------------------
echo "==> Tagging & pushing"
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
echo "==> All ${#REPOS[@]} repo(s) tagged '$TAG' and pushed."
