#!/usr/bin/env bash
# The twelve checkouts: axiam at the release tag, the eleven SDKs beside it.
# Idempotent: an existing checkout is fetched, not re-cloned.
#
# Runbook: claude_dev/bench-vm-runbook.md §6. Every SDK bench resolves its SDK
# at ../../../../axiam-<lang>-sdk from benchmarks/sdk/<lang>/, so the SDKs must
# sit BESIDE axiam, under $BENCH_DIR.
#
# If the repositories are private, set up read access first (`gh auth login`,
# or a fine-grained PAT with Contents: read on these twelve repositories in a
# git credential helper). This script never asks for or stores a token.
#
#   AXIAM_TAG=v1.4.0   the release (default: versions.env)
#   AXIAM_REF=<ref>    the harness checkout (default: the tag). Another ref is
#                      accepted only if the tag is its ancestor and no product
#                      source differs (crates/, proto/, Cargo.toml, Cargo.lock).
#   SDK_REF=<ref>      check every SDK out at this ref; default: leave the
#                      default branch. Every SDK record carries the version it
#                      built either way (benchmarks/sdk/_sdkversion.sh).
#
# Usage:  ./03-checkouts.sh           Then: ./04-verify.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
# shellcheck source=versions.env
source "$HERE/versions.env"
stop_loudly
need git

GH="https://github.com/ilpanich"
mkdir -p "$BENCH_DIR/logs"
cd "$BENCH_DIR"

# --filter=blob:none keeps the full history (the provenance check needs
# origin/main) without downloading every old file.
clone_or_fetch() {
    local repo="$1"
    if [[ -d "$repo/.git" ]]; then
        git -C "$repo" fetch --quiet --tags origin
    else
        git ls-remote --exit-code "$GH/$repo.git" HEAD >/dev/null 2>&1 \
            || die "Cannot read $GH/$repo.git. If it is private, set up read access first (see the header of this script)."
        git clone --quiet --filter=blob:none "$GH/$repo.git"
    fi
}

# ---------------------------------------------------------------------------
# axiam, at the tag — refuse to continue on a tag that is not published
# ---------------------------------------------------------------------------
git ls-remote --exit-code --tags "$GH/axiam.git" "refs/tags/$AXIAM_TAG" >/dev/null 2>&1 \
    || die "Tag $AXIAM_TAG is not published yet. The round measures a release (bench-vm-runbook.md §6.1); provisioning can go on without it, the checkout cannot."
clone_or_fetch axiam
git -C axiam fetch --quiet origin main
# shellcheck disable=SC2015  # die when either diff is non-empty
git -C axiam diff --quiet && git -C axiam diff --cached --quiet \
    || die "axiam has local changes; the run's build_ref must describe a clean tag. Stash or discard them first."
if [[ "$AXIAM_REF" != "$AXIAM_TAG" ]]; then
    ref_commit="$(git -C axiam rev-parse -q --verify "$AXIAM_REF^{commit}")" \
        || die "AXIAM_REF=$AXIAM_REF does not resolve in the axiam checkout."
    git -C axiam merge-base --is-ancestor "$AXIAM_TAG" "$ref_commit" \
        || die "$AXIAM_TAG is not an ancestor of $AXIAM_REF: the harness would not contain the release."
    git -C axiam diff --quiet "$AXIAM_TAG" "$ref_commit" -- crates proto Cargo.toml Cargo.lock \
        || die "Product source differs between $AXIAM_TAG and $AXIAM_REF (crates/, proto/, Cargo.toml or Cargo.lock): the image measured would not match the harness. Use a ref that changes only harness and docs."
    git -C axiam checkout --quiet --detach "$ref_commit"
    ok "harness at $AXIAM_REF ($(git -C axiam rev-parse --short=12 HEAD)); product source identical to $AXIAM_TAG"
else
    git -C axiam checkout --quiet "$AXIAM_TAG"
fi
git -C axiam merge-base --is-ancestor HEAD origin/main \
    || die "$(git -C axiam rev-parse --short=12 HEAD) is not on origin/main; run-benchmark.sh would refuse every AXIAM cell."
version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' axiam/Cargo.toml | head -1)"
[[ "$version" == "${AXIAM_TAG#v}" ]] || die "Cargo.toml at $AXIAM_REF says version $version, not ${AXIAM_TAG#v}."
surreal="$(sed -n 's/.*BENCH_SURREALDB_IMAGE:-\([^}]*\)}.*/\1/p' axiam/benchmarks/targets/axiam/docker-compose.yml | head -1)"
ok "axiam $AXIAM_TAG, harness @ $(git -C axiam rev-parse --short=12 HEAD) (version $version; harness SurrealDB default: $surreal)"

# ---------------------------------------------------------------------------
# The eleven SDKs
# ---------------------------------------------------------------------------
for lang in $SDK_REPOS; do
    clone_or_fetch "axiam-$lang-sdk"
    if [[ -n "${SDK_REF:-}" ]]; then git -C "axiam-$lang-sdk" checkout --quiet "$SDK_REF"; fi
done
{
    echo "# $(date -u +%FT%TZ)  checkouts under $BENCH_DIR"
    printf '%-24s %s\n' axiam "$AXIAM_TAG (harness $AXIAM_REF) $(git -C axiam rev-parse HEAD)"
    for lang in $SDK_REPOS; do
        printf '%-24s %s\n' "axiam-$lang-sdk" "$(git -C "axiam-$lang-sdk" describe --tags --always) $(git -C "axiam-$lang-sdk" rev-parse HEAD)"
    done
} | tee "$BENCH_DIR/logs/checkouts.txt"

ok "Checkouts in place. Next: ./04-verify.sh (after the registry logins, runbook §4)"
