#!/usr/bin/env bash
# M1 regression guard: an extension-less `--scenario` must still be filtered.
#
# `--scenario authz_check_rest` used to be passed through verbatim. Two things
# broke at once and only one of them was audible:
#
#   * `k6 run scenarios/authz_check_rest` is not a file — loud, and the reason
#     the bug looked harmless;
#   * every membership test in run-benchmark.sh's filter_scenarios() compares
#     against `.js`-suffixed names (PENDING_SCENARIOS, AXIAM_ONLY_SCENARIOS,
#     ZITADEL_ONLY_SCENARIOS, OAUTH2_SCENARIOS, BENCH_SCENARIO_EXCLUDE), so an
#     extension-less name matched NONE of them and silently bypassed the lot —
#     including the pending-scenario guard, whose entire job is to stop a
#     not-yet-runnable cell from being run.
#
# So this asserts the filters, not the filename: it drives the REAL runner in
# dry-run mode with extension-less names that must be skipped, and checks the
# dry-run ledger records the skip against the normalized `.js` cell name.
# Passing names the filters do NOT skip is out of scope here — that path needs
# k6 and a live stack.
#
# Hermetic: no docker, no k6, no seeded stack (BENCH_SKIP_SEED_CHECK=1; the
# runner never reaches its k6 invocation because every scenario is filtered
# out first). Runs in CI on every PR.
# Usage: scenario-filter-selftest.sh          (from benchmarks/)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

fail=0

# target, scenario-as-typed, expected cell name in the ledger, why it must skip
check_skip() {
  local target="$1" typed="$2" cell="$3" why="$4"
  local out="$FIX/$target-$cell"
  mkdir -p "$out"
  # The runner exits non-zero here by design (every scenario filtered out, and
  # in this environment it also has no k6) — the ledger row is the assertion.
  BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$out" \
    bash "$HERE/run-benchmark.sh" --target "$target" --profile p0-plaintext \
      --scenario "$typed" --dry-run >"$out/runner.log" 2>&1 || true

  # Literal match on the TSV row prefix (fixed-string, real tabs) rather than
  # a regex over names that contain regex metacharacters.
  local want
  want="$(printf '%s\tp0-plaintext\t%s\tSKIP\t' "$target" "$cell")"
  if ! grep -qF "$want" "$out/dry-run.tsv" 2>/dev/null; then
    echo "[scenario-filter-selftest] '--scenario $typed' (target $target) was NOT skipped as $cell ($why)." >&2
    echo "  ledger: $(cat "$out/dry-run.tsv" 2>/dev/null || echo '<no dry-run.tsv written>')" >&2
    fail=1
  fi
}

# Pending guard — the costliest bypass: this cell is pending precisely because
# running it unsupervised turns a skip into a red matrix cell.
check_skip axiam    scim_provisioning    scim_provisioning "pending scenario"
# Target-scoping guard — an AXIAM-only cell run against another vendor.
check_skip keycloak authz_check_rest     authz_check_rest  "AXIAM-only scenario"
# The already-correct spelling must behave identically — normalization is
# idempotent, not a second code path.
check_skip axiam    scim_provisioning.js scim_provisioning "pending scenario, spelled with .js"

[ "$fail" -eq 0 ] || { echo "[scenario-filter-selftest] FAILED" >&2; exit 1; }
echo "[scenario-filter-selftest] OK — extension-less --scenario names are normalized before filtering."
