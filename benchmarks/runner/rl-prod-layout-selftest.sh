#!/usr/bin/env bash
# M2 regression guard: rl_prod_check.py must read a `bench-matrix` results
# tree, not only a flat one.
#
# `bench-matrix` writes `results/run-<i>/<target>/<profile>/…` — even at
# `repeat=1` — while a plain `bench-run` writes the flat
# `results/<target>/<profile>/…`. rl_prod_check.py used to read only the flat
# layout, so `just rl-prod-check` against a matrix tree reported "no data" for
# EVERY endpoint and exited 0: a whole rl=prod pass silently unverified, which
# is the exact failure mode this script exists to prevent (I1's units bug got
# through a by-hand read).
#
# Three assertions, on fixtures built from the script's OWN extracted
# configured limits (never hardcoded here — the limits are tuned from time to
# time and a hardcoded copy would go stale exactly like the one I19 removed):
#
#   1. flat tree, every cell at its configured limit  -> all PASS, exit 0
#   2. matrix tree, same numbers under run-1/         -> all PASS, exit 0
#      (pre-M2 this was "no data" on every row)
#   3. matrix tree, three passes at 0.5x / 1.0x / 1.5x the configured limit
#      -> all PASS, because the MEDIAN is taken across passes as report.py
#      does. Reading any single pass instead would put two thirds of the
#      fixture outside the +-10% band and fail.
#
# Hermetic: pure python3 + the checked-in Rust sources the script extracts
# from. No docker, no k6, no results tree. Runs in CI on every PR.
# Usage: rl-prod-layout-selftest.sh          (from benchmarks/)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

python3 - "$HERE" "$FIX" <<'PY'
import json, os, subprocess, sys

here, fix = sys.argv[1], sys.argv[2]
sys.path.insert(0, here)
import rl_prod_check as rl

TARGET, PROFILE = "axiam", "p0-plaintext"
configured = rl.read_configured_defaults()


def write_cell(cell_dir, scenario_file, admitted_per_min):
    """One cell's artifact pair, in the shape run-benchmark.sh writes: a
    <scenario>.meta.json naming its k6 summary, and that summary carrying the
    bench_ok counter report.load_k6_summary reads throughput from (ops/s)."""
    os.makedirs(cell_dir, exist_ok=True)
    stem = scenario_file[:-3]
    k6_name = f"{stem}.k6.json"
    with open(os.path.join(cell_dir, f"{stem}.meta.json"), "w") as f:
        json.dump({"k6_summary_file": k6_name}, f)
    with open(os.path.join(cell_dir, k6_name), "w") as f:
        json.dump({"metrics": {"bench_ok": {"rate": admitted_per_min / 60.0,
                                            "count": admitted_per_min}}}, f)


def write_tree(root, factor_per_pass, matrix):
    """One results tree: pass i admits `factor_per_pass[i] x configured` for
    every scenario-backed endpoint. `matrix` selects the layout — run-<i>/
    subtrees (bench-matrix) vs. a single flat <target>/<profile>/ (bench-run)."""
    for i, factor in enumerate(factor_per_pass, start=1):
        base = os.path.join(root, f"run-{i}") if matrix else root
        cell_dir = os.path.join(base, TARGET, PROFILE)
        for field, (scenario_file, _label) in rl.ENDPOINTS.items():
            if scenario_file is None:
                continue
            write_cell(cell_dir, scenario_file, configured[field] * factor)



def run(root):
    return subprocess.run(
        [sys.executable, os.path.join(here, "rl_prod_check.py"),
         "--results", root, "--target", TARGET, "--profile", PROFILE],
        capture_output=True, text=True)


fail = False
CASES = [
    ("flat tree at the configured limit", "flat", [1.0], False),
    ("matrix tree, single pass (repeat=1)", "matrix-1", [1.0], True),
    ("matrix tree, median of three passes", "matrix-3", [0.5, 1.0, 1.5], True),
]
for name, subdir, factors, matrix in CASES:
    root = os.path.join(fix, subdir)
    write_tree(root, factors, matrix)
    res = run(root)
    if res.returncode != 0:
        print(f"[rl-prod-layout-selftest] {name}: expected exit 0, got "
              f"{res.returncode}\n{res.stdout}\n{res.stderr}", file=sys.stderr)
        fail = True
    if "no data" in res.stdout:
        print(f"[rl-prod-layout-selftest] {name}: endpoints reported 'no data' — "
              f"the layout was not read\n{res.stdout}", file=sys.stderr)
        fail = True
    summary = os.path.join(root, "rl-prod-summary.md")
    if not os.path.exists(summary):
        print(f"[rl-prod-layout-selftest] {name}: no rl-prod-summary.md written",
              file=sys.stderr)
        fail = True

# The check must still FAIL loudly when admission really is off-limit: a
# layout fix that made everything pass would be worse than the bug.
off = os.path.join(fix, "matrix-off")
write_tree(off, [2.0], True)
res = run(off)
if res.returncode == 0:
    print("[rl-prod-layout-selftest] a matrix tree admitting 2x the configured "
          f"limit was reported as PASS\n{res.stdout}", file=sys.stderr)
    fail = True

sys.exit(1 if fail else 0)
PY

echo "[rl-prod-layout-selftest] OK — flat and run-*/ matrix trees are both read; passes are medianed."
