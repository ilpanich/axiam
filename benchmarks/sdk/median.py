#!/usr/bin/env python3
"""median.py — I15 (improvement-after-run4-benchmark.md §D): median-of-N
aggregation for repeated SDK bench passes.

`just sdk-bench-all` (justfile) now supports `repeat=N` (default 3, same
knob/default as the server-side matrix's C1 median-of-N — see
runner/report.py's `_median_of`), running `sdk/run-all.sh` N times into
`${BENCH_RESULTS_DIR}/sdk-run-<i>/sdk/<profile>/<lang>.json` and then calling
this script to fold the N passes into a single median record per
(language, profile) at the canonical `${BENCH_RESULTS_DIR}/sdk/<profile>/
<lang>.json` location `collect.py`/`report.py` already read.

Median semantics mirror the server-side aggregator: each of `p50_ms`,
`p95_ms`, `p99_ms`, `throughput_rps`, `errors`, `client_cpu_ms_total`, and
`client_rss_mib_peak` is medianed independently across the "ok" passes (a
per-field median-of-N, not "pick the median run" — the same choice
runner/report.py's `_median_of` makes and documents). A record only counts
as a usable pass if its top-level `status` is "ok"; `error`/`pending` passes
are excluded from the median but do not by themselves fail the aggregation
as long as at least one pass was "ok" for that language. `notes` on the
merged record says how many of the N passes were usable.

Stdlib only, matching collect.py.

Usage:
    python3 median.py --runs results/sdk-run-1 results/sdk-run-2 results/sdk-run-3 \\
        --out results/sdk
"""
import argparse
import json
import os
import statistics
import sys

OP_KEYS = ("login", "refresh", "check_access", "batch_check")
NUMERIC_OP_FIELDS = ("p50_ms", "p95_ms", "p99_ms", "throughput_rps", "errors")
RECORD_NUMERIC_FIELDS = ("client_cpu_ms_total", "client_rss_mib_peak")


def median(values):
    """statistics.median with an empty-list guard (mirrors report.py's C1 helper)."""
    return statistics.median(values) if values else 0.0


def load_pass_records(run_dir):
    """Load every axiam.sdk-bench/v1 record under run_dir/sdk/<profile>/<lang>.json,
    keyed by (sdk, profile). Reuses collect.py's own walker so the two stay in
    sync on the results/sdk/ layout (profile-scoped subdir, or the legacy flat
    layout)."""
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    try:
        import collect as sdk_collect
    finally:
        if here in sys.path:
            sys.path.remove(here)
    recs = sdk_collect.load_sdk_records(run_dir)
    by_key = {}
    for r in recs:
        key = (r.get("sdk"), r.get("profile", "?"))
        by_key.setdefault(key, []).append(r)
    return by_key


def merge_records(records):
    """Merge N passes' records (same sdk+profile) into one median record.

    `records` may include non-"ok" passes (error/pending) — only "ok" passes
    contribute to the medianed numbers; the merged record's own status/notes
    reflect how many of the N passes were usable.
    """
    ok = [r for r in records if r.get("status") == "ok"]
    n_total = len(records)
    n_ok = len(ok)
    base = ok[0] if ok else records[0]

    if not ok:
        # No usable pass at all — return the first record as-is (already a
        # valid error/pending axiam.sdk-bench/v1 record) so the aggregator
        # never invents data for a language that never produced a real
        # measurement across any of the N passes.
        return dict(base)

    merged = dict(base)
    merged_ops = {}
    for op in OP_KEYS:
        per_pass = [r.get("ops", {}).get(op, {}) for r in ok if op in r.get("ops", {})]
        if not per_pass:
            merged_ops[op] = {f: 0 for f in NUMERIC_OP_FIELDS}
            continue
        merged_ops[op] = {
            f: median([p.get(f, 0) for p in per_pass]) for f in NUMERIC_OP_FIELDS
        }
    merged["ops"] = merged_ops
    for f in RECORD_NUMERIC_FIELDS:
        merged[f] = median([r.get(f, 0) for r in ok])
    merged["status"] = "ok"
    note_prefix = f"median of {n_total} passes ({n_ok} ok)"
    existing_notes = base.get("notes") or ""
    merged["notes"] = f"{note_prefix}; {existing_notes}" if existing_notes else note_prefix
    return merged


def write_merged(out_root, sdk, profile, record):
    out_dir = os.path.join(out_root, "sdk", profile)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{sdk}.json")
    with open(out_path, "w") as f:
        json.dump(record, f, indent=2)
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True,
                     help="One BENCH_RESULTS_DIR root per pass (each holding sdk/<profile>/*.json)")
    ap.add_argument("--out", required=True,
                     help="Results root to write the merged sdk/<profile>/<lang>.json into")
    args = ap.parse_args()

    by_key = {}
    for run_dir in args.runs:
        for key, recs in load_pass_records(run_dir).items():
            by_key.setdefault(key, []).extend(recs)

    if not by_key:
        print(f"[median] no SDK records found under any of: {args.runs}", file=sys.stderr)
        sys.exit(1)

    n_passes = len(args.runs)
    for (sdk, profile), records in sorted(by_key.items()):
        merged = merge_records(records)
        out_path = write_merged(args.out, sdk, profile, merged)
        n_ok = sum(1 for r in records if r.get("status") == "ok")
        print(f"[median] {sdk}@{profile}: {n_ok}/{len(records)} pass(es) ok "
              f"(of {n_passes} requested) -> {out_path}")


if __name__ == "__main__":
    main()
