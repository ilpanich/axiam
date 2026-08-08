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


def _pass_label(run_dir):
    """Short, stable name for a pass directory (results/sdk-run-2 -> sdk-run-2)."""
    return os.path.basename(os.path.normpath(run_dir)) or run_dir


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


def merge_records(records, requested_passes=None, present_passes=None):
    """Merge N passes' records (same sdk+profile) into one median record.

    `records` may include non-"ok" passes (error/pending) — only "ok" passes
    contribute to the medianed numbers; the merged record's own status/notes
    reflect how many of the N passes were usable.

    J8: run 5's C# row read "median of 2" against a `repeat=3` request, and
    nothing anywhere said which pass went missing or why. A pass that produces
    no record at all is invisible to a merger that only looks at the records
    it received — `len(records)` was already 2, so "2 of 2 ok" was truthfully
    reported and completely misleading. `requested_passes`/`present_passes`
    (pass labels, not counts) let the merged record name the absentees, so the
    next occurrence points straight at a run directory to go read.
    """
    ok = [r for r in records if r.get("status") == "ok"]
    n_total = len(records)
    n_ok = len(ok)
    base = ok[0] if ok else records[0]

    requested = list(requested_passes or [])
    present = list(present_passes or [])
    missing = [p for p in requested if p not in present]

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
    # J8: the provenance of the median travels WITH the median. A reader of a
    # single merged record can now tell a clean 3/3 from a 2/3 without going
    # back to the aggregator's stdout, which is not archived.
    merged["passes_requested"] = len(requested) or n_total
    merged["passes_present"] = n_total
    merged["passes_ok"] = n_ok
    merged["passes_missing"] = missing
    note_prefix = f"median of {n_total} passes ({n_ok} ok)"
    if missing:
        note_prefix += (
            f"; {len(missing)} pass(es) produced NO record for this sdk/profile "
            f"({', '.join(missing)}) — check that run's sdk log for the drop reason "
            "(J8)"
        )
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
    ap.add_argument("--allow-partial", action="store_true",
                     help="J8: accept a median built from fewer passes than requested. "
                          "Off by default — a silently-partial median is what let run 5 "
                          "publish a 'median of 2' against repeat=3 unnoticed.")
    args = ap.parse_args()

    by_key = {}
    # J8: remember WHICH pass each record came from, so a pass that produced
    # nothing for a given language can be named rather than merely subtracted.
    seen_in = {}
    for run_dir in args.runs:
        label = _pass_label(run_dir)
        for key, recs in load_pass_records(run_dir).items():
            by_key.setdefault(key, []).extend(recs)
            seen_in.setdefault(key, []).append(label)

    if not by_key:
        print(f"[median] no SDK records found under any of: {args.runs}", file=sys.stderr)
        sys.exit(1)

    requested = [_pass_label(d) for d in args.runs]
    n_passes = len(args.runs)
    incomplete = []
    for (sdk, profile), records in sorted(by_key.items()):
        merged = merge_records(records, requested, seen_in.get((sdk, profile), []))
        out_path = write_merged(args.out, sdk, profile, merged)
        n_ok = merged.get("passes_ok", 0)
        missing = merged.get("passes_missing") or []
        line = (f"[median] {sdk}@{profile}: {n_ok}/{len(records)} pass(es) ok "
                f"(of {n_passes} requested) -> {out_path}")
        if missing:
            line += f"  MISSING: {', '.join(missing)}"
            incomplete.append(f"{sdk}@{profile} (missing {', '.join(missing)})")
        print(line)

    # J8: a silently-partial merge is how run 5 shipped a "median of 2" nobody
    # noticed until analysis. Say it loudly at the end, where it survives a
    # scrolled log, and make it a non-zero exit unless the operator opted in.
    if incomplete:
        print("", file=sys.stderr)
        print(f"[median] {len(incomplete)} sdk/profile pair(s) merged FEWER than the "
              f"{n_passes} requested passes:", file=sys.stderr)
        for item in incomplete:
            print(f"[median]   - {item}", file=sys.stderr)
        print("[median] Each merged record names the absent pass(es) in "
              "`passes_missing`/`notes`; the drop reason is in that pass's own "
              "sdk log (a timeout, a port clash, or a crashed bench).", file=sys.stderr)
        if not args.allow_partial:
            print("[median] Failing — re-run the missing pass, or pass "
                  "--allow-partial to accept a partial median deliberately.", file=sys.stderr)
            sys.exit(1)
        print("[median] --allow-partial: accepting the partial median.", file=sys.stderr)


if __name__ == "__main__":
    main()
