#!/usr/bin/env python3
"""Collect SDK bench records (results/sdk/*.json) into a Markdown section, and —
when matching server-scenario numbers exist — compute per-op SDK overhead.

Stdlib only. Usage: collect.py --results benchmarks/results [--out …]
"""
import argparse
import json
import os
import sys
from collections import defaultdict

# SDK op key -> server scenario name, for overhead deltas. Only ops with a
# genuinely comparable wire scenario are mapped (see ../HARNESS-SPEC.md
# "Comparing SDK overhead"): `login` hits the same /api/v1/auth/login path
# both sides. `refresh` has no exact counterpart (the SDK's refresh() calls
# /api/v1/auth/refresh; token_refresh.js exercises the OAuth2 refresh_token
# grant instead) so it is intentionally left unmapped. `check_access`/
# `batch_check` are REST calls (POST /api/v1/authz/check[/batch]) in every SDK,
# now mapped to the matching REST k6 scenarios (authz_check_rest/authz_batch_rest)
# which hit the identical wire path — so the overhead delta is genuinely
# comparable. (The gRPC authz scenarios remain a separate AXIAM capability metric.)
OP_TO_SCENARIO = {
    "login": "oauth2_password_login",
    "check_access": "authz_check_rest",
    "batch_check": "authz_batch_rest",
}


def load_sdk_records(results):
    """H8/E1.3: results/sdk/ holds two possible layouts —
    results/sdk/<profile>/<lang>.json (current: run-all.sh scopes each run
    by BENCH_PROFILE so a p0 run and a p2 run coexist instead of the later
    one silently clobbering the earlier one's file) and the older flat
    results/sdk/<lang>.json (kept readable for any results/ tree collected
    before this change). Walks both."""
    sdkdir = os.path.join(results, "sdk")
    recs = []
    if not os.path.isdir(sdkdir):
        return recs
    for entry in sorted(os.listdir(sdkdir)):
        entry_path = os.path.join(sdkdir, entry)
        if os.path.isdir(entry_path):
            for fn in sorted(os.listdir(entry_path)):
                if fn.endswith(".json"):
                    try:
                        recs.append(json.load(open(os.path.join(entry_path, fn))))
                    except json.JSONDecodeError:
                        continue
        elif entry.endswith(".json"):
            try:
                recs.append(json.load(open(entry_path)))
            except json.JSONDecodeError:
                continue
    return recs


def server_p95(results, target, profile, scenario):
    """Best-effort lookup of a server scenario p95 to compute overhead."""
    meta = os.path.join(results, target, profile, f"{scenario}.meta.json")
    if not os.path.exists(meta):
        return None
    m = json.load(open(meta))
    k6 = os.path.join(results, target, profile, m.get("k6_summary_file", ""))
    if not os.path.exists(k6):
        return None
    data = json.load(open(k6)).get("metrics", {}).get("bench_op_latency_ms", {})
    return float(data.get("p(95)", 0) or 0) or None


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def build(results, recs):
    lines = ["# SDK Client Overhead (E1.3)", ""]
    if not recs:
        return "\n".join(lines + ["_No SDK records yet. Run `just sdk-bench-all`._"])
    pending = [r for r in recs if r.get("status") == "pending"]
    errored = [r for r in recs if r.get("status") == "error"]
    measured = [r for r in recs if r.get("status") == "ok"]
    lines += [f"- SDKs reporting: {len(recs)} "
              f"({len(measured)} ok, {len(errored)} error, {len(pending)} pending)", ""]

    if measured:
        lines += [
            "## Measured", "",
            "**Host clamp caveat (H2/postseed-transient-investigation.md):** "
            "token/authz endpoints on this host are clamped to ~20 ops/s for a "
            "traffic-cured window after a fresh seed (a DB-side post-ingest "
            "effect, not an AXIAM code defect — see the investigation doc). "
            "Every row below is real, valid data either way, but rows measured "
            "*inside* that window read much slower than the same op measured "
            "*after* it clears. Each SDK record's `notes`/companion `.log` and "
            "the matching k6 scenario's `meta.json` (`settle_timeout`) say "
            "which side of the window a given number falls on — do not average "
            "across the boundary. The wire-baseline p95 used for the overhead "
            "column below is measured on **this same host**, at a **matched "
            "VU/concurrency** to the SDK bench's `SDK_BENCH_CONCURRENCY` "
            "(`BENCH_VUS` set equal to it) — an unmatched-concurrency wire "
            "baseline (e.g. the default 50-VU ramp) produces misleading, "
            "often negative \"overhead\" deltas purely from the load-shape "
            "mismatch, not genuine SDK cost.", "",
        ]
        by_profile = defaultdict(list)
        for r in measured:
            by_profile[r.get("profile", "?")].append(r)
        for profile in sorted(by_profile):
            lines += [f"### profile: {profile}", ""]
            # I10 (improvement-after-run4-benchmark.md §D): C's and PHP's
            # benches honestly record `concurrency: 1` (their `notes` field
            # says so — the C harness is a plain serial loop, PHP's SDK has
            # no async client — see HARNESS-SPEC.md), but this table used to
            # render their rows beside every other SDK's concurrency-16
            # rows, unlabeled — a reader comparing `thr(rps)` across rows
            # would mistake single-threaded throughput for a genuine SDK
            # deficit. Split on the RECORD's overall `concurrency` (not any
            # one op's — `refresh` is contractually concurrency-1 for every
            # SDK per HARNESS-SPEC.md and is not what this is about): a
            # record with concurrency==1 ran its ENTIRE bench serially, and
            # its rows move to a separate, explicitly-labeled table.
            concurrent_rows = []
            serial_rows = []
            for r in by_profile[profile]:
                conc = r.get("concurrency", 0)
                target_rows = serial_rows if conc == 1 else concurrent_rows
                for op, stats in r.get("ops", {}).items():
                    sp95 = server_p95(results, r["target"], profile,
                                      OP_TO_SCENARIO.get(op, ""))
                    wire = ("%.2f" % sp95) if sp95 else "—"
                    overhead = ("%+.2f" % (stats["p95_ms"] - sp95)) if sp95 else "—"
                    target_rows.append([r["sdk"], op, str(conc), f"{stats['p50_ms']:.2f}",
                                        f"{stats['p95_ms']:.2f}", wire,
                                        f"{stats['throughput_rps']:.0f}",
                                        str(stats.get("errors", 0)), overhead])
            headers = ["sdk", "op", "conc", "sdk p50(ms)", "sdk p95(ms)",
                       "wire p95(ms)", "thr(rps)", "errors", "p95 overhead vs wire(ms)"]
            if concurrent_rows:
                lines += [md_table(headers, concurrent_rows), ""]
            if serial_rows:
                lines += [
                    "#### conc=1 — serial benches "
                    "(excluded from cross-SDK throughput comparison above)",
                    "",
                    "I10: these SDKs' benches run every op in a single serial "
                    "process/thread (see each record's own `notes` field for why — "
                    "e.g. the PHP SDK has no async client, the C harness is a plain "
                    "serial loop by HARNESS-SPEC.md's explicit allowance). "
                    "`thr(rps)` here is one worker's throughput, not "
                    "`SDK_BENCH_CONCURRENCY`'s, and is **not comparable** to the "
                    "concurrency-N table above — do not read these rows into a "
                    "cross-SDK throughput ranking. Implementing a multi-process/"
                    "multi-thread driver (PHP: `pcntl_fork`; C: pthreads) would let "
                    "an SDK graduate out of this table; not done here — see "
                    "HARNESS-SPEC.md.", "",
                ]
                lines += [md_table(headers, serial_rows), ""]

    if errored:
        lines += ["## Error (server unreachable / setup failed)", "", ]
        lines += [md_table(["sdk", "profile", "note"],
                           [[r["sdk"], r.get("profile", "?"), r.get("notes", "")]
                            for r in errored]), ""]

    if pending:
        lines += ["## Pending (toolchain/package not installed on this host)", "",
                  "The SDK itself is implemented for each of these languages; "
                  "the bench glue is wired but couldn't run here — see each "
                  "language's `sdk/<lang>/TODO.md`.", ""]
        lines += [md_table(["sdk", "note"],
                           [[r["sdk"], r.get("notes", "")] for r in pending]), ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    recs = load_sdk_records(args.results)
    report = build(args.results, recs)
    out = args.out or os.path.join(args.results, "sdk-report.md")
    with open(out, "w") as f:
        f.write(report)
    print(f"wrote {out}")
    print(report)
    if not recs:
        sys.exit(0)


if __name__ == "__main__":
    main()
