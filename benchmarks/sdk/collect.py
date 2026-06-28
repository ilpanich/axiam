#!/usr/bin/env python3
"""Collect SDK bench records (results/sdk/*.json) into a Markdown section, and —
when matching server-scenario numbers exist — compute per-op SDK overhead.

Stdlib only. Usage: collect.py --results benchmarks/results [--out …]
"""
import argparse
import json
import os
import sys

# SDK op key -> server scenario name, for overhead deltas.
OP_TO_SCENARIO = {
    "client_credentials": "oauth2_client_credentials",
    "introspect": "token_introspection",
    "userinfo": "userinfo",
    "authz_check": "authz_check_grpc",
}


def load_sdk_records(results):
    sdkdir = os.path.join(results, "sdk")
    recs = []
    if not os.path.isdir(sdkdir):
        return recs
    for fn in sorted(os.listdir(sdkdir)):
        if fn.endswith(".json"):
            try:
                recs.append(json.load(open(os.path.join(sdkdir, fn))))
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
    lines = ["# SDK Client Overhead", ""]
    if not recs:
        return "\n".join(lines + ["_No SDK records yet. Run `just sdk-bench-all`._"])
    pending = [r for r in recs if r.get("status") == "pending"]
    measured = [r for r in recs if r.get("status") == "ok"]
    lines += [f"- SDKs reporting: {len(recs)} "
              f"({len(measured)} measured, {len(pending)} pending)", ""]

    if measured:
        lines += ["## Measured", ""]
        rows = []
        for r in measured:
            for op, stats in r.get("ops", {}).items():
                sp95 = server_p95(results, r["target"], r["profile"],
                                  OP_TO_SCENARIO.get(op, ""))
                overhead = ("%.2f" % (stats["p95_ms"] - sp95)) if sp95 else "—"
                rows.append([r["sdk"], op, f"{stats['p50_ms']:.2f}",
                             f"{stats['p95_ms']:.2f}", f"{stats['throughput_rps']:.0f}",
                             overhead])
        lines += [md_table(["sdk", "op", "p50(ms)", "p95(ms)", "thr(rps)",
                            "p95 overhead vs wire(ms)"], rows), ""]

    if pending:
        lines += ["## Pending (SDK not yet wired)", "",
                  "These scaffolds are ready; fill them in as the SDKs land on "
                  "`feature/phase-17`.", ""]
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
