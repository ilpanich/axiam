#!/usr/bin/env python3
"""Aggregate raw benchmark outputs into a comparative Markdown report.

Walks results/<target>/<profile>/<scenario>.{meta.json,k6.json,res.csv}, joins
them, computes performance + resource + efficiency metrics, the security-cost
matrix, and validity gates (see docs/methodology.md), then writes a report.

Stdlib only — no external dependencies.

Usage:
  report.py --results benchmarks/results [--out benchmarks/results/report.md]
            [--max-error 0.01] [--min-samples 10]
"""
import argparse
import csv
import json
import os
import statistics
import sys
from collections import defaultdict


def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def load_k6_summary(path):
    """Extract throughput, latency percentiles, error rate from a k6 summary."""
    with open(path) as f:
        data = json.load(f)
    metrics = data.get("metrics", {})

    def trend(name, stat, dflt=0.0):
        m = metrics.get(name, {})
        # summary-export uses keys like "p(95)", "avg", "med"
        return float(m.get(stat, dflt) or 0.0)

    def counter_rate(name):
        m = metrics.get(name, {})
        return float(m.get("rate", 0.0) or 0.0)

    def counter_count(name):
        m = metrics.get(name, {})
        return float(m.get("count", 0.0) or 0.0)

    def rate_value(name):
        m = metrics.get(name, {})
        # Rate metric -> {"value": <fraction true>}
        return float(m.get("value", 0.0) or 0.0)

    throughput = counter_rate("bench_ok")
    # fall back to iteration rate if custom counter absent
    if throughput == 0.0:
        throughput = counter_rate("iterations")
    return {
        "throughput": throughput,
        "ok_count": counter_count("bench_ok"),
        "failed_count": counter_count("bench_failed"),
        "error_rate": rate_value("bench_error_rate"),
        "p50": trend("bench_op_latency_ms", "med"),
        "p95": trend("bench_op_latency_ms", "p(95)"),
        "p99": trend("bench_op_latency_ms", "p(99)"),
        "avg": trend("bench_op_latency_ms", "avg"),
    }


def load_resource_csv(path):
    """Sum per-timestamp across containers, then aggregate cpu/mem over time."""
    if not os.path.exists(path):
        return {"cpu_cores_avg": 0.0, "cpu_cores_p95": 0.0,
                "mem_mib_avg": 0.0, "mem_mib_p95": 0.0, "samples": 0}
    by_ts_cpu = defaultdict(float)
    by_ts_mem = defaultdict(float)
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                ts = row["epoch_ms"]
                by_ts_cpu[ts] += float(row["cpu_cores"])
                by_ts_mem[ts] += float(row["mem_mib"])
            except (ValueError, KeyError):
                continue
    cpu = list(by_ts_cpu.values())
    mem = list(by_ts_mem.values())
    return {
        "cpu_cores_avg": statistics.fmean(cpu) if cpu else 0.0,
        "cpu_cores_p95": pct(cpu, 95),
        "mem_mib_avg": statistics.fmean(mem) if mem else 0.0,
        "mem_mib_p95": pct(mem, 95),
        "samples": len(cpu),
    }


def derive(perf, res):
    thr = perf["throughput"]
    cpu = res["cpu_cores_avg"]
    mem_gib = res["mem_mib_avg"] / 1024.0
    return {
        "throughput_per_core": (thr / cpu) if cpu > 0 else 0.0,
        "throughput_per_gib": (thr / mem_gib) if mem_gib > 0 else 0.0,
        "cpu_ms_per_request": (cpu * 1000.0 / thr) if thr > 0 else 0.0,
    }


def collect(results_dir, max_error, min_samples):
    cells = []
    for target in sorted(os.listdir(results_dir)):
        tdir = os.path.join(results_dir, target)
        if not os.path.isdir(tdir):
            continue
        for profile in sorted(os.listdir(tdir)):
            pdir = os.path.join(tdir, profile)
            if not os.path.isdir(pdir):
                continue
            for fn in sorted(os.listdir(pdir)):
                if not fn.endswith(".meta.json"):
                    continue
                meta = json.load(open(os.path.join(pdir, fn)))
                k6file = os.path.join(pdir, meta.get("k6_summary_file", ""))
                if not os.path.exists(k6file):
                    continue
                perf = load_k6_summary(k6file)
                res = load_resource_csv(os.path.join(pdir, meta.get("resource_csv", "")))
                der = derive(perf, res)
                reasons = []
                if perf["error_rate"] > max_error:
                    reasons.append(f"error_rate {perf['error_rate']:.3f} > {max_error}")
                if res["samples"] < min_samples:
                    reasons.append(f"only {res['samples']} resource samples")
                if meta.get("k6_exit_code", 0) != 0:
                    reasons.append("k6 threshold breach")
                cells.append({
                    "target": meta["target"], "profile": meta["profile"],
                    "scenario": meta["scenario"], "meta": meta,
                    "perf": perf, "res": res, "der": der,
                    "valid": not reasons, "reasons": reasons,
                })
    return cells


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


PROFILE_RANK = {"p0-plaintext": 0, "p1-tls12": 1, "p2-tls13": 2, "p3-mtls": 3}


def build_report(cells):
    lines = ["# AXIAM Benchmark Report", ""]
    valid = [c for c in cells if c["valid"]]
    invalid = [c for c in cells if not c["valid"]]
    targets = sorted({c["target"] for c in cells})
    scenarios = sorted({c["scenario"] for c in cells})
    profiles = sorted({c["profile"] for c in cells}, key=lambda p: PROFILE_RANK.get(p, 99))
    lines += [
        f"- Targets: {', '.join(targets) or '—'}",
        f"- Profiles: {', '.join(profiles) or '—'}",
        f"- Scenarios: {', '.join(scenarios) or '—'}",
        f"- Valid cells: {len(valid)} / {len(cells)}",
        "",
        "> Efficiency headline: **throughput_per_core** (req/s per CPU core) and "
        "**cpu_ms_per_request** answer *can AXIAM match competitors at lower cost?* "
        "Compare across targets at equal profile + latency.",
        "",
    ]

    # 1. Full results table
    lines += ["## All results", ""]
    rows = []
    for c in sorted(cells, key=lambda c: (c["scenario"], c["profile"], c["target"])):
        p, r, d = c["perf"], c["res"], c["der"]
        rows.append([
            c["scenario"], c["profile"], c["target"],
            f"{p['throughput']:.0f}", f"{p['p95']:.1f}", f"{p['p99']:.1f}",
            f"{p['error_rate']*100:.2f}%",
            f"{r['cpu_cores_avg']:.2f}", f"{r['mem_mib_avg']:.0f}",
            f"{d['throughput_per_core']:.0f}", f"{d['cpu_ms_per_request']:.3f}",
            "✓" if c["valid"] else "✗",
        ])
    lines += [md_table(
        ["scenario", "profile", "target", "thr(req/s)", "p95(ms)", "p99(ms)",
         "err", "cpu(cores)", "mem(MiB)", "thr/core", "cpu_ms/req", "valid"],
        rows), ""]

    # 2. Efficiency comparison per (scenario, profile) across targets
    lines += ["## Efficiency comparison (across targets)", "",
              "Higher `thr/core` and lower `cpu_ms/req` is better.", ""]
    for sc in scenarios:
        for pr in profiles:
            group = [c for c in valid if c["scenario"] == sc and c["profile"] == pr]
            if len(group) < 2:
                continue
            lines += [f"### {sc} @ {pr}", ""]
            rows = []
            best = max(group, key=lambda c: c["der"]["throughput_per_core"])
            for c in sorted(group, key=lambda c: -c["der"]["throughput_per_core"]):
                d, p = c["der"], c["perf"]
                marker = " 🏆" if c is best else ""
                rows.append([c["target"] + marker, f"{p['throughput']:.0f}",
                             f"{p['p95']:.1f}", f"{d['throughput_per_core']:.0f}",
                             f"{d['throughput_per_gib']:.0f}", f"{d['cpu_ms_per_request']:.3f}"])
            lines += [md_table(
                ["target", "thr(req/s)", "p95(ms)", "thr/core", "thr/GiB", "cpu_ms/req"],
                rows), ""]

    # 3. Security-cost matrix per (target, scenario)
    lines += ["## Security cost (relative to p0-plaintext)", "",
              "What each stronger security profile costs vs the plaintext baseline.", ""]
    for tg in targets:
        for sc in scenarios:
            group = [c for c in valid if c["target"] == tg and c["scenario"] == sc]
            base = next((c for c in group if c["profile"] == "p0-plaintext"), None)
            others = [c for c in group if c["profile"] != "p0-plaintext"]
            if not base or not others:
                continue
            lines += [f"### {tg} / {sc}", ""]
            rows = [["p0-plaintext (base)", f"{base['perf']['throughput']:.0f}",
                     f"{base['perf']['p95']:.1f}", "baseline", "baseline"]]
            for c in sorted(others, key=lambda c: PROFILE_RANK.get(c["profile"], 99)):
                tb, pb = base["perf"]["throughput"], base["perf"]["p95"]
                t, p = c["perf"]["throughput"], c["perf"]["p95"]
                d_thr = (1 - t / tb) * 100 if tb else 0.0
                d_p95 = p - pb
                rows.append([c["profile"], f"{t:.0f}", f"{p:.1f}",
                             f"{-d_thr:+.1f}%", f"{d_p95:+.1f}"])
            lines += [md_table(
                ["profile", "thr(req/s)", "p95(ms)", "Δ-throughput", "Δ-p95(ms)"],
                rows), ""]

    # 4. Excluded
    if invalid:
        lines += ["## Excluded (invalid) cells", ""]
        rows = [[c["target"], c["profile"], c["scenario"], "; ".join(c["reasons"])]
                for c in invalid]
        lines += [md_table(["target", "profile", "scenario", "reason"], rows), ""]

    lines += ["---", "_Generated by runner/report.py. See docs/methodology.md for "
              "metric definitions and validity gates._"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-error", type=float, default=0.01)
    ap.add_argument("--min-samples", type=int, default=10)
    args = ap.parse_args()

    if not os.path.isdir(args.results):
        print(f"no results dir: {args.results}", file=sys.stderr)
        sys.exit(1)
    cells = collect(args.results, args.max_error, args.min_samples)
    if not cells:
        print("no result cells found — run a benchmark first", file=sys.stderr)
        sys.exit(1)
    report = build_report(cells)
    out = args.out or os.path.join(args.results, "report.md")
    with open(out, "w") as f:
        f.write(report)
    print(f"wrote {out} ({len(cells)} cells)")
    print(report)


if __name__ == "__main__":
    main()
