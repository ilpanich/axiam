#!/usr/bin/env python3
"""Aggregate raw benchmark outputs into a comparative Markdown report.

Walks results/<target>/<profile>/<scenario>.{meta.json,k6.json,res.csv,host.csv},
joins them, computes performance + resource + efficiency metrics, the
security-cost matrix, host-telemetry honesty flags, and validity gates (see
docs/methodology.md), then writes a report.

Stdlib only — no external dependencies.

Usage:
  report.py --results benchmarks/results [--out benchmarks/results/report.md]
            [--max-error 0.01] [--min-samples 10]
"""
import argparse
import csv
import json
import os
import re
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


def median(values):
    """statistics.median with an empty-list guard (C1: median-of-N)."""
    return statistics.median(values) if values else 0.0


def dash(value, fmt):
    """Format `value` with `fmt`, or an em dash when `value` is None (used to
    blank throughput/latency columns on a 100%-error cell — A5.2)."""
    return "—" if value is None else format(value, fmt)


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
        # A3: iterations that measured a fallback op (e.g. Zitadel login() ->
        # client_credentials, or a userinfo setup() that fell back) rather than
        # the labelled logical op.
        "fallback_count": counter_count("bench_fallback"),
    }


def load_resource_csv(path):
    """Sum per-timestamp across containers for the whole-stack aggregate, and
    keep per-container time-averages for bottleneck attribution (A5.3) and the
    server-container-only efficiency variant (A5.5)."""
    empty = {
        "cpu_cores_avg": 0.0, "cpu_cores_p95": 0.0,
        "mem_mib_avg": 0.0, "mem_mib_p95": 0.0, "samples": 0,
        "containers": {},
    }
    if not path or not os.path.exists(path):
        return empty
    by_ts_cpu = defaultdict(float)
    by_ts_mem = defaultdict(float)
    by_container_cpu = defaultdict(list)
    by_container_mem = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                ts = row["epoch_ms"]
                cname = row["container"]
                cpu = float(row["cpu_cores"])
                mem = float(row["mem_mib"])
            except (ValueError, KeyError):
                continue
            by_ts_cpu[ts] += cpu
            by_ts_mem[ts] += mem
            by_container_cpu[cname].append(cpu)
            by_container_mem[cname].append(mem)
    cpu = list(by_ts_cpu.values())
    mem = list(by_ts_mem.values())
    containers = {}
    for cname, vals in by_container_cpu.items():
        mvals = by_container_mem.get(cname, [])
        containers[cname] = {
            "cpu_avg": statistics.fmean(vals) if vals else 0.0,
            "mem_avg": statistics.fmean(mvals) if mvals else 0.0,
        }
    return {
        "cpu_cores_avg": statistics.fmean(cpu) if cpu else 0.0,
        "cpu_cores_p95": pct(cpu, 95),
        "mem_mib_avg": statistics.fmean(mem) if mem else 0.0,
        "mem_mib_p95": pct(mem, 95),
        "samples": len(cpu),
        "containers": containers,
    }


def load_host_csv(path):
    """A6 host telemetry: CPU frequency, thermal, host utilization, k6 CPU
    headroom over the measure window. Missing/old cells (no host.csv) degrade
    to all-zero rather than crashing report generation (A4 tolerance)."""
    empty = {
        "mhz_avg": 0.0, "mhz_min": 0.0, "mhz_max": 0.0, "temp_max": 0.0,
        "host_cpu_util_avg": 0.0, "k6_cores_avg": 0.0, "samples": 0,
    }
    if not path or not os.path.exists(path):
        return empty
    mhz_avgs, mhz_mins, temps, utils, k6cores = [], [], [], [], []
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                mhz_avgs.append(float(row["cpu_mhz_avg"]))
                mhz_mins.append(float(row["cpu_mhz_min"]))
                temps.append(float(row["temp_c_max"]))
                utils.append(float(row["host_cpu_util_pct"]))
                k6cores.append(float(row["k6_cpu_cores"]))
            except (ValueError, KeyError):
                continue
    return {
        "mhz_avg": statistics.fmean(mhz_avgs) if mhz_avgs else 0.0,
        "mhz_min": min(mhz_mins) if mhz_mins else 0.0,
        # "the window's max" for the clock_variance rule is the max of the
        # per-sample mean-MHz-across-cores series (mirrors mhz_avg's series).
        "mhz_max": max(mhz_avgs) if mhz_avgs else 0.0,
        "temp_max": max(temps) if temps else 0.0,
        "host_cpu_util_avg": statistics.fmean(utils) if utils else 0.0,
        "k6_cores_avg": statistics.fmean(k6cores) if k6cores else 0.0,
        "samples": len(mhz_avgs),
    }


# Compose-file CPU cap defaults (targets/*/docker-compose.yml), used as a
# fallback when a container isn't listed in meta.json["containers"] (old
# results predating A4, or a container the sampler saw but run-benchmark.sh's
# containers_json() didn't — e.g. it exited between sampling and inspection).
def default_cpu_cap(container_name):
    if container_name.endswith("-surrealdb") or container_name.endswith("-postgres"):
        return 2.0  # BENCH_DB_CPUS
    if container_name.endswith("-rabbitmq"):
        return 1.0  # BENCH_MQ_CPUS
    if container_name.endswith("-tls"):
        return 1.0  # BENCH_EDGE_CPUS
    return 2.0  # BENCH_CPUS (the main server/app container)


# Same fallback, for mem (MiB) — used by the C2 DB-sensitivity appendix column
# below when a meta.json predates the "mem_cap_mib" field.
def default_mem_cap(container_name):
    if container_name.endswith("-surrealdb") or container_name.endswith("-postgres"):
        return 1024.0  # BENCH_DB_MEM
    if container_name.endswith("-rabbitmq"):
        return 512.0  # BENCH_MQ_MEM
    if container_name.endswith("-tls"):
        return 128.0  # BENCH_EDGE_MEM
    return 1024.0  # BENCH_MEM (the main server/app container)


def bottleneck(meta, res):
    """The container(s) whose average CPU >= 0.95x their configured cap, or
    'none'. Caps come from meta.json's "containers" (A4); fall back to the
    compose defaults above when meta predates that field or omits a
    container. (A5.3)"""
    containers_meta = {c.get("name"): c for c in (meta.get("containers") or [])}
    hot = []
    for cname, stats in (res.get("containers") or {}).items():
        cap = None
        cm = containers_meta.get(cname)
        if cm is not None and cm.get("cpu_cap") not in (None, ""):
            try:
                cap = float(cm["cpu_cap"])
            except (TypeError, ValueError):
                cap = None
        if cap is None:
            cap = default_cpu_cap(cname)
        if cap and stats.get("cpu_avg", 0.0) >= 0.95 * cap:
            hot.append(cname)
    return ",".join(sorted(hot)) if hot else "none"


# Primary app/server container per target (excludes db/mq/edge), used for the
# server-container-only efficiency variant (A5.5).
SERVER_CONTAINER = {
    "axiam": "bench-axiam-server",
    "keycloak": "bench-keycloak",
    "zitadel": "bench-zitadel",
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


def derive_server_only(perf, res, target):
    """Same derived numbers as derive(), but scoped to just the server
    container's CPU/mem — so AXIAM's broker (RabbitMQ) + DB inclusion in the
    whole-stack numbers doesn't silently understate its per-request cost
    relative to a single-process competitor (A5.5)."""
    cname = SERVER_CONTAINER.get(target)
    stats = (res.get("containers") or {}).get(cname) if cname else None
    if not stats:
        return {"throughput_per_core": 0.0, "throughput_per_gib": 0.0, "cpu_ms_per_request": 0.0}
    server_res = {"cpu_cores_avg": stats.get("cpu_avg", 0.0), "mem_mib_avg": stats.get("mem_avg", 0.0)}
    return derive(perf, server_res)


def host_flags(meta, host):
    """A6: clock_variance (window mean MHz sagged >15% below the window max —
    i.e. the run was not at a flat sustained clock) and generator_saturated
    (k6 itself was eating too much of the host's non-stack CPU headroom to
    trust it as a clean load generator)."""
    flags = []
    mhz_avg, mhz_max = host.get("mhz_avg", 0.0), host.get("mhz_max", 0.0)
    if mhz_max > 0 and mhz_avg < 0.85 * mhz_max:
        flags.append("clock_variance")

    containers = meta.get("containers") or []
    if containers:
        stack_cap_cpus = sum(float(c.get("cpu_cap", 0) or 0) for c in containers)
    else:
        try:
            stack_cap_cpus = float((meta.get("caps") or {}).get("cpus", 2))
        except (TypeError, ValueError):
            stack_cap_cpus = 2.0
    try:
        host_cpus = float((meta.get("host") or {}).get("cpus"))
    except (TypeError, ValueError):
        host_cpus = 0.0
    headroom = host_cpus - stack_cap_cpus
    if headroom > 0 and host.get("k6_cores_avg", 0.0) > 0.8 * headroom:
        flags.append("generator_saturated")
    return flags


def collect_dir(results_dir, max_error, min_samples):
    """Walk ONE flat results tree (results/<target>/<profile>/<scenario>.*) and
    return its raw (unaggregated) cells. This is the entire single-run
    collection logic from before C1 — unchanged — reused both for the classic
    single-run layout and, once per `results/run-<i>/` directory, by the C1
    median-of-N aggregator below."""
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
                k6_name = meta.get("k6_summary_file")
                if not k6_name:
                    continue
                k6file = os.path.join(pdir, k6_name)
                if not os.path.exists(k6file):
                    continue
                perf = load_k6_summary(k6file)
                res_name = meta.get("resource_csv")
                res = load_resource_csv(os.path.join(pdir, res_name) if res_name else None)
                host_name = meta.get("host_csv")  # A6/A4: absent on pre-A6 meta
                host = load_host_csv(os.path.join(pdir, host_name) if host_name else None)
                der = derive(perf, res)
                der_server = derive_server_only(perf, res, meta.get("target", target))
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
                    "rate_limits": meta.get("rate_limits", "unknown"),
                    "perf": perf, "res": res, "der": der, "der_server": der_server,
                    "host": host, "host_flags": host_flags(meta, host),
                    "bottleneck": bottleneck(meta, res),
                    "is_fallback": perf["fallback_count"] > 0,
                    "valid": not reasons, "reasons": reasons,
                })
    return cells


# --- C1: median-of-N run aggregation ----------------------------------------
# `bench-matrix` (justfile) now runs the whole target×profile×scenario matrix
# `repeat` times (default 3), each pass writing into its own
# `results/run-<i>/<target>/<profile>/...` tree using the exact same flat
# per-cell layout `collect_dir` already understands. When one or more
# `results/run-*/` directories are present, aggregate each (target, profile,
# scenario) cell by taking the MEDIAN independently per metric across the
# valid runs, rather than reporting a single run's numbers. Results trees that
# predate this (no `run-*/` dirs — e.g. the existing 2026-07-19 tree) fall
# through to the old single-run behavior completely unchanged.
RUN_DIR_RE = re.compile(r"run-\d+")

# Fields medianed independently per the C1 spec ("throughput, p50/p95/p99,
# cpu, mem"), plus the other numeric perf/res/host fields for consistency.
PERF_MEDIAN_FIELDS = [
    "throughput", "ok_count", "failed_count", "error_rate",
    "p50", "p95", "p99", "avg", "fallback_count",
]
RES_MEDIAN_FIELDS = ["cpu_cores_avg", "cpu_cores_p95", "mem_mib_avg", "mem_mib_p95", "samples"]
HOST_MEDIAN_FIELDS = ["mhz_avg", "mhz_min", "mhz_max", "temp_max", "host_cpu_util_avg", "k6_cores_avg", "samples"]


def _median_of(dicts, fields):
    return {f: median([d.get(f, 0.0) for d in dicts]) for f in fields}


def _median_res(res_list):
    """Median the whole-stack res fields AND, per container, cpu_avg/mem_avg —
    so bottleneck() and the per-container appendix still work on aggregated
    cells exactly as they do on single-run ones."""
    agg = _median_of(res_list, RES_MEDIAN_FIELDS)
    names = set()
    for r in res_list:
        names.update((r.get("containers") or {}).keys())
    containers = {}
    for name in names:
        cpu_vals = [(r.get("containers") or {}).get(name, {}).get("cpu_avg", 0.0)
                    for r in res_list if name in (r.get("containers") or {})]
        mem_vals = [(r.get("containers") or {}).get(name, {}).get("mem_avg", 0.0)
                    for r in res_list if name in (r.get("containers") or {})]
        containers[name] = {"cpu_avg": median(cpu_vals), "mem_avg": median(mem_vals)}
    agg["containers"] = containers
    return agg


def aggregate_cell(runs):
    """Median-aggregate one (target, profile, scenario)'s per-run raw cells
    (as produced by collect_dir, one per results/run-<i>/) into a single cell
    with the same shape build_report expects, plus n_valid_runs/n_runs and the
    throughput min-max spread. A cell is only marked `valid` when >=2 of its
    runs were individually valid (C1) — with 0 or 1 valid runs there is no
    meaningful median, so it's reported (for visibility) but excluded from
    headline comparisons, same as any other invalid cell."""
    target, profile, scenario = runs[0]["target"], runs[0]["profile"], runs[0]["scenario"]
    valid_runs = [r for r in runs if r["valid"]]
    n_valid, n_total = len(valid_runs), len(runs)
    basis = valid_runs if valid_runs else runs

    perf = _median_of([r["perf"] for r in basis], PERF_MEDIAN_FIELDS)
    res = _median_res([r["res"] for r in basis])
    host = _median_of([r["host"] for r in basis], HOST_MEDIAN_FIELDS)

    thr_vals = [r["perf"]["throughput"] for r in basis]
    thr_median = perf["throughput"]
    thr_spread_pct = (((max(thr_vals) - min(thr_vals)) / 2.0) / thr_median * 100.0
                       if thr_vals and thr_median else 0.0)

    meta = basis[0]["meta"]  # containers/caps/scenario_sha etc. are stable across runs
    der = derive(perf, res)
    der_server = derive_server_only(perf, res, target)

    reasons = []
    if n_valid < 2:
        reasons.append(f"only {n_valid}/{n_total} valid run(s) (need >=2 for a median)")

    return {
        "target": target, "profile": profile, "scenario": scenario, "meta": meta,
        "rate_limits": basis[0]["rate_limits"],
        "perf": perf, "res": res, "der": der, "der_server": der_server,
        "host": host, "host_flags": host_flags(meta, host),
        "bottleneck": bottleneck(meta, res),
        "is_fallback": any(r["is_fallback"] for r in runs),
        "valid": n_valid >= 2 and not reasons,
        "reasons": reasons,
        "n_valid_runs": n_valid, "n_runs": n_total, "thr_spread_pct": thr_spread_pct,
    }


def collect(results_dir, max_error, min_samples):
    """Top-level entry point: detect whether `results_dir` holds a
    `results/run-*/` median-of-N layout or the classic flat single-run layout,
    and branch (C1). Returns (cells, multi_run)."""
    try:
        entries = sorted(os.listdir(results_dir))
    except OSError:
        entries = []
    run_dirs = [os.path.join(results_dir, e) for e in entries
                if RUN_DIR_RE.fullmatch(e) and os.path.isdir(os.path.join(results_dir, e))]

    if not run_dirs:
        # Classic single-run layout — completely unchanged behavior.
        cells = collect_dir(results_dir, max_error, min_samples)
        for c in cells:
            c["n_valid_runs"] = 1 if c["valid"] else 0
            c["n_runs"] = 1
            c["thr_spread_pct"] = 0.0
        return cells, False

    grouped = defaultdict(list)
    for run_dir in run_dirs:
        for c in collect_dir(run_dir, max_error, min_samples):
            grouped[(c["target"], c["profile"], c["scenario"])].append(c)
    cells = [aggregate_cell(runs) for runs in grouped.values()]
    return cells, True


def posture_bucket(posture):
    """Collapse a rate-limit posture into a comparability class.

    A head-to-head is only meaningful when every target in the group is
    effectively unthrottled: AXIAM run with `neutralized` limits vs competitors
    (`n/a` — they ship no per-IP limiter). AXIAM in `prod` posture is throttled
    and cannot be compared to an unthrottled competitor; a missing/`unknown`
    marker (e.g. results from before posture stamping) is treated as unknown so
    it is flagged rather than silently mixed in.
    """
    if posture in ("neutralized", "n/a", "none", ""):
        return "unthrottled"
    if posture == "prod":
        return "throttled"
    return "unknown"


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


PROFILE_RANK = {"p0-plaintext": 0, "p1-tls12": 1, "p2-tls13": 2, "p3-mtls": 3}


def build_report(cells, multi_run=False):
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
        "> `fallback` = the cell measured a fallback operation instead of the "
        "labelled logical op (e.g. Zitadel's login() falling back to "
        "client_credentials — see docs/methodology.md). Fallback cells are "
        "excluded from head-to-head winner tables but kept here for the full "
        "picture.",
        "",
        "> `bottleneck` names the stack container(s) whose average CPU reached "
        "≥ 95% of their configured cap during the measure window — `none` "
        "means nothing in the stack saturated (the client, network, or an "
        "un-pegged serialization point is the limiter instead).",
        "",
        "> Cells with `err`=100% have their throughput/latency columns blanked "
        "(`—`) — those numbers would describe the failure path, not the "
        "operation being measured.",
        "",
    ]
    if multi_run:
        max_n = max((c.get("n_runs", 1) for c in cells), default=1)
        lines += [
            f"> **Median-of-N aggregation (C1):** this report was generated from "
            f"`results/run-*/` (up to N={max_n} repeats per cell). Every metric "
            "below (throughput, p50/p95/p99, cpu, mem, host telemetry) is the "
            "MEDIAN taken independently across that cell's valid runs — not a "
            "single run. `runs(valid/n)` shows how many of the N repeats were "
            "individually valid; a cell needs **≥2 valid runs** to be marked "
            "`valid` itself (fewer than that, there's no meaningful median — see "
            "docs/methodology.md). `±thr%` is the throughput spread across valid "
            "runs, `(max−min)/2` as a percentage of the median.",
            "",
        ]

    # 1. Full results table
    lines += ["## All results", ""]
    rows = []
    for c in sorted(cells, key=lambda c: (c["scenario"], c["profile"], c["target"])):
        p, r, d, h = c["perf"], c["res"], c["der"], c["host"]
        full_outage = p["error_rate"] >= 1.0
        thr = None if full_outage else p["throughput"]
        p50 = None if full_outage else p["p50"]
        p95 = None if full_outage else p["p95"]
        p99 = None if full_outage else p["p99"]
        thr_core = None if full_outage else d["throughput_per_core"]
        cpu_ms = None if full_outage else d["cpu_ms_per_request"]
        mhz_ratio = (h["mhz_min"] / h["mhz_max"]) if h["mhz_max"] > 0 else 0.0
        flags = list(c["host_flags"])
        if c["is_fallback"]:
            flags.append("fallback-op")
        row = [
            c["scenario"], c["profile"], c["target"], c["rate_limits"],
            dash(thr, ".0f"), dash(p50, ".1f"), dash(p95, ".1f"), dash(p99, ".1f"),
            f"{p['error_rate']*100:.2f}%",
            f"{r['cpu_cores_avg']:.2f}", f"{r['mem_mib_avg']:.0f}",
            dash(thr_core, ".0f"), dash(cpu_ms, ".3f"),
            c["bottleneck"],
            "yes" if c["is_fallback"] else "no",
            f"{h['mhz_avg']:.0f}", f"{mhz_ratio:.2f}", f"{h['temp_max']:.0f}",
            f"{h['k6_cores_avg']:.2f}",
            ";".join(flags) or "-",
            "✓" if c["valid"] else "✗",
        ]
        if multi_run:
            row += [f"{c.get('n_valid_runs', 0)}/{c.get('n_runs', 1)}",
                    f"±{c.get('thr_spread_pct', 0.0):.1f}%"]
        rows.append(row)
    headers = ["scenario", "profile", "target", "rate_limits", "thr(req/s)", "p50(ms)",
               "p95(ms)", "p99(ms)", "err", "cpu(cores)", "mem(MiB)", "thr/core",
               "cpu_ms/req", "bottleneck", "fallback", "mhz_avg", "mhz_min/max",
               "temp_max(C)", "k6_cores", "host_flags", "valid"]
    if multi_run:
        headers += ["runs(valid/n)", "±thr%"]
    lines += [md_table(headers, rows), ""]

    # 1b. C4: AXIAM production rate-limit-posture cells, called out separately
    # so they never get lost among (or silently averaged into) the neutralized
    # comparison numbers above. posture_bucket()/the efficiency-comparison loop
    # below already refuse to place a `prod`-posture cell head-to-head against
    # an unthrottled competitor; this section is the human-readable label for
    # the same rule, and the one place a `prod` run is summarized on its own.
    prod_cells = [c for c in cells if c["rate_limits"] == "prod"]
    if prod_cells:
        lines += [
            "## AXIAM production rate-limit posture — NOT comparable to competitors",
            "",
            "> These cells were run with `rl=prod` (`just target=axiam rl=prod …`): "
            "AXIAM's shipped-default per-IP rate limits ACTIVE (see the `rl` "
            "variable at the top of `justfile`). They measure the limiter's "
            "throttling behavior, not raw endpoint capacity, and are excluded "
            "from every head-to-head table above/below (`posture_bucket()` "
            "buckets `prod` separately from `neutralized`/`n/a`, so a mixed or "
            "unknown-posture comparison group is refused rather than silently "
            "rendered). The intended framing: *AXIAM ships per-IP rate limits by "
            "default; Keycloak and Zitadel don't* — compare a `prod` row only "
            "against AXIAM's own `neutralized` row for the same "
            "(scenario, profile), never against another target.",
            "",
        ]
        rows = []
        for c in sorted(prod_cells, key=lambda c: (c["scenario"], c["profile"])):
            p = c["perf"]
            full_outage = p["error_rate"] >= 1.0
            rows.append([
                c["scenario"], c["profile"],
                dash(None if full_outage else p["throughput"], ".0f"),
                dash(None if full_outage else p["p50"], ".1f"),
                dash(None if full_outage else p["p95"], ".1f"),
                f"{p['error_rate'] * 100:.2f}%",
                "posture: prod — NOT comparable to competitors",
            ])
        lines += [md_table(
            ["scenario", "profile", "thr(req/s)", "p50(ms)", "p95(ms)", "err", "label"],
            rows), ""]

    # 2. Efficiency comparison per (scenario, profile) across targets
    lines += ["## Efficiency comparison (across targets)", "",
              "Higher `thr/core` and lower `cpu_ms/req` is better. "
              "`server-only` recomputes both against just the primary "
              "server/app container's CPU+mem (excludes DB/broker/edge), so "
              "AXIAM's RabbitMQ+SurrealDB inclusion in the whole-stack numbers "
              "is visible rather than silently folded in (A5.5).", ""]
    for sc in scenarios:
        for pr in profiles:
            group_all = [c for c in valid if c["scenario"] == sc and c["profile"] == pr]
            if len(group_all) < 2:
                continue
            fallback_cells = [c for c in group_all if c["is_fallback"]]
            group = [c for c in group_all if not c["is_fallback"]]
            lines += [f"### {sc} @ {pr}", ""]
            if fallback_cells:
                lines += [
                    "> ⚠️ fallback-op cell(s) excluded from this head-to-head: "
                    + ", ".join(sorted(f"{c['target']}" for c in fallback_cells))
                    + " (see the full matrix above; comparability: fallback-op).", "",
                ]
            if len(group) < 2:
                lines += ["_Fewer than 2 non-fallback targets — nothing to compare._", ""]
                continue
            # Refuse to render a head-to-head across incomparable rate-limit
            # postures (e.g. AXIAM throttled vs an unthrottled competitor, or a
            # cell with an unknown posture). This is the guard that stops the
            # p0-plaintext limiter incident from silently recurring.
            buckets = {posture_bucket(c["rate_limits"]) for c in group}
            if len(buckets) > 1 or "unknown" in buckets:
                postures = ", ".join(sorted(
                    f"{c['target']}={c['rate_limits']}" for c in group))
                lines += [
                    "> ⚠️ **Not comparable — mixed or unknown rate-limit posture** "
                    f"({postures}). A head-to-head is only meaningful when every "
                    "target is unthrottled (AXIAM `neutralized` vs competitors, "
                    "which have no per-IP limiter). Re-run AXIAM with "
                    "`just rl=neutralized … bench-up`; results run in `prod` "
                    "posture measure the limiter, not endpoint capacity.", "",
                ]
                continue
            rows = []
            best = max(group, key=lambda c: c["der"]["throughput_per_core"])
            for c in sorted(group, key=lambda c: -c["der"]["throughput_per_core"]):
                d, ds, p = c["der"], c["der_server"], c["perf"]
                marker = " 🏆" if c is best else ""
                rows.append([c["target"] + marker, f"{p['throughput']:.0f}",
                             f"{p['p50']:.1f}", f"{p['p95']:.1f}",
                             f"{d['throughput_per_core']:.0f}", f"{d['throughput_per_gib']:.0f}",
                             f"{d['cpu_ms_per_request']:.3f}",
                             f"{ds['throughput_per_core']:.0f}", f"{ds['cpu_ms_per_request']:.3f}"])
            lines += [md_table(
                ["target", "thr(req/s)", "p50(ms)", "p95(ms)", "thr/core", "thr/GiB",
                 "cpu_ms/req", "server-only thr/core", "server-only cpu_ms/req"],
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
                     f"{base['perf']['p50']:.1f}", f"{base['perf']['p95']:.1f}",
                     "baseline", "baseline"]]
            for c in sorted(others, key=lambda c: PROFILE_RANK.get(c["profile"], 99)):
                tb, pb = base["perf"]["throughput"], base["perf"]["p95"]
                t, p = c["perf"]["throughput"], c["perf"]["p95"]
                d_thr = (1 - t / tb) * 100 if tb else 0.0
                d_p95 = p - pb
                rows.append([c["profile"], f"{t:.0f}", f"{c['perf']['p50']:.1f}", f"{p:.1f}",
                             f"{-d_thr:+.1f}%", f"{d_p95:+.1f}"])
            lines += [md_table(
                ["profile", "thr(req/s)", "p50(ms)", "p95(ms)", "Δ-throughput", "Δ-p95(ms)"],
                rows), ""]

    # 4. Appendix: per-container resource breakdown (A5.3)
    lines += ["## Appendix: per-container resource breakdown", "",
              "Per-cell, per-container average CPU/mem from the resource sampler, "
              "the caps it was measured against (from meta.json's `cpu_cap`/"
              "`mem_cap_mib` — C2 — falling back to the compose default when "
              "absent), and whether it hit the CPU bottleneck threshold "
              "(cpu_avg ≥ 95% of cpu_cap). `mem_cap(MiB)` is what a "
              "`dbcaps=uncapped` (C2) run shows raised for the `-surrealdb`/"
              "`-postgres` container.", ""]
    rows = []
    for c in sorted(valid, key=lambda c: (c["scenario"], c["profile"], c["target"])):
        containers_meta = {cm.get("name"): cm for cm in (c["meta"].get("containers") or [])}
        for cname, stats in sorted((c["res"].get("containers") or {}).items()):
            cm = containers_meta.get(cname)
            if cm is not None and cm.get("cpu_cap") not in (None, ""):
                try:
                    cap = float(cm["cpu_cap"])
                except (TypeError, ValueError):
                    cap = default_cpu_cap(cname)
            else:
                cap = default_cpu_cap(cname)
            if cm is not None and cm.get("mem_cap_mib") not in (None, ""):
                try:
                    mem_cap = float(cm["mem_cap_mib"])
                except (TypeError, ValueError):
                    mem_cap = default_mem_cap(cname)
            else:
                mem_cap = default_mem_cap(cname)
            hot = "✓" if stats.get("cpu_avg", 0.0) >= 0.95 * cap else "·"
            rows.append([c["scenario"], c["profile"], c["target"], cname,
                         f"{stats.get('cpu_avg', 0.0):.2f}", f"{cap:.2f}",
                         f"{stats.get('mem_avg', 0.0):.0f}", f"{mem_cap:.0f}", hot])
    if rows:
        lines += [md_table(
            ["scenario", "profile", "target", "container", "cpu_avg(cores)",
             "cpu_cap", "mem_avg(MiB)", "mem_cap(MiB)", "hot"],
            rows), ""]
    else:
        lines += ["_No per-container samples available (no res.csv rows)._", ""]

    # 5. Excluded
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
    cells, multi_run = collect(args.results, args.max_error, args.min_samples)
    if not cells:
        print("no result cells found — run a benchmark first", file=sys.stderr)
        sys.exit(1)
    if multi_run:
        print(f"[report] median-of-N layout detected ({len(cells)} aggregated cells)")
    report = build_report(cells, multi_run=multi_run)
    out = args.out or os.path.join(args.results, "report.md")
    with open(out, "w") as f:
        f.write(report)
    print(f"wrote {out} ({len(cells)} cells)")
    print(report)


if __name__ == "__main__":
    main()
