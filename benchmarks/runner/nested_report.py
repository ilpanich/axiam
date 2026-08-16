#!/usr/bin/env python3
"""Aggregate a nested-resource authorization depth sweep into a summary.

N1. `just bench-nested` runs one cell per rung of a depth ladder, writing each
rung into its own results subtree:

    <root>/d<N>/<target>/<profile>/authz_nested_{rest,grpc}.{meta,k6}.json

which is one level deeper than `runner/report.py`'s `collect_dir` walk reaches,
so the matrix aggregator ignores this tree entirely — deliberately, the same way
it ignores `results/dry-run/`. A depth ladder is not a matrix: its cells differ
in a knob, not in a target/profile coordinate, and medianing or ranking them
together would be meaningless. This script is that tree's own reader.

WHAT IT WILL AND WILL NOT SAY
-----------------------------
The primary artifact is per-target depth SENSITIVITY: how each product's own
number moves as the resource being authorized gets deeper, normalised to that
same product's shallowest measured rung. That comparison is sound because each
target is only ever compared against itself.

The absolute cross-target table is printed too, because refusing to print it
would be its own kind of dishonesty, but it carries the model caveat on every
row — the three products are not running the same mechanism (see
scenarios/lib/nested.js):

  * axiam    — a real hierarchy walk (ancestor chain resolved per decision).
  * keycloak — no parent/child relation; nesting is URI paths resolved against
               one `/<root>/*` resource, or, under BENCH_KC_NESTED_MODE=per-node,
               one registered resource per level.
  * zitadel  — NO per-resource decision API exists. That arm is a declared
               capability gap measuring the role-claim round trip a resource
               server makes before deciding locally, and it is depth-invariant
               by construction. This script refuses to compute a slope for it
               and says why, rather than printing a flat line that reads like a
               measurement result.

Usage:
    nested_report.py --results results/nested [--out results/nested/SUMMARY.md]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Targets whose arm is a declared capability gap rather than a nested
# authorization decision. Kept here (not inferred from the numbers) for the
# same reason report.py keeps PROTOCOL_VARIANT_SCENARIOS static: it is a
# permanent fact about the product, and a fact that happens to also be visible
# in the data must still be asserted, or a noisy run could erase it.
DEPTH_INVARIANT_TARGETS = {"zitadel"}

# What each target's arm actually does, printed next to its numbers so the
# table cannot be quoted without its caveat.
TARGET_MODEL = {
    "axiam": "hierarchical resource tree; one role assignment on the root "
             "cascades to every descendant (ancestor chain resolved per decision)",
    "keycloak": "flat resource set; nesting expressed as URI paths resolved by "
                "the server against a single `/<root>/*` resource (no inheritance relation)",
    "zitadel": "no per-resource decision API; project roles ride in the token "
               "and are evaluated by the application — depth-invariant by construction",
}

# Deliberately names the TRANSPORT and not one vendor's URL: each target's REST
# arm hits its own endpoint (AXIAM `POST /api/v1/authz/check`, Keycloak's
# UMA-ticket decision request, Zitadel's introspection round trip), and writing
# AXIAM's path into the shared heading would quietly imply the others were
# calling it too.
SCENARIO_LABEL = {
    "authz_nested_rest": "REST authorization decision",
    "authz_nested_grpc": "gRPC authorization decision "
                         "(axiam.v1.AuthorizationService/CheckAccess) — AXIAM-only",
}


def load_k6(path):
    """Throughput / latency percentiles / error rate from a k6 summary export.

    Deliberately a small local copy of report.py's `load_k6_summary` rather
    than an import: report.py is a 1 400-line module that executes a full
    matrix aggregation at import time boundaries and carries its own CLI, and
    coupling the sweep reader to it would mean a change to the matrix report
    could silently retune the sweep's numbers. The three metric names read here
    (`bench_ok`, `bench_error_rate`, `bench_op_latency_ms`) are fixed by
    scenarios/lib/metrics.js.
    """
    with open(path) as fh:
        metrics = (json.load(fh) or {}).get("metrics", {}) or {}

    def trend(name, stat):
        return float((metrics.get(name) or {}).get(stat, 0.0) or 0.0)

    def count(name):
        return float((metrics.get(name) or {}).get("count", 0.0) or 0.0)

    throughput = float((metrics.get("bench_ok") or {}).get("rate", 0.0) or 0.0)
    if throughput == 0.0:
        throughput = float((metrics.get("iterations") or {}).get("rate", 0.0) or 0.0)
    return {
        "throughput": throughput,
        "ok": count("bench_ok"),
        "failed": count("bench_failed"),
        "throttled": count("bench_throttled"),
        "error_rate": float((metrics.get("bench_error_rate") or {}).get("value", 0.0) or 0.0),
        "p50": trend("bench_op_latency_ms", "med"),
        "p95": trend("bench_op_latency_ms", "p(95)"),
        "p99": trend("bench_op_latency_ms", "p(99)"),
    }


def collect(root):
    """Every nested-sweep cell under `root`, as a list of dicts.

    Finds cells by CONTENT, not by path shape: any `*.meta.json` whose scenario
    is one of the nested ones. The `d<N>/` directory names are how
    `bench-nested` lays the tree out, but the depth of record comes from
    meta.json's `nested_authz.depth` — a cell that was run by hand into some
    other directory is still read correctly, and a directory renamed by hand
    cannot silently relabel a rung.
    """
    cells = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if not fn.endswith(".meta.json"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path) as fh:
                    meta = json.load(fh)
            except (OSError, ValueError) as exc:
                print(f"[nested-report] WARN: unreadable {path}: {exc}", file=sys.stderr)
                continue
            scenario = meta.get("scenario", "")
            if scenario not in SCENARIO_LABEL:
                continue
            if meta.get("dry_run"):
                continue
            nested = meta.get("nested_authz") or {}
            depth = nested.get("depth")
            if depth is None:
                print(f"[nested-report] WARN: {path} carries no nested_authz.depth "
                      "(harness predates N1?) — skipped", file=sys.stderr)
                continue
            k6_name = meta.get("k6_summary_file")
            k6path = os.path.join(dirpath, k6_name) if k6_name else None
            if not k6path or not os.path.exists(k6path):
                print(f"[nested-report] WARN: {path} has no k6 summary alongside it — skipped",
                      file=sys.stderr)
                continue
            perf = load_k6(k6path)
            reasons = []
            if meta.get("k6_exit_code", 0) != 0:
                reasons.append("k6 threshold breach")
            if perf["error_rate"] > 0.01:
                reasons.append(f"error_rate {perf['error_rate']:.3f} > 0.01")
            if perf["ok"] == 0:
                reasons.append("no successful operation")
            cells.append({
                "target": meta.get("target", "?"),
                "profile": meta.get("profile", "?"),
                "scenario": scenario,
                "depth": int(depth),
                "kc_mode": nested.get("kc_mode", "wildcard"),
                "meta": meta,
                "perf": perf,
                "valid": not reasons,
                "reasons": reasons,
            })
    return cells


def pct(new, base):
    """Percent change of `new` relative to `base`, or None when undefined."""
    if not base:
        return None
    return (new - base) / base * 100.0


def fmt_pct(v):
    return "—" if v is None else f"{v:+.1f}%"


def series_table(lines, cells):
    """One depth ladder for one (target, scenario), plus its sensitivity."""
    cells = sorted(cells, key=lambda c: c["depth"])
    target = cells[0]["target"]
    base = cells[0]
    invariant = target in DEPTH_INVARIANT_TARGETS

    lines.append("| depth | throughput (ops/s) | p50 (ms) | p95 (ms) | p99 (ms) | "
                 "error rate | p95 vs depth %d | valid |" % base["depth"])
    lines.append("|---:|---:|---:|---:|---:|---:|---:|:--|")
    for c in cells:
        p = c["perf"]
        delta = "n/a" if invariant else fmt_pct(pct(p["p95"], base["perf"]["p95"]))
        valid = "yes" if c["valid"] else "**NO** — " + "; ".join(c["reasons"])
        lines.append(
            f"| {c['depth']} | {p['throughput']:.1f} | {p['p50']:.2f} | {p['p95']:.2f} | "
            f"{p['p99']:.2f} | {p['error_rate']:.4f} | {delta} | {valid} |"
        )
    lines.append("")

    if invariant:
        lines.append(
            f"> **Depth-invariant by construction — no slope is computed.** {target} exposes no "
            "per-resource authorization decision endpoint, so there is no nested decision to make "
            "deeper. Every request in this ladder is byte-identical; the rows above differ only in "
            "run-to-run noise, and reading them as a flat depth curve would credit the product with "
            "a constant-cost nested check it does not implement. What the numbers DO show is the "
            "cost of the round trip a resource server must make before deciding locally."
        )
        lines.append("")
        return

    valid = [c for c in cells if c["valid"]]
    if len(valid) < 2:
        lines.append("> Not enough valid rungs to state a slope (need at least two).")
        lines.append("")
        return

    lo, hi = valid[0], valid[-1]
    span = hi["depth"] - lo["depth"]
    if span <= 0:
        lines.append("> Only one distinct depth was measured — no slope.")
        lines.append("")
        return
    d_p95 = hi["perf"]["p95"] - lo["perf"]["p95"]
    d_thr = pct(hi["perf"]["throughput"], lo["perf"]["throughput"])
    lines.append(
        f"> **Depth sensitivity, {lo['depth']} → {hi['depth']}:** p95 {lo['perf']['p95']:.2f} → "
        f"{hi['perf']['p95']:.2f} ms ({fmt_pct(pct(hi['perf']['p95'], lo['perf']['p95']))}, "
        f"{d_p95 / span:+.3f} ms per level); throughput {lo['perf']['throughput']:.1f} → "
        f"{hi['perf']['throughput']:.1f} ops/s ({fmt_pct(d_thr)}). "
        "Per-level figures are a linear reading of two endpoints, not a fitted model — read the "
        "full ladder above before quoting them."
    )
    lines.append("")


def provenance(lines, cells):
    metas = [c["meta"] for c in cells]
    first = metas[0]
    profiles = sorted({c["profile"] for c in cells})
    kc_modes = sorted({c["kc_mode"] for c in cells if c["target"] == "keycloak"})
    lines.append("## Provenance")
    lines.append("")
    lines.append(f"- profile(s): `{', '.join(profiles)}`")
    lines.append(f"- load model: {first.get('vus')} VUs, warm-up {first.get('warmup')}, "
                 f"measured {first.get('duration')}")
    lines.append(f"- rate-limit posture: `{first.get('rate_limits', 'unknown')}`")
    lines.append(f"- connection model: `{first.get('connection_model', 'unknown')}`")
    lines.append(f"- k6: `{first.get('k6_version', 'unknown')}`")
    lines.append(f"- AXIAM build ref: `{first.get('build_ref', 'unknown')}`")
    if kc_modes:
        lines.append(f"- Keycloak nesting model: `{', '.join(kc_modes)}` "
                     "(`wildcard` = one `/<root>/*` resource + one permission covers the subtree; "
                     "`per-node` = one resource + permission per level, a control whose decision "
                     "cost is depth-flat by construction)")
    postures = sorted({m.get("rate_limits", "unknown") for m in metas})
    if len(postures) > 1:
        lines.append(f"- ⚠️ **mixed rate-limit postures across rungs ({', '.join(postures)})** — "
                     "rungs measured under different postures are not on the same axis.")
    lines.append("")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default="results/nested",
                    help="root of the nested sweep tree (default results/nested)")
    ap.add_argument("--out", default="",
                    help="output markdown path (default <results>/SUMMARY.md)")
    args = ap.parse_args()

    root = args.results
    if not os.path.isdir(root):
        print(f"[nested-report] no such directory: {root} — run 'just bench-nested' first",
              file=sys.stderr)
        return 1

    cells = collect(root)
    if not cells:
        print(f"[nested-report] no nested-sweep cells found under {root}. Expected "
              "<root>/d<N>/<target>/<profile>/authz_nested_*.meta.json — run 'just bench-nested'.",
              file=sys.stderr)
        return 1

    out_path = args.out or os.path.join(root, "SUMMARY.md")
    lines = []
    lines.append("# Nested-resource authorization — depth sweep")
    lines.append("")
    lines.append(
        "One authorization decision per request, asked about a resource nested N levels below the "
        "one carrying the grant. Each rung of the ladder is its own measured cell; the harness "
        "provisions (and re-uses) the chain in `setup()` and refuses to open the measured window "
        "unless the decision at that depth returns the expected verdict "
        "(`benchmarks/scenarios/lib/nested.js`)."
    )
    lines.append("")
    lines.append(
        "**This is not a matrix.** These cells differ in a knob, not in a target/profile "
        "coordinate, so `bench-report` deliberately does not see them and they must never be "
        "medianed or ranked against default-matrix cells."
    )
    lines.append("")

    provenance(lines, cells)

    lines.append("## What each target's arm actually does")
    lines.append("")
    lines.append("| target | model | depth meaningful? |")
    lines.append("|---|---|---|")
    for t in sorted({c["target"] for c in cells}):
        meaningful = "no — capability gap" if t in DEPTH_INVARIANT_TARGETS else "yes"
        lines.append(f"| {t} | {TARGET_MODEL.get(t, '(unknown target)')} | {meaningful} |")
    lines.append("")
    lines.append(
        "The three are not running the same product mechanism, because only one of them has the "
        "mechanism. Per-target depth sensitivity (each product against itself) is the sound "
        "comparison; the absolute cross-target table below is printed with that caveat attached, "
        "never without it."
    )
    lines.append("")

    lines.append("## Depth ladders (per target, per transport)")
    lines.append("")
    keys = sorted({(c["scenario"], c["target"]) for c in cells})
    for scenario, target in keys:
        group = [c for c in cells if c["scenario"] == scenario and c["target"] == target]
        lines.append(f"### {target} — {SCENARIO_LABEL[scenario]}")
        lines.append("")
        series_table(lines, group)

    lines.append("## Cross-target, per depth (absolute — read the caveats above)")
    lines.append("")
    depths = sorted({c["depth"] for c in cells})
    targets = sorted({c["target"] for c in cells})
    lines.append("| depth | " + " | ".join(f"{t} p95 (ms)" for t in targets) + " |")
    lines.append("|---:|" + "|".join(["---:"] * len(targets)) + "|")
    for d in depths:
        row = [str(d)]
        for t in targets:
            # REST only: it is the one transport all three could in principle
            # speak, so mixing the gRPC cell in here would compare a transport
            # against a capability.
            match = [c for c in cells
                     if c["depth"] == d and c["target"] == t and c["scenario"] == "authz_nested_rest"]
            if not match:
                row.append("—")
            elif not match[0]["valid"]:
                row.append(f"_{match[0]['perf']['p95']:.2f} (invalid)_")
            else:
                suffix = " ⚠️" if t in DEPTH_INVARIANT_TARGETS else ""
                row.append(f"{match[0]['perf']['p95']:.2f}{suffix}")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    if DEPTH_INVARIANT_TARGETS & set(targets):
        marked = ", ".join(sorted(DEPTH_INVARIANT_TARGETS & set(targets)))
        lines.append(f"⚠️ = capability gap ({marked}): the cell is not a nested authorization "
                     "decision at all — see the model table above.")
        lines.append("")
    lines.append("REST cells only. The gRPC ladder is AXIAM-only (no competitor in this harness's "
                 "target set exposes a gRPC authorization-decision RPC), so it appears in the "
                 "per-target section above and never in a cross-target row.")
    lines.append("")

    invalid = [c for c in cells if not c["valid"]]
    if invalid:
        lines.append("## Invalid rungs")
        lines.append("")
        lines.append("| target | scenario | depth | why |")
        lines.append("|---|---|---:|---|")
        for c in sorted(invalid, key=lambda c: (c["target"], c["scenario"], c["depth"])):
            lines.append(f"| {c['target']} | {c['scenario']} | {c['depth']} | "
                         f"{'; '.join(c['reasons'])} |")
        lines.append("")

    text = "\n".join(lines) + "\n"
    with open(out_path, "w") as fh:
        fh.write(text)
    print(f"[nested-report] wrote {out_path} ({len(cells)} cell(s))")
    return 1 if invalid else 0


if __name__ == "__main__":
    sys.exit(main())
