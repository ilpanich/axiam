#!/usr/bin/env python3
"""Aggregate conformance-run artifacts into one Markdown report (X5.2).

Deliberately mirrors `benchmarks/runner/report.py` in the one way that matters:
**it prints the failures.** AXIAM publishes its benchmark receipts including the
regressions and the failing tables, and a conformance report that quietly
summarised "42 tests" without saying which four were red would be exactly the
kind of artifact this project exists not to produce.

Reads `conformance/.run/results/*.results.json` (written by run-plan.sh) and
writes `docs/conformance/<date>-<plan>.md` plus a combined index.

Stdlib only, like report.py — no dependency to install before a report can be
regenerated from artifacts somebody else sent you.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter

# The suite's own vocabulary. Ordered worst-first, because that is the order a
# reader needs them in.
SEVERITY = ["FAILED", "COULD_NOT_START", "TIMEOUT", "INTERRUPTED", "WARNING", "REVIEW", "SKIPPED", "PASSED"]

# What each verdict actually means for a submission, in one line. A reader
# looking at their first conformance report should not have to go and find the
# suite's documentation to know whether REVIEW is a problem.
MEANING = {
    "PASSED": "the module's assertions all held",
    "SKIPPED": "not applicable to this variant",
    "REVIEW": "the suite cannot decide automatically — a human must read the log and judge",
    "WARNING": "a non-fatal deviation; permitted, but worth understanding before submitting",
    "INTERRUPTED": "the module stopped before finishing (often an interactive step nobody completed)",
    "TIMEOUT": "the harness stopped waiting; usually an interactive module, occasionally a hang",
    "COULD_NOT_START": "the suite refused to start the module — a configuration problem, not a result",
    "FAILED": "an assertion did not hold. This is a real finding.",
}


def load(results_dir: pathlib.Path) -> list[dict]:
    runs = []
    for path in sorted(results_dir.glob("*.results.json")):
        try:
            runs.append({"path": path, **json.loads(path.read_text())})
        except (OSError, json.JSONDecodeError) as e:
            print(f"[report] skipping unreadable {path}: {e}", file=sys.stderr)
    return runs


def verdict_of(module: dict) -> str:
    """One verdict per module, preferring the suite's `result` over `status`."""
    result = (module.get("result") or "").upper()
    if result:
        return result
    return (module.get("status") or "UNKNOWN").upper()


def render(run: dict) -> str:
    modules = run.get("modules", [])
    counts = Counter(verdict_of(m) for m in modules)
    total = len(modules)
    passed = counts.get("PASSED", 0)

    out = []
    out.append(f"# {run.get('planName', 'unknown plan')}")
    out.append("")
    out.append(f"- **Plan id**: `{run.get('planId', '?')}`")
    out.append(f"- **Modules**: {total}")
    out.append(f"- **Passed**: {passed}/{total}")
    out.append("")

    # The headline. Stated as a sentence rather than a number, because
    # "38/42" invites a reader to round it up to "basically green".
    not_passed = total - passed - counts.get("SKIPPED", 0)
    if total == 0:
        out.append("**No modules ran.** This is not a green result; it is an empty one.")
    elif not_passed == 0:
        out.append("**Every applicable module passed.**")
    else:
        out.append(
            f"**{not_passed} module(s) did not pass.** A submission built on this run "
            f"would be a submission with {not_passed} open question(s)."
        )
    out.append("")

    out.append("## Verdict summary")
    out.append("")
    out.append("| Verdict | Count | What it means |")
    out.append("|---|---:|---|")
    for verdict in SEVERITY:
        if counts.get(verdict):
            out.append(f"| `{verdict}` | {counts[verdict]} | {MEANING.get(verdict, '')} |")
    for verdict, n in sorted(counts.items()):
        if verdict not in SEVERITY:
            out.append(f"| `{verdict}` | {n} | (unrecognised verdict — read the suite log) |")
    out.append("")

    # Everything that is not a clean pass, listed by name. This is the section
    # the report exists for.
    problems = [m for m in modules if verdict_of(m) not in ("PASSED", "SKIPPED")]
    if problems:
        out.append("## Modules that did not pass")
        out.append("")
        out.append("| Module | Verdict | Suite log |")
        out.append("|---|---|---|")
        order = {v: i for i, v in enumerate(SEVERITY)}
        for m in sorted(problems, key=lambda m: order.get(verdict_of(m), 99)):
            test_id = m.get("testId", "")
            link = f"`{test_id}`" if test_id else "—"
            out.append(f"| `{m['module']}` | `{verdict_of(m)}` | {link} |")
        out.append("")
        out.append(
            "Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. "
            "See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) "
            "for how to read one and how to re-run a single module."
        )
        out.append("")

    if counts.get("PASSED"):
        out.append("<details><summary>Modules that passed</summary>")
        out.append("")
        for m in modules:
            if verdict_of(m) == "PASSED":
                out.append(f"- `{m['module']}`")
        out.append("")
        out.append("</details>")
        out.append("")

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", default="conformance/.run/results",
                    help="directory holding *.results.json from run-plan.sh")
    ap.add_argument("--out", default="docs/conformance",
                    help="where to write the Markdown reports")
    ap.add_argument("--date", default="",
                    help="date stamp for output filenames (YYYY-MM-DD). "
                         "Passed in rather than read from the clock so a "
                         "re-render of old artifacts does not restamp them.")
    args = ap.parse_args()

    results_dir = pathlib.Path(args.results)
    if not results_dir.is_dir():
        print(f"[report] no results directory at {results_dir}", file=sys.stderr)
        print("[report] run 'just conformance-run' first", file=sys.stderr)
        return 1

    runs = load(results_dir)
    if not runs:
        print(f"[report] no *.results.json under {results_dir}", file=sys.stderr)
        return 1

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = f"{args.date}-" if args.date else ""
    index = ["# AXIAM conformance reports", "",
             "Generated by `just conformance-report`. Published in full — green and "
             "red alike — for the same reason the benchmark archive is.", ""]

    exit_code = 0
    for run in runs:
        name = run["path"].name.replace(".results.json", "")
        dest = out_dir / f"{stamp}{name}.md"
        dest.write_text(render(run))
        print(f"[report] wrote {dest}")

        modules = run.get("modules", [])
        bad = [m for m in modules if verdict_of(m) not in ("PASSED", "SKIPPED")]
        state = "green" if modules and not bad else f"{len(bad)} not passing"
        index.append(f"- [`{name}`]({dest.name}) — {len(modules)} modules, {state}")
        if bad or not modules:
            exit_code = 2

    (out_dir / "README.md").write_text("\n".join(index) + "\n")
    print(f"[report] wrote {out_dir / 'README.md'}")
    if exit_code:
        print("[report] at least one plan is not green — see the reports above", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
