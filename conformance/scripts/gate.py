#!/usr/bin/env python3
"""Gate a conformance run on its machine-readable result (P23W5-11, D-60).

`fapi-conformance.yml` drives no browser, so every interactive module ends
`WAITING` on an unattended run and `run-plan.sh` (which exits non-zero for
anything that is not `PASSED`/`SKIPPED`) fails every run. A gate that is red by
design signals nothing, and a gate nobody trusts is one people learn to click
past. This script is the gate that can be trusted: it reads the same
`*.results.json` files `report.py` reads, plus the committed baseline
(`conformance/baseline.json`, the 2026-09-25 runs), and exits non-zero only on a
REGRESSION:

* a module the suite ended `FAILED`, `COULD_NOT_START` or `INTERRUPTED`, or that
  was still running (or never answered) when the harness stopped waiting;
* a module that ended in a verdict below its baseline (it was `PASSED` and is
  now `REVIEW` or `WARNING`);
* a module the baseline names that the run did not report at all;
* a plan the baseline names that the run left no result file for, or a plan
  that evaluated nothing (no module `PASSED`).

`WAITING` (parked on a browser, so no assertion was evaluated) and `SKIPPED`
(not applicable to the variant) are tolerated, and so is a module the baseline
has never heard of unless it failed outright. "Tolerated" is not "passed": the
summary names every module it tolerated, and the report step still renders them.

Stdlib only, like `report.py`.

    gate.py --results conformance/.run/results --plan fapi2-security-profile-final-mtls ...  # the CI gate
    gate.py --results DIR --write-baseline > baseline.json  # record a new baseline
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# The suite's own vocabulary (see report.py), grouped by what the gate does.
TOLERATED = {"WAITING", "SKIPPED"}
# Best verdict a module can have; a module at or above its baseline's rank holds.
RANK = {"PASSED": 2, "REVIEW": 1, "WARNING": 1}
# A module never ends below rank 0; a baseline of SKIPPED asks for nothing.
GOOD = set(RANK)

DEFAULT_BASELINE = pathlib.Path(__file__).resolve().parent.parent / "baseline.json"


def verdict_of(module: dict) -> str:
    """One verdict per module, preferring the suite's `result` over `status`.

    Same rule as `report.py`: `run-plan.sh` records `result` empty for a module
    that did not finish, and the status (`WAITING`, `RUNNING`, `TIMEOUT`) is then
    the only thing there is to say.
    """
    result = (module.get("result") or "").upper()
    if result:
        return result
    return (module.get("status") or "UNKNOWN").upper()


def load_results(results_dir: pathlib.Path) -> dict[str, dict]:
    """Plan name (the results file's stem) to its parsed run."""
    runs = {}
    for path in sorted(results_dir.glob("*.results.json")):
        try:
            runs[path.name[: -len(".results.json")]] = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            # An unreadable result is a regression, not a skipped file: the
            # plan it belonged to is then reported as having no result.
            print(f"[gate] unreadable {path}: {e}", file=sys.stderr)
    return runs


def check_plan(name: str, run: dict, baseline: dict | None) -> tuple[list[str], list[str]]:
    """Return (regressions, tolerated notes) for one plan's run."""
    regressions: list[str] = []
    notes: list[str] = []
    modules = {m.get("module", "?"): verdict_of(m) for m in run.get("modules", [])}
    expected = (baseline or {}).get("modules", {})

    for module, verdict in sorted(modules.items()):
        base = expected.get(module)
        if verdict in TOLERATED:
            notes.append(f"{name}: {module} {verdict}")
        elif verdict not in GOOD:
            regressions.append(f"{name}: {module} ended {verdict}")
        elif base in RANK and RANK[verdict] < RANK[base]:
            regressions.append(f"{name}: {module} ended {verdict}, below its baseline {base}")

    for module in sorted(set(expected) - set(modules)):
        regressions.append(f"{name}: {module} is in the baseline but the run did not report it")

    if modules and not any(v == "PASSED" for v in modules.values()):
        regressions.append(f"{name}: no module PASSED — nothing was evaluated")
    elif not modules:
        regressions.append(f"{name}: the run reported no modules")
    return regressions, notes


def gate(results_dir: pathlib.Path, baseline: dict, only: list[str] | None = None) -> int:
    """Gate the plans in `only` (default: every plan the baseline names)."""
    runs = load_results(results_dir) if results_dir.is_dir() else {}
    plans = baseline.get("plans", {})
    required = sorted(only or plans)
    if only:
        runs = {n: r for n, r in runs.items() if n in only}
    regressions: list[str] = []
    notes: list[str] = []

    for name in required:
        if name not in runs:
            regressions.append(f"{name}: no result file under {results_dir}")
    for name, run in sorted(runs.items()):
        r, n = check_plan(name, run, plans.get(name))
        regressions += r
        notes += n
        if name not in plans:
            notes.append(f"{name}: no baseline for this plan; only outright failures are checked")

    if not runs and not required:
        regressions.append(f"no *.results.json under {results_dir} — the run wrote no result")

    for line in notes:
        print(f"[gate] tolerated  {line}")
    for line in regressions:
        print(f"[gate] REGRESSION {line}", file=sys.stderr)
    if regressions:
        print(f"[gate] {len(regressions)} regression(s); {len(notes)} tolerated", file=sys.stderr)
        return 1
    print(f"[gate] no regression against the baseline; {len(notes)} module(s) tolerated "
          "(WAITING/SKIPPED are not passes — read the report)")
    return 0


def write_baseline(results_dir: pathlib.Path) -> dict:
    """Record a run's good verdicts as the baseline (PASSED, REVIEW, WARNING)."""
    plans = {}
    for name, run in load_results(results_dir).items():
        plans[name] = {"modules": {
            m["module"]: verdict_of(m) for m in run.get("modules", []) if verdict_of(m) in GOOD
        }}
    return {"plans": plans}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default="conformance/.run/results",
                    help="directory holding *.results.json from run-plan.sh")
    ap.add_argument("--baseline", default=str(DEFAULT_BASELINE),
                    help="the committed baseline (default: conformance/baseline.json)")
    ap.add_argument("--plan", action="append", default=[], metavar="NAME",
                    help="gate only this plan (the results file's stem); repeatable. "
                         "Each one named must have a result file. Default: every "
                         "plan the baseline names")
    ap.add_argument("--write-baseline", action="store_true",
                    help="print a baseline built from --results instead of gating")
    args = ap.parse_args()

    results_dir = pathlib.Path(args.results)
    if args.write_baseline:
        json.dump(write_baseline(results_dir), sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    try:
        baseline = json.loads(pathlib.Path(args.baseline).read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"[gate] cannot read the baseline {args.baseline}: {e}", file=sys.stderr)
        return 1
    return gate(results_dir, baseline, args.plan)


if __name__ == "__main__":
    sys.exit(main())
