#!/usr/bin/env python3
"""Gate a conformance run on its machine-readable result (P23W5-11, D-60).

`fapi-conformance.yml` drives no browser, so every interactive module ends
`WAITING` on an unattended run and `run-plan.sh` (which exits non-zero for
anything that is not `PASSED`/`SKIPPED`) fails every run. A gate that is red by
design signals nothing, and a gate nobody trusts is one people learn to click
past. This script is the gate that can be trusted: it reads the same
`*.results.json` files `report.py` reads, plus two committed baselines, and
exits non-zero only on a REGRESSION:

* `conformance/baseline.json` is the browser-driven 2026-09-25 run: what a
  module may reach when somebody drives the browser;
* `conformance/baseline-unattended.json` is the other half: which modules park
  (`WAITING`) on the runner because they need a browser. A module that
  completed unattended and now parks is a regression, which `baseline.json`
  alone cannot see (every browser module is `PASSED` there and `WAITING` here).

The regressions are:

* a module the suite ended `FAILED`, `COULD_NOT_START` or `INTERRUPTED`, or that
  was still running (or never answered) when the harness stopped waiting;
* a module that ended in a verdict below its baseline (it was `PASSED` and is
  now `REVIEW` or `WARNING`);
* a module the baseline names that the run did not report at all;
* a module that ended `WAITING` and is not listed for its plan in the unattended
  baseline (it completed unattended before, or it is new and nobody has said
  it needs a browser);
* a plan the baseline names that the run left no result file for, or a plan
  that evaluated nothing (no module `PASSED`);
* a plan that is not in `baseline.json` at all, unless `--new-plan NAME` says it
  is new (see below).

`WAITING` is tolerated only for a module the unattended baseline lists for that
plan, and only then; `SKIPPED` (not applicable to the variant) is tolerated, and
so is a module the baseline has never heard of unless it failed outright (or
parked, see above). "Tolerated" is not "passed": the summary names every module
it tolerated, and the report step still renders them.

The gate fails closed on its inputs: an unreadable or malformed baseline of
either kind, an unreadable result file, or a plan the unattended baseline does
not name (every `WAITING` in it is then a regression) all end red, never
silently tolerant. A plan the main baseline does not name is refused: with
nothing to compare against, the gate would check outright failures only (not
even `WAITING`), so a typo in `--plan`, or a plan added to the workflow and
never baselined, would read as green (R101W4-10, #630). `--new-plan NAME`
(repeatable) is the explicit statement that a plan is new: it is then checked
for outright failures only, and the summary says so. The flag is as narrow as
it can be: every `--new-plan` must also be named by `--plan` (so it has to have
a result file), and a `--new-plan` for a plan `baseline.json` already names is
refused, so a flag left in a workflow after the plan was baselined cannot
quietly downgrade its checks. The cure for a new plan is to record it
(`--write-baseline`, `--record-unattended`), after which the flag goes away.

Stdlib only, like `report.py`.

    gate.py --results conformance/.run/results --plan fapi2-security-profile-final-mtls ...  # the CI gate
    gate.py --results DIR --plan NEWPLAN --new-plan NEWPLAN  # a plan no baseline names yet (failures only)
    gate.py --results DIR --write-baseline > baseline.json  # record a new baseline (browser-driven run)
    gate.py --results DIR --record-unattended > baseline-unattended.json  # record the parked set (unattended run)
"""

from __future__ import annotations

import argparse
import datetime
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
DEFAULT_UNATTENDED = pathlib.Path(__file__).resolve().parent.parent / "baseline-unattended.json"


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


def check_plan(name: str, run: dict, baseline: dict | None,
               parked: set[str] | None = None) -> tuple[list[str], list[str]]:
    """Return (regressions, tolerated notes) for one plan's run.

    `parked` is the set of modules the unattended baseline lists for this plan,
    i.e. the only ones allowed to end `WAITING`. `None` (not an empty set) means
    "do not check parking", which is only right for a plan the main baseline
    does not name; an empty set means nothing may park.
    """
    regressions: list[str] = []
    notes: list[str] = []
    modules = {m.get("module", "?"): verdict_of(m) for m in run.get("modules", [])}
    expected = (baseline or {}).get("modules", {})

    for module, verdict in sorted(modules.items()):
        base = expected.get(module)
        if verdict == "WAITING" and parked is not None and module not in parked:
            if base in RANK:
                regressions.append(
                    f"{name}: {module} is WAITING for a browser but completed unattended "
                    f"before (the unattended baseline does not list it)")
            else:
                regressions.append(
                    f"{name}: {module} is WAITING for a browser and the unattended baseline "
                    f"does not list it (a new module that needs one? re-record after reading it)")
        elif verdict in TOLERATED:
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


def gate(results_dir: pathlib.Path, baseline: dict, unattended: dict,
         only: list[str] | None = None, new_plans: list[str] | None = None) -> int:
    """Gate the plans in `only` (default: every plan the baseline names).

    `unattended` is the parsed unattended baseline (see `read_unattended`); it is
    required, not optional, so a caller that forgets it cannot get the old
    tolerate-every-WAITING behaviour by accident.

    `new_plans` names plans that `baseline.json` does not (yet) know. A plan the
    gate meets that is neither in `baseline.json` nor in `new_plans` is a
    regression, and a `new_plans` entry the baseline already names, or that
    `only` does not name, is one too (see the module doc).
    """
    runs = load_results(results_dir) if results_dir.is_dir() else {}
    plans = baseline.get("plans", {})
    parked_by_plan = unattended.get("plans", {})
    new_plans = sorted(set(new_plans or []))
    required = sorted(only or plans)
    if only:
        runs = {n: r for n, r in runs.items() if n in only}
    regressions: list[str] = []
    notes: list[str] = []

    for name in new_plans:
        if name in plans:
            regressions.append(f"{name}: --new-plan, but baseline.json already names this plan "
                               "(drop the flag; it would only weaken the checks)")
        elif name not in (only or []):
            regressions.append(f"{name}: --new-plan, but the plan is not among the --plan arguments")

    for name in required:
        if name not in runs:
            regressions.append(f"{name}: no result file under {results_dir}")
            if name not in plans and name not in new_plans:
                regressions.append(f"{name}: the plan is not in baseline.json and --new-plan "
                                   f"{name} was not given")
    for name, run in sorted(runs.items()):
        if name not in plans and name not in new_plans:
            regressions.append(f"{name}: the plan is not in baseline.json and --new-plan {name} "
                               "was not given (a typo, or a new plan nobody has recorded?)")
            continue
        # A plan the main baseline names must say which modules park; one that
        # the unattended baseline omits has none, so any WAITING in it is red.
        parked = set(parked_by_plan.get(name, {}).get("waiting", [])) if name in plans else None
        r, n = check_plan(name, run, plans.get(name), parked)
        regressions += r
        notes += n
        if name not in plans:
            notes.append(f"{name}: NEW PLAN (--new-plan), no baseline; only outright failures are "
                         "checked, not WAITING. Record it with --write-baseline and "
                         "--record-unattended, then drop the flag")

    if not runs and not required:
        regressions.append(f"no *.results.json under {results_dir} — the run wrote no result")

    for line in notes:
        print(f"[gate] tolerated  {line}")
    for line in regressions:
        print(f"[gate] REGRESSION {line}", file=sys.stderr)
    if regressions:
        print(f"[gate] {len(regressions)} regression(s); {len(notes)} tolerated", file=sys.stderr)
        return 1
    print(f"[gate] no regression against the baselines; {len(notes)} module(s) tolerated "
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


def read_unattended(path: pathlib.Path) -> dict:
    """Parse and shape-check the unattended baseline; raise on anything else.

    The shape is `{"plans": {<plan>: {"waiting": [<module>, ...]}}}` plus free
    `source`/`note` provenance. A file that parses but has another shape (a
    `waiting` that is a string, a plan that is a list) would read as "nothing
    parks" or crash mid-gate; both must be a refusal here instead.
    """
    data = json.loads(path.read_text())
    plans = data.get("plans") if isinstance(data, dict) else None
    if not isinstance(plans, dict):
        raise ValueError('expected an object with a "plans" object')
    for name, plan in plans.items():
        waiting = plan.get("waiting") if isinstance(plan, dict) else None
        if not isinstance(waiting, list) or not all(isinstance(m, str) for m in waiting):
            raise ValueError(f'plan {name}: expected {{"waiting": [module names]}}')
    return data


def record_unattended(results_dir: pathlib.Path) -> dict:
    """Record which modules a run left `WAITING`, per plan.

    Refuses a plan in which no module `PASSED`: a suite that never answered
    leaves everything parked, and baselining that would let the gate tolerate
    exactly the outage it exists to catch.
    """
    plans = {}
    runs = load_results(results_dir)
    if not runs:
        raise ValueError(f"no *.results.json under {results_dir}")
    for name, run in runs.items():
        verdicts = {m["module"]: verdict_of(m) for m in run.get("modules", [])}
        if "PASSED" not in verdicts.values():
            raise ValueError(f"{name}: no module PASSED — this run evaluated nothing, "
                             "so it is not a baseline of anything")
        plans[name] = {"waiting": sorted(m for m, v in verdicts.items() if v == "WAITING")}
    return {"plans": plans}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default="conformance/.run/results",
                    help="directory holding *.results.json from run-plan.sh")
    ap.add_argument("--baseline", default=str(DEFAULT_BASELINE),
                    help="the committed baseline (default: conformance/baseline.json)")
    ap.add_argument("--baseline-unattended", default=str(DEFAULT_UNATTENDED),
                    help="the committed unattended baseline: the modules that park on "
                         "a browser on the runner (default: conformance/baseline-unattended.json)")
    ap.add_argument("--plan", action="append", default=[], metavar="NAME",
                    help="gate only this plan (the results file's stem); repeatable. "
                         "Each one named must have a result file. Default: every "
                         "plan the baseline names")
    ap.add_argument("--new-plan", action="append", default=[], metavar="NAME",
                    help="say that this --plan is new, i.e. absent from the baseline: it is "
                         "then checked for outright failures only and reported as new. Without "
                         "it a --plan absent from the baseline is a regression. Repeatable; "
                         "each must also be a --plan, and must not be in the baseline")
    ap.add_argument("--write-baseline", action="store_true",
                    help="print a baseline built from --results instead of gating "
                         "(record it from a browser-driven run)")
    ap.add_argument("--record-unattended", action="store_true",
                    help="print an unattended baseline built from --results instead of "
                         "gating (record it from an unattended run)")
    args = ap.parse_args()

    results_dir = pathlib.Path(args.results)
    if args.write_baseline:
        json.dump(write_baseline(results_dir), sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    if args.record_unattended:
        try:
            recorded = record_unattended(results_dir)
        except ValueError as e:
            print(f"[gate] cannot record an unattended baseline: {e}", file=sys.stderr)
            return 1
        json.dump({
            "source": f"gate.py --record-unattended over {results_dir}, "
                      f"{datetime.date.today().isoformat()}",
            "note": "The modules that ended WAITING (parked on a browser) on an unattended "
                    "run. gate.py tolerates WAITING only for these.",
            **recorded,
        }, sys.stdout, indent=2)
        print()
        return 0
    try:
        baseline = json.loads(pathlib.Path(args.baseline).read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"[gate] cannot read the baseline {args.baseline}: {e}", file=sys.stderr)
        return 1
    try:
        unattended = read_unattended(pathlib.Path(args.baseline_unattended))
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"[gate] cannot read the unattended baseline {args.baseline_unattended}: {e}",
              file=sys.stderr)
        return 1
    return gate(results_dir, baseline, unattended, args.plan, args.new_plan)


if __name__ == "__main__":
    sys.exit(main())
