#!/usr/bin/env python3
"""Tests for the conformance gate (P23W5-11).

Run: python3 -m unittest discover -s conformance/scripts -p 'test_*.py'

Fixtures are written as the JSON `run-plan.sh` produces, so the tests exercise
the real file format end to end, through `gate.main`'s file loading.
"""

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import gate

PLAN = "fapi2-security-profile-final-mtls"

BASELINE = {
    "plans": {
        PLAN: {
            "modules": {
                "discovery": "PASSED",
                "happy-flow": "PASSED",
                "par-reuse": "REVIEW",
                "claims": "WARNING",
            }
        }
    }
}


# Which modules park on the runner: only the interactive one here.
UNATTENDED = {"plans": {PLAN: {"waiting": ["happy-flow", "claims-interactive"]}}}


def module(name, result="", status="FINISHED"):
    return {"module": name, "testId": "t-" + name, "status": status, "result": result}


def run_of(*modules):
    return {"planId": "p", "planName": "n", "modules": list(modules)}


# What an unattended CI run looks like against the baseline: the non-interactive
# modules finish, the interactive ones are parked on a browser.
HEALTHY = [
    module("discovery", "PASSED"),
    module("happy-flow", status="WAITING"),
    module("par-reuse", "REVIEW"),
    module("claims", "WARNING"),
]


class GateTest(unittest.TestCase):
    def check(self, *modules, baseline=BASELINE, plan=PLAN, unattended=UNATTENDED):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            if modules:
                (tmp / f"{plan}.results.json").write_text(json.dumps(run_of(*modules)))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = gate.gate(tmp, baseline, unattended)
            return rc, out.getvalue(), err.getvalue()

    def test_a_pass_with_the_interactive_module_waiting(self):
        rc, out, err = self.check(*HEALTHY)
        self.assertEqual(rc, 0, err)
        # Tolerated is named, not hidden.
        self.assertIn("happy-flow WAITING", out)

    def test_a_failed_non_interactive_module_is_a_regression(self):
        rc, _, err = self.check(module("discovery", "FAILED"), *HEALTHY[1:])
        self.assertEqual(rc, 1)
        self.assertIn("discovery ended FAILED", err)

    def test_could_not_start_and_interrupted_are_regressions(self):
        for verdict in ("COULD_NOT_START", "INTERRUPTED"):
            rc, _, err = self.check(module("discovery", verdict), *HEALTHY[1:])
            self.assertEqual(rc, 1, verdict)
            self.assertIn(verdict, err)

    def test_a_module_below_its_baseline_is_a_regression(self):
        rc, _, err = self.check(module("discovery", "REVIEW"), *HEALTHY[1:])
        self.assertEqual(rc, 1)
        self.assertIn("below its baseline PASSED", err)

    def test_a_module_at_or_above_its_baseline_holds(self):
        # REVIEW -> PASSED is an improvement; REVIEW <-> WARNING is the same rank.
        rc, _, err = self.check(
            module("discovery", "PASSED"),
            module("happy-flow", "PASSED"),
            module("par-reuse", "PASSED"),
            module("claims", "REVIEW"),
        )
        self.assertEqual(rc, 0, err)

    def test_a_waiting_module_the_unattended_baseline_lists_is_tolerated_even_if_the_baseline_passed_it(self):
        # Kept from R1W2-06's pin, narrowed: tolerated because the unattended
        # baseline lists it, not because WAITING is always tolerated.
        rc, out, _ = self.check(*HEALTHY)
        self.assertEqual(rc, 0)
        self.assertIn("happy-flow WAITING", out)

    def test_a_module_that_completed_unattended_before_and_parks_now_is_a_regression(self):
        # R1W2-06: `discovery` is PASSED in the baseline and absent from the
        # unattended one, i.e. it finishes on the runner. Parking is the bug.
        rc, out, err = self.check(module("discovery", status="WAITING"), *HEALTHY[1:])
        self.assertEqual(rc, 1)
        self.assertIn("discovery is WAITING for a browser but completed unattended before", err)
        self.assertNotIn("discovery WAITING", out)

    def test_a_new_module_that_parks_is_a_regression_until_it_is_recorded(self):
        # Unknown to both baselines: not tolerated, and the message says why.
        rc, _, err = self.check(*HEALTHY, module("brand-new", status="WAITING"))
        self.assertEqual(rc, 1)
        self.assertIn("brand-new is WAITING for a browser and the unattended baseline does not list it", err)

    def test_a_listed_module_that_now_completes_is_not_a_regression(self):
        rc, _, err = self.check(module("discovery", "PASSED"), module("happy-flow", "PASSED"), *HEALTHY[2:])
        self.assertEqual(rc, 0, err)

    def test_a_plan_the_unattended_baseline_omits_tolerates_no_waiting(self):
        rc, _, err = self.check(*HEALTHY, unattended={"plans": {}})
        self.assertEqual(rc, 1)
        self.assertIn("happy-flow is WAITING", err)

    def test_a_plan_without_a_main_baseline_still_tolerates_waiting(self):
        # The pre-existing leniency for an unknown plan is unchanged: only
        # outright failures are checked there.
        rc, out, err = self.check(module("m", "PASSED"), module("n", status="WAITING"),
                                  baseline={"plans": {}}, unattended={"plans": {}})
        self.assertEqual(rc, 0, err)
        self.assertIn("n WAITING", out)

    def test_skipped_is_tolerated(self):
        rc, out, err = self.check(module("happy-flow", "SKIPPED"), *HEALTHY[:1], *HEALTHY[2:])
        self.assertEqual(rc, 0, err)
        self.assertIn("happy-flow SKIPPED", out)

    def test_a_module_that_overran_the_timeout_is_a_regression(self):
        # run-plan.sh records the status when the deadline passes; a module
        # still RUNNING was not parked on a browser.
        rc, _, err = self.check(module("discovery", status="RUNNING"), *HEALTHY[1:])
        self.assertEqual(rc, 1)
        self.assertIn("discovery ended RUNNING", err)

    def test_a_module_missing_from_the_run_is_a_regression(self):
        rc, _, err = self.check(*HEALTHY[:3])
        self.assertEqual(rc, 1)
        self.assertIn("claims is in the baseline but the run did not report it", err)

    def test_a_new_module_fails_only_if_it_failed(self):
        rc, _, err = self.check(*HEALTHY, module("brand-new", "REVIEW"))
        self.assertEqual(rc, 0, err)
        rc, _, err = self.check(*HEALTHY, module("brand-new", "FAILED"))
        self.assertEqual(rc, 1)
        self.assertIn("brand-new ended FAILED", err)

    def test_a_plan_the_run_did_not_write_is_a_regression(self):
        rc, _, err = self.check()
        self.assertEqual(rc, 1)
        self.assertIn(f"{PLAN}: no result file", err)

    def test_a_run_that_evaluated_nothing_is_a_regression(self):
        # The suite unreachable would leave every module WAITING or SKIPPED.
        rc, _, err = self.check(
            module("discovery", status="WAITING"),
            module("happy-flow", status="WAITING"),
            baseline={"plans": {PLAN: {"modules": {}}}},
            unattended={"plans": {PLAN: {"waiting": ["discovery", "happy-flow"]}}},
        )
        self.assertEqual(rc, 1)
        self.assertIn("nothing was evaluated", err)

    def test_a_plan_without_a_baseline_checks_outright_failures_only(self):
        rc, out, err = self.check(module("m", "PASSED"), baseline={"plans": {}}, unattended={"plans": {}})
        self.assertEqual(rc, 0, err)
        self.assertIn("no baseline for this plan", out)
        rc, _, _ = self.check(module("m", "FAILED"), baseline={"plans": {}}, unattended={"plans": {}})
        self.assertEqual(rc, 1)

    def test_only_restricts_the_gate_to_the_named_plans(self):
        baseline = {"plans": {PLAN: BASELINE["plans"][PLAN], "oidcc-basic-static": {"modules": {"x": "PASSED"}}}}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / f"{PLAN}.results.json").write_text(json.dumps(run_of(*HEALTHY)))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                # The Basic plan is in the baseline but this workflow never runs it.
                self.assertEqual(gate.gate(tmp, baseline, UNATTENDED), 1)
                self.assertEqual(gate.gate(tmp, baseline, UNATTENDED, [PLAN]), 0)
                # A named plan without a result file is still a regression.
                self.assertEqual(
                    gate.gate(tmp, baseline, UNATTENDED, [PLAN, "fapi2-security-profile-final-self-signed"]), 1)

    def test_write_baseline_keeps_only_good_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / f"{PLAN}.results.json").write_text(json.dumps(run_of(
                module("a", "PASSED"), module("b", "REVIEW"), module("c", "FAILED"),
                module("d", status="WAITING"), module("e", "SKIPPED"),
            )))
            self.assertEqual(
                gate.write_baseline(tmp),
                {"plans": {PLAN: {"modules": {"a": "PASSED", "b": "REVIEW"}}}},
            )

    def test_record_unattended_keeps_only_the_waiting_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / f"{PLAN}.results.json").write_text(json.dumps(run_of(
                module("a", "PASSED"), module("b", status="WAITING"), module("c", "FAILED"),
                module("d", status="WAITING"), module("e", "SKIPPED"),
            )))
            self.assertEqual(
                gate.record_unattended(tmp),
                {"plans": {PLAN: {"waiting": ["b", "d"]}}},
            )

    def test_record_unattended_refuses_a_run_that_evaluated_nothing(self):
        # A suite that never answered parks everything; baselining that would
        # make the gate tolerate the outage it exists to catch.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / f"{PLAN}.results.json").write_text(json.dumps(run_of(
                module("a", status="WAITING"), module("b", status="WAITING"))))
            with self.assertRaisesRegex(ValueError, "no module PASSED"):
                gate.record_unattended(tmp)
            with self.assertRaisesRegex(ValueError, "no \\*.results.json"):
                gate.record_unattended(tmp / "absent")

    def test_a_recorded_unattended_baseline_round_trips_through_the_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / f"{PLAN}.results.json").write_text(json.dumps(run_of(*HEALTHY)))
            recorded = gate.record_unattended(tmp)
            out = tmp / "baseline-unattended.json"
            out.write_text(json.dumps(recorded))
            unattended = gate.read_unattended(out)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gate.gate(tmp, BASELINE, unattended), 0)

    def test_read_unattended_rejects_a_malformed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "u.json"
            for bad in ('[]', '{}', '{"plans": []}', '{"plans": {"p": []}}',
                        '{"plans": {"p": {"waiting": "happy-flow"}}}',
                        '{"plans": {"p": {"waiting": [1]}}}', 'not json'):
                path.write_text(bad)
                with self.assertRaises((ValueError, json.JSONDecodeError), msg=bad):
                    gate.read_unattended(path)
            path.write_text('{"plans": {"p": {"waiting": ["m"]}}}')
            self.assertEqual(gate.read_unattended(path)["plans"]["p"]["waiting"], ["m"])

    def test_the_gate_fails_closed_without_a_readable_unattended_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / f"{PLAN}.results.json").write_text(json.dumps(run_of(*HEALTHY)))
            good = tmp / "baseline.json"
            good.write_text(json.dumps(BASELINE))
            unreadable = tmp / "baseline-unattended.json"
            argv = ["gate.py", "--results", str(tmp), "--baseline", str(good),
                    "--baseline-unattended", str(unreadable)]
            for content in (None, "not json", '{"plans": {"p": {"waiting": "x"}}}'):
                if content is not None:
                    unreadable.write_text(content)
                err = io.StringIO()
                with mock.patch.object(sys, "argv", argv), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    self.assertEqual(gate.main(), 1, content)
                self.assertIn("cannot read the unattended baseline", err.getvalue())
            # ...and the same run is green once the file is right.
            unreadable.write_text(json.dumps(UNATTENDED))
            with mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gate.main(), 0)

    def test_the_committed_unattended_baseline_is_consistent_with_the_main_one(self):
        baseline = json.loads(gate.DEFAULT_BASELINE.read_text())
        unattended = gate.read_unattended(gate.DEFAULT_UNATTENDED)
        # The workflow's three plans are covered; Basic is not run in CI.
        self.assertEqual(
            sorted(unattended["plans"]),
            ["fapi2-security-profile-final-mtls",
             "fapi2-security-profile-final-private-key-jwt",
             "fapi2-security-profile-final-self-signed"],
        )
        for name, plan in unattended["plans"].items():
            waiting = plan["waiting"]
            self.assertEqual(waiting, sorted(set(waiting)), name)
            # A parked module must be one the browser-driven baseline names,
            # or the list is describing modules the plan does not have.
            self.assertFalse(set(waiting) - set(baseline["plans"][name]["modules"]), name)
            # ...and some module must complete unattended, or nothing is evaluated.
            self.assertLess(len(waiting), len(baseline["plans"][name]["modules"]), name)

    def test_the_committed_baselines_gate_an_unattended_run_that_matches_them(self):
        baseline = json.loads(gate.DEFAULT_BASELINE.read_text())
        unattended = gate.read_unattended(gate.DEFAULT_UNATTENDED)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            for name, plan in unattended["plans"].items():
                parked = set(plan["waiting"])
                (tmp / f"{name}.results.json").write_text(json.dumps(run_of(*[
                    module(m, status="WAITING") if m in parked else module(m, v)
                    for m, v in baseline["plans"][name]["modules"].items()
                ])))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = gate.gate(tmp, baseline, unattended, sorted(unattended["plans"]))
            self.assertEqual(rc, 0, err.getvalue())
            # One module that finishes unattended and now parks turns it red.
            name = "fapi2-security-profile-final-mtls"
            path = tmp / f"{name}.results.json"
            run = json.loads(path.read_text())
            done = next(m for m in run["modules"] if m["status"] != "WAITING")
            done.update(status="WAITING", result="")
            path.write_text(json.dumps(run))
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                self.assertEqual(gate.gate(tmp, baseline, unattended, sorted(unattended["plans"])), 1)
            self.assertIn(done["module"], err.getvalue())

    def test_the_committed_baseline_gates_its_own_shape(self):
        baseline = json.loads(gate.DEFAULT_BASELINE.read_text())
        self.assertEqual(
            sorted(baseline["plans"]),
            ["fapi2-security-profile-final-mtls",
             "fapi2-security-profile-final-private-key-jwt",
             "fapi2-security-profile-final-self-signed",
             "oidcc-basic-static"],
        )
        # A run that reproduces the baseline exactly is not a regression.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            for name, plan in baseline["plans"].items():
                (tmp / f"{name}.results.json").write_text(json.dumps(run_of(
                    *[module(m, v) for m, v in plan["modules"].items()]
                )))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                # Every module at its baseline verdict: nothing parks, which the
                # unattended baseline allows (a listed module may complete).
                self.assertEqual(gate.gate(tmp, baseline, {"plans": {}}), 0, err.getvalue())


if __name__ == "__main__":
    unittest.main()
