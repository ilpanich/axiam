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
import tempfile
import unittest

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
    def check(self, *modules, baseline=BASELINE, plan=PLAN):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            if modules:
                (tmp / f"{plan}.results.json").write_text(json.dumps(run_of(*modules)))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = gate.gate(tmp, baseline)
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

    def test_a_waiting_interactive_module_is_tolerated_even_if_the_baseline_passed_it(self):
        rc, out, _ = self.check(*HEALTHY)
        self.assertEqual(rc, 0)
        self.assertIn("happy-flow WAITING", out)

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
        )
        self.assertEqual(rc, 1)
        self.assertIn("nothing was evaluated", err)

    def test_a_plan_without_a_baseline_checks_outright_failures_only(self):
        rc, out, err = self.check(module("m", "PASSED"), baseline={"plans": {}})
        self.assertEqual(rc, 0, err)
        self.assertIn("no baseline for this plan", out)
        rc, _, _ = self.check(module("m", "FAILED"), baseline={"plans": {}})
        self.assertEqual(rc, 1)

    def test_only_restricts_the_gate_to_the_named_plans(self):
        baseline = {"plans": {PLAN: BASELINE["plans"][PLAN], "oidcc-basic-static": {"modules": {"x": "PASSED"}}}}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / f"{PLAN}.results.json").write_text(json.dumps(run_of(*HEALTHY)))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                # The Basic plan is in the baseline but this workflow never runs it.
                self.assertEqual(gate.gate(tmp, baseline), 1)
                self.assertEqual(gate.gate(tmp, baseline, [PLAN]), 0)
                # A named plan without a result file is still a regression.
                self.assertEqual(gate.gate(tmp, baseline, [PLAN, "fapi2-security-profile-final-self-signed"]), 1)

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
                self.assertEqual(gate.gate(tmp, baseline), 0, err.getvalue())


if __name__ == "__main__":
    unittest.main()
