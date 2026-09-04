#!/usr/bin/env python3
"""Tests for the Vault status reporter, notably the T-180 token-scope check.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import pathlib
import re
import unittest

from vault_status_report import (
    CA_KEY_DATA_PROBE,
    CA_KEY_METADATA_PROBE,
    EXPECTED,
    EXPECTED_CAPABILITIES,
    PROBE_PATHS,
    is_over_scoped,
    is_root,
    is_under_scoped,
    read_capabilities,
    scope_findings,
    seal_findings,
    seal_is_production_ready,
    secret_presence,
    unexpected_fields,
)

POLICY_FILE = pathlib.Path(__file__).resolve().parent.parent / "docker" / "vault" / "axiam-policy.hcl"


class SecretPresence(unittest.TestCase):
    """Presence only — the reporter must never need a value to do its job."""

    def test_every_expected_secret_is_reported(self):
        result = secret_presence({"data": {"data": {}}})
        self.assertEqual(list(result), EXPECTED)
        self.assertTrue(all(present is False for present in result.values()))

    def test_a_set_secret_is_reported_present(self):
        body = {"data": {"data": {"auth_pepper": "anything"}}}
        self.assertIs(secret_presence(body)["auth_pepper"], True)

    def test_an_empty_string_counts_as_missing(self):
        # A field Vault holds but whose value is empty would fail at startup
        # just as surely as an absent one.
        body = {"data": {"data": {"auth_pepper": ""}}}
        self.assertIs(secret_presence(body)["auth_pepper"], False)

    def test_only_a_boolean_crosses_the_boundary(self):
        # The property the CodeQL alert of 2026-08-28 was about: nothing
        # derived from Vault's response leaves this function except a flag, so
        # no value — and no name taken from the response — can reach a print.
        body = {"data": {"data": {"auth_pepper": "s3cr3t", "surprise": "x"}}}
        result = secret_presence(body)
        self.assertEqual(list(result), EXPECTED)
        self.assertTrue(all(isinstance(v, bool) for v in result.values()))
        self.assertNotIn("surprise", result)

    def test_fields_axiam_does_not_read_are_listed_separately(self):
        body = {"data": {"data": {"auth_pepper": "x", "someone_elses_key": "y"}}}
        self.assertEqual(unexpected_fields(body), ["someone_elses_key"])

    def test_a_response_with_no_data_is_all_missing(self):
        self.assertEqual(len(secret_presence({})), len(EXPECTED))


class CapabilityParsing(unittest.TestCase):
    """Vault reports the same thing three ways; read all of them the same."""

    def test_multi_path_response(self):
        body = {
            "data": {
                "secret/data/axiam": ["read"],
                "secret/metadata/axiam": ["read"],
            },
            "secret/data/axiam": ["read"],
            "secret/metadata/axiam": ["read"],
        }
        self.assertEqual(
            read_capabilities(body),
            {"secret/data/axiam": ["read"], "secret/metadata/axiam": ["read"]},
        )

    def test_single_path_response_ignores_the_bare_capabilities_key(self):
        # For one path Vault echoes the list twice: once under the path and
        # once under `capabilities`. Counting the latter as a path would
        # produce a phantom finding named "capabilities".
        body = {"capabilities": ["read"], "secret/data/axiam": ["read"]}
        self.assertEqual(read_capabilities(body), {"secret/data/axiam": ["read"]})

    def test_a_response_without_a_data_envelope_still_parses(self):
        body = {"secret/data/axiam": ["read"]}
        self.assertEqual(read_capabilities(body), {"secret/data/axiam": ["read"]})

    def test_junk_is_not_mistaken_for_a_path(self):
        body = {"data": {"secret/data/axiam": ["read"], "lease_id": "", "renewable": False}}
        self.assertEqual(read_capabilities(body), {"secret/data/axiam": ["read"]})


class ScopeVerdict(unittest.TestCase):
    """The finding T-180 describes: a token that can do more than read."""

    def test_read_only_on_both_paths_is_clean(self):
        per_path = {"secret/data/axiam": ["read"], "secret/metadata/axiam": ["read"]}
        self.assertFalse(is_over_scoped(per_path))
        self.assertFalse(is_root(per_path))

    def test_deny_is_not_over_scope(self):
        # `deny` is stricter than read, not looser — flagging it would train
        # operators to ignore the warning.
        self.assertFalse(is_over_scoped({"secret/data/axiam": ["deny"]}))

    def test_write_on_the_axiam_path_is_flagged(self):
        per_path = {"secret/data/axiam": ["read", "update"]}
        self.assertTrue(is_over_scoped(per_path))
        self.assertEqual(scope_findings(per_path)[0][2], ["update"])

    def test_delete_and_list_are_flagged(self):
        per_path = {"secret/data/axiam": ["read", "delete", "list"]}
        self.assertEqual(scope_findings(per_path)[0][2], ["delete", "list"])

    def test_a_root_token_is_flagged_as_root(self):
        per_path = {"secret/data/axiam": ["root"]}
        self.assertTrue(is_over_scoped(per_path))
        self.assertTrue(is_root(per_path))

    def test_one_bad_path_out_of_two_still_reports(self):
        per_path = {
            "secret/data/axiam": ["read"],
            "secret/metadata/axiam": ["read", "delete"],
        }
        self.assertTrue(is_over_scoped(per_path))
        findings = scope_findings(per_path)
        self.assertEqual(findings[0][2], [])
        self.assertEqual(findings[1][2], ["delete"])

    def test_no_capabilities_reported_is_not_a_finding(self):
        # "Vault told us nothing" must not read as "the token is fine" *or* as
        # a false alarm; the caller prints "not checked" for this case.
        self.assertFalse(is_over_scoped({}))

    def test_writing_ca_keys_is_not_over_scope(self):
        # The whole point of the per-path expectation. `create` on the startup
        # secret would be a finding; on a CA-key path it is the job.
        per_path = {CA_KEY_DATA_PROBE: ["create", "read", "update"]}
        self.assertFalse(is_over_scoped(per_path))
        self.assertFalse(is_under_scoped(per_path))

    def test_list_on_a_ca_key_path_is_still_over_scope(self):
        per_path = {CA_KEY_DATA_PROBE: ["create", "read", "update", "list"]}
        self.assertTrue(is_over_scoped(per_path))
        self.assertEqual(scope_findings(per_path)[0][2], ["list"])


class UnderScope(unittest.TestCase):
    """The other half: a token that cannot do what the server needs.

    This is the shape that shipped through 1.0.0-beta09 — a token with read on
    the startup secret and nothing on the CA prefix. It boots, it serves, and
    the first CA generation answers `403 Forbidden on write`.
    """

    def test_the_beta09_token_is_under_scoped(self):
        per_path = {
            "secret/data/axiam": ["read"],
            "secret/metadata/axiam": ["read"],
            CA_KEY_DATA_PROBE: ["deny"],
            CA_KEY_METADATA_PROBE: ["deny"],
        }
        self.assertFalse(is_over_scoped(per_path))
        self.assertTrue(is_under_scoped(per_path))
        by_path = {f[0]: f for f in scope_findings(per_path)}
        self.assertEqual(by_path[CA_KEY_DATA_PROBE][3], ["create", "read", "update"])
        self.assertEqual(by_path[CA_KEY_METADATA_PROBE][3], ["delete"])

    def test_a_fully_scoped_token_is_neither(self):
        per_path = {
            "secret/data/axiam": ["read"],
            "secret/metadata/axiam": ["read"],
            CA_KEY_DATA_PROBE: ["create", "read", "update"],
            CA_KEY_METADATA_PROBE: ["delete"],
        }
        self.assertFalse(is_over_scoped(per_path))
        self.assertFalse(is_under_scoped(per_path))

    def test_root_is_never_under_scoped(self):
        # Root holds everything. The finding on a root token is over-scope, and
        # reporting it as *also* missing capabilities would be nonsense.
        per_path = {CA_KEY_DATA_PROBE: ["root"]}
        self.assertFalse(is_under_scoped(per_path))
        self.assertTrue(is_root(per_path))

    def test_a_missing_read_on_the_startup_secret_is_reported(self):
        # The failure operators actually hit before CA custody existed, and the
        # one the troubleshooting table in docs/deployment/vault.md §9 names.
        self.assertTrue(is_under_scoped({"secret/data/axiam": []}))


class PolicyFileAgreement(unittest.TestCase):
    """The reporter and docker/vault/axiam-policy.hcl must say the same thing.

    Without this the two drift silently in the direction that matters least
    visibly: the policy grants what the server needs, the reporter expects
    something else, and `just vault-status` prints a finding about a Vault that
    is correctly configured — which is how a check stops being read.
    """

    @staticmethod
    def _policy_rules() -> dict[str, frozenset[str]]:
        text = POLICY_FILE.read_text(encoding="utf-8")
        # Comments are stripped first so a path named inside one — and this file
        # names several — cannot be read as a rule.
        text = re.sub(r"(?m)^\s*#.*$", "", text)
        pattern = re.compile(
            r'path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}',
            re.S,
        )
        return {
            path: frozenset(re.findall(r'"([^"]+)"', caps))
            for path, caps in pattern.findall(text)
        }

    @staticmethod
    def _matches(rule: str, request_path: str) -> bool:
        """Vault's own matching, reduced to what this policy uses."""
        return request_path.startswith(rule[:-1]) if rule.endswith("*") else rule == request_path

    def test_the_policy_file_parses(self):
        self.assertTrue(self._policy_rules(), f"no rules found in {POLICY_FILE}")

    def test_every_probed_path_gets_exactly_what_the_reporter_expects(self):
        rules = self._policy_rules()
        for probe in PROBE_PATHS:
            matched = [caps for rule, caps in rules.items() if self._matches(rule, probe)]
            self.assertEqual(
                len(matched), 1, f"{probe} should match exactly one rule, matched {len(matched)}"
            )
            self.assertEqual(
                matched[0],
                EXPECTED_CAPABILITIES[probe],
                f"{probe}: policy grants {sorted(matched[0])}, reporter expects "
                f"{sorted(EXPECTED_CAPABILITIES[probe])}",
            )

    def test_the_policy_grants_nothing_the_reporter_does_not_know_about(self):
        # A rule nobody probes is a capability nobody checks. Adding one is
        # fine; adding one without a probe is the thing this catches.
        for rule in self._policy_rules():
            self.assertTrue(
                any(self._matches(rule, probe) for probe in PROBE_PATHS),
                f"{rule} is granted by the policy but no probe path covers it",
            )


class SealStatus(unittest.TestCase):
    """R-7 (T-216) — the seal type is reported, and Shamir is flagged.

    AXIAM cannot configure auto-unseal; what it can do is refuse to be silent
    about its absence. These tests pin the two properties that make the check
    worth having: every auto-unseal type reads as `OK`, and everything else —
    Shamir, an unknown type, an unreachable Vault — reads as something an
    operator has to look at.
    """

    @staticmethod
    def _markers(body):
        return [marker for marker, _ in seal_findings(body)]

    @staticmethod
    def _text(body):
        return " ".join(line for _, line in seal_findings(body))

    def test_every_auto_unseal_type_reports_ok(self):
        for seal_type in ("awskms", "gcpckms", "azurekeyvault", "transit", "pkcs11"):
            body = {"type": seal_type, "sealed": False, "initialized": True}
            self.assertIn("OK", self._markers(body), seal_type)
            self.assertTrue(seal_is_production_ready(body), seal_type)
            self.assertIn(seal_type, self._text(body))

    def test_shamir_is_flagged_with_its_quorum(self):
        body = {"type": "shamir", "sealed": False, "initialized": True, "t": 3, "n": 5}
        self.assertIn("SHAMIR", self._markers(body))
        self.assertFalse(seal_is_production_ready(body))
        text = self._text(body)
        # The numbers matter: "needs key shares" is advice, "needs 3 of 5"
        # is something an operator can plan a restart around.
        self.assertIn("3 of 5", text)
        self.assertIn("Not production", text)

    def test_shamir_without_a_quorum_still_says_what_is_wrong(self):
        # An older Vault, or a response without `t`/`n`. The finding must not
        # degrade into "OK" just because two numbers are missing.
        body = {"type": "shamir", "sealed": False, "initialized": True}
        self.assertIn("SHAMIR", self._markers(body))
        self.assertFalse(seal_is_production_ready(body))
        self.assertIn("quorum of key shares", self._text(body))

    def test_being_sealed_right_now_is_a_separate_line(self):
        # A state, not a policy problem — and it must not turn a correctly
        # configured auto-unseal Vault into a failure.
        body = {"type": "awskms", "sealed": True, "initialized": True}
        markers = self._markers(body)
        self.assertIn("OK", markers)
        self.assertIn("SEALED", markers)
        self.assertTrue(
            seal_is_production_ready(body),
            "a temporarily sealed Vault with auto-unseal is still correctly configured",
        )
        self.assertIn("state, not a policy problem", self._text(body))

    def test_a_failed_seal_status_request_reports_unknown_never_ok(self):
        # The whole point of the check. Reporting the absence of bad news as
        # good news is the failure mode it exists to remove.
        self.assertEqual(self._markers(None), ["unknown"])
        self.assertFalse(seal_is_production_ready(None))
        self.assertNotIn("OK", self._markers(None))
        self.assertIn("NOT confirmed", self._text(None))

    def test_an_unrecognised_seal_type_is_unknown_rather_than_ok(self):
        body = {"type": "something-new", "sealed": False, "initialized": True}
        self.assertIn("unknown", self._markers(body))
        self.assertFalse(seal_is_production_ready(body))

    def test_a_missing_type_is_unknown_rather_than_ok(self):
        for body in ({}, {"type": ""}, {"type": None}):
            self.assertIn("unknown", self._markers(body), body)
            self.assertFalse(seal_is_production_ready(body), body)

    def test_an_uninitialised_vault_says_so_before_naming_the_seal(self):
        body = {"type": "shamir", "sealed": True, "initialized": False, "t": 3, "n": 5}
        markers = self._markers(body)
        self.assertEqual(markers[0], "note", markers)
        self.assertIn("NOT INITIALIZED", self._text(body))

    def test_recovery_seal_is_noted_without_changing_the_verdict(self):
        body = {
            "type": "gcpckms",
            "sealed": False,
            "initialized": True,
            "recovery_seal": True,
        }
        self.assertIn("OK", self._markers(body))
        self.assertIn("note", self._markers(body))
        self.assertTrue(seal_is_production_ready(body))
        self.assertIn("recovery keys", self._text(body))


class SealReportRendering(unittest.TestCase):
    """The I/O half: `print_seal` must render every finding without raising."""

    def test_every_shape_renders(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "vault_status_cli",
            pathlib.Path(__file__).resolve().parent / "vault-status.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        import contextlib
        import io

        for body, expect_ready in (
            ({"type": "awskms", "sealed": False, "initialized": True}, True),
            ({"type": "shamir", "sealed": False, "initialized": True, "t": 3, "n": 5}, False),
            ({"type": "shamir", "sealed": True, "initialized": False}, False),
            (None, False),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ready = module.print_seal(body)
            self.assertEqual(ready, expect_ready, body)
            self.assertIn("seal (T-216)", buf.getvalue())
            # No line may run off a narrow terminal.
            for line in buf.getvalue().splitlines():
                self.assertLessEqual(len(line), 90, line)


if __name__ == "__main__":
    unittest.main()
