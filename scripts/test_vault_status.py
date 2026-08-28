#!/usr/bin/env python3
"""Tests for the Vault status reporter, notably the T-180 token-scope check.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import unittest

from vault_status_report import (
    EXPECTED,
    is_over_scoped,
    is_root,
    read_capabilities,
    scope_findings,
    secret_presence,
    unexpected_fields,
)


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


if __name__ == "__main__":
    unittest.main()
