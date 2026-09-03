#!/usr/bin/env python3
"""Tests for the Vault seeding payload builder.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import contextlib
import io
import json
import os
import unittest
from unittest import mock

from vault_seed_payload import (
    KEY_NAMES,
    PEM_NAMES,
    SeedAbort,
    assert_preserved,
    build,
    interpret_read,
    main,
)


class PreservesExistingSecrets(unittest.TestCase):
    """The property that makes re-running the seeder safe."""

    def test_an_existing_key_is_never_regenerated(self):
        # Regenerating opaque_setup_key would require a password reset for
        # every user in every tenant.
        existing = {name: f"existing-{name}" for name in KEY_NAMES}
        out, minted = build(existing, {}, keygen=lambda: ("p", "u"))
        for name in KEY_NAMES:
            self.assertEqual(out[name], f"existing-{name}")
        self.assertNotIn("opaque_setup_key", minted)

    def test_an_existing_pepper_is_never_regenerated(self):
        # Regenerating it invalidates every stored password hash.
        out, minted = build({"auth_pepper": "keep-me"}, {}, keygen=lambda: ("p", "u"))
        self.assertEqual(out["auth_pepper"], "keep-me")
        self.assertNotIn("auth_pepper", minted)

    def test_seeding_twice_is_a_no_op(self):
        first, _ = build({}, {}, keygen=lambda: ("p", "u"))
        second, minted = build(first, {}, keygen=lambda: ("p", "u"))
        self.assertEqual(first, second)
        self.assertEqual(minted, [])

    def test_only_the_missing_key_is_minted(self):
        existing = {name: "v" for name in KEY_NAMES if name != "pki_encryption_key"}
        existing["auth_pepper"] = "v"
        existing["jwt_private_key_pem"] = "v"
        existing["jwt_public_key_pem"] = "v"
        _, minted = build(existing, {}, keygen=lambda: ("p", "u"))
        self.assertEqual(minted, ["pki_encryption_key"])


class MintsWhatIsAbsent(unittest.TestCase):
    def test_every_key_is_minted_on_an_empty_vault(self):
        out, minted = build({}, {})
        for name in KEY_NAMES:
            self.assertIn(name, out)
            self.assertIn(name, minted)

    def test_keys_are_32_bytes_of_hex(self):
        # The server refuses anything else, and it should fail here rather than
        # at the operator's next startup.
        out, _ = build({}, {})
        for name in KEY_NAMES:
            self.assertEqual(len(out[name]), 64, name)
            int(out[name], 16)  # raises if it is not hex

    def test_each_key_is_distinct(self):
        # A loop bug that reused one value would be invisible in the output and
        # would collapse several independent blast radii into one.
        out, _ = build({}, {})
        values = [out[name] for name in KEY_NAMES]
        self.assertEqual(len(set(values)), len(values))

    def test_two_runs_against_an_empty_vault_differ(self):
        # i.e. it is actually random, not seeded.
        self.assertNotEqual(build({}, {})[0], build({}, {})[0])


class JwtKeysComeFromTheCaller(unittest.TestCase):
    """Precedence when the caller supplies a keypair.

    The "absent everywhere" case used to mean "leave it out of the payload".
    It now means "mint one" — see `MintsTheJwtKeypair` — because leaving it out
    produced a Vault that looked seeded and a server that would not start.
    """

    KEYGEN = staticmethod(lambda: ("MINTED-PRIV", "MINTED-PUB"))

    def test_supplied_keys_are_stored(self):
        env = {"JWT_PRIVATE_KEY_PEM": "PRIV", "JWT_PUBLIC_KEY_PEM": "PUB"}
        out, minted = build({}, env, keygen=self.KEYGEN)
        self.assertEqual(out["jwt_private_key_pem"], "PRIV")
        self.assertEqual(out["jwt_public_key_pem"], "PUB")
        self.assertIn("jwt_private_key_pem", minted)

    def test_supplied_keys_override_stored_ones(self):
        # This is how `just prod-up` moves an on-disk keypair into Vault. It is
        # the one intended overwrite in the whole builder.
        out, _ = build(
            {"jwt_private_key_pem": "OLD"}, {"JWT_PRIVATE_KEY_PEM": "NEW"}, keygen=self.KEYGEN
        )
        self.assertEqual(out["jwt_private_key_pem"], "NEW")

    def test_a_complete_stored_pair_survives_when_the_caller_has_none(self):
        existing = {"jwt_private_key_pem": "KEEP", "jwt_public_key_pem": "KEEP-PUB"}
        out, minted = build(existing, {}, keygen=self.KEYGEN)
        self.assertEqual(out["jwt_private_key_pem"], "KEEP")
        self.assertNotIn("jwt_private_key_pem", minted)

    def test_absent_everywhere_now_mints_rather_than_omitting(self):
        # The old behaviour omitted the field. That wrote a Vault which
        # `vault-status` reported as seeded and which the server then refused
        # to start against, complaining about PEM parsing rather than about a
        # secret nobody had set.
        out, minted = build({}, {}, keygen=self.KEYGEN)
        self.assertEqual(out["jwt_private_key_pem"], "MINTED-PRIV")
        self.assertIn("jwt_private_key_pem", minted)

    def test_an_empty_env_value_is_not_treated_as_supplied(self):
        existing = {"jwt_private_key_pem": "KEEP", "jwt_public_key_pem": "KEEP-PUB"}
        out, _ = build(existing, {"JWT_PRIVATE_KEY_PEM": ""}, keygen=self.KEYGEN)
        self.assertEqual(out["jwt_private_key_pem"], "KEEP")


class MintsTheJwtKeypair(unittest.TestCase):
    """The gap that made a fresh Vault unusable without `just prod-up`."""

    def keygen(self):
        self.generated = getattr(self, "generated", 0) + 1
        return ("PRIV-PEM", "PUB-PEM")

    def test_an_empty_vault_gets_a_freshly_minted_keypair(self):
        # Before this, a fresh Vault came up with no signing key at all unless
        # the caller happened to export one, and the server failed to start
        # with an error about PEM parsing rather than about a missing secret.
        out, minted = build({}, {}, keygen=self.keygen)
        self.assertEqual(out["jwt_private_key_pem"], "PRIV-PEM")
        self.assertEqual(out["jwt_public_key_pem"], "PUB-PEM")
        self.assertIn("jwt_private_key_pem", minted)
        self.assertIn("jwt_public_key_pem", minted)

    def test_an_existing_keypair_is_never_regenerated(self):
        # Regenerating it invalidates every token AXIAM has issued.
        existing = {"jwt_private_key_pem": "keep-priv", "jwt_public_key_pem": "keep-pub"}
        out, minted = build(existing, {}, keygen=self.keygen)
        self.assertEqual(out["jwt_private_key_pem"], "keep-priv")
        self.assertEqual(out["jwt_public_key_pem"], "keep-pub")
        self.assertNotIn("jwt_private_key_pem", minted)
        self.assertEqual(getattr(self, "generated", 0), 0)

    def test_a_supplied_keypair_still_wins(self):
        # `just prod-up` moves a keypair it generated on disk into Vault.
        env = {"JWT_PRIVATE_KEY_PEM": "from-disk", "JWT_PUBLIC_KEY_PEM": "from-disk-pub"}
        out, _ = build({}, env, keygen=self.keygen)
        self.assertEqual(out["jwt_private_key_pem"], "from-disk")
        self.assertEqual(getattr(self, "generated", 0), 0)

    def test_a_supplied_keypair_overrides_an_existing_one(self):
        existing = {"jwt_private_key_pem": "old", "jwt_public_key_pem": "old-pub"}
        env = {"JWT_PRIVATE_KEY_PEM": "new", "JWT_PUBLIC_KEY_PEM": "new-pub"}
        out, _ = build(existing, env, keygen=self.keygen)
        self.assertEqual(out["jwt_private_key_pem"], "new")

    def test_half_a_pair_in_vault_is_replaced_wholesale(self):
        # A private key from one pair beside a public key from another verifies
        # nothing. Half a pair is worse than none, because it looks configured.
        out, minted = build({"jwt_private_key_pem": "lonely"}, {}, keygen=self.keygen)
        self.assertEqual(out["jwt_private_key_pem"], "PRIV-PEM")
        self.assertEqual(out["jwt_public_key_pem"], "PUB-PEM")
        self.assertEqual(sorted(n for n in minted if n in PEM_NAMES), sorted(PEM_NAMES))

    def test_seeding_twice_still_mints_nothing_the_second_time(self):
        first, _ = build({}, {}, keygen=self.keygen)
        second, minted = build(first, {}, keygen=self.keygen)
        self.assertEqual(first, second)
        self.assertEqual(minted, [])


class CoversEverySecretTheServerReads(unittest.TestCase):
    """The seeder and `axiam_core::secrets` must not drift apart."""

    def test_the_amqp_signing_key_is_seeded(self):
        # Mandatory in a release build — there is no unsigned AMQP path — and
        # it was the one secret with no provider route at all.
        self.assertIn("amqp_signing_key", KEY_NAMES)
        out, _ = build({}, {}, keygen=lambda: ("p", "u"))
        self.assertEqual(len(out["amqp_signing_key"]), 64)

    def test_every_key_is_256_bits_of_hex(self):
        out, _ = build({}, {}, keygen=lambda: ("p", "u"))
        for name in KEY_NAMES:
            with self.subTest(name=name):
                self.assertEqual(len(out[name]), 64)
                bytes.fromhex(out[name])

    def test_two_runs_never_produce_the_same_key(self):
        # A seeder that produced a deterministic key would be catastrophic and
        # would look exactly like a working one.
        a, _ = build({}, {}, keygen=lambda: ("p", "u"))
        b, _ = build({}, {}, keygen=lambda: ("p", "u"))
        for name in KEY_NAMES:
            with self.subTest(name=name):
                self.assertNotEqual(a[name], b[name])
        self.assertNotEqual(a["auth_pepper"], b["auth_pepper"])


class ARefusedReadIsNeverAnEmptyVault(unittest.TestCase):
    """The regression that cost a live deployment every one of its keys.

    `build()` cannot tell "the Vault is empty" from "the read failed" — both
    arrive as `{}` — so the distinction has to be made before it is called. It
    used to be made by `curl --fail || echo '{}'`, which is to say not at all:
    a Vault that answered 500 because it had been unsealed a moment earlier and
    had not yet taken leadership produced a full set of freshly minted keys, a
    successful write over the real ones, and a `→ Seeded` on the way out. The
    only symptom was every login answering, from then on,

        Cryptography error: AES-GCM decrypt: aead::Error
    """

    OK_BODY = json.dumps(
        {"data": {"data": {"opaque_setup_key": "keep"}, "metadata": {"version": 7}}}
    )

    def test_a_populated_read_is_preserved_and_pinned_to_its_version(self):
        fields, cas = interpret_read(200, self.OK_BODY)
        self.assertEqual(fields, {"opaque_setup_key": "keep"})
        self.assertEqual(cas, 7)

    def test_a_standby_node_aborts_rather_than_minting(self):
        # HTTP 500 "local node not active but active cluster node not found" —
        # what Raft-backed Vault answers between `sys/unseal` returning and the
        # node winning leadership, which is exactly where `just prod-up` used
        # to seed.
        with self.assertRaises(SeedAbort):
            interpret_read(500, '{"errors":["local node not active"]}')

    def test_a_sealed_vault_aborts_rather_than_minting(self):
        with self.assertRaises(SeedAbort):
            interpret_read(503, '{"errors":["Vault is sealed"]}')

    def test_a_revoked_or_underscoped_token_aborts_rather_than_minting(self):
        # A token with write but not read on the path is the deterministic
        # version of this bug: the read fails, the write succeeds.
        with self.assertRaises(SeedAbort):
            interpret_read(403, '{"errors":["permission denied"]}')

    def test_no_answer_at_all_aborts_rather_than_minting(self):
        # curl reports `000` for a connection refused or a TLS trust failure.
        with self.assertRaises(SeedAbort):
            interpret_read(0, "")

    def test_a_body_that_is_not_json_aborts(self):
        with self.assertRaises(SeedAbort):
            interpret_read(200, "<html>proxy error</html>")

    def test_a_200_without_a_data_object_aborts(self):
        with self.assertRaises(SeedAbort):
            interpret_read(200, '{"data":{"metadata":{"version":1}}}')

    def test_a_200_without_a_version_aborts(self):
        # Without it the write cannot be pinned, and an unpinned write is how
        # secrets get overwritten.
        with self.assertRaises(SeedAbort):
            interpret_read(200, '{"data":{"data":{},"metadata":{}}}')

    def test_the_abort_message_names_the_status(self):
        with self.assertRaises(SeedAbort) as caught:
            interpret_read(503, "{}")
        self.assertIn("503", str(caught.exception))


class AFourOhFourIsAPositiveStatement(unittest.TestCase):
    """404 is the one failure status that *is* about the contents."""

    def test_a_path_that_never_existed_is_created_with_cas_zero(self):
        fields, cas = interpret_read(404, '{"errors":[]}')
        self.assertEqual(fields, {})
        # cas 0 means "create, and fail if anything is already there".
        self.assertEqual(cas, 0)

    def test_a_deleted_latest_version_builds_on_the_version_it_left(self):
        body = json.dumps(
            {"data": {"data": None, "metadata": {"version": 4, "deletion_time": "now"}}}
        )
        fields, cas = interpret_read(404, body)
        self.assertEqual(fields, {})
        self.assertEqual(cas, 4)

    def test_an_empty_body_is_tolerated(self):
        self.assertEqual(interpret_read(404, ""), ({}, 0))


class TheWriteIsPinnedToTheReadThroughMain(unittest.TestCase):
    """`main()` is what `vault-seed.sh` actually calls."""

    def _run(self, status, body, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=False):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["--http-status", str(status), body])
        return code, out.getvalue(), err.getvalue()

    def test_a_good_read_emits_a_cas_pinned_payload(self):
        body = json.dumps(
            {"data": {"data": {"opaque_setup_key": "keep"}, "metadata": {"version": 3}}}
        )
        code, stdout, _ = self._run(200, body)
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["options"]["cas"], 3)
        self.assertEqual(payload["data"]["opaque_setup_key"], "keep")

    def test_a_refused_read_exits_non_zero_and_emits_no_payload(self):
        # `vault-seed.sh` runs under `set -e`, so a non-zero exit here is what
        # stops the write from happening at all.
        code, stdout, stderr = self._run(503, '{"errors":["Vault is sealed"]}')
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("503", stderr)

    def test_replacing_half_a_stored_jwt_pair_is_still_allowed(self):
        # `build()` replaces an incomplete pair wholesale on purpose, so the
        # clobber guard must not mistake it for the accident it exists to catch.
        body = json.dumps(
            {
                "data": {
                    "data": {"opaque_setup_key": "keep", "jwt_private_key_pem": "lonely"},
                    "metadata": {"version": 1},
                }
            }
        )
        code, stdout, _ = self._run(200, body)
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertNotEqual(payload["data"]["jwt_private_key_pem"], "lonely")
        self.assertEqual(payload["data"]["opaque_setup_key"], "keep")

    def test_a_complete_stored_jwt_pair_is_protected_when_none_is_supplied(self):
        # Nothing should replace it, and the guard is armed in case something
        # one day tries to.
        body = json.dumps(
            {
                "data": {
                    "data": {
                        "jwt_private_key_pem": "keep-priv",
                        "jwt_public_key_pem": "keep-pub",
                    },
                    "metadata": {"version": 1},
                }
            }
        )
        code, stdout, _ = self._run(200, body, env={"JWT_PRIVATE_KEY_PEM": "", "JWT_PUBLIC_KEY_PEM": ""})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["data"]["jwt_private_key_pem"], "keep-priv")


class NothingAlreadyThereIsEverReplaced(unittest.TestCase):
    """Belt and braces over `build()`, checked on the operator's machine."""

    def test_an_untouched_payload_passes(self):
        existing = {"opaque_setup_key": "keep"}
        assert_preserved(existing, {"opaque_setup_key": "keep", "mfa_encryption_key": "new"})

    def test_a_replaced_secret_is_refused(self):
        with self.assertRaises(SeedAbort) as caught:
            assert_preserved({"opaque_setup_key": "keep"}, {"opaque_setup_key": "clobbered"})
        self.assertIn("opaque_setup_key", str(caught.exception))

    def test_a_deliberately_supplied_jwt_key_is_allowed_through(self):
        # The one intended overwrite: `just prod-up` moving an on-disk keypair
        # into Vault.
        assert_preserved(
            {"jwt_private_key_pem": "old"},
            {"jwt_private_key_pem": "from-disk"},
            overwritable=("jwt_private_key_pem",),
        )


if __name__ == "__main__":
    unittest.main()
