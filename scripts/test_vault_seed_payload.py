#!/usr/bin/env python3
"""Tests for the Vault seeding payload builder.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import unittest

from vault_seed_payload import KEY_NAMES, build


class PreservesExistingSecrets(unittest.TestCase):
    """The property that makes re-running the seeder safe."""

    def test_an_existing_key_is_never_regenerated(self):
        # Regenerating opaque_setup_key would require a password reset for
        # every user in every tenant.
        existing = {name: f"existing-{name}" for name in KEY_NAMES}
        out, minted = build(existing, {})
        for name in KEY_NAMES:
            self.assertEqual(out[name], f"existing-{name}")
        self.assertNotIn("opaque_setup_key", minted)

    def test_an_existing_pepper_is_never_regenerated(self):
        # Regenerating it invalidates every stored password hash.
        out, minted = build({"auth_pepper": "keep-me"}, {})
        self.assertEqual(out["auth_pepper"], "keep-me")
        self.assertNotIn("auth_pepper", minted)

    def test_seeding_twice_is_a_no_op(self):
        first, _ = build({}, {})
        second, minted = build(first, {})
        self.assertEqual(first, second)
        self.assertEqual(minted, [])

    def test_only_the_missing_key_is_minted(self):
        existing = {name: "v" for name in KEY_NAMES if name != "pki_encryption_key"}
        existing["auth_pepper"] = "v"
        _, minted = build(existing, {})
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
    def test_supplied_keys_are_stored(self):
        env = {"JWT_PRIVATE_KEY_PEM": "PRIV", "JWT_PUBLIC_KEY_PEM": "PUB"}
        out, minted = build({}, env)
        self.assertEqual(out["jwt_private_key_pem"], "PRIV")
        self.assertEqual(out["jwt_public_key_pem"], "PUB")
        self.assertIn("jwt_private_key_pem", minted)

    def test_supplied_keys_override_stored_ones(self):
        # This is how `just prod-up` moves an on-disk keypair into Vault. It is
        # the one intended overwrite in the whole builder.
        out, _ = build({"jwt_private_key_pem": "OLD"}, {"JWT_PRIVATE_KEY_PEM": "NEW"})
        self.assertEqual(out["jwt_private_key_pem"], "NEW")

    def test_stored_keys_survive_when_the_caller_has_none(self):
        out, minted = build({"jwt_private_key_pem": "KEEP"}, {})
        self.assertEqual(out["jwt_private_key_pem"], "KEEP")
        self.assertNotIn("jwt_private_key_pem", minted)

    def test_absent_everywhere_means_absent_from_the_payload(self):
        # Writing an empty string would look "set" to `vault-status` and to the
        # server, which would then fail to parse it.
        out, _ = build({}, {})
        self.assertNotIn("jwt_private_key_pem", out)

    def test_an_empty_env_value_is_not_treated_as_supplied(self):
        out, _ = build({"jwt_private_key_pem": "KEEP"}, {"JWT_PRIVATE_KEY_PEM": ""})
        self.assertEqual(out["jwt_private_key_pem"], "KEEP")


if __name__ == "__main__":
    unittest.main()
