#!/usr/bin/env python3
"""Tests for the Vault seeding payload builder.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import unittest

from vault_seed_payload import KEY_NAMES, PEM_NAMES, build


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


if __name__ == "__main__":
    unittest.main()
