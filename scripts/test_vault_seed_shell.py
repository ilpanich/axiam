#!/usr/bin/env python3
"""End-to-end tests for `vault-seed.sh` against a fake Vault.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'

# Why these exist as well as `test_vault_seed_payload.py`

The payload builder was always correct, and always unit-tested: it has never
regenerated a secret it was told already existed. The seeder still rotated
every key on a live deployment, because the *shell* around it turned every
failed read into `{}` —

    EXISTING="$(curl --fail ... || echo '{}')"

— which the builder cannot tell apart from an empty Vault. A well-tested pure
function behind an untested boundary is exactly as safe as the boundary.

So these tests drive the real script, over real HTTP, against a Vault that
misbehaves in the ways a Vault actually misbehaves, and assert on **what was
written** rather than on an exit code. The scenario that matters most —
`test_a_standby_node_writes_nothing` — is the one that cost a running stack
every one of its keys and left every login answering

    Cryptography error: AES-GCM decrypt: aead::Error

`curl` and `bash` are the only requirements beyond the standard library.
"""

import json
import os
import shutil
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "vault-seed.sh"

#: What the fake Vault claims to be holding already. Distinguishable at a
#: glance from anything the seeder would mint, which is the whole assertion.
STORED = {
    "opaque_session_key": "11" * 32,
    "opaque_setup_key": "22" * 32,
    "mfa_encryption_key": "33" * 32,
    "federation_encryption_key": "44" * 32,
    "email_encryption_key": "55" * 32,
    "gdpr_pseudonym_pepper": "66" * 32,
    "pki_encryption_key": "77" * 32,
    "amqp_signing_key": "88" * 32,
    "auth_pepper": "the-existing-pepper",
    "jwt_private_key_pem": "EXISTING PRIVATE PEM",
    "jwt_public_key_pem": "EXISTING PUBLIC PEM",
}

STORED_VERSION = 7


class FakeVault:
    """A Vault that answers however a test needs it to.

    `read_status` is the status of `GET secret/data/axiam`; `health_statuses`
    is consumed one per probe, so a test can make the node come up standby and
    become active a moment later.
    """

    def __init__(self, read_status=200, health_statuses=None, write_status=200):
        self.read_status = read_status
        self.health_statuses = list(health_statuses or [])
        self.write_status = write_status
        self.writes = []
        self.health_probes = 0

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: D102 - quiet under test
                pass

            def _reply(self, code, body=None):
                raw = b"" if body is None else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if raw:
                    self.wfile.write(raw)

            def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
                if self.path == "/v1/sys/health":
                    outer.health_probes += 1
                    status = (
                        outer.health_statuses.pop(0) if outer.health_statuses else 200
                    )
                    return self._reply(status, {"initialized": True})
                if self.path == "/v1/sys/mounts/secret":
                    return self._reply(200, {"type": "kv"})
                if self.path == "/v1/secret/data/axiam":
                    return self._reply(outer.read_status, outer.read_body())
                return self._reply(404, {"errors": []})

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/v1/secret/data/axiam":
                    if outer.write_status == 200:
                        outer.writes.append(payload)
                        return self._reply(200, {"data": {"version": 8}})
                    return self._reply(
                        outer.write_status,
                        {"errors": ["check-and-set parameter did not match"]},
                    )
                return self._reply(204)

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def read_body(self):
        if self.read_status == 200:
            return {"data": {"data": STORED, "metadata": {"version": STORED_VERSION}}}
        if self.read_status == 404:
            return {"errors": []}
        return {"errors": ["something went wrong"]}

    @property
    def address(self):
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False


def run_seeder(vault, **env):
    environment = {
        **os.environ,
        "VAULT_ADDR": vault.address,
        "VAULT_TOKEN": "a-token",
        "VAULT_READY_TIMEOUT": "5",
        # Unset so the builder's "supplied keypair wins" branch stays out of
        # the way; tests that want it pass it explicitly.
        "JWT_PRIVATE_KEY_PEM": "",
        "JWT_PUBLIC_KEY_PEM": "",
        **env,
    }
    return subprocess.run(
        ["bash", str(SCRIPT)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )


@unittest.skipUnless(
    shutil.which("curl") and shutil.which("bash"), "needs curl and bash"
)
class ARefusedReadWritesNothing(unittest.TestCase):
    """No answer about the contents means no write. Ever."""

    def assert_nothing_written(self, vault, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(vault.writes, [], "the seeder wrote despite a refused read")

    def test_a_standby_node_writes_nothing(self):
        # THE regression. Raft-backed Vault answers `sys/unseal` while the node
        # is still a standby contending for leadership; every request in that
        # window gets this. `just prod-up` seeds immediately after unsealing,
        # so this is the state the seeder used to meet on every restart-driven
        # run — and it answered by minting a complete new set of keys and
        # writing them over the live ones.
        with FakeVault(read_status=500) as vault:
            result = run_seeder(vault)
        self.assert_nothing_written(vault, result)
        self.assertIn("500", result.stderr)

    def test_a_sealed_vault_writes_nothing(self):
        with FakeVault(read_status=503) as vault:
            result = run_seeder(vault)
        self.assert_nothing_written(vault, result)

    def test_a_revoked_or_underscoped_token_writes_nothing(self):
        # A credential with write but not read on the path is the deterministic
        # form of the same bug: the read fails, the write succeeds.
        with FakeVault(read_status=403) as vault:
            result = run_seeder(vault)
        self.assert_nothing_written(vault, result)

    def test_an_unreachable_vault_writes_nothing(self):
        with FakeVault() as vault:
            address = vault.address
        # The server is closed; curl reports 000 and there is nothing to write
        # to anyway. The assertion is that it fails fast rather than hanging or
        # claiming success.
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env={
                **os.environ,
                "VAULT_ADDR": address,
                "VAULT_TOKEN": "a-token",
                "VAULT_READY_TIMEOUT": "2",
            },
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(
    shutil.which("curl") and shutil.which("bash"), "needs curl and bash"
)
class AGoodReadPreservesEverything(unittest.TestCase):
    def test_existing_secrets_are_written_back_unchanged(self):
        with FakeVault(read_status=200) as vault:
            result = run_seeder(vault)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(vault.writes), 1)
        written = vault.writes[0]["data"]
        for name, value in STORED.items():
            with self.subTest(name=name):
                self.assertEqual(written[name], value)
        self.assertIn("nothing minted", result.stderr)

    def test_the_write_is_pinned_to_the_version_that_was_read(self):
        # Without `cas`, a read this script trusted can still be stale by the
        # time the write lands, and ten secrets go with it.
        with FakeVault(read_status=200) as vault:
            run_seeder(vault)
        self.assertEqual(vault.writes[0]["options"]["cas"], STORED_VERSION)

    def test_a_supplied_jwt_keypair_still_wins(self):
        # The one intended overwrite: `just prod-up` moving the pair it
        # generated on disk into Vault.
        with FakeVault(read_status=200) as vault:
            run_seeder(
                vault,
                JWT_PRIVATE_KEY_PEM="FROM DISK PRIV",
                JWT_PUBLIC_KEY_PEM="FROM DISK PUB",
            )
        written = vault.writes[0]["data"]
        self.assertEqual(written["jwt_private_key_pem"], "FROM DISK PRIV")
        # ...and it changes nothing else.
        self.assertEqual(written["opaque_setup_key"], STORED["opaque_setup_key"])


@unittest.skipUnless(
    shutil.which("curl") and shutil.which("bash"), "needs curl and bash"
)
class AFreshVaultIsSeeded(unittest.TestCase):
    def test_a_missing_path_mints_a_full_set(self):
        with FakeVault(read_status=404) as vault:
            result = run_seeder(vault)
        self.assertEqual(result.returncode, 0, result.stderr)
        written = vault.writes[0]["data"]
        self.assertEqual(len(written["opaque_setup_key"]), 64)
        self.assertNotEqual(written["opaque_setup_key"], STORED["opaque_setup_key"])

    def test_a_missing_path_is_created_rather_than_overwritten(self):
        # cas 0 is "create, and fail if anything is already there" — so even a
        # 404 that was wrong about the contents cannot destroy them.
        with FakeVault(read_status=404) as vault:
            run_seeder(vault)
        self.assertEqual(vault.writes[0]["options"]["cas"], 0)


@unittest.skipUnless(
    shutil.which("curl") and shutil.which("bash"), "needs curl and bash"
)
class ItWaitsForAnActiveNode(unittest.TestCase):
    def test_a_sealed_then_active_vault_is_waited_out(self):
        # `sys/health`: 503 sealed, 429 unsealed-but-standby, 200 active. The
        # seeder proceeds only on 200, which is what makes seeding immediately
        # after `sys/unseal` safe.
        with FakeVault(health_statuses=[503, 429, 200]) as vault:
            result = run_seeder(vault)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(vault.health_probes, 3)
        self.assertEqual(len(vault.writes), 1)

    def test_a_vault_that_never_becomes_active_writes_nothing(self):
        with FakeVault(health_statuses=[503] * 100) as vault:
            result = run_seeder(vault)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(vault.writes, [])
        self.assertIn("sealed", result.stderr)


@unittest.skipUnless(
    shutil.which("curl") and shutil.which("bash"), "needs curl and bash"
)
class AConflictingWriteIsReported(unittest.TestCase):
    def test_a_cas_mismatch_fails_loudly(self):
        # Vault refused the write because something changed underneath. The
        # seeder must not retry blindly, and must not report success.
        with FakeVault(read_status=200, write_status=400) as vault:
            result = run_seeder(vault)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("check-and-set", result.stderr)
        self.assertNotIn("Seeded", result.stdout)


if __name__ == "__main__":
    unittest.main()
