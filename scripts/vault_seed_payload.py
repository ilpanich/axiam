#!/usr/bin/env python3
"""Build the KV v2 payload that seeds AXIAM's secrets, preserving what exists.

Split out of `vault-seed.sh` so it can be tested. The shell script does I/O —
talking to Vault — and this does the one decision that carries real risk.

# The rule this exists to enforce

**A secret already present is never regenerated.** That is not politeness:

- Regenerating `opaque_setup_key` makes every OPAQUE registration record in
  every tenant unopenable, requiring a password reset for every user.
- Regenerating `auth_pepper` invalidates every stored password hash.
- Regenerating `pki_encryption_key` makes every stored CA private key
  undecryptable.
- Regenerating `gdpr_pseudonym_pepper` breaks the link between existing audit
  pseudonyms and future ones.

Re-running the seeder is something an operator will do — after adding a key,
after a restore, by accident. It must be safe.

# Why the read is interpreted here too

`build()` only preserves what it is *told* exists, so the guarantee above is
worth exactly as much as the read that feeds it. The shell used to collapse
every failed read — a sealed or standby Vault, a revoked token, a TLS error, a
truncated body — into `{}`, which `build()` cannot tell apart from an empty
Vault and answers by minting a full set of new keys. A read that fails and a
write that then succeeds is all it takes to rotate `opaque_setup_key` under a
live datastore, and the only symptom is every login answering

    Cryptography error: AES-GCM decrypt: aead::Error

[`interpret_read`] therefore lives here, next to the rule it protects: only an
HTTP 200 (or a 404, which is Vault stating positively that the path holds
nothing) may reach `build()`. Anything else aborts without writing.

The version it returns is sent back as KV v2's `cas`, so even a correct read
followed by somebody else's write cannot be overwritten blindly.
"""

import argparse
import json
import os
import secrets
import subprocess
import sys

#: 256-bit keys, hex-encoded. Names match `axiam_core::secrets`' constants
#: exactly; that mapping is the entire interface between this and the server.
KEY_NAMES = [
    "opaque_session_key",
    "opaque_setup_key",
    "mfa_encryption_key",
    "federation_encryption_key",
    "email_encryption_key",
    "gdpr_pseudonym_pepper",
    "pki_encryption_key",
    "amqp_signing_key",
]

#: Text secrets, which are not keys. The pepper is concatenated with a password
#: before Argon2id; the JWT keys are PEM documents.
PEM_NAMES = ["jwt_private_key_pem", "jwt_public_key_pem"]


def generate_ed25519_keypair():
    """Mint an Ed25519 keypair, PEM-encoded, as `(private, public)`.

    Shells out to `openssl` rather than importing `cryptography`, for two
    reasons. This script runs on operator machines during deployment, where
    "pip install" is a worse ask than "you already have openssl" — and openssl
    is already a hard requirement of `gen-broker-tls.sh`, `gen-vault-tls.sh`
    and the `run-local` recipe, so it adds no new dependency.

    The key never touches disk: openssl writes the private PEM to stdout and
    reads it back from stdin to derive the public half. `just prod-up` writes
    its keypair to `docker/.secrets/` because a Compose stack has to mount it;
    a Vault-backed deployment has no such need, and not creating the file is
    strictly better than creating one and remembering to protect it.
    """
    private = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    public = subprocess.run(
        ["openssl", "pkey", "-pubout"],
        input=private.encode(),
        capture_output=True,
        check=True,
    ).stdout.decode()
    return private, public


def build(existing_fields, env, keygen=generate_ed25519_keypair):
    """Return `(fields, minted_names)`.

    `existing_fields` is the `data.data` object of a KV v2 read, or `{}`.
    `env` supplies `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM` when the caller
    has them on disk. `keygen` is injectable so the tests need no `openssl`.
    """
    out, minted = {}, []

    for name in KEY_NAMES:
        if existing_fields.get(name):
            out[name] = existing_fields[name]
        else:
            out[name] = secrets.token_hex(32)
            minted.append(name)

    if existing_fields.get("auth_pepper"):
        out["auth_pepper"] = existing_fields["auth_pepper"]
    else:
        # URL-safe rather than hex: it is text prepended to a password, so
        # there is no reason to constrain it to an even number of hex nibbles.
        out["auth_pepper"] = secrets.token_urlsafe(48)
        minted.append("auth_pepper")

    # The JWT keypair, in precedence order: an explicitly supplied pair wins,
    # then whatever Vault already holds, and only a genuinely empty slot is
    # minted.
    supplied = {name: env.get(name.upper()) for name in PEM_NAMES}
    if any(supplied.values()):
        # A caller that explicitly hands us a keypair wins: this is how
        # `just prod-up` moves the JWT keys it generated on disk into Vault.
        # Overwriting is intended here and nowhere else.
        for name in PEM_NAMES:
            if supplied[name]:
                if not existing_fields.get(name):
                    minted.append(name)
                out[name] = supplied[name]
            elif existing_fields.get(name):
                out[name] = existing_fields[name]
    elif all(existing_fields.get(name) for name in PEM_NAMES):
        for name in PEM_NAMES:
            out[name] = existing_fields[name]
    else:
        # Neither supplied nor present: mint one. Both halves are replaced
        # together — a private key from one pair beside a public key from
        # another verifies nothing, and half a pair in Vault is a worse state
        # than none, because it looks configured.
        private, public = keygen()
        out["jwt_private_key_pem"] = private
        out["jwt_public_key_pem"] = public
        minted.extend(PEM_NAMES)

    return out, minted


class SeedAbort(Exception):
    """The read cannot be trusted, so nothing may be written.

    Raised instead of falling back to an empty view of the Vault. Every
    instance of this is a case where minting would be indistinguishable from
    seeding a fresh deployment, and would silently rotate keys under a live
    datastore.
    """


def interpret_read(http_status, body_text):
    """Turn a KV v2 read into `(existing_fields, cas_version)`.

    `http_status` is the numeric status of `GET <mount>/data/<path>`; `0` is
    the conventional "the request never got an answer" (curl's `%{http_code}`
    for a connection or TLS failure).

    Only two statuses are a statement about the *contents* of the path:

    - **200** — the path holds data. The fields are preserved and the write is
      pinned to the version that was read.
    - **404** — Vault is telling us positively that there is nothing to read.
      For a path that never existed there is no metadata and the write is
      pinned to version 0 ("create only"); for one whose latest version was
      deleted, the metadata still carries the version to build on.

    Everything else — 403 from a revoked or under-scoped token, 503 from a
    sealed Vault, 500 from a node that has been unsealed but has not yet become
    active, 0 from a TLS failure — says nothing about the contents, and is
    raised as [`SeedAbort`].
    """
    if http_status not in (200, 404):
        raise SeedAbort(
            f"Vault answered HTTP {http_status or '(no response)'} to the read of "
            "the existing secret. That is not a statement that the path is "
            "empty, so seeding would mint a fresh set of keys over whatever is "
            "actually there — refusing.\n"
            "  503 = sealed, 500 = unsealed but not yet the active node, "
            "403 = the token is revoked or lacks read on this path, "
            "(no response) = the address or the CA bundle is wrong."
        )

    try:
        body = json.loads(body_text or "{}")
    except json.JSONDecodeError as exc:
        raise SeedAbort(
            f"Vault's reply to the read was not JSON ({exc}). Refusing to treat "
            "an unreadable answer as an empty Vault."
        ) from exc

    data = body.get("data") or {}
    metadata = data.get("metadata") or {}
    version = metadata.get("version")

    if http_status == 404:
        # No data either way; the version, when present, is what a deleted
        # latest version leaves behind and is what `cas` must build on.
        return {}, int(version) if isinstance(version, int) else 0

    fields = data.get("data")
    if not isinstance(fields, dict):
        raise SeedAbort(
            "Vault answered 200 but the reply carried no `data.data` object. "
            "Refusing to treat a shape we do not recognise as an empty Vault."
        )
    if not isinstance(version, int):
        raise SeedAbort(
            "Vault answered 200 but the reply carried no `data.metadata.version`. "
            "Without it the write cannot be pinned to the version that was read, "
            "and an unpinned write is how secrets get overwritten."
        )
    return fields, version


def assert_preserved(existing_fields, out, overwritable=()):
    """Fail loudly if `build()` replaced a value that was already there.

    Belt and braces over the property the unit tests already assert: it costs
    nothing, and it runs on the operator's machine rather than in CI, which is
    where an accident would actually be paid for. `overwritable` names the
    fields whose replacement the caller has decided is intended — only ever the
    JWT pair, and only in the two cases `main` documents.
    """
    clobbered = [
        name
        for name, value in existing_fields.items()
        if value and name not in overwritable and name in out and out[name] != value
    ]
    if clobbered:
        raise SeedAbort(
            "Refusing to write: the payload would replace secrets that already "
            "exist in Vault — " + ", ".join(sorted(clobbered)) + ". This is a bug "
            "in the seeder, not an operator error; nothing has been written."
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the KV v2 payload that seeds AXIAM's secrets.",
    )
    parser.add_argument(
        "--http-status",
        type=int,
        required=True,
        help="numeric status of the GET that produced BODY (0 = no response)",
    )
    parser.add_argument(
        "body",
        nargs="?",
        default="",
        help="raw body of the KV v2 read",
    )
    args = parser.parse_args(argv)

    try:
        fields, cas = interpret_read(args.http_status, args.body)
    except SeedAbort as exc:
        sys.stderr.write(f"✗ {exc}\n")
        return 1

    out, minted = build(fields, os.environ)

    # The JWT pair has two documented, intended replacement paths — a keypair
    # supplied by the caller (how `just prod-up` moves the one it generated on
    # disk into Vault), and a stored pair that is only half there, which is
    # replaced wholesale because a private key from one pair beside a public key
    # from another verifies nothing. Everything else — the eight keys and the
    # pepper — has no such path, and a payload that would replace one is a bug
    # in this file rather than an operator error.
    supplied = any(os.environ.get(name.upper()) for name in PEM_NAMES)
    stored_pair_complete = all(fields.get(name) for name in PEM_NAMES)
    overwritable = PEM_NAMES if (supplied or not stored_pair_complete) else ()

    try:
        assert_preserved(fields, out, overwritable=overwritable)
    except SeedAbort as exc:
        sys.stderr.write(f"✗ {exc}\n")
        return 1

    # `cas` makes the write conditional on the version that was read: 0 creates
    # the path and fails if it exists, N updates it and fails if anything wrote
    # in between. A read this script trusted can still be stale by the time the
    # write lands, and a blind overwrite of ten secrets is not something to
    # leave to timing.
    print(json.dumps({"options": {"cas": cas}, "data": out}))
    sys.stderr.write(
        "→ Minting: " + ", ".join(minted) + "\n"
        if minted
        else "→ All secrets already present; nothing minted\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
