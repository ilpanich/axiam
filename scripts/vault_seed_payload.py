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
"""

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


def main() -> int:
    raw = sys.argv[1] if len(sys.argv) > 1 else "{}"
    try:
        existing = json.loads(raw or "{}")
    except json.JSONDecodeError:
        existing = {}
    fields = (existing.get("data") or {}).get("data") or {}

    out, minted = build(fields, os.environ)
    print(json.dumps({"data": out}))
    sys.stderr.write(
        "→ Minting: " + ", ".join(minted) + "\n"
        if minted
        else "→ All secrets already present; nothing minted\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
