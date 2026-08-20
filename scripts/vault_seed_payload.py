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
]

#: Text secrets, which are not keys. The pepper is concatenated with a password
#: before Argon2id; the JWT keys are PEM documents.
PEM_NAMES = ["jwt_private_key_pem", "jwt_public_key_pem"]


def build(existing_fields, env):
    """Return `(fields, minted_names)`.

    `existing_fields` is the `data.data` object of a KV v2 read, or `{}`.
    `env` supplies `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM` when the caller
    has them on disk.
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

    for name in PEM_NAMES:
        supplied = env.get(name.upper())
        if supplied:
            # A caller that explicitly hands us a keypair wins: this is how
            # `just prod-up` moves the JWT keys it generated on disk into
            # Vault. Overwriting is intended here and nowhere else.
            if not existing_fields.get(name):
                minted.append(name)
            out[name] = supplied
        elif existing_fields.get(name):
            out[name] = existing_fields[name]

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
