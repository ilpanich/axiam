#!/usr/bin/env python3
"""Report which AXIAM secrets a Vault path holds, without printing any of them.

Reads a Vault KV v2 read response on stdin. Deliberately prints only presence:
a `just` recipe's output ends up in scrollback, CI logs and screenshots, and
none of those are places for the OPAQUE setup key.
"""

import json
import sys

# Mirrors `axiam_core::secrets`. A name here that the server does not know is
# harmless; a name the server needs and Vault lacks is what this is for.
EXPECTED = [
    "opaque_session_key",
    "opaque_setup_key",
    "mfa_encryption_key",
    "federation_encryption_key",
    "email_encryption_key",
    "gdpr_pseudonym_pepper",
    "pki_encryption_key",
    "amqp_signing_key",
    "auth_pepper",
    "jwt_private_key_pem",
    "jwt_public_key_pem",
]


def main() -> int:
    try:
        body = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("could not parse Vault's response — is it sealed?", file=sys.stderr)
        return 1

    fields = (body.get("data") or {}).get("data") or {}
    missing = []
    for name in EXPECTED:
        present = bool(fields.get(name))
        print(f"  {'set  ' if present else 'MISSING'}  {name}")
        if not present:
            missing.append(name)

    extra = sorted(set(fields) - set(EXPECTED))
    if extra:
        print(f"\n  also present (not read by AXIAM): {', '.join(extra)}")

    if missing:
        print(
            f"\n{len(missing)} secret(s) missing — run `just vault-seed` to mint them "
            "(or `just vault-up` for the dev-mode Vault)."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
