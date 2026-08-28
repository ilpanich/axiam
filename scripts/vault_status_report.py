#!/usr/bin/env python3
"""Pure reporting logic behind `vault-status.py`, split out so it can be tested.

`vault-status.py` does the I/O (stdin, files, exit codes); everything that
decides *what to say* lives here, mirroring the `vault-seed.sh` /
`vault_seed_payload.py` split.
"""

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

# Everything AXIAM's runtime token is supposed to be able to do. The server only
# ever GETs its secret: it never writes one, never lists the mount, and never
# needs `sudo`. `deny` is not over-scope — it is strictly less than read.
ALLOWED_CAPABILITIES = frozenset({"read", "deny"})

# `root` is called out separately because it is not "one capability too many":
# it is every capability on every path, and it is the default in dev-mode Vault.
ROOT_CAPABILITY = "root"


def secret_presence(body: dict) -> dict[str, bool]:
    """Which of the secrets AXIAM reads are present, keyed by name.

    Returns a `name -> bool` mapping rather than `(name, present)` pairs so the
    caller loops over [`EXPECTED`] — a module constant — and only the boolean
    comes from Vault's response. That is not a style preference: when the names
    were carried out of here alongside the flags, CodeQL's taint tracking
    followed `body` into the printed name and raised a high-severity
    "clear-text logging of sensitive information" alert (2026-08-28). The alert
    was a false positive — the names have always come from `EXPECTED` and no
    value is ever printed — but a shape that makes a reader, or an analyser,
    ask the question at all is the wrong shape for a script whose entire job is
    to not print secrets. Now the only thing crossing this boundary is a
    presence flag.
    """
    fields = (body.get("data") or {}).get("data") or {}
    return {name: bool(fields.get(name)) for name in EXPECTED}


def unexpected_fields(body: dict) -> list[str]:
    """Field names present in Vault that AXIAM never reads."""
    fields = (body.get("data") or {}).get("data") or {}
    return sorted(set(fields) - set(EXPECTED))


def read_capabilities(body: dict) -> dict[str, list[str]]:
    """Extract the per-path capability lists from a `capabilities-self` reply.

    Vault answers with the queried paths as top-level keys (and repeats them
    under `data`), plus a `capabilities` key that is only meaningful for a
    single-path query. Take the per-path keys and ignore the rest, so
    single-path and multi-path queries are read the same way.
    """
    source = body.get("data") if isinstance(body.get("data"), dict) else body
    if not isinstance(source, dict):
        return {}
    return {
        path: [c for c in caps if isinstance(c, str)]
        for path, caps in source.items()
        if path != "capabilities" and isinstance(caps, list)
    }


def excess_capabilities(caps: list[str]) -> list[str]:
    """Capabilities on this path beyond the read-only posture T-180 asks for."""
    return sorted(set(caps) - ALLOWED_CAPABILITIES)


def is_root(per_path: dict[str, list[str]]) -> bool:
    """True when Vault reported `root` on any queried path."""
    return any(ROOT_CAPABILITY in caps for caps in per_path.values())


def scope_findings(per_path: dict[str, list[str]]) -> list[tuple[str, list[str], list[str]]]:
    """`(path, capabilities, excess)` per queried path, sorted by path."""
    return [
        (path, sorted(per_path[path]), excess_capabilities(per_path[path]))
        for path in sorted(per_path)
    ]


def is_over_scoped(per_path: dict[str, list[str]]) -> bool:
    """True when any queried path grants more than `read`."""
    return any(excess for _, _, excess in scope_findings(per_path))
