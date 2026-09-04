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

# What AXIAM's runtime token is supposed to be able to do on a path it is not
# otherwise known to need. The server only ever GETs its startup secret: it
# never writes one, never lists the mount, and never needs `sudo`. `deny` is not
# over-scope — it is strictly less than read.
ALLOWED_CAPABILITIES = frozenset({"read", "deny"})

# `root` is called out separately because it is not "one capability too many":
# it is every capability on every path, and it is the default in dev-mode Vault.
ROOT_CAPABILITY = "root"

# A CA key path is written at runtime, one secret per CA, so there is no real
# path to ask about at the moment the question is worth asking. Vault answers
# `sys/capabilities-self` about a REQUEST path, matching it against the policy's
# globs, so any concrete path under the prefix reports what the real ones will
# get. These two ids are not UUIDs precisely so that a reader of an audit log
# can tell a capability probe from a CA that exists.
CA_KEY_DATA_PROBE = "secret/data/axiam/ca-keys/probe/probe"
CA_KEY_METADATA_PROBE = "secret/metadata/axiam/ca-keys/probe/probe"

# Every path worth asking about, and what the policy in
# docker/vault/axiam-policy.hcl grants on each.
#
# The CA-key entries are why this is a mapping rather than one global allow-set:
# `create` on the startup-secret path would be over-scope, and its absence on
# the CA-key path is a server that boots cleanly and then cannot generate a CA.
# One posture cannot express both.
EXPECTED_CAPABILITIES: dict[str, frozenset[str]] = {
    "secret/data/axiam": frozenset({"read"}),
    "secret/metadata/axiam": frozenset({"read"}),
    CA_KEY_DATA_PROBE: frozenset({"create", "read", "update"}),
    CA_KEY_METADATA_PROBE: frozenset({"delete"}),
}

# The body of the `sys/capabilities-self` request that fills the report in.
PROBE_PATHS = list(EXPECTED_CAPABILITIES)

# The subset whose absence is a warning rather than an error, because the
# deployment it does not apply to is a real one: a deployment holding CA keys in
# the database, or pointing `AXIAM__PKI__VAULT_TOKEN` at a second credential, is
# correctly configured with nothing granted here.
CA_KEY_PATHS = frozenset({CA_KEY_DATA_PROBE, CA_KEY_METADATA_PROBE})


def expected_for(path: str) -> frozenset[str]:
    """What this token should hold on `path`.

    An unlisted path falls back to the read-only posture rather than to "no
    expectation": someone querying an extra path wants to know if the token
    reaches further than it should there too.
    """
    return EXPECTED_CAPABILITIES.get(path, frozenset({"read"}))


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


def excess_capabilities(caps: list[str], expected: frozenset[str] | None = None) -> list[str]:
    """Capabilities on this path beyond what AXIAM asks for.

    `expected` defaults to the read-only posture T-180 asks for, which is what
    every path had before CA key custody could write to one of them.
    """
    allowed = ALLOWED_CAPABILITIES if expected is None else (expected | {"deny"})
    return sorted(set(caps) - allowed)


def missing_capabilities(caps: list[str], expected: frozenset[str]) -> list[str]:
    """Capabilities AXIAM needs on this path and the token does not hold.

    The other half of the scope question, and the half that was not asked until
    a CA generation answered it with a 403. `root` holds everything, so nothing
    is ever missing from it — over-scope is the finding there, not under-scope.
    """
    if ROOT_CAPABILITY in caps:
        return []
    return sorted(expected - set(caps))


def is_root(per_path: dict[str, list[str]]) -> bool:
    """True when Vault reported `root` on any queried path."""
    return any(ROOT_CAPABILITY in caps for caps in per_path.values())


def scope_findings(
    per_path: dict[str, list[str]],
) -> list[tuple[str, list[str], list[str], list[str]]]:
    """`(path, capabilities, excess, missing)` per queried path, sorted by path."""
    findings = []
    for path in sorted(per_path):
        caps = per_path[path]
        expected = expected_for(path)
        findings.append(
            (
                path,
                sorted(caps),
                excess_capabilities(caps, expected),
                missing_capabilities(caps, expected),
            )
        )
    return findings


def is_over_scoped(per_path: dict[str, list[str]]) -> bool:
    """True when any queried path grants more than AXIAM asks for there."""
    return any(excess for _, _, excess, _ in scope_findings(per_path))


def is_under_scoped(per_path: dict[str, list[str]]) -> bool:
    """True when any queried path grants less than AXIAM needs there."""
    return any(missing for _, _, _, missing in scope_findings(per_path))

# ---------------------------------------------------------------------------
# R-7 — the seal type (narrows T-216)
# ---------------------------------------------------------------------------
#
# AXIAM cannot configure auto-unseal: every Vault OSS seal type needs a cloud
# KMS or a second Vault elsewhere, and `pkcs11` is Enterprise-only, so a TPM is
# not an option whatever the hardware. That is out of scope and stays out of
# scope (remediation plan §10).
#
# What AXIAM can do is make the gap **checkable**, the way H-4 made the token's
# scope checkable for T-180. Before this, `just vault-status` reported which
# secrets a path holds and how far the token reaches, and said nothing at all
# about whether the Vault comes back sealed after a restart — which on a Shamir
# seal means a human with `t` of `n` key shares, in the middle of the night,
# before a single login can succeed.
#
# `sys/seal-status` is unauthenticated, so this works even against a Vault whose
# token is wrong, and even against one that is sealed right now.

#: Seal types that unseal without a human. Vault's own names, not ours.
AUTO_UNSEAL_TYPES = frozenset(
    {"awskms", "gcpckms", "azurekeyvault", "alicloudkms", "ocikms", "transit", "pkcs11"}
)

#: The one that does not.
SHAMIR = "shamir"


def seal_findings(body: dict | None) -> list[tuple[str, str]]:
    """Describe a `sys/seal-status` response as `(marker, line)` pairs.

    `None` — the request failed, or its body did not parse — reports
    ``unknown``, never ``OK``. A seal check that cannot reach Vault has learned
    nothing, and reporting the absence of bad news as good news is exactly the
    failure mode the check exists to remove.

    The `sealed: true` line is a **state**, not a policy problem, and says so:
    a Vault that is sealed right now is a Vault someone is about to unseal, and
    conflating that with "this deployment has no auto-unseal" would train an
    operator to ignore both.
    """
    if body is None:
        return [
            (
                "unknown",
                "seal status could not be read — auto-unseal is NOT confirmed. "
                "This is not a pass.",
            )
        ]

    findings: list[tuple[str, str]] = []
    seal_type = str(body.get("type") or "").strip() or "unknown"

    if not body.get("initialized", True):
        findings.append(
            (
                "note",
                "this Vault is NOT INITIALIZED yet — `vault operator init` has not run. "
                "The seal type below is what it will use once it does.",
            )
        )

    if seal_type in AUTO_UNSEAL_TYPES:
        findings.append(
            (
                "OK",
                f"seal type `{seal_type}` — auto-unseal. A restart comes back on its "
                "own, with no key shares and no human.",
            )
        )
    elif seal_type == SHAMIR:
        threshold = body.get("t")
        shares = body.get("n")
        quorum = (
            f"{threshold} of {shares} key share(s)"
            if threshold is not None and shares is not None
            else "a quorum of key shares"
        )
        findings.append(
            (
                "SHAMIR",
                f"no auto-unseal; every restart needs {quorum}, entered by a human "
                "before AXIAM can serve a single login. Not production. "
                "docs/deployment/vault.md §5.3 has the option table — GCP Cloud KMS "
                "at roughly $0.06 per key per month is the cheapest real answer.",
            )
        )
    else:
        findings.append(
            (
                "unknown",
                f"seal type `{seal_type}` is not one this report recognises. "
                "Treat it as unconfirmed rather than as auto-unseal.",
            )
        )

    # Deliberately last, and deliberately its own line: being sealed right now
    # is orthogonal to which seal is configured.
    if body.get("sealed"):
        findings.append(
            (
                "SEALED",
                "this Vault is SEALED right now — AXIAM cannot read a secret from it "
                "until it is unsealed. That is a state, not a policy problem: it says "
                "nothing about whether the seal type above is right.",
            )
        )

    if body.get("recovery_seal"):
        findings.append(
            (
                "note",
                "recovery keys are in use (an auto-unseal Vault's break-glass path). "
                "They do not unseal on a restart; the seal type above does.",
            )
        )

    return findings


def seal_is_production_ready(body: dict | None) -> bool:
    """Whether the configured seal brings this Vault back without a human.

    `False` for Shamir, for an unreadable response and for a type this report
    does not recognise — the same conservative reading `seal_findings` gives.
    Being sealed *right now* does not make it False: that is a transient state,
    and `--strict` should not fail a correctly configured deployment for it.
    """
    if body is None:
        return False
    return str(body.get("type") or "").strip() in AUTO_UNSEAL_TYPES

