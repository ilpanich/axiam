#!/usr/bin/env python3
"""Report which AXIAM secrets a Vault path holds, without printing any of them.

Reads a Vault KV v2 read response on stdin. Deliberately prints only presence:
a `just` recipe's output ends up in scrollback, CI logs and screenshots, and
none of those are places for the OPAQUE setup key.

Optionally also reports the *scope* of the token that produced that response
(H-4 / T-180). Nothing in AXIAM can stop an operator handing the server a Vault
token with write — or root — on the whole KV store; what it can do is make the
misconfiguration visible instead of silent. Pass the response body of

    POST /v1/sys/capabilities-self   {"paths": ["secret/data/axiam", ...]}

as `--capabilities FILE` and this script says whether the token matches the
policy in `docker/vault/axiam-policy.hcl`. It reports both directions: a token
that reaches further than AXIAM asks for, and — since 1.0.0-beta10 — one that
does not reach far enough, which is what a stack looks like right up until its
first CA generation answers with a 403. `--print-paths` emits the request body
that fills this in, so the path list lives here and not in the caller.

Capabilities are not secrets — unlike the KV fields, they are printed in full.

And, since R-7 (T-216), the **seal**. AXIAM cannot configure auto-unseal — every
Vault OSS seal type needs a cloud KMS or a second Vault elsewhere, and `pkcs11`
is Enterprise-only — but it can make the absence of one checkable, the way H-4
made the token's scope checkable. Pass the body of the *unauthenticated*

    GET /v1/sys/seal-status

as `--seal-status FILE` and this script names the seal type, flags `shamir` as
"every restart needs key shares, not production" with the `t`/`n` quorum from
the response, and reports a Vault that is sealed right now as the separate state
it is. A request that fails reports `unknown`, never `OK`.

The decision logic lives in `vault_status_report.py` so it can be unit-tested;
this file is the I/O half.
"""

import argparse
import json
import sys

from vault_status_report import (
    CA_KEY_PATHS,
    EXPECTED,
    PROBE_PATHS,
    is_root,
    read_capabilities,
    scope_findings,
    seal_findings,
    seal_is_production_ready,
    secret_presence,
    unexpected_fields,
)


def print_secrets(body: dict) -> list[str]:
    """Print presence for every expected field; return the missing names."""
    present = secret_presence(body)
    missing = []
    # Iterating EXPECTED rather than the returned mapping is deliberate: the
    # name printed here is then a module constant, and the only thing this loop
    # takes from Vault's response is a boolean. See `secret_presence`.
    for name in EXPECTED:
        label = "set  " if present[name] else "MISSING"
        print(f"  {label}  {name}")
        if not present[name]:
            missing.append(name)

    extra = unexpected_fields(body)
    if extra:
        print(f"\n  also present (not read by AXIAM): {', '.join(extra)}")
    return missing


def print_scope(per_path: dict[str, list[str]]) -> bool:
    """Print the token's scope. Returns True if any path grants too much.

    Reports both directions. Over-scope is the security finding T-180 asked
    for; under-scope is the *functional* one, and it is the reason a stack can
    boot cleanly, serve every request, and then answer the first CA generation
    with a 403 nothing in the startup log predicted.
    """
    if not per_path:
        print("\n  token scope: Vault returned no per-path capabilities — not checked.")
        return False

    print("\n  token scope (T-180):")
    over_scoped = False
    under_scoped_ca_keys = False
    for path, caps, excess, missing in scope_findings(per_path):
        if excess:
            over_scoped = True
            mark = "OVER-SCOPED"
        elif missing:
            if path in CA_KEY_PATHS:
                under_scoped_ca_keys = True
            mark = "MISSING    "
        else:
            mark = "ok         "
        line = f"    {mark}  {path}: {', '.join(caps) or '(none)'}"
        if missing and not excess:
            line += f"  (needs {', '.join(missing)})"
        print(line)

    if over_scoped:
        print()
        if is_root(per_path):
            print(
                "  WARNING: this is a ROOT token. It can read, rewrite and delete\n"
                "           every secret in this Vault, not only AXIAM's."
            )
        else:
            print(
                "  WARNING: this token reaches further than AXIAM asks for on one of\n"
                "           the paths above. The server only ever reads its startup\n"
                "           secret; a token that can also write one turns a leak into\n"
                "           a way to REPLACE the JWT signing key rather than merely\n"
                "           to read it."
            )
        print(
            "           Fix: the policy in docker/vault/axiam-policy.hcl —\n"
            "           `just vault-policy`, or docs/deployment/vault.md §5.4.\n"
            "           Expected on the dev-mode Vault `just vault-up` starts — it\n"
            "           uses a fixed root token on purpose. Never in production."
        )

    if under_scoped_ca_keys:
        print(
            "\n  NOTE: this token cannot write organization CA signing keys. That is\n"
            "        correct ONLY if CA keys live in the database\n"
            "        (AXIAM__PKI__CA_KEY_STORE=database) or a separate\n"
            "        AXIAM__PKI__VAULT_TOKEN holds them. Otherwise CA generation\n"
            "        will fail with `403 Forbidden on write` — apply the policy in\n"
            "        docker/vault/axiam-policy.hcl (`just vault-policy`). It takes\n"
            "        effect immediately; Vault evaluates policies per request, so\n"
            "        nothing needs restarting or re-initialising."
        )
    return over_scoped


def print_seal(body: dict | None) -> bool:
    """Print the Seal section. Returns True when auto-unseal is confirmed.

    R-7 (T-216). AXIAM cannot configure auto-unseal — every Vault OSS seal type
    needs a cloud KMS or a second Vault, and `pkcs11` is Enterprise-only — but
    it can make its absence checkable, exactly as H-4 made the token's scope
    checkable for T-180. Before this, nothing in `just vault-status` reported
    whether the Vault comes back sealed after a restart, which on Shamir means a
    human with key shares before a single login can succeed.
    """
    print("\n  seal (T-216):")
    for marker, line in seal_findings(body):
        # Wrap continuation lines under the text, not under the marker, so the
        # markers stay scannable in a column.
        head, *rest = _wrapped(line)
        print(f"    {marker:<8}  {head}")
        for extra in rest:
            print(f"              {extra}")
    return seal_is_production_ready(body)


def _wrapped(text: str, width: int = 66) -> list[str]:
    """Greedy wrap, so a long finding does not run off a terminal."""
    words = text.split()
    lines: list[str] = [""]
    for word in words:
        candidate = f"{lines[-1]} {word}".strip()
        if len(candidate) > width and lines[-1]:
            lines.append(word)
        else:
            lines[-1] = candidate
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report AXIAM secret presence (and optionally token scope) "
        "for a Vault KV v2 path, without printing any secret value."
    )
    parser.add_argument(
        "--capabilities",
        metavar="FILE",
        help="JSON body of a Vault `sys/capabilities-self` response. Without it, "
        "only secret presence is reported.",
    )
    parser.add_argument(
        "--print-paths",
        action="store_true",
        help="Print the JSON body for a Vault `sys/capabilities-self` request and "
        "exit. The caller does the I/O, so the path list stays in one place.",
    )
    parser.add_argument(
        "--seal-status",
        metavar="FILE",
        help="JSON body of a Vault `sys/seal-status` response (unauthenticated). "
        "Without it, the seal is not reported at all — an absent section is "
        "honest, an OK we did not verify is not.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when the token holds more than `read` on AXIAM's path, "
        "or when auto-unseal is not confirmed. Off by default so the dev stack — "
        "a root token on a Shamir Vault, both on purpose — does not turn every "
        "local run red.",
    )
    args = parser.parse_args()

    if args.print_paths:
        # Emitted rather than duplicated in the `just` recipe: a probe path that
        # drifts from the one the report expects reports `(none)` for a token
        # that is perfectly configured.
        print(json.dumps({"paths": PROBE_PATHS}))
        return 0

    try:
        body = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("could not parse Vault's response — is it sealed?", file=sys.stderr)
        return 1

    missing = print_secrets(body)

    over_scoped = False
    if args.capabilities:
        try:
            with open(args.capabilities, encoding="utf-8") as fh:
                caps_body = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            # Not fatal. A Vault that answers the KV read but not
            # `capabilities-self` is unusual, not broken, and the presence
            # report above still answers the question that was asked.
            print(f"\n  token scope: could not be read ({exc}) — not checked.")
        else:
            over_scoped = print_scope(read_capabilities(caps_body))

    # R-7: reported whenever the caller supplied a response, including one that
    # would not parse — `seal_findings(None)` says `unknown`, never `OK`.
    auto_unseal = True
    if args.seal_status:
        try:
            with open(args.seal_status, encoding="utf-8") as fh:
                seal_body = json.load(fh)
        except (OSError, json.JSONDecodeError):
            seal_body = None
        auto_unseal = print_seal(seal_body)

    if missing:
        print(
            f"\n{len(missing)} secret(s) missing — run `just vault-seed` to mint them "
            "(or `just vault-up` for the dev-mode Vault)."
        )
        return 1
    if args.strict and (over_scoped or not auto_unseal):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
