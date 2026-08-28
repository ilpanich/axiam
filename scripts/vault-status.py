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

as `--capabilities FILE` and this script says whether the token is the
read-only, single-path credential `docs/deployment/vault.md` §5.4 describes.
Capabilities are not secrets — unlike the KV fields, they are printed in full.

The decision logic lives in `vault_status_report.py` so it can be unit-tested;
this file is the I/O half.
"""

import argparse
import json
import sys

from vault_status_report import (
    EXPECTED,
    is_root,
    read_capabilities,
    scope_findings,
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
    """Print the token's scope. Returns True if anything exceeds read-only."""
    if not per_path:
        print("\n  token scope: Vault returned no per-path capabilities — not checked.")
        return False

    print("\n  token scope (T-180):")
    over_scoped = False
    for path, caps, excess in scope_findings(per_path):
        if excess:
            over_scoped = True
        mark = "OVER-SCOPED" if excess else "ok         "
        print(f"    {mark}  {path}: {', '.join(caps) or '(none)'}")

    if over_scoped:
        print()
        if is_root(per_path):
            print(
                "  WARNING: this is a ROOT token. It can read, rewrite and delete\n"
                "           every secret in this Vault, not only AXIAM's."
            )
        else:
            print(
                "  WARNING: this token has more than `read` on AXIAM's KV path.\n"
                "           The server only ever reads its secret; a token that can\n"
                "           also write one turns a leak into a way to REPLACE the\n"
                "           JWT signing key rather than merely to read it."
            )
        print(
            "           Fix: the read-only policy in docs/deployment/vault.md §5.4.\n"
            "           Expected on the dev-mode Vault `just vault-up` starts — it\n"
            "           uses a fixed root token on purpose. Never in production."
        )
    return over_scoped


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
        "--strict",
        action="store_true",
        help="Exit non-zero when the token holds more than `read` on AXIAM's path. "
        "Off by default so the dev-mode root token does not fail the recipe.",
    )
    args = parser.parse_args()

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

    if missing:
        print(
            f"\n{len(missing)} secret(s) missing — run `just vault-seed` to mint them "
            "(or `just vault-up` for the dev-mode Vault)."
        )
        return 1
    if over_scoped and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
