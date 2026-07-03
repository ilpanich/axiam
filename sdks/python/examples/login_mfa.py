"""login_mfa.py demonstrates the two-phase login/verify_mfa flow
(CONTRACT.md §1, §5), for both the sync and async surfaces of the same
AxiamClient object (SC#1).

It constructs an AxiamClient with a non-optional tenant_slug (§5 — there is
no default tenant), calls login(), and branches on LoginResult.mfa_required:
when the server responds with an MFA challenge instead of a completed
session, it calls verify_mfa(mfa_token, code) with the challenge token and a
TOTP code to complete the flow.

This example is illustrative/compilable — it reads connection details from
environment variables and does not require a live AXIAM server to
byte-compile. Running it end-to-end requires a reachable AXIAM server
matching the configured base URL.

Run: python examples/login_mfa.py
"""

from __future__ import annotations

import asyncio
import os

from axiam_sdk import AuthError, AxiamClient


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


def sync_login_mfa() -> None:
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    email = getenv("AXIAM_EMAIL", "user@example.com")
    password = getenv("AXIAM_PASSWORD", "changeme")
    totp_code = getenv("AXIAM_TOTP_CODE", "000000")

    # §5: tenant_slug is a non-optional constructor parameter — an empty
    # value raises AuthError, never a silent default. TLS is always
    # verify=True (§6, SC#3) — the only escape hatch is an explicit
    # custom_ca parameter, never a boolean bypass.
    with AxiamClient(base_url=base_url, tenant_slug=tenant_slug) as client:
        try:
            result = client.login(email, password)
        except AuthError as exc:
            print(f"login failed: {exc}")
            return

        if result.mfa_required:
            print("MFA required — completing the two-phase flow")
            # verify_mfa(mfa_token, code) completes the flow started by
            # login() when mfa_required was true (SC#1's literal target).
            completed = client.verify_mfa(result.mfa_token, totp_code)
            print(
                f"MFA verified — session_id: {completed.session_id}, "
                f"expires_in: {completed.expires_in}s"
            )
        else:
            print(
                f"Login complete (no MFA) — session_id: {result.session_id}, "
                f"expires_in: {result.expires_in}s"
            )


async def async_login_mfa() -> None:
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    email = getenv("AXIAM_EMAIL", "user@example.com")
    password = getenv("AXIAM_PASSWORD", "changeme")
    totp_code = getenv("AXIAM_TOTP_CODE", "000000")

    # await client.async_login(...) exists on the SAME AxiamClient object as
    # the sync client.login(...) above (D-01/SC#1) — one shared session.
    async with AxiamClient(base_url=base_url, tenant_slug=tenant_slug) as client:
        try:
            result = await client.async_login(email, password)
        except AuthError as exc:
            print(f"async login failed: {exc}")
            return

        if result.mfa_required:
            print("MFA required (async) — completing the two-phase flow")
            completed = await client.async_verify_mfa(result.mfa_token, totp_code)
            print(
                f"MFA verified (async) — session_id: {completed.session_id}, "
                f"expires_in: {completed.expires_in}s"
            )
        else:
            print(
                f"Async login complete (no MFA) — session_id: {result.session_id}, "
                f"expires_in: {result.expires_in}s"
            )


if __name__ == "__main__":
    sync_login_mfa()
    asyncio.run(async_login_mfa())
