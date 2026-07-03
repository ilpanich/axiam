"""rest_authz.py demonstrates the REST authorization surface:
check_access, can (the browser/UI alias), and batch_check (CONTRACT.md §1).

It logs in first (see examples/login_mfa.py for the full MFA-aware flow),
then exercises POST /api/v1/authz/check and POST /api/v1/authz/check/batch
(FND-04).

This example is illustrative/compilable — it reads connection details from
environment variables and does not require a live AXIAM server to
byte-compile.

Run: python examples/rest_authz.py
"""

from __future__ import annotations

import os

from axiam_sdk import AccessCheck, AuthError, AuthzError, AxiamClient


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


def main() -> None:
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    email = getenv("AXIAM_EMAIL", "user@example.com")
    password = getenv("AXIAM_PASSWORD", "changeme")
    resource_id = getenv("AXIAM_RESOURCE_ID", "00000000-0000-0000-0000-000000000000")

    with AxiamClient(base_url=base_url, tenant_slug=tenant_slug) as client:
        try:
            result = client.login(email, password)
        except AuthError as exc:
            print(f"login failed: {exc}")
            return

        if result.mfa_required:
            print("MFA is required for this account — see examples/login_mfa.py first.")
            return

        # POST /api/v1/authz/check — single access check.
        try:
            check = client.check_access("resource:read", resource_id)
            print(f"check_access -> allowed: {check.allowed}, reason: {check.reason!r}")
        except AuthzError as exc:
            print(f"check_access denied: {exc}")

        # can() — the browser/UI-facing alias for check_access (CONTRACT.md
        # §1 note); returns only the allowed boolean.
        can_write = client.can("resource:write", resource_id)
        print(f"can(resource:write) -> {can_write}")

        # POST /api/v1/authz/check/batch — an ordered batch of checks;
        # results preserve input order.
        checks = [
            AccessCheck(action="resource:read", resource_id=resource_id),
            AccessCheck(action="resource:delete", resource_id=resource_id, scope="admin"),
        ]
        results = client.batch_check(checks)
        for i, r in enumerate(results):
            print(f"batch_check[{i}] -> allowed: {r.allowed}")


if __name__ == "__main__":
    main()
