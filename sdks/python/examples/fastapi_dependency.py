"""fastapi_dependency.py demonstrates guarding a FastAPI route with
axiam_sdk.fastapi.require_authenticated_user(...) (CONTRACT.md §10, D-09,
SC#4).

require_authenticated_user(verifier, configured_tenant) verifies the inbound
session LOCALLY via a JWKS-backed verifier (no per-request AXIAM-server
round-trip on a cache hit), enforces the configured-tenant claim, and injects
the authenticated identity (AxiamUser) into the route via Depends(...) — or
raises HTTPException(401) automatically before the route handler ever runs.

This example is illustrative/importable — it does not require a live AXIAM
server to byte-compile or to construct the FastAPI app object (SC#4).
Serving real traffic requires the configured AXIAM_BASE_URL to be a
reachable AXIAM server (for the verifier's JWKS fetch).

Run: uvicorn examples.fastapi_dependency:app --reload
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI

from axiam_sdk.fastapi import AxiamUser, JwksVerifier, require_authenticated_user


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")

# JwksVerifier is the same local-verification primitive the Django
# middleware example uses, bound to {base_url}/oauth2/jwks (§10, D-16).
verifier = JwksVerifier(base_url)

app = FastAPI()

# require_authenticated_user(...) is a dependency FACTORY — the verifier and
# configured tenant must be configured per-app, mirroring the Go
# middleware's Middleware(verifier, configuredTenant, opts...) pattern.
authenticated_user = require_authenticated_user(verifier, tenant_slug)


@app.get("/protected")
async def protected(user: AxiamUser = Depends(authenticated_user)) -> dict[str, object]:  # noqa: B008
    """A route guarded by the FastAPI dependency — reaching this handler
    means the caller's token was verified locally and matched the
    configured tenant (T-19-19 cross-tenant replay defense)."""
    return {
        "message": f"Hello, user {user.user_id} (tenant {user.tenant_id})",
        "roles": user.roles,
    }
