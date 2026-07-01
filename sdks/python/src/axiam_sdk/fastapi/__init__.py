"""FastAPI ``Depends(...)`` dependency-injection integration (D-09, CONTRACT.md §10).

Verifies an AXIAM access token LOCALLY (no per-request round-trip to the
AXIAM server on a JWKS cache hit) via :class:`axiam_sdk._jwks.JwksVerifier`
and returns the authenticated identity (``user_id``, ``tenant_id``,
``roles``) for injection into a FastAPI route via ``Depends(...)``.

This module is a **dependency-only** integration (D-09) — there is
deliberately no ASGI-middleware variant. It is imported ONLY as
``axiam_sdk.fastapi`` (never from the top-level ``axiam_sdk/__init__.py``,
see Anti-Pattern/T-19-22) so that pure-REST/gRPC/AMQP consumers of
``axiam-sdk`` are never forced to install ``fastapi``.

Security-critical invariant — cross-tenant token replay defense (T-19-19):
the AXIAM JWKS is organization-wide, not tenant-scoped, so a token that is
signature-valid may still belong to a *different* tenant. This dependency
enforces ``claims["tenant_id"] == configured_tenant`` BEFORE any claim is
trusted further — mirrors ``sdks/go/middleware/nethttp.go`` lines 78-95.

Security-critical invariant — expiry (T-19-20): ``JwksVerifier.verify()``
checks the signature only, not ``exp`` (documented on that class). This
dependency independently rejects an expired-but-signature-valid token.

Security-critical invariant — no token leakage (T-19-21): no raw token
value is ever included in any ``HTTPException`` detail.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from fastapi import HTTPException, Request

from axiam_sdk._jwks import JwksVerifier

#: Standardized "missing credentials" / "invalid or expired token" / tenant
#: mismatch failures all surface as 401 (CONTRACT.md §10, mirrors
#: nethttp.go's writeError(..., http.StatusUnauthorized, "authentication_failed", ...)).
_AUTH_FAILED_STATUS = 401


@dataclass(frozen=True)
class AxiamUser:
    """The authenticated identity injected by :func:`require_authenticated_user`.

    Mirrors the Go middleware's ``User`` struct (``user_id``, ``tenant_id``,
    ``roles``) — CONTRACT.md §10's minimum identity fields.
    """

    user_id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)


def _extract_token(request: Request) -> str:
    """Extract the bearer token from ``Authorization: Bearer <token>``,
    falling back to the ``axiam_access`` session cookie.

    Ported 1:1 from ``sdks/go/middleware/nethttp.go``'s ``extractToken``
    (lines 109-125): Bearer header first, cookie fallback second, standardized
    401 with no token value on failure — this exact ordering is a Shared
    Pattern (19-PATTERNS.md) also used by the Django middleware.
    """
    header = request.headers.get("authorization")
    if header:
        scheme, _, credentials = header.strip().partition(" ")
        if scheme.lower() == "bearer" and credentials.strip():
            return credentials.strip()
        raise HTTPException(
            status_code=_AUTH_FAILED_STATUS, detail="missing authentication credentials"
        )

    cookie = request.cookies.get("axiam_access")
    if cookie:
        return cookie

    raise HTTPException(
        status_code=_AUTH_FAILED_STATUS, detail="missing authentication credentials"
    )


def require_authenticated_user(
    verifier: JwksVerifier, configured_tenant: str
) -> Callable[[Request], Awaitable[AxiamUser]]:
    """Factory returning a ``Depends(...)``-compatible async dependency
    (mirrors the Go middleware's ``Middleware(verifier, configuredTenant,
    opts...)`` factory pattern, D-09).

    Usage::

        @app.get("/me")
        async def me(user: AxiamUser = Depends(require_authenticated_user(verifier, "acme"))):
            ...

    The returned dependency:
    1. Extracts the token (Authorization Bearer, else ``axiam_access`` cookie).
    2. Verifies it locally via ``verifier.verify()`` (signature + ``sub`` only).
    3. Independently checks ``exp`` — the verifier does not (T-19-20).
    4. Enforces ``claims["tenant_id"] == configured_tenant`` BEFORE trusting
       any claim further (cross-tenant replay defense, T-19-19).
    5. Returns :class:`AxiamUser` on success; raises ``HTTPException`` 401 on
       any authentication failure, never including the raw token value.
    """

    async def _dependency(request: Request) -> AxiamUser:
        token = _extract_token(request)

        try:
            claims = verifier.verify(token)
        except Exception as exc:
            raise HTTPException(
                status_code=_AUTH_FAILED_STATUS, detail="invalid or expired token"
            ) from exc

        exp = claims.get("exp")
        if exp is not None and time.time() >= float(exp):
            raise HTTPException(status_code=_AUTH_FAILED_STATUS, detail="invalid or expired token")

        # Cross-tenant replay defense (T-19-19): the JWKS is organization-wide,
        # not tenant-scoped, so a signature-valid token may belong to a
        # different tenant. MUST be enforced before any claim is trusted
        # further (mirrors nethttp.go lines 78-95).
        tenant_id = claims.get("tenant_id")
        if not tenant_id or tenant_id != configured_tenant:
            raise HTTPException(
                status_code=_AUTH_FAILED_STATUS,
                detail="token tenant_id does not match the configured tenant",
            )

        roles_claim = claims.get("scope", "")
        roles = roles_claim.split() if isinstance(roles_claim, str) else list(roles_claim)

        return AxiamUser(user_id=claims["sub"], tenant_id=tenant_id, roles=roles)

    return _dependency


__all__ = ["AxiamUser", "JwksVerifier", "require_authenticated_user"]
