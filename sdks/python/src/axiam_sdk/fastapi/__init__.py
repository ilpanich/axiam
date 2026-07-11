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

CSRF (cookie double-submit, CONTRACT.md §3): a request authenticated via
the ``axiam_access`` COOKIE is not CSRF-immune the way a ``Authorization:
Bearer`` header request is — a cross-site attacker cannot set arbitrary
request headers, but a same-site cookie is attached to cross-site requests
automatically by the browser. For any cookie-sourced credential on a
state-changing method (anything other than GET/HEAD/OPTIONS), this
dependency additionally requires the ``X-CSRF-Token`` request header to be
present and equal (constant-time) to the ``axiam_csrf`` cookie value,
rejecting with 403 on mismatch/absence. This mirrors, locally, the same
double-submit check the AXIAM server performs on its own endpoints (§3) —
see also ``sdks/java/.../AxiamAuthenticationFilter.java`` for the same
pattern applied to the Spring integration.
"""

from __future__ import annotations

import hmac
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from fastapi import HTTPException, Request

from axiam_sdk._jwks import JwksVerifier

#: Standardized "missing credentials" / "invalid or expired token" / tenant
#: mismatch failures all surface as 401 (CONTRACT.md §10, mirrors
#: nethttp.go's writeError(..., http.StatusUnauthorized, "authentication_failed", ...)).
_AUTH_FAILED_STATUS = 401

#: CSRF double-submit failures surface as 403 (CONTRACT.md §3), mirroring
#: the AXIAM server's own AuthorizationDenied -> "authorization_denied" (403)
#: mapping (crates/axiam-api-rest/src/error.rs) rather than 401.
_CSRF_FAILED_STATUS = 403

_CSRF_COOKIE_NAME = "axiam_csrf"
_CSRF_HEADER_NAME = "x-csrf-token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class AxiamUser:
    """The authenticated identity injected by :func:`require_authenticated_user`.

    Mirrors the Go middleware's ``User`` struct (``user_id``, ``tenant_id``,
    ``roles``) — CONTRACT.md §10's minimum identity fields.
    """

    user_id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Credential:
    """A verified-candidate token plus whether it was sourced from the
    ``axiam_access`` cookie (as opposed to the ``Authorization`` header) —
    needed to decide whether the CSRF double-submit check applies."""

    value: str
    from_cookie: bool


def _extract_token(request: Request) -> _Credential:
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
            return _Credential(credentials.strip(), from_cookie=False)
        raise HTTPException(
            status_code=_AUTH_FAILED_STATUS, detail="missing authentication credentials"
        )

    cookie = request.cookies.get("axiam_access")
    if cookie:
        return _Credential(cookie, from_cookie=True)

    raise HTTPException(
        status_code=_AUTH_FAILED_STATUS, detail="missing authentication credentials"
    )


def _assert_csrf_valid(request: Request) -> None:
    """Cookie double-submit check (CONTRACT.md §3): the ``X-CSRF-Token``
    request header must be present and equal, constant-time, to the
    ``axiam_csrf`` cookie value. Raises ``HTTPException`` 403 on
    mismatch/absence.

    Only called for cookie-sourced credentials on state-changing methods
    (see ``_dependency``) — a Bearer-header request is CSRF-immune by
    construction, since a cross-site attacker cannot set arbitrary request
    headers.
    """
    header = request.headers.get(_CSRF_HEADER_NAME)
    cookie = request.cookies.get(_CSRF_COOKIE_NAME)
    if not header or not cookie or not hmac.compare_digest(header, cookie):
        raise HTTPException(status_code=_CSRF_FAILED_STATUS, detail="CSRF validation failed")


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
    2. When the credential is cookie-sourced AND the request method is
       state-changing (not GET/HEAD/OPTIONS), enforces the CSRF
       double-submit check (CONTRACT.md §3) before verification proceeds —
       raises ``HTTPException`` 403 on failure.
    3. Verifies it locally via ``verifier.verify()`` (signature + ``sub`` only).
    4. Independently checks ``exp`` — the verifier does not (T-19-20).
    5. Enforces ``claims["tenant_id"] == configured_tenant`` BEFORE trusting
       any claim further (cross-tenant replay defense, T-19-19).
    6. Returns :class:`AxiamUser` on success; raises ``HTTPException`` 401 on
       any authentication failure, never including the raw token value.
    """

    async def _dependency(request: Request) -> AxiamUser:
        credential = _extract_token(request)

        if credential.from_cookie and request.method.upper() not in _SAFE_METHODS:
            _assert_csrf_valid(request)

        token = credential.value

        try:
            claims = verifier.verify(token)
            # SDK-11: coerce ``exp`` to float INSIDE the verify try/except so a
            # signature-valid token carrying a non-numeric ``exp`` (e.g. a
            # string) maps to the normal invalid-token -> 401 path rather than
            # a ValueError/TypeError propagating as an unhandled 500. Preserves
            # the "malformed token -> 401" invariant (CONTRACT.md §10).
            exp = claims.get("exp")
            exp_ts = float(exp) if exp is not None else None
        except Exception as exc:
            raise HTTPException(
                status_code=_AUTH_FAILED_STATUS, detail="invalid or expired token"
            ) from exc

        if exp_ts is not None and time.time() >= exp_ts:
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

        # WR-02: ``dict.get("scope", "")`` returns ``None`` (not ``""``) when
        # the claim is PRESENT with an explicit JSON ``null`` value, and
        # ``list(None)`` raises TypeError — which would propagate AFTER the
        # verify() try/except above and surface as an unhandled 500 for an
        # otherwise signature-valid token. ``claims.get("scope") or ""`` maps
        # both absent AND null scope to empty roles, matching how an absent
        # scope is already handled (CONTRACT.md §10: malformed claims must
        # still degrade to a standardized 401, never a 500).
        roles_claim = claims.get("scope") or ""
        roles = roles_claim.split() if isinstance(roles_claim, str) else list(roles_claim)

        subject = claims.get("sub")
        if not subject:
            raise HTTPException(status_code=_AUTH_FAILED_STATUS, detail="invalid or expired token")

        return AxiamUser(user_id=subject, tenant_id=tenant_id, roles=roles)

    return _dependency


__all__ = ["AxiamUser", "JwksVerifier", "require_authenticated_user"]
