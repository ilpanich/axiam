"""Django middleware attaching ``request.axiam_user`` (D-10, CONTRACT.md §10).

Primary target sync-WSGI, but declares Django's ``sync_capable``/
``async_capable`` flags (and marks itself a coroutine function via
``asgiref.sync.markcoroutinefunction`` when wrapping an async
``get_response``) so it also works under ASGI without Django forcing an
unnecessary sync<->async adaptation shim.

This module is imported ONLY as ``axiam_sdk.django.middleware`` (never from
the top-level ``axiam_sdk/__init__.py``), so pure-REST/gRPC/AMQP consumers
of ``axiam-sdk`` are never forced to install ``django``.

Security-critical invariant — cross-tenant token replay defense (T-19-19):
the AXIAM JWKS is organization-wide, not tenant-scoped, so a token that is
signature-valid may still belong to a *different* tenant. ``_authenticate``
enforces ``claims["tenant_id"] == configured_tenant`` BEFORE any claim is
trusted further — mirrors ``sdks/go/middleware/nethttp.go`` lines 78-95.

Security-critical invariant — expiry (T-19-20): ``JwksVerifier.verify()``
checks the signature only, not ``exp`` (documented on that class).
``_authenticate`` independently rejects an expired-but-signature-valid
token.

Security-critical invariant — no token leakage (T-19-21): no raw token
value is ever included in any response body.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from axiam_sdk._jwks import JwksVerifier

#: Standardized 401 JSON error body shape (CONTRACT.md §10), no raw token
#: value ever included — mirrors nethttp.go's errorBody{Error, Message}.
_AUTH_FAILED_STATUS = 401


@dataclass(frozen=True)
class AxiamUser:
    """The authenticated identity attached to ``request.axiam_user``.

    Deliberately a separate definition from ``axiam_sdk.fastapi.AxiamUser``
    (same shape: ``user_id``, ``tenant_id``, ``roles``) rather than a shared
    import — the django and fastapi integration modules MUST stay mutually
    independent optional extras (importing one must never pull in the
    other's framework dependency).
    """

    user_id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)


def _extract_token(request: HttpRequest) -> str | None:
    """Extract the bearer token from ``Authorization: Bearer <token>``,
    falling back to the ``axiam_access`` session cookie.

    Ported 1:1 from ``sdks/go/middleware/nethttp.go``'s ``extractToken``
    (lines 109-125): Bearer header first, cookie fallback second — this
    exact ordering is a Shared Pattern (19-PATTERNS.md) also used by the
    FastAPI dependency.
    """
    header: str = request.headers.get("Authorization", "")
    if header:
        scheme, _, credentials = header.strip().partition(" ")
        if scheme.lower() == "bearer" and credentials.strip():
            return str(credentials.strip())
        return None

    cookie: str | None = request.COOKIES.get("axiam_access")
    return cookie or None


def _build_user(claims: dict[str, Any]) -> AxiamUser:
    roles_claim = claims.get("scope", "")
    roles = roles_claim.split() if isinstance(roles_claim, str) else list(roles_claim)
    return AxiamUser(user_id=claims["sub"], tenant_id=claims["tenant_id"], roles=roles)


def _error_response(message: str) -> JsonResponse:
    return JsonResponse(
        {"error": "authentication_failed", "message": message}, status=_AUTH_FAILED_STATUS
    )


class AxiamAuthMiddleware:
    """Django middleware verifying AXIAM access tokens locally and attaching
    ``request.axiam_user`` on success (D-10).

    Register in ``settings.py``::

        MIDDLEWARE = [..., "axiam_sdk.django.middleware.AxiamAuthMiddleware"]

    The verifier and configured tenant are resolved from Django settings at
    construction time:
      - ``AXIAM_JWKS_BASE_URL`` — the AXIAM server base URL (passed to
        :class:`~axiam_sdk._jwks.JwksVerifier`).
      - ``AXIAM_TENANT_SLUG`` — the configured tenant this deployment serves;
        enforced against every token's ``tenant_id`` claim (T-19-19).

    Declares ``sync_capable``/``async_capable`` per Django's "Marking
    middleware as async-capable" contract, so it runs correctly whether
    ``get_response`` is the sync WSGI chain (primary target) or an async
    ASGI chain.
    """

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response
        if iscoroutinefunction(self.get_response):
            markcoroutinefunction(self)

        base_url = getattr(settings, "AXIAM_JWKS_BASE_URL", None)
        if not base_url:
            raise ValueError(
                "AxiamAuthMiddleware requires settings.AXIAM_JWKS_BASE_URL to be configured"
            )
        self._configured_tenant = getattr(settings, "AXIAM_TENANT_SLUG", None)
        if not self._configured_tenant:
            raise ValueError(
                "AxiamAuthMiddleware requires settings.AXIAM_TENANT_SLUG to be configured"
            )
        self._verifier = JwksVerifier(base_url)

    def __call__(self, request: HttpRequest) -> Any:
        if iscoroutinefunction(self.get_response):
            return self.__acall__(request)
        return self._sync_call(request)

    def _sync_call(self, request: HttpRequest) -> HttpResponse:
        error = self._authenticate(request)
        if error is not None:
            return error
        return self.get_response(request)

    async def __acall__(self, request: HttpRequest) -> HttpResponse:
        error = self._authenticate(request)
        if error is not None:
            return error
        return await self.get_response(request)

    def _authenticate(self, request: HttpRequest) -> JsonResponse | None:
        token = _extract_token(request)
        if not token:
            return _error_response("missing authentication credentials")

        try:
            claims = self._verifier.verify(token)
        except Exception:
            return _error_response("invalid or expired token")

        exp = claims.get("exp")
        if exp is not None and time.time() >= float(exp):
            return _error_response("invalid or expired token")

        # Cross-tenant replay defense (T-19-19): the JWKS is organization-wide,
        # not tenant-scoped, so a signature-valid token may belong to a
        # different tenant. MUST be enforced before any claim is trusted
        # further (mirrors nethttp.go lines 78-95).
        tenant_id = claims.get("tenant_id")
        if not tenant_id or tenant_id != self._configured_tenant:
            return _error_response("token tenant_id does not match the configured tenant")

        request.axiam_user = _build_user(claims)
        return None


__all__ = ["AxiamAuthMiddleware"]
