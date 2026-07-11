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

CSRF (cookie double-submit, CONTRACT.md §3): a request authenticated via
the ``axiam_access`` COOKIE is not CSRF-immune the way a ``Authorization:
Bearer`` header request is — a cross-site attacker cannot set arbitrary
request headers, but a same-site cookie is attached to cross-site requests
automatically by the browser. For any cookie-sourced credential on a
state-changing method (anything other than GET/HEAD/OPTIONS), ``_authenticate``
additionally requires the ``X-CSRF-Token`` request header to be present and
equal (constant-time) to the ``axiam_csrf`` cookie value, rejecting with
403 on mismatch/absence. This mirrors, locally, the same double-submit
check the AXIAM server performs on its own endpoints (§3) — see also
``sdks/java/.../AxiamAuthenticationFilter.java`` for the same pattern
applied to the Spring integration.
"""

from __future__ import annotations

import hmac
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

#: CSRF double-submit failures surface as 403 (CONTRACT.md §3), mirroring
#: the AXIAM server's own AuthorizationDenied -> "authorization_denied" (403)
#: mapping (crates/axiam-api-rest/src/error.rs) rather than 401.
_CSRF_FAILED_STATUS = 403

_CSRF_COOKIE_NAME = "axiam_csrf"
_CSRF_HEADER_NAME = "X-CSRF-Token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


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


@dataclass(frozen=True)
class _Credential:
    """A verified-candidate token plus whether it was sourced from the
    ``axiam_access`` cookie (as opposed to the ``Authorization`` header) —
    needed to decide whether the CSRF double-submit check applies."""

    value: str
    from_cookie: bool


def _extract_token(request: HttpRequest) -> _Credential | None:
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
            return _Credential(str(credentials.strip()), from_cookie=False)
        return None

    cookie: str | None = request.COOKIES.get("axiam_access")
    if cookie:
        return _Credential(cookie, from_cookie=True)
    return None


def _is_csrf_valid(request: HttpRequest) -> bool:
    """Cookie double-submit check (CONTRACT.md §3): the ``X-CSRF-Token``
    request header must be present and equal, constant-time, to the
    ``axiam_csrf`` cookie value.

    Only consulted for cookie-sourced credentials on state-changing methods
    (see ``_authenticate``) — a Bearer-header request is CSRF-immune by
    construction, since a cross-site attacker cannot set arbitrary request
    headers.
    """
    header = request.headers.get(_CSRF_HEADER_NAME, "")
    cookie = request.COOKIES.get(_CSRF_COOKIE_NAME, "")
    if not header or not cookie:
        return False
    return hmac.compare_digest(header, cookie)


class _MalformedClaims(Exception):
    """Raised by :func:`_build_user` when a signature-valid token carries a
    malformed claim shape (e.g. ``scope: null``, missing ``sub``), so the
    caller can degrade it to a standardized 401 rather than an unhandled 500
    (WR-02, CONTRACT.md §10)."""


def _build_user(claims: dict[str, Any]) -> AxiamUser:
    """Build the :class:`AxiamUser` attached to ``request.axiam_user`` from
    verified token claims.

    Args:
        claims: The decoded, signature-verified access token claims.

    Returns:
        An ``AxiamUser`` with ``user_id`` from ``sub``, ``tenant_id`` from
        ``tenant_id``, and ``roles`` split from the space-delimited
        ``scope`` claim (empty when ``scope`` is absent or ``null``).

    Raises:
        _MalformedClaims: if ``sub`` or ``tenant_id`` is missing, so the
            caller can degrade to a standardized 401 instead of an
            unhandled 500 (WR-02).
    """
    # WR-02: ``dict.get("scope", "")`` returns ``None`` (not ``""``) when the
    # claim is PRESENT with an explicit JSON ``null`` value, and ``list(None)``
    # raises TypeError. ``claims.get("scope") or ""`` maps both absent AND null
    # scope to empty roles, matching how an absent scope is already handled.
    roles_claim = claims.get("scope") or ""
    roles = roles_claim.split() if isinstance(roles_claim, str) else list(roles_claim)
    subject = claims.get("sub")
    tenant_id = claims.get("tenant_id")
    if not subject or not tenant_id:
        raise _MalformedClaims("access token is missing sub/tenant_id")
    return AxiamUser(user_id=subject, tenant_id=tenant_id, roles=roles)


def _error_response(message: str) -> JsonResponse:
    """Standardized 401 ``{"error": "authentication_failed", "message":
    ...}`` JSON body (CONTRACT.md §10) — ``message`` must never contain a
    raw token value (T-19-21)."""
    return JsonResponse(
        {"error": "authentication_failed", "message": message}, status=_AUTH_FAILED_STATUS
    )


def _csrf_error_response(message: str) -> JsonResponse:
    """Standardized 403 JSON error body for CSRF double-submit failures
    (CONTRACT.md §3) — mirrors the AXIAM server's own AuthorizationDenied ->
    ``"authorization_denied"`` (403) error-code mapping
    (crates/axiam-api-rest/src/error.rs), same body shape as
    :func:`_error_response`."""
    return JsonResponse(
        {"error": "authorization_denied", "message": message}, status=_CSRF_FAILED_STATUS
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
        """Construct the middleware for Django's standard one-arg
        middleware-factory protocol.

        Args:
            get_response: The next callable in the middleware chain (sync or
                coroutine function); marked as a coroutine function itself
                via ``markcoroutinefunction`` when ``get_response`` is async,
                per Django's async-capable middleware contract.

        Raises:
            ValueError: if ``settings.AXIAM_JWKS_BASE_URL`` or
                ``settings.AXIAM_TENANT_SLUG`` is not configured.
        """
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
        """Dispatch to the sync or async call path depending on whether the
        wrapped ``get_response`` is a coroutine function — Django invokes
        this same ``__call__`` regardless of chain type."""
        if iscoroutinefunction(self.get_response):
            return self.__acall__(request)
        return self._sync_call(request)

    def _sync_call(self, request: HttpRequest) -> HttpResponse:
        """Synchronous request path: authenticate, then either short-circuit
        with the auth/CSRF error response or forward to ``get_response``."""
        error = self._authenticate(request)
        if error is not None:
            return error
        return self.get_response(request)

    async def __acall__(self, request: HttpRequest) -> HttpResponse:
        """Async twin of :meth:`_sync_call`, awaiting ``get_response``."""
        error = self._authenticate(request)
        if error is not None:
            return error
        return await self.get_response(request)

    def _authenticate(self, request: HttpRequest) -> JsonResponse | None:
        """Run the full authentication + CSRF pipeline for one request.

        Extracts the credential (Bearer header, else ``axiam_access``
        cookie); for a cookie-sourced credential on a state-changing method,
        enforces the CSRF double-submit check (§3) first. Verifies the
        token's signature (:class:`~axiam_sdk._jwks.JwksVerifier`,
        signature-only), then independently checks ``exp`` (T-19-20) and
        that ``tenant_id`` matches the configured tenant (T-19-19,
        cross-tenant replay defense) before attaching ``request.axiam_user``.

        Returns:
            ``None`` on success (``request.axiam_user`` has been set), or a
            standardized 401/403 :class:`~django.http.JsonResponse` on any
            failure — never propagating the raw token value (T-19-21).
        """
        credential = _extract_token(request)
        if not credential:
            return _error_response("missing authentication credentials")

        if credential.from_cookie and request.method.upper() not in _SAFE_METHODS:
            if not _is_csrf_valid(request):
                return _csrf_error_response("CSRF validation failed")

        token = credential.value

        try:
            claims = self._verifier.verify(token)
            # SDK-11: coerce ``exp`` to float INSIDE the verify try/except so a
            # signature-valid token carrying a non-numeric ``exp`` (e.g. a
            # string) degrades to the standardized invalid-token 401 rather
            # than a ValueError/TypeError propagating as an unhandled 500.
            # Preserves the "malformed token -> 401" invariant (CONTRACT.md §10).
            exp = claims.get("exp")
            exp_ts = float(exp) if exp is not None else None
        except Exception:
            return _error_response("invalid or expired token")

        if exp_ts is not None and time.time() >= exp_ts:
            return _error_response("invalid or expired token")

        # Cross-tenant replay defense (T-19-19): the JWKS is organization-wide,
        # not tenant-scoped, so a signature-valid token may belong to a
        # different tenant. MUST be enforced before any claim is trusted
        # further (mirrors nethttp.go lines 78-95).
        tenant_id = claims.get("tenant_id")
        if not tenant_id or tenant_id != self._configured_tenant:
            return _error_response("token tenant_id does not match the configured tenant")

        # WR-02: a malformed-but-signed claim shape (e.g. scope: null) must
        # degrade to the standardized 401, never an unhandled 500.
        try:
            request.axiam_user = _build_user(claims)
        except _MalformedClaims:
            return _error_response("invalid or expired token")
        return None


__all__ = ["AxiamAuthMiddleware"]
