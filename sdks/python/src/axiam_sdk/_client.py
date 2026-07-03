"""Unified AxiamClient — sync + async REST surface (D-01/D-19, SC#1).

One ``AxiamClient`` exposes sync ``login``/``verify_mfa``/``refresh``/
``logout``/``check_access``/``can``/``batch_check`` AND their ``async_*``
twins on the SAME object, sharing one ``_Session`` (cookie jar, CSRF state,
tenant/org context, refresh guard). Mirrors ``sdks/go/client.go`` +
``sdks/go/login.go`` + ``sdks/go/authz.go``, adapted to Python's sync+async
duality.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx

from axiam_sdk._errors import AuthError, error_from_http_status
from axiam_sdk._models import AccessCheck, AccessResult, BatchCheckResult, LoginResult
from axiam_sdk._session import _Session

LOGIN_PATH = "/api/v1/auth/login"
MFA_VERIFY_PATH = "/api/v1/auth/mfa/verify"
REFRESH_PATH = "/api/v1/auth/refresh"
LOGOUT_PATH = "/api/v1/auth/logout"
CHECK_PATH = "/api/v1/authz/check"
BATCH_CHECK_PATH = "/api/v1/authz/check/batch"

ACCESS_COOKIE = "axiam_access"
REFRESH_COOKIE = "axiam_refresh"


def _decode_unverified_claims(token: str) -> dict[str, Any]:
    """Base64url-decode a JWT's payload segment WITHOUT verifying its
    signature — signature verification is the JWKS/middleware concern
    (``_jwks.py``, ``fastapi``/``django`` integrations), not this
    org_id/tenant_id-resolution helper. Mirrors Go's
    ``decodeUnverifiedClaims``."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError(f"malformed access token: expected 3 segments, got {len(parts)}")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        claims: Any = json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthError(f"failed to decode access token claims: {exc}") from None
    # IN-02: json.loads succeeds for any valid JSON, including arrays/scalars.
    # The function's own signature promises a dict; every caller does
    # ``.get(...)`` on the result, which would raise AttributeError on a
    # non-object payload. Validate the shape here so a malformed token
    # surfaces a clean AuthError, mirroring the isinstance(..., dict) checks
    # already in _jwks.py and amqp/_hmac.py.
    if not isinstance(claims, dict):
        raise AuthError("access token payload is not a JSON object")
    return claims


class AxiamClient:
    """The AXIAM SDK's unified REST entry point (CONTRACT.md §1-§10).

    Both ``client.login(...)`` (sync) and ``await client.async_login(...)``
    (async) exist on this SAME object and both return a typed
    :class:`~axiam_sdk._models.LoginResult` with ``mfa_required`` (SC#1).
    """

    def __init__(
        self,
        *,
        base_url: str,
        tenant_slug: str,
        org_slug: str | None = None,
        org_id: str | None = None,
        custom_ca: str | None = None,
        timeout: httpx.Timeout | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if not tenant_slug:
            raise AuthError(
                "tenant_slug is required — AXIAM is multi-tenant and there is no default "
                "tenant (CONTRACT.md §5)"
            )
        if org_slug and org_id:
            raise AuthError("org_slug and org_id are mutually exclusive — supply at most one")

        self._org_slug = org_slug
        self._org_id = org_id
        self._resolved_org_id: str | None = org_id

        self._logger = logger or _null_logger()

        self._session = _Session(
            base_url=base_url,
            tenant_slug=tenant_slug,
            custom_ca=custom_ca,
            timeout=timeout,
            logger=self._logger,
        )

    # ------------------------------------------------------------------
    # Lifecycle (D-19)
    # ------------------------------------------------------------------

    def __enter__(self) -> AxiamClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    async def __aenter__(self) -> AxiamClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def close(self) -> None:
        """Close the sync httpx client, if constructed (D-19)."""
        self._session.close()

    async def aclose(self) -> None:
        """Close the async httpx client, if constructed (D-19)."""
        await self._session.aclose()

    # ------------------------------------------------------------------
    # org_id resolution (Pitfall 3 — the real login/refresh endpoints
    # require an org_id/org_slug beyond CONTRACT.md §5's tenant-only
    # minimum)
    # ------------------------------------------------------------------

    def resolved_org_id(self) -> str | None:
        """The organization UUID to use in a request body: the explicitly
        configured ``org_id`` if present, otherwise the value resolved from
        the access token's ``org_id`` claim after login/refresh, if any."""
        return self._resolved_org_id

    def _set_resolved_org_id(self, org_id: str) -> None:
        self._resolved_org_id = org_id

    # ------------------------------------------------------------------
    # login / verify_mfa (sync + async)
    # ------------------------------------------------------------------

    def login(self, email: str, password: str) -> LoginResult:
        """``POST /api/v1/auth/login`` (CONTRACT.md §1). Returns a typed
        :class:`LoginResult`; check ``mfa_required`` before assuming the
        session is established (SC#1)."""
        request = self._session.sync_client.build_request(
            "POST", LOGIN_PATH, json=self._login_body(email, password)
        )
        response = self._session._send_sync(request)
        return self._handle_login_response(response)

    async def async_login(self, email: str, password: str) -> LoginResult:
        """Async twin of :meth:`login`, on the same client/session (SC#1)."""
        request = self._session.async_client.build_request(
            "POST", LOGIN_PATH, json=self._login_body(email, password)
        )
        response = await self._session._send_async(request)
        return self._handle_login_response(response)

    def verify_mfa(self, mfa_token: Any, code: str) -> LoginResult:
        """``POST /api/v1/auth/mfa/verify`` (CONTRACT.md §1) — completes the
        two-phase flow started by :meth:`login` when ``mfa_required`` was
        true."""
        request = self._session.sync_client.build_request(
            "POST", MFA_VERIFY_PATH, json=self._mfa_verify_body(mfa_token, code)
        )
        response = self._session._send_sync(request)
        return self._handle_login_response(response)

    async def async_verify_mfa(self, mfa_token: Any, code: str) -> LoginResult:
        """Async twin of :meth:`verify_mfa`."""
        request = self._session.async_client.build_request(
            "POST", MFA_VERIFY_PATH, json=self._mfa_verify_body(mfa_token, code)
        )
        response = await self._session._send_async(request)
        return self._handle_login_response(response)

    def _login_body(self, email: str, password: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "tenant_slug": self._session.tenant_slug,
            "username_or_email": email,
            "password": password,
        }
        if self._org_id:
            body["org_id"] = self._org_id
        elif self._org_slug:
            body["org_slug"] = self._org_slug
        return body

    def _mfa_verify_body(self, mfa_token: Any, code: str) -> dict[str, str]:
        token_value = (
            mfa_token.get_secret_value() if hasattr(mfa_token, "get_secret_value") else mfa_token
        )
        return {"challenge_token": token_value, "totp_code": code}

    def _handle_login_response(self, response: httpx.Response) -> LoginResult:
        if response.status_code == httpx.codes.OK:
            wire = response.json()
            result = LoginResult(
                mfa_required=False,
                user_id=wire.get("user", {}).get("id"),
                tenant_id=self._session.tenant_slug,
                session_id=wire.get("session_id"),
                expires_in=wire.get("expires_in"),
            )
            self._absorb_session_cookies()
            return result
        if response.status_code == httpx.codes.ACCEPTED:
            wire = response.json()
            return LoginResult(
                mfa_required=True,
                mfa_token=wire.get("challenge_token"),
            )
        # D-15: log the failure with status code only — never the request
        # body, response body, or any token/credential value.
        self._logger.warning("axiam_sdk: login/verify_mfa failed: status=%s", response.status_code)
        raise error_from_http_status(
            response.status_code, "login/verify_mfa failed", response=response
        )

    def _absorb_session_cookies(self) -> None:
        """Read the access/refresh tokens the server just set via
        Set-Cookie (already captured by the shared cookie jar), decode the
        access token's org_id claim (Pitfall 3) and cache it, and seed the
        refresh guard so a subsequent 401 has the correct observed
        baseline."""
        access = self._session.cookie_value(ACCESS_COOKIE)
        if not access:
            raise AuthError("server response did not set the axiam_access cookie")
        refresh = self._session.cookie_value(REFRESH_COOKIE)

        claims = _decode_unverified_claims(access)
        org_id_claim = claims.get("org_id")
        if org_id_claim:
            self._set_resolved_org_id(org_id_claim)

        self._session.refresh_guard.seed(access, refresh, claims.get("exp"))

    # ------------------------------------------------------------------
    # refresh (sync + async) — exactly one literal /api/v1/auth/refresh
    # POST, routed through the single-flight guard (Pitfall 4, §9.3)
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """``POST /api/v1/auth/refresh`` (CONTRACT.md §1), routed through
        the shared single-flight guard (§9) so concurrent 401s collapse
        into exactly one in-flight refresh call. A 401 on the refresh call
        itself is ``AuthError`` with no retry (§9.3, Pitfall 4)."""
        observed_access = self._session.cookie_value(ACCESS_COOKIE)
        if not observed_access:
            raise AuthError("no access token to refresh — call login() first")

        tenant_id, org_id = self._refresh_identifiers(observed_access)
        # D-15: diagnostic-only, never a token value. Off by default
        # (NullHandler); integrates with the consuming app's logging config.
        self._logger.debug("axiam_sdk: token refresh triggered")
        self._session.refresh_guard.refresh_if_needed_sync(
            observed_access, lambda: self._do_refresh_sync(tenant_id, org_id)
        )

    async def async_refresh(self) -> None:
        """Async twin of :meth:`refresh`."""
        observed_access = self._session.cookie_value(ACCESS_COOKIE)
        if not observed_access:
            raise AuthError("no access token to refresh — call async_login() first")

        tenant_id, org_id = self._refresh_identifiers(observed_access)
        self._logger.debug("axiam_sdk: token refresh triggered")
        await self._session.refresh_guard.refresh_if_needed_async(
            observed_access, lambda: self._do_refresh_async(tenant_id, org_id)
        )

    def _refresh_identifiers(self, observed_access: str) -> tuple[str, str]:
        claims = _decode_unverified_claims(observed_access)
        tenant_id = claims.get("tenant_id")
        if not tenant_id:
            raise AuthError("tenant_id could not be resolved from the access token")
        org_id = self.resolved_org_id() or claims.get("org_id")
        if not org_id:
            raise AuthError(
                "org_id could not be resolved; login() must succeed before refresh() — "
                "supply org_id/org_slug or call login() first"
            )
        return tenant_id, org_id

    def _refresh_body(self, tenant_id: str, org_id: str) -> dict[str, str]:
        return {"tenant_id": tenant_id, "org_id": org_id}

    def _do_refresh_sync(self, tenant_id: str, org_id: str) -> dict[str, Any]:
        # The literal /api/v1/auth/refresh path is required so the
        # Path-scoped axiam_refresh cookie attaches (Pitfall 4).
        request = self._session.sync_client.build_request(
            "POST", "/api/v1/auth/refresh", json=self._refresh_body(tenant_id, org_id)
        )
        response = self._session._send_sync(request)
        return self._handle_refresh_response(response)

    async def _do_refresh_async(self, tenant_id: str, org_id: str) -> dict[str, Any]:
        request = self._session.async_client.build_request(
            "POST", "/api/v1/auth/refresh", json=self._refresh_body(tenant_id, org_id)
        )
        response = await self._session._send_async(request)
        return self._handle_refresh_response(response)

    def _handle_refresh_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code != httpx.codes.OK:
            # §9.3: no retry loop on refresh failure — propagate as-is.
            # D-15: status code only, never a token value.
            self._logger.warning("axiam_sdk: token refresh failed: status=%s", response.status_code)
            raise error_from_http_status(response.status_code, "refresh failed", response=response)

        new_access = self._session.cookie_value(ACCESS_COOKIE)
        if not new_access:
            raise AuthError("refresh response did not set axiam_access")
        new_refresh = self._session.cookie_value(REFRESH_COOKIE)
        claims = _decode_unverified_claims(new_access)
        return {"access": new_access, "refresh": new_refresh, "exp": claims.get("exp")}

    # ------------------------------------------------------------------
    # logout (sync + async)
    # ------------------------------------------------------------------

    def logout(self) -> None:
        """``POST /api/v1/auth/logout`` (CONTRACT.md §1)."""
        session_id = self._session_id_for_logout()
        request = self._session.sync_client.build_request(
            "POST", LOGOUT_PATH, json={"session_id": session_id}
        )
        response = self._session._send_sync(request)
        if response.status_code >= 300:
            raise error_from_http_status(response.status_code, "logout failed", response=response)
        self._session.refresh_guard = type(self._session.refresh_guard)()

    async def async_logout(self) -> None:
        """Async twin of :meth:`logout`."""
        session_id = self._session_id_for_logout()
        request = self._session.async_client.build_request(
            "POST", LOGOUT_PATH, json={"session_id": session_id}
        )
        response = await self._session._send_async(request)
        if response.status_code >= 300:
            raise error_from_http_status(response.status_code, "logout failed", response=response)
        self._session.refresh_guard = type(self._session.refresh_guard)()

    def _session_id_for_logout(self) -> str:
        access = self._session.cookie_value(ACCESS_COOKIE)
        if not access:
            raise AuthError("no active session to log out")
        claims = _decode_unverified_claims(access)
        jti = claims.get("jti")
        if not jti:
            raise AuthError("access token has no session id (jti) to log out")
        return str(jti)

    # ------------------------------------------------------------------
    # REST authz: check_access / can / batch_check (Task 3)
    # ------------------------------------------------------------------

    def check_access(self, action: str, resource_id: str, scope: str | None = None) -> AccessResult:
        """``POST /api/v1/authz/check`` (CONTRACT.md §1)."""
        body = self._access_check_body(action, resource_id, scope)
        wire = self._authz_post_sync(CHECK_PATH, body)
        return AccessResult(**wire)

    async def async_check_access(
        self, action: str, resource_id: str, scope: str | None = None
    ) -> AccessResult:
        """Async twin of :meth:`check_access`."""
        body = self._access_check_body(action, resource_id, scope)
        wire = await self._authz_post_async(CHECK_PATH, body)
        return AccessResult(**wire)

    def can(self, action: str, resource_id: str, scope: str | None = None) -> bool:
        """Alias for ``check_access`` returning only the allowed boolean
        (CONTRACT.md §1 note, browser/UI scenarios)."""
        return self.check_access(action, resource_id, scope).allowed

    async def async_can(self, action: str, resource_id: str, scope: str | None = None) -> bool:
        """Async twin of :meth:`can`."""
        result = await self.async_check_access(action, resource_id, scope)
        return result.allowed

    def batch_check(self, checks: list[AccessCheck]) -> list[AccessResult]:
        """``POST /api/v1/authz/check/batch`` (CONTRACT.md §1) — results
        returned in the same order as ``checks``."""
        body = {"checks": [c.model_dump(exclude_none=True) for c in checks]}
        wire = self._authz_post_sync(BATCH_CHECK_PATH, body)
        return BatchCheckResult(**wire).results

    async def async_batch_check(self, checks: list[AccessCheck]) -> list[AccessResult]:
        """Async twin of :meth:`batch_check`."""
        body = {"checks": [c.model_dump(exclude_none=True) for c in checks]}
        wire = await self._authz_post_async(BATCH_CHECK_PATH, body)
        return BatchCheckResult(**wire).results

    def _access_check_body(
        self, action: str, resource_id: str, scope: str | None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"action": action, "resource_id": resource_id}
        if scope is not None:
            body["scope"] = scope
        return body

    def _authz_post_sync(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        request = self._session.sync_client.build_request("POST", path, json=body)
        response = self._session._send_sync(request)

        if response.status_code == httpx.codes.UNAUTHORIZED:
            response = self._retry_after_refresh_sync(request)

        if response.status_code < 200 or response.status_code >= 300:
            raise error_from_http_status(
                response.status_code, "authz check failed", response=response
            )
        result: dict[str, Any] = response.json()
        return result

    async def _authz_post_async(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        request = self._session.async_client.build_request("POST", path, json=body)
        response = await self._session._send_async(request)

        if response.status_code == httpx.codes.UNAUTHORIZED:
            response = await self._retry_after_refresh_async(request)

        if response.status_code < 200 or response.status_code >= 300:
            raise error_from_http_status(
                response.status_code, "authz check failed", response=response
            )
        result: dict[str, Any] = response.json()
        return result

    def _retry_after_refresh_sync(self, original_request: httpx.Request) -> httpx.Response:
        """On a 401, refresh exactly once (via the shared single-flight
        guard) then retry the failed authz call exactly once. A second
        failure propagates through the caller's own status check (§9.3, no
        retry loop)."""
        self.refresh()
        retry_request = self._session.sync_client.build_request(
            original_request.method,
            original_request.url,
            content=original_request.content,
            headers={
                k: v
                for k, v in original_request.headers.items()
                if k.lower() not in ("content-length", "x-csrf-token")
            },
        )
        return self._session._send_sync(retry_request)

    async def _retry_after_refresh_async(self, original_request: httpx.Request) -> httpx.Response:
        """Async twin of :meth:`_retry_after_refresh_sync`."""
        await self.async_refresh()
        retry_request = self._session.async_client.build_request(
            original_request.method,
            original_request.url,
            content=original_request.content,
            headers={
                k: v
                for k, v in original_request.headers.items()
                if k.lower() not in ("content-length", "x-csrf-token")
            },
        )
        return await self._session._send_async(retry_request)


def _null_logger() -> logging.Logger:
    """An injectable stdlib logger with a NullHandler attached, OFF by
    default (D-15) — silent unless the consuming app configures logging."""
    logger = logging.getLogger("axiam_sdk")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger
