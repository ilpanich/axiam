"""AsyncAxiamClient — the AXIAM SDK's dedicated async REST surface (SDK-Q08).

A SEPARATE class from the sync :class:`~axiam_sdk.AxiamClient` (D-01/D-19,
CONTRACT.md §1 note on SDK-Q08's ruling): exposes the canonical operation
names (``login``, ``verify_mfa``, ``refresh``, ``logout``, ``check_access``,
``can``, ``batch_check``) as ``async def`` — NOT as ``async_*`` twins on the
sync client. Shares :class:`axiam_sdk._client._AxiamClientBase`'s
construction/body-building/response-parsing logic (one ``_Session``: cookie
jar, CSRF state, tenant/org context, refresh guard) with ``AxiamClient``; only
the transport (async httpx client) and the single-flight async refresh-guard
call path are specific to this class. Mirrors ``sdks/go/client.go`` +
``sdks/go/login.go`` + ``sdks/go/authz.go``, adapted to Python's async idiom.
"""

from __future__ import annotations

from typing import Any

import httpx

from axiam_sdk._client import (
    ACCESS_COOKIE,
    BATCH_CHECK_PATH,
    CHECK_PATH,
    LOGIN_PATH,
    LOGOUT_PATH,
    MFA_VERIFY_PATH,
    _AxiamClientBase,
)
from axiam_sdk._errors import AuthError, error_from_http_status
from axiam_sdk._models import AccessCheck, AccessResult, BatchCheckResult, LoginResult


class AsyncAxiamClient(_AxiamClientBase):
    """The AXIAM SDK's dedicated async REST entry point (CONTRACT.md §1-§10,
    SDK-Q08).

    ``await client.login(...)`` returns a typed
    :class:`~axiam_sdk._models.LoginResult` with ``mfa_required`` (SC#1) — the
    same contract as the sync :class:`~axiam_sdk.AxiamClient`, on its own
    dedicated async object. Constructing both an ``AxiamClient`` and an
    ``AsyncAxiamClient`` against the same ``base_url``/``tenant_slug`` gives
    each its own independent ``_Session`` (cookie jar, CSRF state, refresh
    guard) — the two classes do NOT share session state with each other, only
    each shares consistently within its own sync or async call path.
    """

    # ------------------------------------------------------------------
    # Lifecycle (D-19)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> AsyncAxiamClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the async httpx client, if constructed (D-19)."""
        await self._session.aclose()

    # ------------------------------------------------------------------
    # login / verify_mfa
    # ------------------------------------------------------------------

    async def login(self, email: str, password: str) -> LoginResult:
        """``POST /api/v1/auth/login`` (CONTRACT.md §1). Returns a typed
        :class:`LoginResult`; check ``mfa_required`` before assuming the
        session is established (SC#1)."""
        request = self._session.async_client.build_request(
            "POST", LOGIN_PATH, json=self._login_body(email, password)
        )
        response = await self._session._send_async(request)
        return self._handle_login_response(response)

    async def verify_mfa(self, mfa_token: Any, code: str) -> LoginResult:
        """``POST /api/v1/auth/mfa/verify`` (CONTRACT.md §1) — completes the
        two-phase flow started by :meth:`login` when ``mfa_required`` was
        true."""
        request = self._session.async_client.build_request(
            "POST", MFA_VERIFY_PATH, json=self._mfa_verify_body(mfa_token, code)
        )
        response = await self._session._send_async(request)
        return self._handle_login_response(response)

    # ------------------------------------------------------------------
    # refresh — exactly one literal /api/v1/auth/refresh POST, routed
    # through the single-flight guard (Pitfall 4, §9.3)
    # ------------------------------------------------------------------

    async def refresh(self) -> None:
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
        await self._session.refresh_guard.refresh_if_needed_async(
            observed_access, lambda: self._do_refresh_async(tenant_id, org_id)
        )

    async def _do_refresh_async(self, tenant_id: str, org_id: str) -> dict[str, Any]:
        # The literal /api/v1/auth/refresh path is required so the
        # Path-scoped axiam_refresh cookie attaches (Pitfall 4).
        request = self._session.async_client.build_request(
            "POST", "/api/v1/auth/refresh", json=self._refresh_body(tenant_id, org_id)
        )
        response = await self._session._send_async(request)
        return self._handle_refresh_response(response)

    # ------------------------------------------------------------------
    # logout
    # ------------------------------------------------------------------

    async def logout(self) -> None:
        """``POST /api/v1/auth/logout`` (CONTRACT.md §1)."""
        session_id = self._session_id_for_logout()
        request = self._session.async_client.build_request(
            "POST", LOGOUT_PATH, json={"session_id": session_id}
        )
        response = await self._session._send_async(request)
        if response.status_code >= 300:
            raise error_from_http_status(response.status_code, "logout failed", response=response)
        self._session.refresh_guard = type(self._session.refresh_guard)()

    # ------------------------------------------------------------------
    # REST authz: check_access / can / batch_check
    # ------------------------------------------------------------------

    async def check_access(
        self, action: str, resource_id: str, scope: str | None = None
    ) -> AccessResult:
        """``POST /api/v1/authz/check`` (CONTRACT.md §1)."""
        body = self._access_check_body(action, resource_id, scope)
        wire = await self._authz_post_async(CHECK_PATH, body)
        return AccessResult(**wire)

    async def can(self, action: str, resource_id: str, scope: str | None = None) -> bool:
        """Alias for ``check_access`` returning only the allowed boolean
        (CONTRACT.md §1 note, browser/UI scenarios)."""
        result = await self.check_access(action, resource_id, scope)
        return result.allowed

    async def batch_check(self, checks: list[AccessCheck]) -> list[AccessResult]:
        """``POST /api/v1/authz/check/batch`` (CONTRACT.md §1) — results
        returned in the same order as ``checks``."""
        body = {"checks": [c.model_dump(exclude_none=True) for c in checks]}
        wire = await self._authz_post_async(BATCH_CHECK_PATH, body)
        return BatchCheckResult(**wire).results

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

    async def _retry_after_refresh_async(self, original_request: httpx.Request) -> httpx.Response:
        """On a 401, refresh exactly once (via the shared single-flight
        guard) then retry the failed authz call exactly once. A second
        failure propagates through the caller's own status check (§9.3, no
        retry loop)."""
        await self.refresh()
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
