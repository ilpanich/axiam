"""AxiamClient regression tests (Task 2/3, SC#1, D-01/D-19, Pitfall 3/4).

Uses ``respx`` to mock ``/api/v1/auth/login``, ``/mfa/verify``,
``/api/v1/auth/refresh``, and the REST authz endpoints — proving BOTH
``client.login(...)`` and ``await client.async_login(...)`` return a typed
``LoginResult`` with ``mfa_required`` (SC#1 literal), the two-phase MFA
flow, org_id/tenant_id enforcement, single-flight 401-retry-once authz, and
context-manager cleanup.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from axiam_sdk import AuthError, AuthzError, AxiamClient, LoginResult

BASE_URL = "https://example.test"


def _make_access_token(
    *,
    sub: str = "user-1",
    tenant_id: str = "tenant-uuid-1",
    org_id: str = "org-uuid-1",
    jti: str = "session-uuid-1",
    exp: int = 9999999999,
) -> str:
    """A structurally-valid (unsigned) JWT for exercising the client's
    unverified claim decode — signature verification is out of scope for
    this transport-layer test (covered by ``_jwks.py``'s own tests)."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"sub": sub, "tenant_id": tenant_id, "org_id": org_id, "jti": jti, "exp": exp}
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fake-signature"


def _set_cookie_header(name: str, value: str, path: str = "/") -> tuple[str, str]:
    return ("Set-Cookie", f"{name}={value}; Path={path}; HttpOnly")


# ---------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------


def test_empty_tenant_slug_raises_at_construction() -> None:
    with pytest.raises(AuthError):
        AxiamClient(base_url=BASE_URL, tenant_slug="")


def test_missing_tenant_slug_raises_at_construction() -> None:
    with pytest.raises(TypeError):
        AxiamClient(base_url=BASE_URL)  # type: ignore[call-arg]


def test_org_slug_and_org_id_are_mutually_exclusive() -> None:
    with pytest.raises(AuthError):
        AxiamClient(
            base_url=BASE_URL,
            tenant_slug="acme",
            org_slug="acme-org",
            org_id="org-uuid-1",
        )


# ---------------------------------------------------------------------
# login (sync + async) — SC#1 literal target
# ---------------------------------------------------------------------


def test_sync_login_returns_login_result_with_mfa_required(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "session-uuid-1", "expires_in": 900},
            headers=[
                _set_cookie_header("axiam_access", access),
                _set_cookie_header("axiam_refresh", "refresh-token-1", path="/api/v1/auth/refresh"),
                ("X-CSRF-Token", "csrf-token-1"),
            ],
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        result = client.login("user@example.com", "password123")

    assert isinstance(result, LoginResult)
    assert result.mfa_required is False
    assert result.session_id == "session-uuid-1"


@pytest.mark.asyncio
async def test_async_login_returns_login_result_with_mfa_required(
    respx_mock: respx.MockRouter,
) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "session-uuid-2", "expires_in": 900},
            headers=[
                _set_cookie_header("axiam_access", access),
                _set_cookie_header("axiam_refresh", "refresh-token-2", path="/api/v1/auth/refresh"),
            ],
        )
    )

    async with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        result = await client.async_login("user@example.com", "password123")

    assert isinstance(result, LoginResult)
    assert result.mfa_required is False
    assert result.session_id == "session-uuid-2"


def test_login_request_body_includes_org_slug(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    route = respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme-org") as client:
        client.login("user@example.com", "password123")

    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body["org_slug"] == "acme-org"
    assert sent_body["tenant_slug"] == "acme"


def test_login_mfa_required_returns_mfa_token(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            202,
            json={
                "mfa_required": True,
                "challenge_token": "challenge-abc",
                "available_methods": ["totp"],
            },
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        result = client.login("user@example.com", "password123")

    assert result.mfa_required is True
    assert result.mfa_token is not None
    assert result.mfa_token.get_secret_value() == "challenge-abc"


def test_verify_mfa_completes_two_phase_flow(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            202,
            json={
                "mfa_required": True,
                "challenge_token": "challenge-xyz",
                "available_methods": ["totp"],
            },
        )
    )
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/mfa/verify'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s2", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        first = client.login("user@example.com", "password123")
        assert first.mfa_required is True
        second = client.verify_mfa(first.mfa_token, "123456")

    assert second.mfa_required is False
    assert second.session_id == "s2"


@pytest.mark.asyncio
async def test_async_verify_mfa_completes_two_phase_flow(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            202,
            json={
                "mfa_required": True,
                "challenge_token": "challenge-async",
                "available_methods": ["totp"],
            },
        )
    )
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/mfa/verify'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s3", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )

    async with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        first = await client.async_login("user@example.com", "password123")
        second = await client.async_verify_mfa(first.mfa_token, "123456")

    assert second.mfa_required is False
    assert second.session_id == "s3"


def test_login_error_response_maps_to_auth_error(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(401, json={"error": "invalid credentials"})
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError):
            client.login("user@example.com", "wrong-password")


# ---------------------------------------------------------------------
# refresh — literal path + single-flight (Pitfall 4, §9.3)
# ---------------------------------------------------------------------


def test_refresh_posts_exact_literal_path(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )
    new_access = _make_access_token(jti="session-uuid-2")
    refresh_route = respx_mock.post(f"{BASE_URL}{'/api/v1/auth/refresh'}").mock(
        return_value=httpx.Response(
            200,
            json={"expires_in": 900},
            headers=[_set_cookie_header("axiam_access", new_access, path="/api/v1/auth/refresh")],
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        client.login("user@example.com", "password123")
        client.refresh()

    assert refresh_route.called
    assert refresh_route.calls.last.request.url.path == "/api/v1/auth/refresh"


def test_refresh_401_raises_auth_error_without_retry(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )
    refresh_route = respx_mock.post(f"{BASE_URL}{'/api/v1/auth/refresh'}").mock(
        return_value=httpx.Response(401, json={"error": "refresh token expired"})
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        client.login("user@example.com", "password123")
        with pytest.raises(AuthError):
            client.refresh()

    assert refresh_route.call_count == 1


# ---------------------------------------------------------------------
# REST authz: check_access / can / batch_check + 401 single-flight retry
# (Task 3)
# ---------------------------------------------------------------------


def _login_and_get_client(respx_mock: respx.MockRouter, base_url: str = BASE_URL) -> AxiamClient:
    access = _make_access_token()
    respx_mock.post(f"{base_url}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )
    client = AxiamClient(base_url=base_url, tenant_slug="acme")
    client.login("user@example.com", "password123")
    return client


def test_check_access_returns_access_result(respx_mock: respx.MockRouter) -> None:
    client = _login_and_get_client(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )

    result = client.check_access("users:read", "user-42")

    assert result.allowed is True


def test_can_returns_bool(respx_mock: respx.MockRouter) -> None:
    client = _login_and_get_client(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": "denied"})
    )

    allowed = client.can("users:delete", "user-42")

    assert allowed is False


def test_batch_check_returns_ordered_results(respx_mock: respx.MockRouter) -> None:
    client = _login_and_get_client(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check/batch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"allowed": True, "reason": None},
                    {"allowed": False, "reason": "denied"},
                ]
            },
        )
    )

    from axiam_sdk import AccessCheck

    results = client.batch_check(
        [
            AccessCheck(action="users:read", resource_id="user-1"),
            AccessCheck(action="users:delete", resource_id="user-2"),
        ]
    )

    assert [r.allowed for r in results] == [True, False]


def test_authz_401_triggers_exactly_one_refresh_and_one_retry(
    respx_mock: respx.MockRouter,
) -> None:
    client = _login_and_get_client(respx_mock)

    new_access = _make_access_token(jti="session-uuid-refreshed")
    refresh_route = respx_mock.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
        return_value=httpx.Response(
            200,
            json={"expires_in": 900},
            headers=[_set_cookie_header("axiam_access", new_access, path="/api/v1/auth/refresh")],
        )
    )

    check_route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check")
    check_route.side_effect = [
        httpx.Response(401, json={"error": "token expired"}),
        httpx.Response(200, json={"allowed": True, "reason": None}),
    ]

    result = client.check_access("users:read", "user-42")

    assert result.allowed is True
    assert refresh_route.call_count == 1
    assert check_route.call_count == 2


def test_authz_403_raises_authz_error(respx_mock: respx.MockRouter) -> None:
    client = _login_and_get_client(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )

    with pytest.raises(AuthzError):
        client.check_access("users:delete", "user-42")


@pytest.mark.asyncio
async def test_async_check_access_shares_session_with_sync_login(
    respx_mock: respx.MockRouter,
) -> None:
    """Sync login() then async_check_access() on the same client must
    reuse the session cookie (SC-adjacent: cross-paradigm session share)."""
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )
    check_route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )

    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    client.login("user@example.com", "password123")
    result = await client.async_check_access("users:read", "user-42")

    assert result.allowed is True
    sent_request = check_route.calls.last.request
    assert "axiam_access" in sent_request.headers.get("cookie", "")


# ---------------------------------------------------------------------
# Public import surface
# ---------------------------------------------------------------------


def test_public_import_surface() -> None:
    from axiam_sdk import (  # noqa: F401
        AuthError,
        AuthzError,
        AxiamClient,
        LoginResult,
        NetworkError,
    )


# ---------------------------------------------------------------------
# IN-02: _decode_unverified_claims payload-shape validation
# ---------------------------------------------------------------------


def _token_with_payload(payload_obj: object) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(payload_obj).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fake-signature"


def test_decode_unverified_claims_rejects_non_dict_array_payload() -> None:
    """IN-02: a token whose payload segment decodes to valid JSON that is NOT
    an object (e.g. an array) must raise a clean AuthError, not the
    AttributeError a caller's ``.get(...)`` would otherwise raise."""
    from axiam_sdk._client import _decode_unverified_claims

    token = _token_with_payload([1, 2, 3])
    with pytest.raises(AuthError, match="not a JSON object"):
        _decode_unverified_claims(token)


def test_decode_unverified_claims_rejects_non_dict_scalar_payload() -> None:
    """IN-02: a scalar (e.g. a JSON number/string) payload also raises
    AuthError rather than propagating an AttributeError downstream."""
    from axiam_sdk._client import _decode_unverified_claims

    for scalar in (42, "just-a-string", True):
        token = _token_with_payload(scalar)
        with pytest.raises(AuthError, match="not a JSON object"):
            _decode_unverified_claims(token)


def test_decode_unverified_claims_accepts_object_payload() -> None:
    """Control for IN-02: a normal JSON-object payload still decodes to the
    claims dict, so the shape check does not over-reject."""
    from axiam_sdk._client import _decode_unverified_claims

    token = _token_with_payload({"sub": "user-1", "tenant_id": "acme"})
    claims = _decode_unverified_claims(token)
    assert claims["sub"] == "user-1"
    assert claims["tenant_id"] == "acme"


# ---------------------------------------------------------------------
# IN-01 (D-15): injectable stdlib logger actually logs lifecycle events,
# and NEVER logs a token/secret value.
# ---------------------------------------------------------------------


class _CapturingHandler:
    """A minimal logging.Handler that records every emitted message (fully
    formatted, so any %-args are interpolated into the final string)."""

    def __init__(self) -> None:
        import logging

        self.records: list[str] = []

        handler = self

        class _H(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                handler.records.append(record.getMessage())

        self._handler = _H()
        self._handler.setLevel(logging.DEBUG)

    @property
    def handler(self) -> object:
        return self._handler

    def joined(self) -> str:
        return "\n".join(self.records)


def _logger_with_capture() -> tuple[object, _CapturingHandler]:
    import logging

    cap = _CapturingHandler()
    logger = logging.getLogger("axiam_sdk.test.in01")
    logger.handlers.clear()
    logger.addHandler(cap.handler)  # type: ignore[arg-type]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, cap


def test_logger_logs_refresh_lifecycle_without_token_values(
    respx_mock: respx.MockRouter,
) -> None:
    """IN-01/D-15: the injectable logger logs the refresh lifecycle event,
    and the raw access/refresh token values never appear in any emitted log
    record."""
    logger, cap = _logger_with_capture()

    access = _make_access_token()
    new_access = _make_access_token(jti="session-uuid-2")
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )
    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/refresh'}").mock(
        return_value=httpx.Response(
            200,
            json={"expires_in": 900},
            headers=[_set_cookie_header("axiam_access", new_access, path="/api/v1/auth/refresh")],
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme", logger=logger) as client:  # type: ignore[arg-type]
        client.login("user@example.com", "password123")
        client.refresh()

    logged = cap.joined()
    # A lifecycle event was actually logged (D-15 feature is wired, not inert).
    assert "refresh triggered" in logged
    # No raw token value ever appears in any log record (redaction guarantee).
    assert access not in logged
    assert new_access not in logged


def test_logger_logs_login_failure_status_without_secrets(
    respx_mock: respx.MockRouter,
) -> None:
    """IN-01/D-15: a login failure is logged with the status code only —
    never the submitted password or any response body/token value."""
    logger, cap = _logger_with_capture()

    respx_mock.post(f"{BASE_URL}{'/api/v1/auth/login'}").mock(
        return_value=httpx.Response(401, json={"error": "invalid credentials"})
    )

    secret_password = "SUPER-SECRET-PASSWORD-123"
    with AxiamClient(base_url=BASE_URL, tenant_slug="acme", logger=logger) as client:  # type: ignore[arg-type]
        with pytest.raises(AuthError):
            client.login("user@example.com", secret_password)

    logged = cap.joined()
    assert "login/verify_mfa failed" in logged
    assert "status=401" in logged
    assert secret_password not in logged


def test_logger_is_off_by_default_null_handler() -> None:
    """IN-01/D-15: with no logger injected, the default logger has a
    NullHandler so the SDK is silent unless the app configures logging."""
    import logging

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        default_logger = client._logger
    assert any(isinstance(h, logging.NullHandler) for h in default_logger.handlers)
