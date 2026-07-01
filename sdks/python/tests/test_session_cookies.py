"""Assumption-A1 regression tests for ``_Session`` (Task 1, CF-01/CF-02/CF-03).

Proves, against the pinned httpx 0.27.x, that the sync and async httpx
clients built by ``_Session`` share ONE underlying cookie jar — a cookie set
via the sync client's jar must be visible via the async client's jar (and
vice versa), since a caller mixing ``client.login()`` (sync) then
``await client.async_check_access()`` (async) on the same ``AxiamClient``
must reuse the session established by the first call.
"""

from __future__ import annotations

import httpx
import pytest

from axiam_sdk._session import _Session


def test_sync_and_async_clients_share_one_cookie_jar() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")

    sync_client = session.sync_client
    async_client = session.async_client

    assert sync_client.cookies.jar is async_client.cookies.jar


def test_cookie_set_via_sync_client_visible_via_async_client() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")

    session.sync_client.cookies.set("axiam_access", "sync-set-token")

    assert session.async_client.cookies.get("axiam_access") == "sync-set-token"


def test_cookie_set_via_async_client_visible_via_sync_client() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")

    session.async_client.cookies.set("axiam_refresh", "async-set-token")

    assert session.sync_client.cookies.get("axiam_refresh") == "async-set-token"


def test_sync_and_async_clients_are_lazy() -> None:
    """Neither client is constructed until first accessed (paradigm:
    avoid opening a sync connection pool a purely-async caller never
    needs, and vice versa)."""
    session = _Session(base_url="https://example.test", tenant_slug="acme")

    assert session._sync_client is None
    assert session._async_client is None

    _ = session.sync_client
    assert session._sync_client is not None
    assert session._async_client is None

    _ = session.async_client
    assert session._async_client is not None


def test_verify_defaults_to_true_never_false() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")
    assert session._verify is True


def test_custom_ca_is_the_only_verify_override() -> None:
    session = _Session(
        base_url="https://example.test", tenant_slug="acme", custom_ca="/path/to/ca.pem"
    )
    assert session._verify == "/path/to/ca.pem"


def test_prepare_request_sets_x_tenant_id_header() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme-tenant")
    request = httpx.Request("GET", "https://example.test/api/v1/auth/me")

    session._prepare_request(request)

    assert request.headers["X-Tenant-ID"] == "acme-tenant"


def test_prepare_request_echoes_csrf_only_on_state_changing_methods() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")
    session._csrf_token = "captured-csrf-token"

    get_request = httpx.Request("GET", "https://example.test/api/v1/auth/me")
    session._prepare_request(get_request)
    assert "X-CSRF-Token" not in get_request.headers

    post_request = httpx.Request("POST", "https://example.test/api/v1/auth/login")
    session._prepare_request(post_request)
    assert post_request.headers["X-CSRF-Token"] == "captured-csrf-token"


def test_prepare_request_omits_csrf_header_when_none_captured_yet() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")

    post_request = httpx.Request("POST", "https://example.test/api/v1/auth/login")
    session._prepare_request(post_request)

    assert "X-CSRF-Token" not in post_request.headers


def test_capture_csrf_stores_token_from_response_header() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")
    response = httpx.Response(
        200,
        headers={"X-CSRF-Token": "fresh-token-value"},
        request=httpx.Request("POST", "https://example.test/api/v1/auth/login"),
    )

    session._capture_csrf(response)

    assert session._get_csrf_token() == "fresh-token-value"


def test_capture_csrf_ignores_response_without_header() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")
    session._csrf_token = "existing-token"
    response = httpx.Response(
        200, request=httpx.Request("GET", "https://example.test/api/v1/auth/me")
    )

    session._capture_csrf(response)

    assert session._get_csrf_token() == "existing-token"


@pytest.mark.asyncio
async def test_send_async_prepares_and_captures_through_respx(respx_mock: object) -> None:
    import respx

    router: respx.MockRouter = respx_mock  # type: ignore[assignment]
    route = router.post("https://example.test/api/v1/auth/login").mock(
        return_value=httpx.Response(200, json={}, headers={"X-CSRF-Token": "async-captured"})
    )

    session = _Session(base_url="https://example.test", tenant_slug="acme")
    request = session.async_client.build_request("POST", "/api/v1/auth/login", json={})
    response = await session._send_async(request)

    assert route.called
    assert response.status_code == 200
    assert session._get_csrf_token() == "async-captured"
    assert request.headers["X-Tenant-ID"] == "acme"


def test_send_sync_prepares_and_captures_through_respx(respx_mock: object) -> None:
    import respx

    router: respx.MockRouter = respx_mock  # type: ignore[assignment]
    route = router.post("https://example.test/api/v1/auth/login").mock(
        return_value=httpx.Response(200, json={}, headers={"X-CSRF-Token": "sync-captured"})
    )

    session = _Session(base_url="https://example.test", tenant_slug="acme")
    request = session.sync_client.build_request("POST", "/api/v1/auth/login", json={})
    response = session._send_sync(request)

    assert route.called
    assert response.status_code == 200
    assert session._get_csrf_token() == "sync-captured"
    assert request.headers["X-Tenant-ID"] == "acme"


def test_close_only_closes_constructed_sync_client() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")
    # No client constructed yet — close() must be a no-op, not construct one.
    session.close()
    assert session._sync_client is None


@pytest.mark.asyncio
async def test_aclose_only_closes_constructed_async_client() -> None:
    session = _Session(base_url="https://example.test", tenant_slug="acme")
    await session.aclose()
    assert session._async_client is None
