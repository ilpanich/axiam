"""Assumption-A1 regression tests for ``_Session`` (Task 1, CF-01/CF-02/CF-03).

Proves, against the pinned httpx 0.27.x, that the sync and async httpx
clients built by ``_Session`` share ONE underlying cookie jar — a cookie set
via the sync client's jar must be visible via the async client's jar (and
vice versa), since a caller mixing ``client.login()`` (sync) then
``await client.async_check_access()`` (async) on the same ``AxiamClient``
must reuse the session established by the first call.
"""

from __future__ import annotations

import datetime
import http.server
import socket
import ssl
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

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


# --------------------------------------------------------------------------
# WR-05: negative TLS path — prove strict verification actually REJECTS an
# untrusted (self-signed) server certificate, not just that verify=True is
# textually present. A regression that kept `verify` truthy but non-functional
# (or accidentally trusted an arbitrary CA) would let this connection succeed;
# this test would catch it.
# --------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _generate_self_signed_cert() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


class _SelfSignedHttpsServer:
    """An in-process HTTPS server presenting a throwaway self-signed cert
    that is NOT in any system trust store — used only to prove strict TLS
    verification rejects an untrusted certificate."""

    def __init__(self) -> None:
        self.cert_pem, self.key_pem = _generate_self_signed_cert()
        self.port = _free_port()
        self._tmpdir = tempfile.TemporaryDirectory()
        cert_path = Path(self._tmpdir.name) / "cert.pem"
        key_path = Path(self._tmpdir.name) / "key.pem"
        cert_path.write_bytes(self.cert_pem)
        key_path.write_bytes(self.key_pem)
        self.ca_path = str(cert_path)

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args: object) -> None:  # silence test noise
                return

        self._httpd = http.server.HTTPServer(("localhost", self.port), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"https://localhost:{self.port}"

    def __enter__(self) -> _SelfSignedHttpsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)
        self._tmpdir.cleanup()


@pytest.fixture
def self_signed_https_server() -> Iterator[_SelfSignedHttpsServer]:
    with _SelfSignedHttpsServer() as server:
        yield server


def test_untrusted_server_certificate_is_rejected_sync(
    self_signed_https_server: _SelfSignedHttpsServer,
) -> None:
    """WR-05 (REST sync negative path): a _Session with NO custom_ca uses
    verify=True (system trust store), which does not contain the server's
    self-signed cert — so the TLS handshake MUST be rejected."""
    session = _Session(
        base_url=self_signed_https_server.base_url, tenant_slug="acme", custom_ca=None
    )
    assert session._verify is True  # strict verification, no bypass
    try:
        with pytest.raises(httpx.ConnectError) as exc_info:
            request = session.sync_client.build_request("GET", "/")
            session._send_sync(request)
        # The failure must be a certificate-verification failure specifically,
        # proving verification is active (non-vacuous).
        assert (
            "CERTIFICATE_VERIFY_FAILED" in str(exc_info.value)
            or "certificate verify" in str(exc_info.value).lower()
        )
    finally:
        session.close()


@pytest.mark.asyncio
async def test_untrusted_server_certificate_is_rejected_async(
    self_signed_https_server: _SelfSignedHttpsServer,
) -> None:
    """WR-05 (REST async negative path)."""
    session = _Session(
        base_url=self_signed_https_server.base_url, tenant_slug="acme", custom_ca=None
    )
    assert session._verify is True
    try:
        with pytest.raises(httpx.ConnectError) as exc_info:
            request = session.async_client.build_request("GET", "/")
            await session._send_async(request)
        assert (
            "CERTIFICATE_VERIFY_FAILED" in str(exc_info.value)
            or "certificate verify" in str(exc_info.value).lower()
        )
    finally:
        await session.aclose()


def test_custom_ca_allows_self_signed_server_sync(
    self_signed_https_server: _SelfSignedHttpsServer,
) -> None:
    """Control for WR-05: supplying the server's own cert as custom_ca makes
    verification SUCCEED against the same self-signed server — proving the
    rejection above is due to trust, not an unrelated connection failure."""
    session = _Session(
        base_url=self_signed_https_server.base_url,
        tenant_slug="acme",
        custom_ca=self_signed_https_server.ca_path,
    )
    try:
        request = session.sync_client.build_request("GET", "/")
        response = session._send_sync(request)
        assert response.status_code == 200
    finally:
        session.close()
