"""Regression tests for AxiamAuthMiddleware (D-10, SC#4).

Configures minimal Django settings in-test, instantiates the middleware
with both a sync ``get_response`` fake and an async fake, and reuses the
in-test Ed25519 keypair + mock JWKS pattern from ``test_jwks.py`` (no real
network fetch is ever attempted).

Verifies:
  - a valid same-tenant token attaches ``request.axiam_user`` and calls
    through to ``get_response`` (both sync and async dispatch paths);
  - a missing token yields a standardized 401 JSON response;
  - a signature-valid cross-tenant token yields 401 (cross-tenant replay
    defense, T-19-19);
  - ``request.axiam_user`` is populated with user_id/tenant_id/roles on
    success.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import django
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings as django_settings
from django.http import HttpResponse
from django.test import RequestFactory

if not django_settings.configured:
    django_settings.configure(
        DEBUG=True,
        USE_TZ=True,
        AXIAM_JWKS_BASE_URL="https://axiam.example.test",
        AXIAM_TENANT_SLUG="acme",
    )
    django.setup()

from axiam_sdk._jwks import JwksVerifier  # noqa: E402
from axiam_sdk.django.middleware import AxiamAuthMiddleware  # noqa: E402


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ed25519_keypair_and_jwk(kid: str) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk_dict = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }
    return private_key, jwk_dict


def _sign_eddsa_token(private_key: Ed25519PrivateKey, kid: str, claims: dict[str, Any]) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": kid})


class _FakeJwksEndpoint:
    def __init__(self, jwk_dicts: list[dict[str, Any]]) -> None:
        self.jwk_dicts = jwk_dicts
        self.call_count = 0

    def bind(self, verifier: JwksVerifier) -> None:
        verifier._client.fetch_data = self._fetch_data  # type: ignore[method-assign]

    def _fetch_data(self) -> dict[str, Any]:
        self.call_count += 1
        return {"keys": self.jwk_dicts}


@pytest.fixture
def eddsa_keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return _make_ed25519_keypair_and_jwk("test-kid-1")


@pytest.fixture
def bound_verifier(eddsa_keypair, monkeypatch) -> JwksVerifier:
    """Bind the fake JWKS endpoint onto the middleware's real, per-instance
    verifier (constructed inside __init__ from settings) via a monkeypatch
    of JwksVerifier.__init__ so no real network fetch ever happens."""
    _private_key, jwk_dict = eddsa_keypair
    endpoint = _FakeJwksEndpoint([jwk_dict])

    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        real_init(self, base_url, **kwargs)
        endpoint.bind(self)

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)
    return endpoint  # type: ignore[return-value]


def _sync_get_response(request: Any) -> HttpResponse:
    return HttpResponse(f"ok:{getattr(request, 'axiam_user', None)}")


async def _async_get_response(request: Any) -> HttpResponse:
    return HttpResponse(f"ok:{getattr(request, 'axiam_user', None)}")


def test_valid_same_tenant_token_attaches_axiam_user_sync(eddsa_keypair, bound_verifier) -> None:
    private_key, _jwk_dict = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "acme", "exp": time.time() + 3600}
    )
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    response = middleware(request)

    assert response.status_code == 200
    assert request.axiam_user.user_id == "user-1"
    assert request.axiam_user.tenant_id == "acme"


@pytest.mark.asyncio
async def test_valid_same_tenant_token_attaches_axiam_user_async(
    eddsa_keypair, bound_verifier
) -> None:
    private_key, _jwk_dict = eddsa_keypair
    middleware = AxiamAuthMiddleware(_async_get_response)
    factory = RequestFactory()

    token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "acme", "exp": time.time() + 3600}
    )
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    response = await middleware(request)

    assert response.status_code == 200
    assert request.axiam_user.user_id == "user-1"


def test_missing_token_yields_401_json_sync(bound_verifier) -> None:
    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()
    request = factory.get("/")

    response = middleware(request)

    assert response.status_code == 401
    import json

    body = json.loads(response.content)
    assert body["error"] == "authentication_failed"


@pytest.mark.asyncio
async def test_missing_token_yields_401_json_async(bound_verifier) -> None:
    middleware = AxiamAuthMiddleware(_async_get_response)
    factory = RequestFactory()
    request = factory.get("/")

    response = await middleware(request)

    assert response.status_code == 401


def test_cross_tenant_token_is_rejected_sync(eddsa_keypair, bound_verifier) -> None:
    """A signature-valid token whose tenant_id does not match the
    configured tenant MUST be rejected (T-19-19)."""
    private_key, _jwk_dict = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "other-tenant", "exp": time.time() + 3600},
    )
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    response = middleware(request)

    assert response.status_code == 401
    assert not hasattr(request, "axiam_user")


@pytest.mark.asyncio
async def test_cross_tenant_token_is_rejected_async(eddsa_keypair, bound_verifier) -> None:
    private_key, _jwk_dict = eddsa_keypair
    middleware = AxiamAuthMiddleware(_async_get_response)
    factory = RequestFactory()

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "other-tenant", "exp": time.time() + 3600},
    )
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    response = await middleware(request)

    assert response.status_code == 401


def test_expired_token_yields_401(eddsa_keypair, bound_verifier) -> None:
    private_key, _jwk_dict = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    expired_token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "acme", "exp": time.time() - 3600}
    )
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {expired_token}")

    response = middleware(request)

    assert response.status_code == 401


def test_axiam_user_populated_with_roles(eddsa_keypair, bound_verifier) -> None:
    private_key, _jwk_dict = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {
            "sub": "user-1",
            "tenant_id": "acme",
            "scope": "read write",
            "exp": time.time() + 3600,
        },
    )
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    middleware(request)

    assert request.axiam_user.user_id == "user-1"
    assert request.axiam_user.tenant_id == "acme"
    assert request.axiam_user.roles == ["read", "write"]


def test_cookie_fallback_extraction(eddsa_keypair, bound_verifier) -> None:
    private_key, _jwk_dict = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "acme", "exp": time.time() + 3600}
    )
    request = factory.get("/")
    request.COOKIES["axiam_access"] = token

    response = middleware(request)

    assert response.status_code == 200
    assert request.axiam_user.user_id == "user-1"


def test_sync_capable_and_async_capable_dispatch(bound_verifier) -> None:
    sync_middleware = AxiamAuthMiddleware(_sync_get_response)
    assert sync_middleware.sync_capable is True
    assert sync_middleware.async_capable is True

    from asgiref.sync import iscoroutinefunction

    async_middleware = AxiamAuthMiddleware(_async_get_response)
    assert iscoroutinefunction(async_middleware) is True
