"""Shared cross-tenant replay-defense regression test (T-19-19, SC#4).

A focused, non-vacuous regression proving the org-wide-JWKS cross-tenant
defense holds identically in BOTH the FastAPI dependency and the Django
middleware: mints two otherwise-identical valid EdDSA tokens differing
ONLY in the ``tenant_id`` claim (one matching the configured tenant, one
not), and asserts:

  - BOTH integrations ACCEPT the matching-tenant token — proving the test
    is non-vacuous (rejection of the mismatched token is specifically due
    to the tenant check, not a broken/malformed token or a broken
    verifier).
  - BOTH integrations REJECT the mismatched-tenant token — proving the
    org-wide-JWKS cross-tenant replay defense (claims["tenant_id"] ==
    configured_tenant, enforced BEFORE any claim is trusted further) holds
    in both surfaces.
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
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

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
from axiam_sdk.fastapi import AxiamUser, require_authenticated_user  # noqa: E402

_CONFIGURED_TENANT = "acme"
_OTHER_TENANT = "other-tenant"


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
def matching_and_mismatched_tokens(eddsa_keypair) -> tuple[str, str]:
    """Two otherwise-identical valid EdDSA tokens differing ONLY in
    tenant_id — one matching the configured tenant, one not."""
    private_key, _jwk_dict = eddsa_keypair
    exp = time.time() + 3600
    matching = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": _CONFIGURED_TENANT, "exp": exp}
    )
    mismatched = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": _OTHER_TENANT, "exp": exp}
    )
    return matching, mismatched


# --- FastAPI ---------------------------------------------------------------


def _make_fastapi_app(verifier: JwksVerifier) -> FastAPI:
    app = FastAPI()
    dependency = require_authenticated_user(verifier, _CONFIGURED_TENANT)

    @app.get("/me")
    async def me(user: AxiamUser = Depends(dependency)):  # noqa: B008 (idiomatic FastAPI DI)
        return {"user_id": user.user_id, "tenant_id": user.tenant_id}

    return app


def test_fastapi_accepts_matching_tenant_and_rejects_mismatched_tenant(
    eddsa_keypair, matching_and_mismatched_tokens
) -> None:
    _private_key, jwk_dict = eddsa_keypair
    matching_token, mismatched_token = matching_and_mismatched_tokens

    verifier = JwksVerifier("https://axiam.example.test")
    endpoint = _FakeJwksEndpoint([jwk_dict])
    endpoint.bind(verifier)

    app = _make_fastapi_app(verifier)
    client = TestClient(app)

    # Non-vacuous: the SAME structurally-valid token, just with the correct
    # tenant_id, MUST be accepted — proving rejection below is specifically
    # due to the tenant mismatch, not a broken token or a broken verifier.
    accepted = client.get("/me", headers={"Authorization": f"Bearer {matching_token}"})
    assert accepted.status_code == 200
    assert accepted.json()["tenant_id"] == _CONFIGURED_TENANT

    rejected = client.get("/me", headers={"Authorization": f"Bearer {mismatched_token}"})
    assert rejected.status_code == 401


# --- Django ------------------------------------------------------------


def _sync_get_response(request: Any) -> HttpResponse:
    return HttpResponse(f"ok:{getattr(request, 'axiam_user', None)}")


def test_django_accepts_matching_tenant_and_rejects_mismatched_tenant(
    eddsa_keypair, matching_and_mismatched_tokens, monkeypatch
) -> None:
    _private_key, jwk_dict = eddsa_keypair
    matching_token, mismatched_token = matching_and_mismatched_tokens

    endpoint = _FakeJwksEndpoint([jwk_dict])
    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        real_init(self, base_url, **kwargs)
        endpoint.bind(self)

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)

    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    # Non-vacuous: the SAME structurally-valid token, just with the correct
    # tenant_id, MUST be accepted.
    accepted_request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {matching_token}")
    accepted_response = middleware(accepted_request)
    assert accepted_response.status_code == 200
    assert accepted_request.axiam_user.tenant_id == _CONFIGURED_TENANT

    rejected_request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {mismatched_token}")
    rejected_response = middleware(rejected_request)
    assert rejected_response.status_code == 401
    assert not hasattr(rejected_request, "axiam_user")
