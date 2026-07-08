"""Regression tests for the FastAPI ``Depends(...)`` dependency (D-09, SC#4).

Reuses the in-test Ed25519 keypair + mock JWKS pattern from
``test_jwks.py``: a real Ed25519 keypair is generated in-test and bound
onto the verifier's internal ``PyJWKClient.fetch_data`` so no real network
fetch is ever attempted.

Verifies:
  - a valid same-tenant EdDSA token yields 200 + the injected identity;
  - a missing token yields 401;
  - an expired (but signature-valid) token yields 401 (the dependency
    checks ``exp`` independently of the verifier, which does not);
  - a signature-valid token whose ``tenant_id`` does not match the
    configured tenant yields 401 (cross-tenant replay defense, T-19-19);
  - no raw token value ever appears in a raised ``HTTPException`` detail.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from axiam_sdk._jwks import JwksVerifier
from axiam_sdk.fastapi import AxiamUser, require_authenticated_user


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
def verifier_and_endpoint(eddsa_keypair) -> tuple[JwksVerifier, _FakeJwksEndpoint]:
    _private_key, jwk_dict = eddsa_keypair
    verifier = JwksVerifier("https://axiam.example.test")
    endpoint = _FakeJwksEndpoint([jwk_dict])
    endpoint.bind(verifier)
    return verifier, endpoint


def _make_app(verifier: JwksVerifier, configured_tenant: str = "acme") -> FastAPI:
    app = FastAPI()
    dependency = require_authenticated_user(verifier, configured_tenant)

    @app.get("/me")
    async def me(user: AxiamUser = Depends(dependency)):  # noqa: B008 (idiomatic FastAPI DI)
        return {"user_id": user.user_id, "tenant_id": user.tenant_id, "roles": user.roles}

    return app


def test_valid_same_tenant_token_yields_200_and_identity(
    eddsa_keypair, verifier_and_endpoint
) -> None:
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    client = TestClient(app)

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "acme", "scope": "read write", "exp": time.time() + 3600},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == "user-1"
    assert body["tenant_id"] == "acme"
    assert body["roles"] == ["read", "write"]


def test_missing_token_yields_401(verifier_and_endpoint) -> None:
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier)
    client = TestClient(app)

    response = client.get("/me")

    assert response.status_code == 401


def test_expired_token_yields_401(eddsa_keypair, verifier_and_endpoint) -> None:
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    client = TestClient(app)

    expired_token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "acme", "exp": time.time() - 3600},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {expired_token}"})

    assert response.status_code == 401


def test_non_numeric_exp_yields_401_not_500(eddsa_keypair, verifier_and_endpoint) -> None:
    """SDK-11: a signature-valid token whose ``exp`` claim is non-numeric
    (e.g. a string) must degrade to the standardized 401, never an unhandled
    500 from ``float(exp)`` raising outside the verify try/except."""
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    # raise_server_exceptions=False so a would-be 500 surfaces as a response.
    client = TestClient(app, raise_server_exceptions=False)

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "acme", "exp": "not-a-number"},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code != 500
    assert response.status_code == 401


def test_cross_tenant_token_is_rejected(eddsa_keypair, verifier_and_endpoint) -> None:
    """A signature-valid token whose tenant_id does not match the
    configured tenant MUST be rejected (T-19-19, cross-tenant replay
    defense — the JWKS is organization-wide, not tenant-scoped)."""
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    client = TestClient(app)

    other_tenant_token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "other-tenant", "exp": time.time() + 3600},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {other_tenant_token}"})

    assert response.status_code == 401


def test_scope_null_does_not_500(eddsa_keypair, verifier_and_endpoint) -> None:
    """WR-02: a signature-valid token whose ``scope`` claim is explicitly
    JSON ``null`` (present, not absent) must NOT raise an unhandled 500 from
    ``list(None)``. We normalize null scope to empty roles — identical to how
    an absent scope is handled — so the request succeeds (200) with empty
    roles rather than crashing. The critical WR-02 assertion is: never a 500.
    """
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    # raise_server_exceptions=False so a would-be 500 surfaces as a response,
    # not a re-raised exception, proving we truly do not 500.
    client = TestClient(app, raise_server_exceptions=False)

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "acme", "scope": None, "exp": time.time() + 3600},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code != 500
    assert response.status_code == 200
    assert response.json()["roles"] == []


def test_scope_absent_yields_empty_roles(eddsa_keypair, verifier_and_endpoint) -> None:
    """Control for WR-02: an absent scope claim yields an empty roles list
    (200), confirming null and absent are handled identically."""
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    client = TestClient(app)

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "acme", "exp": time.time() + 3600},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["roles"] == []


def test_cookie_fallback_extraction(eddsa_keypair, verifier_and_endpoint) -> None:
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    client = TestClient(app)

    token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "acme", "exp": time.time() + 3600},
    )
    client.cookies.set("axiam_access", token)

    response = client.get("/me")

    assert response.status_code == 200
    assert response.json()["user_id"] == "user-1"


def test_no_token_value_in_exception_detail(eddsa_keypair, verifier_and_endpoint) -> None:
    """No raw token value may appear in any raised HTTPException detail
    (T-19-21)."""
    private_key, _jwk_dict = eddsa_keypair
    verifier, _endpoint = verifier_and_endpoint
    app = _make_app(verifier, configured_tenant="acme")
    client = TestClient(app)

    other_tenant_token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "other-tenant", "exp": time.time() + 3600},
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {other_tenant_token}"})

    assert response.status_code == 401
    assert other_tenant_token not in response.text

    expired_token = _sign_eddsa_token(
        private_key,
        "test-kid-1",
        {"sub": "user-1", "tenant_id": "acme", "exp": time.time() - 3600},
    )
    response = client.get("/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert expired_token not in response.text
