"""Regression tests for JwksVerifier (D-16/CF-07).

Generates a real Ed25519 keypair in-test, serves a mock JWKS by
instance-binding a fake ``fetch_data`` onto the verifier's internal
``PyJWKClient`` (``PyJWKClient`` fetches via ``urllib.request``, not
``httpx``, so this is the correct mock seam — no real network fetch is ever
attempted). Verifies:
  - a validly EdDSA-signed token verifies successfully;
  - an alg:HS256 / alg:none token is rejected BEFORE any JWKS network fetch;
  - an unknown-kid triggers exactly one forced refetch.
"""

from __future__ import annotations

import base64
import json
import threading
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.exceptions import PyJWKSetError

from axiam_sdk._jwks import JWKS_PATH, JwksVerifier


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


@pytest.fixture
def eddsa_keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return _make_ed25519_keypair_and_jwk("test-kid-1")


class _FakeJwksEndpoint:
    """Tracks calls to a fake JWKS fetch, returning a fixed JWKS payload
    (mutable so a test can simulate rotation mid-test). Bound onto a
    ``PyJWKClient`` instance's ``fetch_data`` so no real network fetch ever
    happens."""

    def __init__(self, jwk_dicts: list[dict[str, Any]]) -> None:
        self.jwk_dicts = jwk_dicts
        self.call_count = 0

    def bind(self, verifier: JwksVerifier) -> None:
        verifier._client.fetch_data = self._fetch_data  # type: ignore[method-assign]

    def _fetch_data(self) -> dict[str, Any]:
        self.call_count += 1
        return {"keys": self.jwk_dicts}


def _make_verifier(jwk_dicts: list[dict[str, Any]]) -> tuple[JwksVerifier, _FakeJwksEndpoint]:
    verifier = JwksVerifier("https://axiam.example.test")
    endpoint = _FakeJwksEndpoint(jwk_dicts)
    endpoint.bind(verifier)
    return verifier, endpoint


def test_verify_valid_eddsa_token_succeeds(eddsa_keypair) -> None:
    private_key, jwk_dict = eddsa_keypair
    verifier, endpoint = _make_verifier([jwk_dict])

    token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "tenant-1", "exp": 9999999999}
    )

    claims = verifier.verify(token)

    assert claims["sub"] == "user-1"
    assert claims["tenant_id"] == "tenant-1"
    assert endpoint.call_count == 1


def test_verify_rejects_non_eddsa_alg_before_any_network_fetch(eddsa_keypair) -> None:
    _private_key, jwk_dict = eddsa_keypair
    verifier, endpoint = _make_verifier([jwk_dict])

    # A well-formed HS256 token, signed with an arbitrary secret — must be
    # rejected purely by header inspection, before any keyset lookup.
    hs256_token = jwt.encode(
        {"sub": "attacker", "exp": 9999999999}, "irrelevant-secret", algorithm="HS256"
    )

    with pytest.raises(ValueError, match="only EdDSA is accepted"):
        verifier.verify(hs256_token)

    assert endpoint.call_count == 0, "no JWKS network fetch should occur for a non-EdDSA alg"


def test_verify_rejects_none_alg_before_any_network_fetch(eddsa_keypair) -> None:
    _private_key, jwk_dict = eddsa_keypair
    verifier, endpoint = _make_verifier([jwk_dict])

    # Craft an alg:none token by hand (PyJWT refuses to encode alg=none
    # directly without an explicit opt-in) to simulate an attacker-supplied
    # unsigned token.
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(
        b"="
    )
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "attacker", "exp": 9999999999}).encode()
    ).rstrip(b"=")
    none_token = (header + b"." + payload + b".").decode("ascii")

    with pytest.raises(ValueError, match="only EdDSA is accepted"):
        verifier.verify(none_token)

    assert endpoint.call_count == 0


def test_wrong_key_signature_is_rejected(eddsa_keypair) -> None:
    _private_key, jwk_dict = eddsa_keypair
    verifier, _endpoint = _make_verifier([jwk_dict])

    other_private_key, _other_jwk = _make_ed25519_keypair_and_jwk("test-kid-1")
    forged_token = _sign_eddsa_token(
        other_private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "t1", "exp": 9999999999}
    )

    with pytest.raises(jwt.InvalidSignatureError):
        verifier.verify(forged_token)


def test_unknown_kid_triggers_exactly_one_forced_refetch(eddsa_keypair) -> None:
    """Non-empty keyset that does not (yet) contain the token's kid — the
    literal 'unknown kid' scenario a key rotation produces."""
    private_key, jwk_dict = eddsa_keypair
    _other_private_key, stale_jwk_dict = _make_ed25519_keypair_and_jwk("stale-kid")
    verifier, endpoint = _make_verifier([stale_jwk_dict])

    token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "t1", "exp": 9999999999}
    )

    # PyJWKClient's own get_signing_key already retries once internally on a
    # kid-mismatch (refresh=True) before raising PyJWKClientError — since our
    # fake endpoint always returns the same (stale) keyset, that internal
    # retry also fails, so the wrapper's own forced-refetch-once path is what
    # we exercise below.
    with pytest.raises(jwt.PyJWKClientError):
        verifier.verify(token)
    calls_after_first_attempt = endpoint.call_count
    assert calls_after_first_attempt >= 1

    # Now "rotate" the key into the server-side keyset and retry — the
    # verifier's forced-refetch-once path (rate-limited) should pick it up.
    verifier._last_forced_refetch = None  # bypass the 60s rate limit for this test
    endpoint.jwk_dicts = [jwk_dict]

    claims = verifier.verify(token)
    assert claims["sub"] == "user-1"
    # Exactly one additional forced refetch should have occurred for the
    # successful retry (not an unbounded retry loop).
    assert endpoint.call_count == calls_after_first_attempt + 1


def test_empty_keyset_triggers_forced_refetch(eddsa_keypair) -> None:
    """An entirely empty keyset (e.g. a rotation window where the new key
    has not yet propagated at all) also routes through the same
    forced-refetch-once path, via the broader PyJWTError catch."""
    private_key, jwk_dict = eddsa_keypair
    verifier, endpoint = _make_verifier([])

    token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "t1", "exp": 9999999999}
    )

    with pytest.raises(PyJWKSetError):
        verifier.verify(token)
    calls_after_first_attempt = endpoint.call_count
    assert calls_after_first_attempt >= 1

    verifier._last_forced_refetch = None  # bypass the 60s rate limit for this test
    endpoint.jwk_dicts = [jwk_dict]

    claims = verifier.verify(token)
    assert claims["sub"] == "user-1"
    assert endpoint.call_count == calls_after_first_attempt + 1


def test_concurrent_cache_miss_burst_triggers_exactly_one_fetch(eddsa_keypair) -> None:
    """PERF-03 / D-08-D-09 oracle: 8 concurrent verify() calls against a
    cold cache collapse to exactly one JWKS fetch. The fetch guard makes
    this deterministic regardless of thread-scheduling order — only the
    total fetch count is asserted (never an ordering assumption)."""
    private_key, jwk_dict = eddsa_keypair
    verifier, endpoint = _make_verifier([jwk_dict])

    token = _sign_eddsa_token(
        private_key, "test-kid-1", {"sub": "user-1", "tenant_id": "tenant-1", "exp": 9999999999}
    )

    thread_count = 8
    barrier = threading.Barrier(thread_count)
    results: list[Any] = [None] * thread_count

    def worker(index: int) -> None:
        barrier.wait()
        try:
            results[index] = verifier.verify(token)
        except BaseException as exc:  # noqa: BLE001 - captured for the main thread's assertions
            results[index] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for result in results:
        assert isinstance(
            result, dict
        ), f"every concurrent caller must verify successfully, got {result!r}"
        assert result["sub"] == "user-1"

    assert endpoint.call_count == 1, (
        "exactly one JWKS fetch must occur across 8 concurrent cold-cache callers (D-08/D-09)"
    )


def test_jwks_path_is_org_wide_endpoint() -> None:
    assert JWKS_PATH == "/oauth2/jwks"
