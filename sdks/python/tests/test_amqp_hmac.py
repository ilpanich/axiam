"""Cross-language HMAC verification test (CONTRACT.md §8, Assumption A2).

Loads tests/fixtures/amqp_hmac_vectors.json — real vectors emitted by the
Rust server's `crates/axiam-amqp/src/messages.rs::sign_payload` (not
hand-fabricated) — and proves `axiam_sdk.amqp._hmac.verify_hmac` reproduces
the server's canonicalization byte-for-byte: valid vectors verify True,
tampered/wrong-key/malformed vectors verify False (non-vacuous).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from axiam_sdk.amqp._hmac import verify_hmac

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "amqp_hmac_vectors.json"


def _load_vectors() -> list[dict]:
    with FIXTURES_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


VECTORS = _load_vectors()


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_hmac_vector(vector: dict) -> None:
    signing_key = bytes.fromhex(vector["signing_key_hex"])
    # Reconstruct the wire body bytes: the full message JSON including
    # hmac_signature, in the same key order the server emitted (Python
    # dicts preserve insertion order from the JSON fixture file, which
    # itself preserves the order captured from the real Rust signer).
    body = json.dumps(vector["message"], separators=(",", ":")).encode("utf-8")

    result = verify_hmac(signing_key, body)

    assert result is vector["expected_valid"], (
        f"vector {vector['name']!r}: expected verify_hmac to return "
        f"{vector['expected_valid']}, got {result}"
    )


def test_at_least_one_valid_vector_is_server_signed() -> None:
    """Non-vacuous sanity check: at least one vector must assert True."""
    assert any(v["expected_valid"] for v in VECTORS)


def test_at_least_one_tampered_vector_rejected() -> None:
    """Non-vacuous sanity check: at least one vector must assert False
    specifically because the body/key was tampered (not just malformed)."""
    tampered_names = {"authz_request_tampered_action", "audit_event_wrong_key"}
    tampered_vectors = [v for v in VECTORS if v["name"] in tampered_names]
    assert len(tampered_vectors) == 2
    assert all(v["expected_valid"] is False for v in tampered_vectors)


def test_malformed_json_returns_false_never_raises() -> None:
    key = bytes.fromhex(VECTORS[0]["signing_key_hex"])
    assert verify_hmac(key, b"{not json") is False


def test_missing_signature_returns_false_never_raises() -> None:
    key = bytes.fromhex(VECTORS[0]["signing_key_hex"])
    body = json.dumps({"action": "read"}, separators=(",", ":")).encode("utf-8")
    assert verify_hmac(key, body) is False


def test_non_json_object_returns_false_never_raises() -> None:
    key = bytes.fromhex(VECTORS[0]["signing_key_hex"])
    assert verify_hmac(key, b"[1, 2, 3]") is False
    assert verify_hmac(key, b'"just a string"') is False
