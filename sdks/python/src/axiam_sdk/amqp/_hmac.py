"""AMQP HMAC-SHA256 verification (CONTRACT.md §8).

Byte-for-byte port of the canonical protocol implemented by the Rust server
in ``crates/axiam-amqp/src/messages.rs`` (``sign_payload``/``verify_payload``).
This module cannot import that crate (the SDK MUST NOT depend on server
crates), so the algorithm is reimplemented here and proven correct against a
real server-signed fixture in ``tests/test_amqp_hmac.py`` (Assumption A2 /
Pitfall 2 — see 19-RESEARCH.md).

Critical correctness note: the Rust wire types (``AuthzRequest``,
``AuditEventMessage``) are typed structs, not maps — ``serde_json``
serializes them in FIELD DECLARATION ORDER, not alphabetical order. A JSON
object parsed by Python's ``json.loads`` into a ``dict`` preserves the
insertion order of the keys as they appeared on the wire (PEP 468 / CPython
3.7+ guarantee), and re-serializing that dict with its keys left alone
reproduces the same order. Therefore canonicalization here MUST NOT
alphabetize keys — it must simply re-serialize the received message (minus
``hmac_signature``) in the order it arrived, which reproduces the exact
byte sequence the server signed.
"""

from __future__ import annotations

import hashlib
import hmac
import json


def verify_hmac(signing_key: bytes, body: bytes) -> bool:
    """Verify an HMAC-SHA256 signature over an AMQP message body.

    Returns ``True`` only if the message's ``hmac_signature`` field
    (hex-encoded) matches HMAC-SHA256(signing_key, canonical_json) where
    ``canonical_json`` is the message with ``hmac_signature`` removed,
    re-serialized via ``json.dumps(msg, separators=(",", ":"))`` with the
    keys left in their received (insertion) order — preserving the wire
    order emitted by the server's declared-order struct serialization.

    Never raises. Returns ``False`` for: malformed JSON, a body that does
    not decode to a JSON object, a missing ``hmac_signature`` field, a
    non-hex or wrong-length signature, a tampered body, or a wrong signing
    key. The signature and computed digest are never logged or returned —
    only this boolean (T-19-03).
    """
    try:
        msg = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return False

    if not isinstance(msg, dict):
        return False

    sig_hex = msg.pop("hmac_signature", None)
    if sig_hex is None or not isinstance(sig_hex, str):
        # Strict mode default (CONTRACT.md §8.3): a message with no
        # hmac_signature field (or a non-string value) is rejected, never
        # silently accepted.
        return False

    # Keys are left in their received order (see module docstring) — do not
    # alphabetize them. This reproduces the exact byte sequence the Rust
    # signer actually signed.
    canonical = json.dumps(msg, separators=(",", ":")).encode("utf-8")

    try:
        expected = bytes.fromhex(sig_hex)
    except ValueError:
        return False

    computed = hmac.new(signing_key, canonical, hashlib.sha256).digest()
    return hmac.compare_digest(computed, expected)
