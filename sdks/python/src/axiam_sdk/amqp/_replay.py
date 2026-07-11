"""AMQP v2 replay-protection validation (NEW-4).

The v2 wire protocol (``crates/axiam-amqp/src/messages.rs``) adds three
fields to the signed body of ``AuthzRequest``/``AuditEventMessage``, in
declaration order after the existing fields and before ``hmac_signature``:
``key_version``, ``nonce``, ``issued_at``.

The consumer's HMAC canonicalization (:func:`axiam_sdk.amqp._hmac.verify_hmac`)
is schema-agnostic — it re-serializes whatever keys arrived (minus
``hmac_signature``) in their received order, so these three fields are
*already* covered by the signature with no canonicalization change. What
the signature alone cannot express is the semantic replay-protection
policy, which this module adds as a POST-HMAC-verification step:

- ``key_version`` must be >= 2. A message signed under the old v1 shape
  (no ``nonce``/``issued_at`` at all) is rejected once v2 is required —
  it carries no replay protection regardless of signature validity.
- ``issued_at`` (ISO 8601 / RFC 3339) must be within +/- ``skew_seconds``
  of wall-clock now (default 300s / 5 minutes) — bounds how long a
  captured message stays acceptable at all.
- ``nonce`` must not have been seen before within the freshness window
  — the actual replay guard. A message with a valid signature and a
  fresh timestamp is still rejected if its nonce was already consumed.

Any failure here MUST be treated identically to an HMAC failure by the
caller: nack-without-requeue plus a fact-only security log line (never
echoing the nonce, timestamp, or signature values).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

#: Default allowed clock-skew window for ``issued_at`` freshness, in
#: seconds. Configurable per-consumer via ``consume(..., skew_seconds=...)``.
DEFAULT_SKEW_SECONDS: float = 300.0

#: Minimum ``key_version`` accepted once v2 replay protection is enforced.
MIN_KEY_VERSION = 2


class NonceStore:
    """In-memory nonce dedup store, naturally bounded by TTL pruning.

    Maps ``nonce -> expiry`` (a :func:`time.monotonic` timestamp). A nonce
    is recorded the first time it is seen; any repeat before its entry
    expires is a replay and is rejected. Pruning is opportunistic — it runs
    on every :meth:`check_and_record` call rather than on a timer/background
    task — so the store never needs its own scheduling and stays roughly
    bounded to (messages seen within one TTL window) entries.

    Exactly ONE instance MUST be shared across every delivery on a given
    consumer loop: :func:`axiam_sdk.amqp._consumer.consume` creates a
    single store and threads it through every call to ``_on_message`` for
    the lifetime of the consumer. A fresh store per-message (or per-call)
    would make replay detection a no-op, since nothing would ever be
    remembered between deliveries.
    """

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}

    def check_and_record(self, nonce: str, *, now: float | None = None) -> bool:
        """Record ``nonce`` and report whether it was fresh.

        Returns ``True`` the first time a given ``nonce`` is seen (and
        records it with an expiry of ``now + ttl_seconds``). Returns
        ``False`` if ``nonce`` is already present and unexpired — the
        caller MUST treat that as a replay and reject the message.
        """
        if now is None:
            now = time.monotonic()
        self._prune(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now + self._ttl_seconds
        return True

    def _prune(self, now: float) -> None:
        expired = [n for n, expiry in self._seen.items() if expiry <= now]
        for n in expired:
            del self._seen[n]

    def __len__(self) -> int:
        return len(self._seen)


def _parse_rfc3339(value: str) -> datetime:
    """Parse an ISO 8601 / RFC 3339 timestamp, accepting a trailing 'Z'.

    ``datetime.fromisoformat`` does not accept a bare 'Z' offset suffix on
    Python < 3.11, so it is normalized to '+00:00' first for broad
    compatibility with this SDK's ``requires-python = ">=3.10"``. Raises
    ``ValueError`` for anything unparseable (matching ``fromisoformat``'s
    own contract) so callers can catch a single exception type.
    """
    normalized = value.strip()
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def validate_freshness(
    event: dict[str, Any],
    nonce_store: NonceStore,
    *,
    skew_seconds: float = DEFAULT_SKEW_SECONDS,
    now: datetime | None = None,
) -> str | None:
    """Run the NEW-4 post-HMAC-verification checks on a parsed message.

    MUST only be called after :func:`axiam_sdk.amqp._hmac.verify_hmac` has
    already succeeded for this exact delivery — ``key_version``, ``nonce``,
    and ``issued_at`` are part of the signed body, so an attacker cannot
    forge or strip them without also forging the HMAC signature.

    Returns ``None`` if the message passes every check. Otherwise returns
    a short, non-sensitive rejection reason string (safe to put in a
    security log line — it never contains the actual nonce, timestamp, or
    signature values) that the caller should log before nacking without
    requeue.
    """
    key_version = event.get("key_version")
    if not isinstance(key_version, int) or isinstance(key_version, bool):
        return "missing or invalid key_version"
    if key_version < MIN_KEY_VERSION:
        return "unsupported key_version (replay protection unavailable)"

    issued_at_raw = event.get("issued_at")
    if not isinstance(issued_at_raw, str):
        return "missing or invalid issued_at"
    try:
        issued_at = _parse_rfc3339(issued_at_raw)
    except ValueError:
        return "unparseable issued_at"

    reference = now if now is not None else datetime.now(timezone.utc)
    delta_seconds = abs((reference - issued_at).total_seconds())
    if delta_seconds > skew_seconds:
        return "stale issued_at outside allowed clock-skew window"

    nonce = event.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return "missing or invalid nonce"

    if not nonce_store.check_and_record(nonce):
        return "replayed nonce"

    return None
