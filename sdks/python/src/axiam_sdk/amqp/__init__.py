"""AXIAM SDK AMQP transport (CONTRACT.md §8, D-02).

Async-only event consumer (``aio-pika``) with mandatory HMAC-SHA256
verify-before-handler and v2 replay protection (NEW-4). Public surface:

- :func:`consume` — closure-handler consumer; the SDK owns the ack/nack
  loop, verifies every delivery's HMAC signature before the caller's
  handler is ever invoked, and rejects stale/replayed/pre-v2 messages.
- :class:`ErrDrop` — sentinel a handler raises to signal "poison message,
  nack WITHOUT requeue" (mirrors Go's exported ``ErrDrop``).
- :func:`verify_hmac` — the underlying HMAC-SHA256 verifier (19-01),
  re-exported for callers that need to verify a message body directly.
- :class:`NonceStore` / :func:`validate_freshness` / :data:`DEFAULT_SKEW_SECONDS`
  — the NEW-4 replay-protection primitives ``consume()`` uses internally,
  re-exported for callers that need to verify freshness directly or inject
  a shared store across multiple consumers.
"""

from axiam_sdk.amqp._consumer import ErrDrop, consume
from axiam_sdk.amqp._hmac import verify_hmac
from axiam_sdk.amqp._replay import DEFAULT_SKEW_SECONDS, NonceStore, validate_freshness

__all__ = [
    "consume",
    "ErrDrop",
    "verify_hmac",
    "NonceStore",
    "validate_freshness",
    "DEFAULT_SKEW_SECONDS",
]
