"""AXIAM SDK AMQP transport (CONTRACT.md §8, D-02).

Async-only event consumer (``aio-pika``) with mandatory HMAC-SHA256
verify-before-handler. Public surface:

- :func:`consume` — closure-handler consumer; the SDK owns the ack/nack
  loop and verifies every delivery's HMAC signature before the caller's
  handler is ever invoked.
- :class:`ErrDrop` — sentinel a handler raises to signal "poison message,
  nack WITHOUT requeue" (mirrors Go's exported ``ErrDrop``).
- :func:`verify_hmac` — the underlying HMAC-SHA256 verifier (19-01),
  re-exported for callers that need to verify a message body directly.
"""

from axiam_sdk.amqp._consumer import ErrDrop, consume
from axiam_sdk.amqp._hmac import verify_hmac

__all__ = [
    "consume",
    "ErrDrop",
    "verify_hmac",
]
