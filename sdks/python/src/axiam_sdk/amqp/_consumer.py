"""Async AMQP event consumer with HMAC verify-before-handler (CONTRACT.md §8).

Closure-handler consumer built on ``aio-pika`` (D-02, async-only). Ports
``sdks/go/amqp/consumer.go``'s ``verifyAndDispatch`` ack/nack decision matrix
and ``sdks/go/amqp/errdrop.go``'s exported ``ErrDrop`` sentinel.

Security invariant (T-19-16/T-19-17/T-19-18): every delivery's HMAC-SHA256
signature is verified via :func:`axiam_sdk.amqp._hmac.verify_hmac` — proven
byte-for-byte compatible with the Rust server in 19-01 — BEFORE the
caller-supplied handler is ever invoked. An unverified message never reaches
the handler. The SDK owns the ack/nack loop (``message.process(
ignore_processed=True)``); ``aio-pika``'s automatic context-manager
auto-acking is never used.

Ack/nack decision matrix (§8):

- HMAC verification fails                -> nack(requeue=False) + security log
- Post-verify JSON/body parse fails       -> nack(requeue=False) + security log
- NEW-4 replay-protection check fails     -> nack(requeue=False) + security log
- handler(event) returns ``None``         -> ack()
- handler(event) raises :class:`ErrDrop`  -> nack(requeue=False)
- handler(event) raises any other error   -> nack(requeue=True)

The security-log message on HMAC/parse/replay failure NEVER includes the
received or computed signature, nonce, or timestamp value — only the fact
of failure (§8.4).

NEW-4 (AMQP replay protection, v2 wire protocol): once the HMAC verifies,
the parsed body is additionally checked by
:func:`axiam_sdk.amqp._replay.validate_freshness` — ``key_version`` must be
>= 2, ``issued_at`` must be within a configurable clock-skew window (default
5 minutes) of now, and ``nonce`` must not have been seen before within the
freshness window (2x skew). A single :class:`axiam_sdk.amqp._replay.NonceStore`
is created once per :func:`consume` call and threaded through every delivery
so nonce dedup actually persists across the consumer's lifetime.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

from aio_pika.abc import AbstractChannel, AbstractIncomingMessage

from axiam_sdk.amqp._hmac import verify_hmac
from axiam_sdk.amqp._replay import DEFAULT_SKEW_SECONDS, NonceStore, validate_freshness

#: Default AMQP QoS prefetch count applied unless the caller overrides it
#: via ``consume(..., prefetch=...)`` (CF-06; mirrors Go's ``defaultPrefetch
#: = 10``).
DEFAULT_PREFETCH = 10

#: Consumer tag identifying this SDK's consumer to the broker (mirrors Go's
#: ``consumerTag``).
CONSUMER_TAG = "axiam-sdk-consumer"

Handler = Callable[[dict[str, Any]], Awaitable[None]]


class ErrDrop(Exception):
    """Sentinel a handler raises to signal "poison message" (D-02, §8).

    Raising ``ErrDrop`` from a ``consume()`` handler causes the delivery to
    be nacked WITHOUT requeue, exactly like an HMAC or parse failure — the
    message is dropped rather than looping the queue. Any OTHER exception
    raised by the handler is treated as transient and nacks WITH requeue.
    Mirrors Go's exported ``var ErrDrop = errors.New(...)`` sentinel
    (``sdks/go/amqp/errdrop.go``).
    """


async def _on_message(
    message: AbstractIncomingMessage,
    signing_key: bytes,
    handler: Handler,
    logger: logging.Logger,
    *,
    nonce_store: NonceStore | None = None,
    skew_seconds: float = DEFAULT_SKEW_SECONDS,
    now: datetime | None = None,
) -> None:
    """Verify, parse, and dispatch a single delivery per the §8 matrix.

    The SDK drives ack/nack itself via ``message.process(
    ignore_processed=True)`` — this disables aio-pika's automatic
    ack-on-success-else-requeue context-manager behavior so every outcome
    below is an explicit, deliberate decision.

    ``nonce_store`` SHOULD be a single instance shared across every
    delivery on the consumer loop (:func:`consume` does this for you); if
    omitted, a throwaway single-use store is created for this call only,
    which makes replay detection meaningless beyond duplicate nonces
    within this one call — acceptable for standalone/test invocations of
    this private helper, never for production use via :func:`consume`.

    ``now`` overrides the wall-clock reference used for the ``issued_at``
    freshness check (default ``None`` uses real UTC now via
    :func:`axiam_sdk.amqp._replay.validate_freshness`'s own default). This
    parameter exists purely so tests can exercise the freshness check
    deterministically against a fixed reference vector's ``issued_at``;
    :func:`consume` never passes it, so production traffic always uses
    the real clock.
    """
    if nonce_store is None:
        nonce_store = NonceStore(ttl_seconds=2 * skew_seconds)

    async with message.process(ignore_processed=True):
        # HMAC verification MUST happen before anything else touches the
        # body — the handler must never see an unverified message
        # (T-19-16). verify_hmac() never raises.
        if not verify_hmac(signing_key, message.body):
            # Security event (§8.4): the fact of failure only. NEVER the
            # received or computed signature value (T-19-17).
            logger.warning(
                "axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue"
            )
            await message.nack(requeue=False)
            return

        try:
            event = json.loads(message.body)
            if not isinstance(event, dict):
                raise TypeError("AMQP message body is not a JSON object")
            event.pop("hmac_signature", None)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            logger.warning(
                "axiam_sdk_security: AMQP message body failed to parse "
                "after HMAC verification; nacking without requeue"
            )
            await message.nack(requeue=False)
            return

        # NEW-4 replay protection: key_version/nonce/issued_at are already
        # covered by the HMAC (verify_hmac is schema-agnostic and signs
        # whatever keys arrived), but the signature alone can't express
        # "not too old" or "not seen before" — that's checked here, after
        # verification, never before (an attacker cannot forge these
        # fields without also forging the signature).
        rejection_reason = validate_freshness(
            event, nonce_store, skew_seconds=skew_seconds, now=now
        )
        if rejection_reason is not None:
            logger.warning(
                "axiam_sdk_security: AMQP replay-protection check failed (%s); "
                "nacking without requeue",
                rejection_reason,
            )
            await message.nack(requeue=False)
            return

        try:
            await handler(event)
        except ErrDrop:
            # Poison message (§8, T-19-18): drop without requeue rather
            # than looping the queue.
            await message.nack(requeue=False)
            return
        except Exception:
            # Transient/retryable handler error: requeue.
            await message.nack(requeue=True)
            return

        await message.ack()


async def consume(
    channel: AbstractChannel,
    queue_name: str,
    signing_key: bytes,
    handler: Handler,
    *,
    prefetch: int = DEFAULT_PREFETCH,
    skew_seconds: float = DEFAULT_SKEW_SECONDS,
    nonce_store: NonceStore | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """Consume ``queue_name`` on ``channel``, verifying HMAC before dispatch.

    Sets QoS prefetch (default :data:`DEFAULT_PREFETCH`), passively declares
    ``queue_name`` (the queue MUST already exist server-side — the SDK does
    not create infrastructure), and registers an async per-message callback
    with ``no_ack=False`` so the SDK — not aio-pika — owns every ack/nack
    decision (§8).

    ``signing_key`` MUST be obtained from the AXIAM management API for the
    tenant whose queue is being consumed (§8.1); hardcoding a signing key is
    prohibited.

    NEW-4 (AMQP replay protection): ``skew_seconds`` bounds how far
    ``issued_at`` may drift from wall-clock now (default 300s / 5 minutes)
    before a message is rejected as stale. ``nonce_store`` is an optional
    injectable :class:`axiam_sdk.amqp._replay.NonceStore`; if omitted, a
    single store with TTL ``2 * skew_seconds`` is created here — once, for
    the lifetime of this ``consume()`` call — and threaded through every
    delivery's ``_on_message`` invocation so nonce replay detection
    persists across the whole consumer loop rather than resetting per
    message.

    ``logger`` is an injectable ``logging.Logger`` (D-15: observability
    off-by-default). If omitted, a module-level logger with a
    :class:`logging.NullHandler` is used so the consumer is silent unless
    the caller configures logging.
    """
    if logger is None:
        logger = _DEFAULT_LOGGER
    if nonce_store is None:
        nonce_store = NonceStore(ttl_seconds=2 * skew_seconds)

    await channel.set_qos(prefetch_count=prefetch)
    queue = await channel.declare_queue(queue_name, durable=True, passive=True)

    async def _callback(message: AbstractIncomingMessage) -> None:
        await _on_message(
            message,
            signing_key,
            handler,
            logger,
            nonce_store=nonce_store,
            skew_seconds=skew_seconds,
        )

    await queue.consume(_callback, no_ack=False, consumer_tag=CONSUMER_TAG)


_DEFAULT_LOGGER = logging.getLogger("axiam_sdk.amqp")
_DEFAULT_LOGGER.addHandler(logging.NullHandler())
