"""amqp_consumer.py demonstrates axiam_sdk.amqp.consume with a handler that
shows the full ack/nack matrix (CONTRACT.md §8, D-02).

The SDK verifies each delivery's HMAC-SHA256 signature BEFORE the handler
ever sees the message body, and nacks-without-requeue on any verification
failure. The handler here decides ack (return None), a transient
requeue-eligible failure (raise a plain exception), or a poison message that
must never be requeued (raise axiam_sdk.amqp.ErrDrop) — it never touches
ack/nack directly; that is owned entirely by the SDK.

This example is illustrative/compilable — it reads connection details from
environment variables and does not require a live AMQP broker to
byte-compile. Running it end-to-end requires a reachable RabbitMQ broker at
AMQP_URL.

Run: python examples/amqp_consumer.py
"""

from __future__ import annotations

import asyncio
import binascii
import os
import signal
from typing import Any

import aio_pika

from axiam_sdk.amqp import ErrDrop, consume


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


async def handler(event: dict[str, Any]) -> None:
    """The SDK owns the full ack/nack loop (D-02): this handler is invoked
    only after a delivery's HMAC signature has been verified."""
    action = event.get("action")
    if action is None:
        # Not the message shape this handler expects — treat as a poison
        # message rather than requeuing it forever.
        raise ErrDrop("event missing required 'action' field")
    print(f"Verified AMQP event: action={action}")


async def main() -> None:
    amqp_url = getenv("AMQP_URL", "amqp://guest:guest@localhost:5672")
    queue_name = getenv("AXIAM_AMQP_QUEUE", "axiam.authz.request")

    # §8.1: the per-tenant AMQP signing secret MUST be obtained from the
    # AXIAM management API — never hardcoded. This example reads it from an
    # environment variable as a stand-in for that management-API fetch.
    signing_key_hex = getenv("AXIAM_AMQP_SIGNING_KEY_HEX", "00112233445566778899aabbccddeeff")
    try:
        signing_key = bytes.fromhex(signing_key_hex)
    except (ValueError, binascii.Error) as exc:
        raise SystemExit(f"invalid AXIAM_AMQP_SIGNING_KEY_HEX: {exc}") from exc

    connection = await aio_pika.connect_robust(amqp_url)
    async with connection:
        channel = await connection.channel()

        print(f"Consuming from {queue_name!r} — HMAC verification runs before every handler call.")

        # The SDK owns the full ack/nack loop; handler is invoked only after
        # a delivery's HMAC signature has been verified.
        await consume(channel, queue_name, signing_key, handler, prefetch=10)

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)
        await stop_event.wait()


if __name__ == "__main__":
    asyncio.run(main())
