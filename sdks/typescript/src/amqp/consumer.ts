// Closure-handler AMQP consumer (D-12, CONTRACT.md §8.3g/§8.4).
//
// The SDK owns the full ack/nack loop. Every delivery is HMAC-verified
// (CONTRACT.md §8) BEFORE the caller-supplied handler is ever invoked. On
// any verification failure (signature mismatch, missing signature in the
// default strict mode, or a body that fails to parse as JSON) the delivery
// is nacked WITHOUT requeue and a security event is emitted — the event
// never contains the received/expected HMAC value or the signing key. Only
// a verified delivery reaches the handler, and only then is it acked.
//
// This is the TS port of the already-tested Rust `verify_and_dispatch`/
// `consume` (sdks/rust/src/amqp/consumer.rs).

import amqp from 'amqplib';
import type { Channel, ConsumeMessage } from 'amqplib';
import type { Sensitive } from '../core/index.js';
import { verifyPayload } from './hmac.js';

/**
 * Minimal seam over the channel operations this module needs
 * (ack/nack/consume). `amqplib`'s `Channel` implements this directly;
 * tests provide a recording fake that never touches a live broker, so the
 * security-sensitive nack-without-requeue behavior can be asserted without
 * a running RabbitMQ instance.
 */
export interface ConsumeChannel {
  consume(
    queue: string,
    onMessage: (msg: ConsumeMessage | null) => void | Promise<void>,
  ): Promise<unknown>;
  /** `channel.ack(msg, allUpTo?)` — allUpTo intentionally omitted/false here. */
  ack(msg: ConsumeMessage): void;
  /** `channel.nack(msg, allUpTo, requeue)` — positional booleans (Pitfall 4). */
  nack(msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void;
}

export interface ConsumeLogger {
  warn(event: string, message: string, context?: Record<string, unknown>): void;
}

export interface ConsumeOptions {
  logger?: ConsumeLogger;
  /**
   * Strict mode (default true, CONTRACT.md §8.3): a message with no
   * `hmac_signature` is treated as a verification failure (nack-no-requeue),
   * not a pass-through. Lenient mode (false) is a temporary rolling-
   * deployment measure only — strict MUST remain the default.
   */
  strict?: boolean;
}

/**
 * Verify a single delivery's HMAC signature (CONTRACT.md §8 steps a-g) and,
 * only on success, invoke `handler` with the parsed body (hmac_signature
 * removed) before acking. On any failure the delivery is nacked without
 * requeue and a security event is emitted that never contains the HMAC
 * value or the signing key.
 *
 * Exported (not just used internally) so it is the same separately-testable
 * unit backing `consume`'s per-message loop, mirroring the Rust SDK's
 * `verify_and_dispatch`.
 */
export async function verifyAndDispatch(
  channel: ConsumeChannel,
  msg: ConsumeMessage,
  signingKey: Buffer,
  handler: (event: Record<string, unknown>) => Promise<void>,
  options: ConsumeOptions = {},
): Promise<void> {
  const { logger, strict = true } = options;

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(msg.content.toString('utf8')) as Record<string, unknown>;
  } catch {
    logger?.warn('axiam_sdk.security', 'AMQP message body failed JSON parse; nacking without requeue', {
      exchange: msg.fields.exchange,
      routingKey: msg.fields.routingKey,
    });
    // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
    channel.nack(msg, false, false);
    return;
  }

  const sig = typeof body.hmac_signature === 'string' ? body.hmac_signature : undefined;
  delete body.hmac_signature;
  const canonical = Buffer.from(JSON.stringify(body), 'utf8');

  // Strict mode (default, CONTRACT.md §8.3): a missing signature is treated
  // as a verification failure, not a pass-through. A present signature is
  // always verified regardless of strict/lenient mode; lenient mode only
  // changes the outcome for a MISSING signature (temporary rolling-
  // deployment measure — strict MUST remain the default).
  let verified: boolean;
  if (sig !== undefined) {
    verified = verifyPayload(signingKey, canonical, sig);
  } else {
    verified = !strict;
  }

  if (!verified) {
    // Security event (§8.4): timestamp, exchange, routing key, and tenant
    // context (if present in the body) — NEVER the signature value or the
    // signing key.
    const tenantContext: Record<string, unknown> = {};
    if (typeof body.tenant_id === 'string') tenantContext.tenantId = body.tenant_id;
    logger?.warn('axiam_sdk.security', 'AMQP HMAC verification failed; nacking without requeue', {
      timestamp: new Date().toISOString(),
      exchange: msg.fields.exchange,
      routingKey: msg.fields.routingKey,
      ...tenantContext,
    });
    // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
    channel.nack(msg, false, false);
    return;
  }

  try {
    await handler(body);
  } catch (err) {
    // Do not requeue a handler-crashing message into a hot loop.
    logger?.warn('axiam_sdk.security', 'AMQP handler threw; nacking without requeue', {
      exchange: msg.fields.exchange,
      routingKey: msg.fields.routingKey,
      error: err instanceof Error ? err.message : String(err),
    });
    // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
    channel.nack(msg, false, false);
    return;
  }

  channel.ack(msg);
}

/**
 * Connect to the AMQP broker at `amqpUrl`, declare `queue` as durable, and
 * consume from it — verifying each delivery's HMAC-SHA256 signature
 * (CONTRACT.md §8) BEFORE invoking `handler`. The handler never sees an
 * unverified message; verification failures are nacked without requeue and
 * logged as a security event.
 *
 * `signingKey` is a required, caller-supplied `Sensitive<Buffer>` — the SDK
 * does not fetch it from the server (no such endpoint exists; CONTRACT.md
 * §8.1 assumes out-of-band provisioning).
 *
 * This function owns the full ack/nack loop; `handler` MUST NOT itself call
 * ack/nack (there is no delivery handle exposed to it).
 */
export async function consume(
  amqpUrl: string,
  queue: string,
  signingKey: Sensitive<Buffer>,
  handler: (event: Record<string, unknown>) => Promise<void>,
  options: ConsumeOptions = {},
): Promise<void> {
  const connection = await amqp.connect(amqpUrl);
  const channel: Channel = await connection.createChannel();
  await channel.assertQueue(queue, { durable: true });

  await channel.consume(queue, (msg) => {
    if (!msg) return;
    void verifyAndDispatch(channel, msg, signingKey.expose(), handler, options);
  });
}
