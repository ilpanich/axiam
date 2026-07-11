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
// NEW-4 (CONTRACT.md §8 "v2 — Replay Protection", hard cutover): once the
// HMAC verifies, the delivery is ADDITIONALLY rejected (same nack-without-
// requeue path) when `key_version < 2`, `issued_at` falls outside the
// ±skew freshness window, or `nonce` has already been seen. Because this
// module verifies by re-serializing the parsed body (minus
// `hmac_signature`) in insertion order (Pitfall 5), `nonce`/`issued_at` are
// already covered by the HMAC bytes with no canonicalization change — only
// the three validation gates below are new.
//
// This is the TS port of the already-tested Rust `verify_and_dispatch`/
// `consume` (sdks/rust/src/amqp/consumer.rs).

import amqp from 'amqplib';
import type { Channel, ConsumeMessage } from 'amqplib';
import type { Sensitive } from '../core/index.js';
import { verifyPayload } from './hmac.js';

/**
 * Default freshness skew for `issued_at` acceptance (NEW-4): a message is
 * accepted only when its `issued_at` lies within ±5 minutes of the
 * verifier's clock, matching the server's
 * `DEFAULT_FRESHNESS_SKEW_SECS = 300` / `AXIAM__AMQP__REPLAY_SKEW_SECS`
 * (CONTRACT.md §8 v2).
 */
export const DEFAULT_REPLAY_SKEW_MS = 5 * 60 * 1000;

/**
 * Nonce replay-dedup store (NEW-4). `checkAndRecord` returns `true` when
 * `nonce` has already been recorded and its dedup entry has not yet
 * expired (i.e. this delivery is a replay); otherwise it records the nonce
 * with the given TTL and returns `false`.
 */
export interface NonceStore {
  checkAndRecord(nonce: string, ttlMs: number): boolean;
}

/**
 * Default in-memory nonce dedup store (NEW-4). Naturally bounded: each
 * entry expires after `ttlMs` (the caller passes 2x the freshness skew, so
 * a nonce can never still be "fresh" once its dedup entry has lapsed) and
 * expired entries are pruned opportunistically on each check — no
 * background timer and no unbounded growth under sustained traffic.
 *
 * Share ONE instance across every delivery from the same consumer (as
 * `consume()` does by default) — a fresh store per call provides no
 * cross-message replay protection.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly seenUntilMs = new Map<string, number>();

  checkAndRecord(nonce: string, ttlMs: number): boolean {
    const now = Date.now();
    this.prune(now);
    const expiry = this.seenUntilMs.get(nonce);
    if (expiry !== undefined && expiry > now) {
      return true;
    }
    this.seenUntilMs.set(nonce, now + ttlMs);
    return false;
  }

  private prune(now: number): void {
    for (const [nonce, expiry] of this.seenUntilMs) {
      if (expiry <= now) this.seenUntilMs.delete(nonce);
    }
  }
}

type ReplayRejectReason = 'key_version' | 'issued_at' | 'nonce';

/**
 * NEW-4 validation gates, checked only AFTER the HMAC has already verified.
 * Returns the failing gate's name, or `undefined` when all three pass.
 * `ttlMs` for the nonce store is 2x `skewMs` — the freshness window plus a
 * margin so a nonce cannot be replayed the instant its dedup entry expires
 * while `issued_at` might still (barely) be judged fresh by a differently-
 * skewed verifier.
 */
function checkReplayProtection(
  body: Record<string, unknown>,
  skewMs: number,
  nonceStore: NonceStore,
): ReplayRejectReason | undefined {
  const keyVersion = body.key_version;
  if (typeof keyVersion !== 'number' || keyVersion < 2) {
    return 'key_version';
  }

  const issuedAtRaw = body.issued_at;
  if (typeof issuedAtRaw !== 'string') {
    return 'issued_at';
  }
  const issuedAtMs = Date.parse(issuedAtRaw);
  if (Number.isNaN(issuedAtMs) || Math.abs(Date.now() - issuedAtMs) > skewMs) {
    return 'issued_at';
  }

  const nonce = body.nonce;
  if (typeof nonce !== 'string' || nonce.length === 0) {
    return 'nonce';
  }
  if (nonceStore.checkAndRecord(nonce, skewMs * 2)) {
    return 'nonce';
  }

  return undefined;
}

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
  /**
   * Freshness skew window for `issued_at` validation (NEW-4), in
   * milliseconds. Defaults to {@link DEFAULT_REPLAY_SKEW_MS} (5 minutes),
   * matching the server default (CONTRACT.md §8 v2).
   */
  skewMs?: number;
  /**
   * Nonce replay-dedup store (NEW-4). Defaults to a fresh
   * `InMemoryNonceStore` per call when omitted — `consume()` creates and
   * shares ONE store across every delivery on that connection by default;
   * callers invoking `verifyAndDispatch` directly across multiple messages
   * must pass the same store explicitly for dedup to take effect.
   */
  nonceStore?: NonceStore;
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

  // NEW-4 (CONTRACT.md §8 v2, hard cutover): only reached once the HMAC has
  // verified. `body` was re-serialized in insertion order to compute
  // `canonical` above, so `nonce`/`issued_at` are already inside the bytes
  // that were just verified — these are the three ADDITIONAL validation
  // gates (key_version, freshness, replay), not re-verification.
  const skewMs = options.skewMs ?? DEFAULT_REPLAY_SKEW_MS;
  const nonceStore = options.nonceStore ?? new InMemoryNonceStore();
  const replayRejectReason = checkReplayProtection(body, skewMs, nonceStore);
  if (replayRejectReason) {
    const tenantContext: Record<string, unknown> = {};
    if (typeof body.tenant_id === 'string') tenantContext.tenantId = body.tenant_id;
    logger?.warn(
      'axiam_sdk.security',
      `AMQP v2 replay-protection check failed (${replayRejectReason}); nacking without requeue`,
      {
        timestamp: new Date().toISOString(),
        exchange: msg.fields.exchange,
        routingKey: msg.fields.routingKey,
        ...tenantContext,
      },
    );
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

  // NEW-4: one nonce store shared across every delivery on this consumer —
  // a fresh store per message (the per-call default in `verifyAndDispatch`)
  // would defeat replay dedup entirely.
  const sharedOptions: ConsumeOptions = {
    ...options,
    nonceStore: options.nonceStore ?? new InMemoryNonceStore(),
  };

  await channel.consume(queue, (msg) => {
    if (!msg) return;
    void verifyAndDispatch(channel, msg, signingKey.expose(), handler, sharedOptions);
  });
}
