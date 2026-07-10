import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { signPayload } from '../../src/amqp/hmac.js';
import {
  verifyAndDispatch,
  InMemoryNonceStore,
  DEFAULT_REPLAY_SKEW_MS,
  type ConsumeChannel,
  type ConsumeLogger,
} from '../../src/amqp/consumer.js';

const SIGNING_KEY = Buffer.from('consumer-test-signing-key', 'utf8');

function makeMessage(content: Buffer, exchange = 'axiam.authz.request', routingKey = 'authz'): ConsumeMessage {
  return {
    content,
    fields: {
      deliveryTag: 1,
      redelivered: false,
      exchange,
      routingKey,
      consumerTag: 'test-consumer',
    },
    properties: {} as ConsumeMessage['properties'],
  };
}

/**
 * Builds a v2 (NEW-4, `key_version = 2`) signed body: correlation_id,
 * action, key_version, nonce, issued_at, hmac_signature — declaration
 * order doesn't matter for these ad hoc test bodies (unlike the real DTOs)
 * since the HMAC is computed over whatever order `JSON.stringify` produces
 * here and verified the same way; `overrides` lets replay/freshness/
 * version tests build an otherwise-valid-but-deliberately-bad body.
 */
function makeSignedBody(overrides: Record<string, unknown> = {}): {
  body: Record<string, unknown>;
  data: Buffer;
} {
  const body: Record<string, unknown> = {
    correlation_id: '00000000-0000-0000-0000-000000000000',
    action: 'read',
    key_version: 2,
    nonce: randomUUID(),
    issued_at: new Date().toISOString(),
    ...overrides,
  };
  const canonical = Buffer.from(JSON.stringify(body), 'utf8');
  const sig = signPayload(SIGNING_KEY, canonical);
  const signedBody = { ...body, hmac_signature: sig };
  return { body: signedBody, data: Buffer.from(JSON.stringify(signedBody), 'utf8') };
}

/**
 * Recording fake channel: never touches a live broker. Records ack calls
 * and nack calls with their (allUpTo, requeue) args separately, mirroring
 * the Rust SDK's `RecordingDelivery` test fixture.
 */
class RecordingChannel implements ConsumeChannel {
  acked: ConsumeMessage[] = [];
  nackCalls: Array<{ msg: ConsumeMessage; allUpTo: boolean; requeue: boolean }> = [];

  async consume(): Promise<unknown> {
    throw new Error('not used in these unit tests');
  }

  ack(msg: ConsumeMessage): void {
    this.acked.push(msg);
  }

  nack(msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void {
    this.nackCalls.push({ msg, allUpTo, requeue });
  }
}

function makeRecordingLogger(): { logger: ConsumeLogger; events: Array<{ event: string; message: string; context?: Record<string, unknown> }> } {
  const events: Array<{ event: string; message: string; context?: Record<string, unknown> }> = [];
  return {
    events,
    logger: {
      warn(event, message, context) {
        events.push({ event, message, context });
      },
    },
  };
}

describe('amqp/consumer verifyAndDispatch', () => {
  it('valid signature: handler is called once (signature stripped) and message is acked', async () => {
    const { data } = makeSignedBody();
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async (event: Record<string, unknown>) => {
      expect(event.hmac_signature).toBeUndefined();
      expect(event.action).toBe('read');
    });

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(channel.acked).toHaveLength(1);
    expect(channel.nackCalls).toHaveLength(0);
  });

  it('mismatched signature: handler NOT called, nack(false,false), and security event omits the signature hex', async () => {
    const { body } = makeSignedBody();
    const tamperedBody = { ...body, hmac_signature: '0'.repeat(64) };
    const data = Buffer.from(JSON.stringify(tamperedBody), 'utf8');
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});
    const { logger, events } = makeRecordingLogger();

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler, { logger });

    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toHaveLength(0);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });

    const serializedEvents = JSON.stringify(events);
    expect(serializedEvents).not.toContain('0'.repeat(64));
    expect(serializedEvents).not.toContain(SIGNING_KEY.toString('utf8'));
    expect(events.length).toBeGreaterThan(0);
  });

  it('missing signature (strict default): handler NOT called, nack(false,false)', async () => {
    const body = {
      correlation_id: '00000000-0000-0000-0000-000000000000',
      action: 'read',
      key_version: 2,
      nonce: randomUUID(),
      issued_at: new Date().toISOString(),
    };
    const data = Buffer.from(JSON.stringify(body), 'utf8');
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});
    const { logger } = makeRecordingLogger();

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler, { logger });

    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toHaveLength(0);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });
  });

  it('unparseable JSON body: nack(false,false), handler NOT called', async () => {
    const msg = makeMessage(Buffer.from('not valid json {{{', 'utf8'));
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler);

    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toHaveLength(0);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });
  });

  it('handler throwing: nack(false,false), message not acked (no hot-loop requeue)', async () => {
    const { data } = makeSignedBody();
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {
      throw new Error('handler crashed');
    });

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(channel.acked).toHaveLength(0);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });
  });

  it('lenient mode (strict:false): missing signature passes through to handler and is acked', async () => {
    // Still v2-valid (key_version/nonce/issued_at present) — lenient mode
    // only changes the outcome for a MISSING signature; it is not a bypass
    // of the NEW-4 replay-protection gates (CONTRACT.md §8 v2, hard cutover).
    const body = {
      correlation_id: '00000000-0000-0000-0000-000000000000',
      action: 'read',
      key_version: 2,
      nonce: randomUUID(),
      issued_at: new Date().toISOString(),
    };
    const data = Buffer.from(JSON.stringify(body), 'utf8');
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler, { strict: false });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(channel.acked).toHaveLength(1);
    expect(channel.nackCalls).toHaveLength(0);
  });

  it('every failure path (mismatch, missing, parse-fail) records requeue===false exactly', async () => {
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    // mismatch
    const { body } = makeSignedBody();
    const tampered = { ...body, hmac_signature: '1'.repeat(64) };
    await verifyAndDispatch(channel, makeMessage(Buffer.from(JSON.stringify(tampered), 'utf8')), SIGNING_KEY, handler);

    // missing
    await verifyAndDispatch(
      channel,
      makeMessage(Buffer.from(JSON.stringify({ action: 'read' }), 'utf8')),
      SIGNING_KEY,
      handler,
    );

    // parse-fail
    await verifyAndDispatch(channel, makeMessage(Buffer.from('{{{', 'utf8')), SIGNING_KEY, handler);

    expect(channel.nackCalls).toHaveLength(3);
    for (const call of channel.nackCalls) {
      expect(call.requeue).toBe(false);
    }
    expect(handler).not.toHaveBeenCalled();
  });
});

describe('amqp/consumer verifyAndDispatch NEW-4 replay protection (CONTRACT.md §8 v2, hard cutover)', () => {
  it('key_version < 2: valid signature but v1 body is rejected, nack(false,false)', async () => {
    const { data } = makeSignedBody({ key_version: 1 });
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});
    const { logger, events } = makeRecordingLogger();

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler, { logger });

    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toHaveLength(0);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });
    expect(events.some((e) => e.message.includes('key_version'))).toBe(true);
  });

  it('key_version missing entirely (pre-NEW-4 body): rejected, nack(false,false)', async () => {
    const { data } = makeSignedBody({ key_version: undefined });
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler);

    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toHaveLength(0);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });
  });

  it('stale issued_at (outside default ±5min skew): rejected, nack(false,false)', async () => {
    const staleTimestamp = new Date(Date.now() - (DEFAULT_REPLAY_SKEW_MS + 60_000)).toISOString();
    const { data } = makeSignedBody({ issued_at: staleTimestamp });
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});
    const { logger, events } = makeRecordingLogger();

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler, { logger });

    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toHaveLength(0);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });
    expect(events.some((e) => e.message.includes('issued_at'))).toBe(true);
  });

  it('future issued_at (outside skew) is also rejected as stale', async () => {
    const futureTimestamp = new Date(Date.now() + (DEFAULT_REPLAY_SKEW_MS + 60_000)).toISOString();
    const { data } = makeSignedBody({ issued_at: futureTimestamp });
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler);

    expect(handler).not.toHaveBeenCalled();
    expect(channel.nackCalls[0]).toEqual({ msg, allUpTo: false, requeue: false });
  });

  it('issued_at just inside a custom skewMs is accepted', async () => {
    const skewMs = 1000;
    const withinSkew = new Date(Date.now() - 500).toISOString();
    const { data } = makeSignedBody({ issued_at: withinSkew });
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler, { skewMs });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(channel.acked).toHaveLength(1);
    expect(channel.nackCalls).toHaveLength(0);
  });

  it('replayed nonce: first delivery accepted, second delivery with the same nonce rejected', async () => {
    const nonceStore = new InMemoryNonceStore();
    const nonce = randomUUID();
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});
    const { logger, events } = makeRecordingLogger();

    const first = makeSignedBody({ nonce });
    await verifyAndDispatch(channel, makeMessage(first.data), SIGNING_KEY, handler, { nonceStore });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(channel.acked).toHaveLength(1);
    expect(channel.nackCalls).toHaveLength(0);

    // Same nonce again (a captured/replayed message) — a distinct
    // hmac_signature (a fresh sign over the same nonce) is irrelevant; the
    // nonce itself is what's deduped.
    const replay = makeSignedBody({ nonce });
    const replayMsg = makeMessage(replay.data);
    await verifyAndDispatch(channel, replayMsg, SIGNING_KEY, handler, { logger, nonceStore });

    expect(handler).toHaveBeenCalledTimes(1); // still 1 — handler NOT invoked again
    expect(channel.acked).toHaveLength(1);
    expect(channel.nackCalls).toHaveLength(1);
    expect(channel.nackCalls[0]).toEqual({ msg: replayMsg, allUpTo: false, requeue: false });
    expect(events.some((e) => e.message.includes('nonce'))).toBe(true);
  });

  it('two distinct nonces from the same store are both accepted (no false-positive dedup)', async () => {
    const nonceStore = new InMemoryNonceStore();
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    const a = makeSignedBody({ nonce: randomUUID() });
    const b = makeSignedBody({ nonce: randomUUID() });
    await verifyAndDispatch(channel, makeMessage(a.data), SIGNING_KEY, handler, { nonceStore });
    await verifyAndDispatch(channel, makeMessage(b.data), SIGNING_KEY, handler, { nonceStore });

    expect(handler).toHaveBeenCalledTimes(2);
    expect(channel.acked).toHaveLength(2);
    expect(channel.nackCalls).toHaveLength(0);
  });

  it('a fresh nonceStore per call (the default) does NOT dedup across separate verifyAndDispatch invocations', async () => {
    // Documents the default: callers wanting cross-message dedup must share
    // one `nonceStore` (as `consume()` does internally) — omitting it is
    // only safe for a single, isolated call.
    const nonce = randomUUID();
    const channel = new RecordingChannel();
    const handler = vi.fn(async () => {});

    const first = makeSignedBody({ nonce });
    const second = makeSignedBody({ nonce });
    await verifyAndDispatch(channel, makeMessage(first.data), SIGNING_KEY, handler);
    await verifyAndDispatch(channel, makeMessage(second.data), SIGNING_KEY, handler);

    expect(handler).toHaveBeenCalledTimes(2);
    expect(channel.nackCalls).toHaveLength(0);
  });

  it('valid v2 body (key_version 2, fresh nonce, fresh issued_at): accepted and hmac_signature stripped', async () => {
    const { data } = makeSignedBody();
    const msg = makeMessage(data);
    const channel = new RecordingChannel();
    const handler = vi.fn(async (event: Record<string, unknown>) => {
      expect(event.hmac_signature).toBeUndefined();
      expect(event.key_version).toBe(2);
      expect(typeof event.nonce).toBe('string');
      expect(typeof event.issued_at).toBe('string');
    });

    await verifyAndDispatch(channel, msg, SIGNING_KEY, handler);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(channel.acked).toHaveLength(1);
    expect(channel.nackCalls).toHaveLength(0);
  });
});

describe('amqp/consumer.ts source guards', () => {
  it('nack calls are explicitly commented with /* requeue */ false (Pitfall 4 guard)', async () => {
    const fs = await import('node:fs/promises');
    const src = await fs.readFile(new URL('../../src/amqp/consumer.ts', import.meta.url), 'utf8');
    const requeueCommentCount = (src.match(/\/\*\s*requeue\s*\*\/\s*false/g) ?? []).length;
    expect(requeueCommentCount).toBeGreaterThan(0);
  });
});
