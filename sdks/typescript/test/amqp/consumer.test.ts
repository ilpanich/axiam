import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { signPayload } from '../../src/amqp/hmac.js';
import { verifyAndDispatch, type ConsumeChannel, type ConsumeLogger } from '../../src/amqp/consumer.js';

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

function makeSignedBody(): { body: Record<string, unknown>; data: Buffer } {
  const body: Record<string, unknown> = {
    correlation_id: '00000000-0000-0000-0000-000000000000',
    action: 'read',
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
    const body = { correlation_id: '00000000-0000-0000-0000-000000000000', action: 'read' };
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
    const body = { correlation_id: '00000000-0000-0000-0000-000000000000', action: 'read' };
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

describe('amqp/consumer.ts source guards', () => {
  it('nack calls are explicitly commented with /* requeue */ false (Pitfall 4 guard)', async () => {
    const fs = await import('node:fs/promises');
    const src = await fs.readFile(new URL('../../src/amqp/consumer.ts', import.meta.url), 'utf8');
    const requeueCommentCount = (src.match(/\/\*\s*requeue\s*\*\/\s*false/g) ?? []).length;
    expect(requeueCommentCount).toBeGreaterThan(0);
  });
});
