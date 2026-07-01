// AMQP consumer example — HMAC-verified event handling with a
// caller-supplied Sensitive signing key (CONTRACT.md §8, D-12).
//
// Illustrative/compilable: `consume()` owns the full ack/nack loop and
// verifies every delivery's HMAC-SHA256 signature BEFORE the handler
// closure ever sees the message body — verification failures are
// nacked-without-requeue and never reach this handler. The signing key is
// a required, caller-supplied `Sensitive<Buffer>`; the SDK never fetches it
// from the server.
//
// Run: `npx tsx examples/amqp-consumer.ts` against a reachable RabbitMQ
// broker with AXIAM_AMQP_SIGNING_KEY set (hex-encoded); the compile check
// (`tsc --noEmit -p examples/tsconfig.json`) is the SC#4 gate here, not
// execution.

import { consume, Sensitive } from 'axiam-sdk/amqp';

const amqpUrl = process.env.AXIAM_AMQP_URL ?? 'amqp://localhost:5672';
const queue = 'axiam.audit.events';
const signingKey = new Sensitive(Buffer.from(process.env.AXIAM_AMQP_SIGNING_KEY ?? '', 'hex'));

async function main(): Promise<void> {
  await consume(amqpUrl, queue, signingKey, async (event) => {
    // Only a verified event ever reaches this closure — the SDK has
    // already checked the HMAC signature and stripped it from `event`.
    console.log('verified audit event:', event);
  });

  console.log(`Consuming from ${queue} — every delivery is HMAC-verified before this handler runs`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
