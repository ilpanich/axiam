// AXIAM SDK — AMQP entry (`axiam-sdk/amqp`), Node-only opt-in subpath.
//
// Re-exports the HMAC sign/verify pair, server-identical message DTOs, and
// the verify-before-handler `consume()` function (D-12, CONTRACT.md §8).
// `Sensitive` is re-exported here too — `consume()`'s public signature
// requires callers to construct a `Sensitive<Buffer>` signing key, so this
// entry point must expose the class itself rather than forcing consumers
// to reach into `axiam-sdk`'s root/`rest` entry just to wrap a key.

export { Sensitive } from '../core/index.js';
export * from './hmac.js';
export * from './messages.js';
export * from './consumer.js';
