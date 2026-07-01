// AXIAM SDK — AMQP entry (`axiam-sdk/amqp`), Node-only opt-in subpath.
//
// Re-exports the HMAC sign/verify pair, server-identical message DTOs, and
// the verify-before-handler `consume()` function (D-12, CONTRACT.md §8).

export * from './hmac.js';
export * from './messages.js';
export * from './consumer.js';
