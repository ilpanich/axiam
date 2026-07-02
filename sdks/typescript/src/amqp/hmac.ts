// AMQP HMAC-SHA256 sign/verify (CONTRACT.md §8, D-12).
//
// Mirror, never import. This module reproduces the server's algorithm in
// crates/axiam-amqp/src/messages.rs:35-50 (and sdks/rust/src/amqp/hmac.rs)
// byte-for-byte using only Node's built-in `node:crypto` module, so the
// SDK's HMAC output is wire-compatible with the AXIAM server for the same
// key + canonical JSON payload bytes.
//
// Protocol (CONTRACT.md §8.2):
//   a. Extract hmac_signature from the message.
//   b. Set hmac_signature to null/absent in the body.
//   c. Serialize the remaining body to canonical JSON (declaration/insertion
//      order, no re-sorting — see messages.ts and Pitfall 5).
//   d. HMAC-SHA256(key, canonical_json_bytes), hex-encoded.
//   e. Constant-time compare against the received signature.

import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Compute the hex-encoded HMAC-SHA256 of `payloadJson` using `key`.
 *
 * `payloadJson` MUST be the canonical JSON bytes of the message body with
 * `hmac_signature` already removed — otherwise the signature is computed
 * over a payload that includes a placeholder signature, making verification
 * impossible (matches the server's `sign_payload` doc comment).
 */
export function signPayload(key: Buffer, payloadJson: Buffer): string {
  return createHmac('sha256', key).update(payloadJson).digest('hex');
}

/**
 * Verify a hex-encoded HMAC-SHA256 signature over `payloadJson` using `key`.
 *
 * Returns `true` only if the signature matches, comparing in constant time
 * via `timingSafeEqual`. Never throws: malformed hex or a length mismatch
 * both return `false`.
 */
export function verifyPayload(key: Buffer, payloadJson: Buffer, signatureHex: string): boolean {
  const expected = createHmac('sha256', key).update(payloadJson).digest();
  let received: Buffer;
  try {
    received = Buffer.from(signatureHex, 'hex');
  } catch {
    return false;
  }
  // timingSafeEqual requires equal-length buffers; a length mismatch is
  // itself not secret information, so a fast-path length check first is
  // safe and matches Rust's hmac crate `verify_slice` behavior.
  if (received.length !== expected.length) return false;
  return timingSafeEqual(received, expected);
}
