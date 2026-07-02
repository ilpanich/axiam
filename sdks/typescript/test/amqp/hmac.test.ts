import { describe, expect, it } from 'vitest';
import { signPayload, verifyPayload } from '../../src/amqp/hmac.js';

describe('amqp/hmac', () => {
  describe('fixed-vector byte-identity (CONTRACT.md §8 / crates/axiam-amqp/src/messages.rs)', () => {
    // Known key + known canonical-JSON bytes -> known hex, cross-checked
    // independently via `openssl dgst -sha256 -hmac "test-fixed-vector-key"`
    // against the same payload bytes. A future change to the
    // serialization/HMAC path that alters this output will fail this test.
    const key = Buffer.from('test-fixed-vector-key', 'utf8');
    const canonicalJson = Buffer.from(
      '{"correlation_id":"00000000-0000-0000-0000-000000000000","tenant_id":"11111111-1111-1111-1111-111111111111","action":"read"}',
      'utf8',
    );
    const expectedHex = '656f19dbda20b9a2aea86db0864a758985f47cc41a58feade28a9fce812faf0e';

    it('signPayload reproduces the fixed-vector hex', () => {
      expect(signPayload(key, canonicalJson)).toBe(expectedHex);
    });

    it('verifyPayload accepts the fixed-vector signature', () => {
      expect(verifyPayload(key, canonicalJson, expectedHex)).toBe(true);
    });

    it('verifyPayload rejects a flipped byte in the signature', () => {
      // Flip the first hex character of the last byte pair.
      const flipped = expectedHex.slice(0, -2) + (expectedHex.slice(-2, -1) === '0' ? '1' : '0') + expectedHex.slice(-1);
      expect(verifyPayload(key, canonicalJson, flipped)).toBe(false);
    });

    it('verifyPayload rejects a tampered payload with the original signature', () => {
      const tampered = Buffer.from(canonicalJson.toString('utf8').replace('"read"', '"write"'), 'utf8');
      expect(verifyPayload(key, tampered, expectedHex)).toBe(false);
    });
  });

  describe('key-order preservation (Pitfall 5)', () => {
    it('JSON.stringify after delete obj.hmac_signature preserves original insertion order', () => {
      const original =
        '{"correlation_id":"c1","tenant_id":"t1","action":"read","hmac_signature":"deadbeef"}';
      const parsed = JSON.parse(original) as Record<string, unknown>;
      delete parsed.hmac_signature;
      const restringified = JSON.stringify(parsed);

      expect(restringified).toBe('{"correlation_id":"c1","tenant_id":"t1","action":"read"}');
      // Explicitly assert key order (not just value equality) via Object.keys.
      expect(Object.keys(parsed)).toEqual(['correlation_id', 'tenant_id', 'action']);
    });
  });

  describe('verifyPayload never throws', () => {
    const key = Buffer.from('some-key', 'utf8');
    const payload = Buffer.from('{"a":1}', 'utf8');

    it('returns false (does not throw) on malformed hex', () => {
      expect(() => verifyPayload(key, payload, 'not-valid-hex!!')).not.toThrow();
      expect(verifyPayload(key, payload, 'not-valid-hex!!')).toBe(false);
    });

    it('returns false on odd-length hex (invalid hex encoding)', () => {
      expect(() => verifyPayload(key, payload, 'abc')).not.toThrow();
      expect(verifyPayload(key, payload, 'abc')).toBe(false);
    });

    it('returns false on a length-mismatched but well-formed hex signature', () => {
      const shortSig = 'aabbcc'; // valid hex, wrong length vs a 32-byte SHA-256 digest
      expect(() => verifyPayload(key, payload, shortSig)).not.toThrow();
      expect(verifyPayload(key, payload, shortSig)).toBe(false);
    });

    it('returns false for an empty signature string', () => {
      expect(verifyPayload(key, payload, '')).toBe(false);
    });
  });
});
