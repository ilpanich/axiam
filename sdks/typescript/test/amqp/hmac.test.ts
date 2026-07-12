import { readFileSync } from 'node:fs';
import { hkdfSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { signPayload, verifyPayload } from '../../src/amqp/hmac.js';

/**
 * Server-generated canonical bytes + expected HMAC for v2 `AuthzRequest`/
 * `AuditEventMessage` (NEW-4). Ground truth for every SDK, not TS-owned —
 * see `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json`.
 */
interface V2ReferenceVectors {
  audit_event: { canonical_signed_json: string; hmac_signature_hex: string };
  authz_request: { canonical_signed_json: string; hmac_signature_hex: string };
  hkdf: { app_salt_utf8: string; derived_subkey_hex: string; domain_tag_utf8: string };
  key_version: number;
  master_signing_key_hex: string;
  tenant_id: string;
}

const fixture: V2ReferenceVectors = JSON.parse(
  readFileSync(
    new URL(
      '../../../../crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as V2ReferenceVectors;

/**
 * HKDF-SHA256(salt=APP_SALT, ikm=master, info=DOMAIN_TAG||key_version(1
 * byte)||tenant_id(16 raw bytes)) — mirrors the server's
 * `derive_tenant_key` (`crates/axiam-amqp/src/messages.rs`). Test-local
 * only: the TS SDK's public API takes an already-derived per-tenant key
 * (CONTRACT.md §8.1, out-of-band provisioning), so this is not exposed from
 * `src/`.
 */
function deriveTenantKey(masterHex: string, tenantId: string, keyVersion: number): Buffer {
  const master = Buffer.from(masterHex, 'hex');
  const salt = Buffer.from(fixture.hkdf.app_salt_utf8, 'utf8');
  const domainTag = Buffer.from(fixture.hkdf.domain_tag_utf8, 'utf8');
  const tenantBytes = Buffer.from(tenantId.replace(/-/g, ''), 'hex');
  const info = Buffer.concat([domainTag, Buffer.from([keyVersion]), tenantBytes]);
  return Buffer.from(hkdfSync('sha256', master, salt, info, 32));
}

describe('amqp/hmac', () => {
  describe('NEW-4 v2 reference vectors (server ground truth, byte-for-byte)', () => {
    it('derives the same per-tenant HKDF subkey as the fixture', () => {
      const subkey = deriveTenantKey(fixture.master_signing_key_hex, fixture.tenant_id, fixture.key_version);
      expect(subkey.toString('hex')).toBe(fixture.hkdf.derived_subkey_hex);
    });

    it('reproduces the server hmac_signature_hex for the AuthzRequest vector', () => {
      const subkey = deriveTenantKey(fixture.master_signing_key_hex, fixture.tenant_id, fixture.key_version);
      const canonical = Buffer.from(fixture.authz_request.canonical_signed_json, 'utf8');

      expect(signPayload(subkey, canonical)).toBe(fixture.authz_request.hmac_signature_hex);
      expect(verifyPayload(subkey, canonical, fixture.authz_request.hmac_signature_hex)).toBe(true);
    });

    it('reproduces the server hmac_signature_hex for the AuditEventMessage vector', () => {
      const subkey = deriveTenantKey(fixture.master_signing_key_hex, fixture.tenant_id, fixture.key_version);
      const canonical = Buffer.from(fixture.audit_event.canonical_signed_json, 'utf8');

      expect(signPayload(subkey, canonical)).toBe(fixture.audit_event.hmac_signature_hex);
      expect(verifyPayload(subkey, canonical, fixture.audit_event.hmac_signature_hex)).toBe(true);
    });

    it('parsing the server message, deleting hmac_signature, and re-stringifying reproduces the canonical bytes (Pitfall 5)', () => {
      // This is the exact TS consumer path (JSON.parse -> delete
      // hmac_signature -> JSON.stringify) proving nonce/issued_at need no
      // canonicalization change: the server's declared field order survives
      // JSON parse/insertion-order re-stringify unchanged.
      for (const vector of [fixture.authz_request, fixture.audit_event] as const) {
        const parsed = JSON.parse(vector.canonical_signed_json) as Record<string, unknown> & {
          hmac_signature?: string;
        };
        parsed.hmac_signature = vector.hmac_signature_hex;
        delete parsed.hmac_signature;
        expect(JSON.stringify(parsed)).toBe(vector.canonical_signed_json);
      }
    });
  });

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
