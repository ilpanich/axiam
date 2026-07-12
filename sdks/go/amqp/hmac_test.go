package amqp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// fixtureSigningKey is the per-tenant AMQP signing subkey used across the
// amqp package's tests (also referenced by consumer_test.go).
const fixtureSigningKey = "consumer-test-signing-key"

// hmacHex computes hex(HMAC-SHA256(key, canonical)) — the exact operation the
// Rust server performs in sign_payload (crates/axiam-amqp/src/messages.rs).
// Tests construct `canonical` as an explicit byte literal in the server's
// field-DECLARATION order, so the resulting signature is independent of the
// verifier's own canonicalization (it is NOT re-derived the same way
// verifyHMAC re-serializes — that would be tautological).
func hmacHex(t *testing.T, key, canonical string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// A realistic, full AuthzRequest whose DECLARATION order
// (correlation_id, tenant_id, subject_id, action, resource_id, key_version,
// nonce, issued_at) differs from ALPHABETICAL order (action, correlation_id,
// issued_at, key_version, nonce, resource_id, subject_id, tenant_id). This
// is the regression case the old buggy verifier (map re-marshal, which
// alphabetizes keys) got wrong: it would sign/verify over the alphabetical
// byte sequence, never the declaration-order sequence the server signed.
//
// NEW-4 (v2): nonce and issued_at are ALWAYS emitted (no skip_serializing_if
// on the server side), landing after key_version and before hmac_signature.
const (
	fixtureCorrelationID = "11111111-1111-1111-1111-111111111111"
	fixtureTenantID      = "22222222-2222-2222-2222-222222222222"
	fixtureSubjectID     = "33333333-3333-3333-3333-333333333333"
	fixtureResourceID    = "44444444-4444-4444-4444-444444444444"
	fixtureNonce         = "99999999-9999-9999-9999-999999999999"
	fixtureIssuedAt      = "2026-07-10T12:00:00Z"

	// Server-signed bytes: serde_json emits AuthzRequest in declaration
	// order, compact, with hmac_signature absent and key_version/nonce/
	// issued_at always present.
	fixtureCanonicalDeclOrder = `{"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"subject_id":"33333333-3333-3333-3333-333333333333",` +
		`"action":"read",` +
		`"resource_id":"44444444-4444-4444-4444-444444444444",` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z"}`

	// The byte sequence the OLD buggy Go verifier signed: the same fields
	// with keys sorted alphabetically (what json.Marshal(map[...]) produces).
	fixtureCanonicalAlphaOrder = `{"action":"read",` +
		`"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"resource_id":"44444444-4444-4444-4444-444444444444",` +
		`"subject_id":"33333333-3333-3333-3333-333333333333",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222"}`
)

// wire builds an on-the-wire AuthzRequest body (declaration order, matching
// how the server actually serializes) with the given hmac_signature attached
// as the trailing field.
func wire(sig string) string {
	return `{"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"subject_id":"33333333-3333-3333-3333-333333333333",` +
		`"action":"read",` +
		`"resource_id":"44444444-4444-4444-4444-444444444444",` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"hmac_signature":"` + sig + `"}`
}

// TestVerifyHMAC_DeclarationOrderAuthzRequest is the core regression test for
// SDK-Q01 / X-1: the verifier MUST canonicalize in the server's declaration
// order, not alphabetical order.
func TestVerifyHMAC_DeclarationOrderAuthzRequest(t *testing.T) {
	key := fixtureSigningKey

	t.Run("accepts a signature over the server's declaration-order bytes", func(t *testing.T) {
		sig := hmacHex(t, key, fixtureCanonicalDeclOrder)
		ok, meta := verifyHMAC([]byte(key), []byte(wire(sig)))
		if !ok {
			t.Fatal("verifyHMAC must accept a signature computed over the server's declaration-order bytes")
		}
		if meta.KeyVersion != 2 || meta.Nonce != fixtureNonce || meta.IssuedAt != fixtureIssuedAt {
			t.Fatalf("unexpected replayMeta: %+v", meta)
		}
	})

	t.Run("rejects a signature over alphabetically-ordered bytes (the old bug)", func(t *testing.T) {
		alphaSig := hmacHex(t, key, fixtureCanonicalAlphaOrder)
		// Sanity: declaration order and alphabetical order are genuinely
		// different byte sequences, so their signatures differ. If they were
		// equal the test would be meaningless.
		if declSig := hmacHex(t, key, fixtureCanonicalDeclOrder); alphaSig == declSig {
			t.Fatal("test fixture is degenerate: alphabetical and declaration order produced the same signature")
		}
		ok, _ := verifyHMAC([]byte(key), []byte(wire(alphaSig)))
		if ok {
			t.Fatal("verifyHMAC must REJECT a signature computed over alphabetically-ordered bytes")
		}
	})
}

func TestVerifyHMAC_RejectsTamperingAndMalformed(t *testing.T) {
	key := fixtureSigningKey
	validSig := hmacHex(t, key, fixtureCanonicalDeclOrder)

	t.Run("flipped signature byte fails verification", func(t *testing.T) {
		// Flip the first hex nibble of a valid signature.
		flipped := flipFirstHex(validSig)
		ok, _ := verifyHMAC([]byte(key), []byte(wire(flipped)))
		if ok {
			t.Fatal("expected verifyHMAC to return false when the signature is tampered")
		}
	})

	t.Run("wrong signing key fails verification", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte("Consumer-test-signing-key"), []byte(wire(validSig)))
		if ok {
			t.Fatal("expected verifyHMAC to return false when the signing key is wrong")
		}
	})

	t.Run("tampered body field fails verification", func(t *testing.T) {
		// Keep the valid signature but change action read -> write.
		tampered := `{"correlation_id":"11111111-1111-1111-1111-111111111111",` +
			`"tenant_id":"22222222-2222-2222-2222-222222222222",` +
			`"subject_id":"33333333-3333-3333-3333-333333333333",` +
			`"action":"write",` +
			`"resource_id":"44444444-4444-4444-4444-444444444444",` +
			`"key_version":2,` +
			`"nonce":"99999999-9999-9999-9999-999999999999",` +
			`"issued_at":"2026-07-10T12:00:00Z",` +
			`"hmac_signature":"` + validSig + `"}`
		ok, _ := verifyHMAC([]byte(key), []byte(tampered))
		if ok {
			t.Fatal("expected verifyHMAC to return false when a signed field is tampered")
		}
	})

	t.Run("missing hmac_signature fails verification (strict default)", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte(fixtureCanonicalDeclOrder))
		if ok {
			t.Fatal("expected verifyHMAC to return false when hmac_signature is absent (strict mode default)")
		}
	})

	t.Run("non-hex signature fails verification without panic", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte(wire("not-hex-zzzz")))
		if ok {
			t.Fatal("expected verifyHMAC to return false for a non-hex signature")
		}
	})

	t.Run("wrong-length signature fails verification without panic", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte(wire("5135")))
		if ok {
			t.Fatal("expected verifyHMAC to return false for a wrong-length signature")
		}
	})

	t.Run("malformed JSON body fails verification without panic", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte("not valid json {{{"))
		if ok {
			t.Fatal("expected verifyHMAC to return false for malformed JSON")
		}
	})
}

// TestVerifyHMAC_DeclarationOrderAuditEvent exercises the second signed
// message layout (AuditEventMessage), whose declaration order also differs
// from alphabetical order, including an optional (omitted) field, the raw-
// JSON metadata field, and the NEW-4 nonce/issued_at fields.
func TestVerifyHMAC_DeclarationOrderAuditEvent(t *testing.T) {
	key := fixtureSigningKey

	// AuditEventMessage declaration order: tenant_id, actor_id, actor_type,
	// action, [resource_id], outcome, [ip_address], [metadata], key_version,
	// nonce, issued_at. Here resource_id and ip_address are omitted (None);
	// metadata present.
	canonical := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z"}`
	sig := hmacHex(t, key, canonical)

	body := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"hmac_signature":"` + sig + `"}`

	ok, meta := verifyHMAC([]byte(key), []byte(body))
	if !ok {
		t.Fatal("verifyHMAC must accept an AuditEventMessage signed over its declaration-order bytes")
	}
	if meta.KeyVersion != 2 || meta.Nonce != fixtureNonce || meta.IssuedAt != fixtureIssuedAt {
		t.Fatalf("unexpected replayMeta: %+v", meta)
	}

	// An alphabetical-order signature over the same fields must be rejected.
	alpha := `{"action":"login",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"key_version":2,` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"outcome":"success",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222"}`
	alphaSig := hmacHex(t, key, alpha)
	alphaBody := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"hmac_signature":"` + alphaSig + `"}`
	ok, _ = verifyHMAC([]byte(key), []byte(alphaBody))
	if ok {
		t.Fatal("verifyHMAC must REJECT an AuditEventMessage signature computed over alphabetically-ordered bytes")
	}
}

// TestVerifyHMAC_ReferenceVectors is the ground-truth parity test for NEW-4:
// it hardcodes the server-generated canonical bytes, the derived per-tenant
// subkey, and the expected HMAC from
// crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json (GENERATED by
// the AXIAM server's sign path) and asserts:
//
//  1. The Go canonical re-marshal (via canonicalCandidates, exercised
//     through verifyHMAC) reproduces `canonical_signed_json` byte-for-byte
//     for BOTH message types — recomputing the HMAC over that candidate
//     must land on the fixture's `hmac_signature_hex` exactly.
//  2. verifyHMAC, given the on-the-wire `message` object (arbitrary/
//     alphabetical key order, as encoded in the fixture JSON — Go's
//     json.Unmarshal into a struct does not care about incoming field
//     order) and the fixture's derived subkey, ACCEPTS the signature.
//
// The Go SDK does not perform HKDF subkey derivation itself (signingKey is
// obtained pre-derived from the AXIAM management API per §8.1), so this
// test uses the fixture's already-derived `derived_subkey_hex` directly as
// the signing key, matching this package's runtime contract.
func TestVerifyHMAC_ReferenceVectors(t *testing.T) {
	// From crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json.
	// masterSigningKeyHex and tenantID are the inputs the server's
	// derive_tenant_key(master, tenant_id, key_version) HKDF-SHA256 step
	// consumed to produce derivedSubkeyHex; recorded here for traceability
	// back to the fixture even though this SDK receives the pre-derived
	// per-tenant subkey (never the master key) and so never performs that
	// derivation itself (§8.1).
	const derivedSubkeyHex = "919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89"
	const masterSigningKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const tenantID = "11111111-1111-1111-1111-111111111111"

	subkey, err := hex.DecodeString(derivedSubkeyHex)
	if err != nil {
		t.Fatalf("fixture derived_subkey_hex is not valid hex: %v", err)
	}

	t.Run("authz_request", func(t *testing.T) {
		const canonicalSignedJSON = `{"correlation_id":"22222222-2222-2222-2222-222222222222",` +
			`"tenant_id":"11111111-1111-1111-1111-111111111111",` +
			`"subject_id":"33333333-3333-3333-3333-333333333333",` +
			`"action":"documents:read",` +
			`"resource_id":"44444444-4444-4444-4444-444444444444",` +
			`"scope":"confidential",` +
			`"key_version":2,` +
			`"nonce":"55555555-5555-5555-5555-555555555555",` +
			`"issued_at":"2026-07-10T12:00:00Z"}`
		const expectedHMACHex = "13d73b3aa8a400fc3f64dbc20b36952d8584142feb822b5f77495b0f587049ed"

		// (1) Byte-for-byte canonical parity: re-marshal via the Go
		// canonical struct and confirm the recomputed HMAC matches the
		// fixture's expected HMAC exactly.
		var authz authzRequestCanonical
		if err := json.Unmarshal([]byte(canonicalSignedJSON), &authz); err != nil {
			t.Fatalf("failed to unmarshal fixture canonical JSON: %v", err)
		}
		remarshaled, err := json.Marshal(&authz)
		if err != nil {
			t.Fatalf("failed to re-marshal canonical struct: %v", err)
		}
		if string(remarshaled) != canonicalSignedJSON {
			t.Fatalf("Go canonical re-marshal does not match fixture canonical_signed_json byte-for-byte:\n got: %s\nwant: %s", remarshaled, canonicalSignedJSON)
		}
		mac := hmac.New(sha256.New, subkey)
		mac.Write(remarshaled)
		gotHMAC := hex.EncodeToString(mac.Sum(nil))
		if gotHMAC != expectedHMACHex {
			t.Fatalf("recomputed HMAC does not match fixture hmac_signature_hex: got %s want %s", gotHMAC, expectedHMACHex)
		}

		// (2) The on-the-wire message (fixture's "message" object, given in
		// alphabetical key order in the JSON file) verifies via verifyHMAC.
		wireBody := `{"action":"documents:read",` +
			`"correlation_id":"22222222-2222-2222-2222-222222222222",` +
			`"hmac_signature":"13d73b3aa8a400fc3f64dbc20b36952d8584142feb822b5f77495b0f587049ed",` +
			`"issued_at":"2026-07-10T12:00:00Z",` +
			`"key_version":2,` +
			`"nonce":"55555555-5555-5555-5555-555555555555",` +
			`"resource_id":"44444444-4444-4444-4444-444444444444",` +
			`"scope":"confidential",` +
			`"subject_id":"33333333-3333-3333-3333-333333333333",` +
			`"tenant_id":"11111111-1111-1111-1111-111111111111"}`
		ok, meta := verifyHMAC(subkey, []byte(wireBody))
		if !ok {
			t.Fatal("verifyHMAC must ACCEPT the server-signed v2 authz_request reference vector")
		}
		if meta.KeyVersion != 2 || meta.Nonce != "55555555-5555-5555-5555-555555555555" || meta.IssuedAt != "2026-07-10T12:00:00Z" {
			t.Fatalf("unexpected replayMeta: %+v", meta)
		}
	})

	t.Run("audit_event", func(t *testing.T) {
		const canonicalSignedJSON = `{"tenant_id":"11111111-1111-1111-1111-111111111111",` +
			`"actor_id":"66666666-6666-6666-6666-666666666666",` +
			`"actor_type":"User",` +
			`"action":"user.login",` +
			`"resource_id":"77777777-7777-7777-7777-777777777777",` +
			`"outcome":"Success",` +
			`"ip_address":"203.0.113.7",` +
			`"metadata":{"method":"password"},` +
			`"key_version":2,` +
			`"nonce":"88888888-8888-8888-8888-888888888888",` +
			`"issued_at":"2026-07-10T12:00:00Z"}`
		const expectedHMACHex = "c87056dfa96bf0606949104108e5fc7296df0a22ad39bf94bbc00512b214f40f"

		var audit auditEventCanonical
		if err := json.Unmarshal([]byte(canonicalSignedJSON), &audit); err != nil {
			t.Fatalf("failed to unmarshal fixture canonical JSON: %v", err)
		}
		remarshaled, err := json.Marshal(&audit)
		if err != nil {
			t.Fatalf("failed to re-marshal canonical struct: %v", err)
		}
		if string(remarshaled) != canonicalSignedJSON {
			t.Fatalf("Go canonical re-marshal does not match fixture canonical_signed_json byte-for-byte:\n got: %s\nwant: %s", remarshaled, canonicalSignedJSON)
		}
		mac := hmac.New(sha256.New, subkey)
		mac.Write(remarshaled)
		gotHMAC := hex.EncodeToString(mac.Sum(nil))
		if gotHMAC != expectedHMACHex {
			t.Fatalf("recomputed HMAC does not match fixture hmac_signature_hex: got %s want %s", gotHMAC, expectedHMACHex)
		}

		wireBody := `{"action":"user.login",` +
			`"actor_id":"66666666-6666-6666-6666-666666666666",` +
			`"actor_type":"User",` +
			`"hmac_signature":"c87056dfa96bf0606949104108e5fc7296df0a22ad39bf94bbc00512b214f40f",` +
			`"ip_address":"203.0.113.7",` +
			`"issued_at":"2026-07-10T12:00:00Z",` +
			`"key_version":2,` +
			`"metadata":{"method":"password"},` +
			`"nonce":"88888888-8888-8888-8888-888888888888",` +
			`"outcome":"Success",` +
			`"resource_id":"77777777-7777-7777-7777-777777777777",` +
			`"tenant_id":"11111111-1111-1111-1111-111111111111"}`
		ok, meta := verifyHMAC(subkey, []byte(wireBody))
		if !ok {
			t.Fatal("verifyHMAC must ACCEPT the server-signed v2 audit_event reference vector")
		}
		if meta.KeyVersion != 2 || meta.Nonce != "88888888-8888-8888-8888-888888888888" || meta.IssuedAt != "2026-07-10T12:00:00Z" {
			t.Fatalf("unexpected replayMeta: %+v", meta)
		}
	})
}

// flipFirstHex flips the first hex character of s to a different value so the
// resulting string stays valid hex but decodes to different bytes.
func flipFirstHex(s string) string {
	if len(s) == 0 {
		return s
	}
	first := s[0]
	var repl byte = '0'
	if first == '0' {
		repl = '1'
	}
	return string(repl) + s[1:]
}
