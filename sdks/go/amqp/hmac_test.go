package amqp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
// (correlation_id, tenant_id, subject_id, action, resource_id, key_version)
// differs from ALPHABETICAL order
// (action, correlation_id, key_version, resource_id, subject_id, tenant_id).
// This is the regression case the old buggy verifier (map re-marshal, which
// alphabetizes keys) got wrong: it would sign/verify over the alphabetical
// byte sequence, never the declaration-order sequence the server signed.
const (
	fixtureCorrelationID = "11111111-1111-1111-1111-111111111111"
	fixtureTenantID      = "22222222-2222-2222-2222-222222222222"
	fixtureSubjectID     = "33333333-3333-3333-3333-333333333333"
	fixtureResourceID    = "44444444-4444-4444-4444-444444444444"

	// Server-signed bytes: serde_json emits AuthzRequest in declaration
	// order, compact, with hmac_signature absent and key_version always
	// present (scope omitted here because it is None).
	fixtureCanonicalDeclOrder = `{"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"subject_id":"33333333-3333-3333-3333-333333333333",` +
		`"action":"read",` +
		`"resource_id":"44444444-4444-4444-4444-444444444444",` +
		`"key_version":1}`

	// The byte sequence the OLD buggy Go verifier signed: the same fields
	// with keys sorted alphabetically (what json.Marshal(map[...]) produces).
	fixtureCanonicalAlphaOrder = `{"action":"read",` +
		`"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"key_version":1,` +
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
		`"key_version":1,` +
		`"hmac_signature":"` + sig + `"}`
}

// TestVerifyHMAC_DeclarationOrderAuthzRequest is the core regression test for
// SDK-Q01 / X-1: the verifier MUST canonicalize in the server's declaration
// order, not alphabetical order.
func TestVerifyHMAC_DeclarationOrderAuthzRequest(t *testing.T) {
	key := fixtureSigningKey

	t.Run("accepts a signature over the server's declaration-order bytes", func(t *testing.T) {
		sig := hmacHex(t, key, fixtureCanonicalDeclOrder)
		if !verifyHMAC([]byte(key), []byte(wire(sig))) {
			t.Fatal("verifyHMAC must accept a signature computed over the server's declaration-order bytes")
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
		if verifyHMAC([]byte(key), []byte(wire(alphaSig))) {
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
		if verifyHMAC([]byte(key), []byte(wire(flipped))) {
			t.Fatal("expected verifyHMAC to return false when the signature is tampered")
		}
	})

	t.Run("wrong signing key fails verification", func(t *testing.T) {
		if verifyHMAC([]byte("Consumer-test-signing-key"), []byte(wire(validSig))) {
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
			`"key_version":1,` +
			`"hmac_signature":"` + validSig + `"}`
		if verifyHMAC([]byte(key), []byte(tampered)) {
			t.Fatal("expected verifyHMAC to return false when a signed field is tampered")
		}
	})

	t.Run("missing hmac_signature fails verification (strict default)", func(t *testing.T) {
		if verifyHMAC([]byte(key), []byte(fixtureCanonicalDeclOrder)) {
			t.Fatal("expected verifyHMAC to return false when hmac_signature is absent (strict mode default)")
		}
	})

	t.Run("non-hex signature fails verification without panic", func(t *testing.T) {
		if verifyHMAC([]byte(key), []byte(wire("not-hex-zzzz"))) {
			t.Fatal("expected verifyHMAC to return false for a non-hex signature")
		}
	})

	t.Run("wrong-length signature fails verification without panic", func(t *testing.T) {
		if verifyHMAC([]byte(key), []byte(wire("5135"))) {
			t.Fatal("expected verifyHMAC to return false for a wrong-length signature")
		}
	})

	t.Run("malformed JSON body fails verification without panic", func(t *testing.T) {
		if verifyHMAC([]byte(key), []byte("not valid json {{{")) {
			t.Fatal("expected verifyHMAC to return false for malformed JSON")
		}
	})
}

// TestVerifyHMAC_DeclarationOrderAuditEvent exercises the second signed
// message layout (AuditEventMessage), whose declaration order also differs
// from alphabetical order, including an optional (omitted) field and the
// raw-JSON metadata field.
func TestVerifyHMAC_DeclarationOrderAuditEvent(t *testing.T) {
	key := fixtureSigningKey

	// AuditEventMessage declaration order: tenant_id, actor_id, actor_type,
	// action, [resource_id], outcome, [ip_address], [metadata], key_version.
	// Here resource_id and ip_address are omitted (None); metadata present.
	canonical := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":1}`
	sig := hmacHex(t, key, canonical)

	body := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":1,` +
		`"hmac_signature":"` + sig + `"}`

	if !verifyHMAC([]byte(key), []byte(body)) {
		t.Fatal("verifyHMAC must accept an AuditEventMessage signed over its declaration-order bytes")
	}

	// An alphabetical-order signature over the same fields must be rejected.
	alpha := `{"action":"login",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"key_version":1,` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"outcome":"success",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222"}`
	alphaSig := hmacHex(t, key, alpha)
	alphaBody := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":1,` +
		`"hmac_signature":"` + alphaSig + `"}`
	if verifyHMAC([]byte(key), []byte(alphaBody)) {
		t.Fatal("verifyHMAC must REJECT an AuditEventMessage signature computed over alphabetically-ordered bytes")
	}
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
