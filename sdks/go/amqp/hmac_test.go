package amqp

import "testing"

// signingKey and validBody/validSignature are a fixture derived from the
// server's canonical protocol (crates/axiam-amqp/src/messages.rs
// sign_payload): canonical = {"action":"read","correlation_id":"0000...
// 0000"} (keys sorted, compact JSON, hmac_signature field absent), and
// validSignature = hex(HMAC-SHA256(signingKey, canonical)). Verified
// byte-identical against both Go's json.Marshal(map[string]json.RawMessage)
// and the server's serde_json::to_vec ordering (BTreeMap-backed, no
// preserve_order feature) before being hardcoded here.
const (
	fixtureSigningKey = "consumer-test-signing-key"
	fixtureSignature  = "51350a8c495e7fd7b73854231382bd53c3d67d9b196fc7a6dd7ba49006ffe415"
	fixtureBody       = `{"action":"read","correlation_id":"00000000-0000-0000-0000-000000000000","hmac_signature":"51350a8c495e7fd7b73854231382bd53c3d67d9b196fc7a6dd7ba49006ffe415"}`
)

func TestVerifyHMAC_MatchesServerProtocol(t *testing.T) {
	key := []byte(fixtureSigningKey)

	t.Run("valid signature verifies true against server-protocol fixture", func(t *testing.T) {
		if !verifyHMAC(key, []byte(fixtureBody)) {
			t.Fatal("expected verifyHMAC to return true for a valid server-protocol fixture")
		}
	})

	t.Run("flipped signature byte fails verification", func(t *testing.T) {
		// Flip the first hex character of the signature (5 -> 6).
		tampered := `{"action":"read","correlation_id":"00000000-0000-0000-0000-000000000000","hmac_signature":"61350a8c495e7fd7b73854231382bd53c3d67d9b196fc7a6dd7ba49006ffe415"}`
		if verifyHMAC(key, []byte(tampered)) {
			t.Fatal("expected verifyHMAC to return false when the signature is tampered")
		}
	})

	t.Run("flipped key byte fails verification", func(t *testing.T) {
		wrongKey := []byte("Consumer-test-signing-key") // capital C vs lowercase c
		if verifyHMAC(wrongKey, []byte(fixtureBody)) {
			t.Fatal("expected verifyHMAC to return false when the signing key is wrong")
		}
	})

	t.Run("flipped body byte fails verification", func(t *testing.T) {
		tampered := `{"action":"write","correlation_id":"00000000-0000-0000-0000-000000000000","hmac_signature":"51350a8c495e7fd7b73854231382bd53c3d67d9b196fc7a6dd7ba49006ffe415"}`
		if verifyHMAC(key, []byte(tampered)) {
			t.Fatal("expected verifyHMAC to return false when the body is tampered")
		}
	})

	t.Run("missing hmac_signature field fails verification (strict default)", func(t *testing.T) {
		noSig := `{"action":"read","correlation_id":"00000000-0000-0000-0000-000000000000"}`
		if verifyHMAC(key, []byte(noSig)) {
			t.Fatal("expected verifyHMAC to return false when hmac_signature is absent (strict mode default)")
		}
	})

	t.Run("non-hex signature fails verification without panic", func(t *testing.T) {
		badHex := `{"action":"read","correlation_id":"00000000-0000-0000-0000-000000000000","hmac_signature":"not-hex-zzzz"}`
		if verifyHMAC(key, []byte(badHex)) {
			t.Fatal("expected verifyHMAC to return false for non-hex signature")
		}
	})

	t.Run("wrong-length signature fails verification without panic", func(t *testing.T) {
		shortSig := `{"action":"read","correlation_id":"00000000-0000-0000-0000-000000000000","hmac_signature":"5135"}`
		if verifyHMAC(key, []byte(shortSig)) {
			t.Fatal("expected verifyHMAC to return false for a wrong-length signature")
		}
	})

	t.Run("malformed JSON body fails verification without panic", func(t *testing.T) {
		if verifyHMAC(key, []byte("not valid json {{{")) {
			t.Fatal("expected verifyHMAC to return false for malformed JSON")
		}
	})
}
