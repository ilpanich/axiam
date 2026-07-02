// Package amqp implements the AXIAM AMQP event consumer: a closure-handler
// Consume loop that HMAC-SHA256-verifies every delivery BEFORE the caller's
// handler ever runs (CONTRACT.md §8, D-07, SC#4).
package amqp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// verifyHMAC reproduces the server's canonical HMAC-SHA256 protocol
// byte-for-byte (crates/axiam-amqp/src/messages.rs sign_payload/
// verify_payload, mirrored — never imported, since this SDK must not depend
// on server crates):
//
//  1. Unmarshal body into a field-preserving map (json.RawMessage values, so
//     every other field's exact byte representation round-trips unchanged).
//  2. Extract the hmac_signature field. Its absence is a verification
//     failure in strict mode (the default, CONTRACT.md §8.3) — never a
//     silent pass-through.
//  3. Delete hmac_signature from the map and re-serialize the remainder to
//     canonical JSON. Go's encoding/json sorts map keys alphabetically,
//     matching the server's serde_json::to_vec ordering (BTreeMap-backed,
//     no preserve_order feature) for the same field set.
//  4. Compute HMAC-SHA256(signingKey, canonical) and hex-decode the
//     received signature.
//  5. Compare using hmac.Equal — constant-time, never bytes.Equal/==.
//
// Returns false (never panics) for malformed JSON, a missing signature, or
// a non-hex/wrong-length signature.
func verifyHMAC(signingKey []byte, body []byte) bool {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return false
	}

	sigRaw, ok := msg["hmac_signature"]
	if !ok {
		// Strict mode default (CONTRACT.md §8.3): a message with no
		// hmac_signature field is rejected, not accepted.
		return false
	}

	var sigHex string
	if err := json.Unmarshal(sigRaw, &sigHex); err != nil {
		return false
	}

	delete(msg, "hmac_signature")
	canonical, err := json.Marshal(msg)
	if err != nil {
		return false
	}

	expected, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	computed := mac.Sum(nil)

	return hmac.Equal(computed, expected)
}
