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
// on server crates).
//
// CRITICAL canonicalization contract: the server's wire types
// (AuthzRequest, AuditEventMessage) are typed Rust structs, NOT maps.
// serde_json serializes a struct's fields in DECLARATION ORDER, not
// alphabetical order, emitting compact JSON (no spaces) with hmac_signature
// absent at signing time (the signature is computed first, then attached).
// Optional fields (`Option<T>` with `skip_serializing_if = "Option::is_none"`)
// are omitted entirely when absent; `key_version` (a `u8` with a serde
// default but NO skip) is ALWAYS emitted as a bare integer.
//
// Go's encoding/json sorts map keys ALPHABETICALLY, so re-marshaling a
// map[string]json.RawMessage would HMAC over a different byte sequence than
// the server signed and reject every real multi-field message. Instead we
// re-serialize into a Go struct whose json-tagged fields are declared in the
// server's exact field order (json.Marshal emits struct fields in
// declaration order), reproducing serde_json's bytes precisely. This mirrors
// the order-preserving canonicalization the Python and TypeScript SDKs get
// for free from their insertion-ordered JSON parsers.
//
// Steps:
//  1. Extract the received hmac_signature (order-independent). Its absence is
//     a verification failure in strict mode (the default, CONTRACT.md §8.3) —
//     never a silent pass-through.
//  2. Reconstruct the canonical signed bytes by unmarshaling the body into
//     each known signed message layout (AuthzRequest, AuditEventMessage) and
//     re-marshaling it in declaration order, with hmac_signature excluded.
//  3. Accept iff HMAC-SHA256(signingKey, canonical) equals the received
//     signature for one of those layouts. A cryptographic match is only
//     possible for the layout the server actually signed, so trying each is
//     safe (no false accept) and needs no separate discriminator field.
//  4. Compare using hmac.Equal — constant-time, never bytes.Equal/==.
//
// Returns false (never panics) for malformed JSON, a missing/non-string
// signature, or a non-hex signature.
func verifyHMAC(signingKey []byte, body []byte) bool {
	// Step 1: extract the received signature, independent of field order.
	var envelope struct {
		HMACSignature *string `json:"hmac_signature"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false
	}
	if envelope.HMACSignature == nil {
		// Strict mode default (CONTRACT.md §8.3): a message with no
		// hmac_signature field (or a non-string value) is rejected, never
		// silently accepted.
		return false
	}

	expected, err := hex.DecodeString(*envelope.HMACSignature)
	if err != nil {
		return false
	}

	// Steps 2-4: try each known declaration-order layout; accept on the
	// first cryptographic match.
	for _, canonical := range canonicalCandidates(body) {
		mac := hmac.New(sha256.New, signingKey)
		mac.Write(canonical)
		if hmac.Equal(mac.Sum(nil), expected) {
			return true
		}
	}
	return false
}

// authzRequestCanonical mirrors the server's AuthzRequest struct
// (crates/axiam-amqp/src/messages.rs) in EXACT field-declaration order.
// UUIDs are serialized by serde as JSON strings, so plain Go strings
// round-trip byte-identically. `scope` is optional (omitted when absent);
// `key_version` is always emitted. `hmac_signature` is intentionally absent —
// it is not part of the signed bytes.
type authzRequestCanonical struct {
	CorrelationID string  `json:"correlation_id"`
	TenantID      string  `json:"tenant_id"`
	SubjectID     string  `json:"subject_id"`
	Action        string  `json:"action"`
	ResourceID    string  `json:"resource_id"`
	Scope         *string `json:"scope,omitempty"`
	KeyVersion    uint8   `json:"key_version"`
}

// auditEventCanonical mirrors the server's AuditEventMessage struct
// (crates/axiam-amqp/src/messages.rs) in EXACT field-declaration order.
// `resource_id`, `ip_address`, and `metadata` are optional (omitted when
// absent); `metadata` is kept as raw JSON so its inner bytes/key order are
// preserved verbatim. `key_version` is always emitted; `hmac_signature` is
// excluded from the signed bytes.
type auditEventCanonical struct {
	TenantID   string          `json:"tenant_id"`
	ActorID    string          `json:"actor_id"`
	ActorType  string          `json:"actor_type"`
	Action     string          `json:"action"`
	ResourceID *string         `json:"resource_id,omitempty"`
	Outcome    string          `json:"outcome"`
	IPAddress  *string         `json:"ip_address,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	KeyVersion uint8           `json:"key_version"`
}

// canonicalCandidates reconstructs the server-signed canonical bytes for
// every known signed message layout. Each candidate is the body re-marshaled
// in the server's declaration order with hmac_signature excluded. Only the
// layout the server actually signed can produce bytes whose HMAC matches the
// received signature, so returning several is safe.
func canonicalCandidates(body []byte) [][]byte {
	candidates := make([][]byte, 0, 2)

	var authz authzRequestCanonical
	if json.Unmarshal(body, &authz) == nil {
		if b, err := json.Marshal(&authz); err == nil {
			candidates = append(candidates, b)
		}
	}

	var audit auditEventCanonical
	if json.Unmarshal(body, &audit) == nil {
		if b, err := json.Marshal(&audit); err == nil {
			candidates = append(candidates, b)
		}
	}

	return candidates
}
