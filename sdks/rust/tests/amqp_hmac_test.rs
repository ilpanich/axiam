//! Wire-format oracle tests: proves the SDK's HMAC-SHA256 sign/verify and
//! `AuthzRequest`/`AuditEventMessage` DTOs are byte-identical to the server
//! reference in `crates/axiam-amqp/src/messages.rs` (CONTRACT.md §8).
//!
//! The expected hex value below was computed once from the server reference
//! (`crates/axiam-amqp/src/messages.rs::sign_payload`) for the literal key
//! and payload bytes used here, via:
//!
//! ```ignore
//! let key = b"test-amqp-signing-key";
//! let payload = b"{\"tenant_id\":\"...\",\"action\":\"read\"}";
//! println!("{}", axiam_amqp::messages::sign_payload(key, payload));
//! ```
//!
//! and is asserted against literally below — NOT re-derived via a
//! self-round-trip — so this test would fail if the SDK's algorithm ever
//! diverged from the server's (e.g. different HMAC construction, different
//! hex casing, or a different key/message ordering).

#![cfg(feature = "amqp")]

use axiam_sdk::amqp::hmac::{sign_payload, verify_payload};
use axiam_sdk::amqp::messages::{AuditEventMessage, AuthzRequest};
use chrono::{TimeZone, Utc};

/// A fixed, deterministic `issued_at` (NEW-4) for tests that only care
/// about `hmac_signature` presence/ordering, not the freshness gate (which
/// lives in the consumer, not these DTO-level tests).
fn fixed_issued_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap()
}

/// Literal fixture shared with the server's test module
/// (`crates/axiam-amqp/src/messages.rs::amqp_hmac_sign_verify_round_trip`).
const FIXTURE_KEY: &[u8] = b"test-amqp-signing-key";
const FIXTURE_PAYLOAD: &[u8] = b"{\"tenant_id\":\"...\",\"action\":\"read\"}";

/// Expected hex output of `sign_payload(FIXTURE_KEY, FIXTURE_PAYLOAD)`,
/// computed once from the server reference implementation
/// (`crates/axiam-amqp/src/messages.rs:35-39`) using the same
/// `hmac = "0.12"` / `sha2 = "0.10"` / `hex = "0.4"` crates. HMAC-SHA256 is
/// deterministic for a given key + message, so this literal is a stable
/// wire-format oracle: if the SDK's algorithm ever diverges from the
/// server's (different construction, different hex casing, truncated
/// digest, etc.), this assertion fails immediately.
const EXPECTED_HEX: &str = "267552b92ccef4be266885e6345220ca2f9361fe346f57a1d3cad0ed0e7c8a2e";

#[test]
fn amqp_hmac_byte_identical_to_server_reference() {
    let sig = sign_payload(FIXTURE_KEY, FIXTURE_PAYLOAD);
    assert_eq!(
        sig, EXPECTED_HEX,
        "SDK sign_payload output must be byte-identical to the server reference \
         (crates/axiam-amqp/src/messages.rs::sign_payload) for the same key + payload"
    );
    assert!(
        verify_payload(FIXTURE_KEY, FIXTURE_PAYLOAD, &sig),
        "a signature produced by sign_payload must verify against the same key + payload"
    );
}

#[test]
fn amqp_hmac_wrong_key_fails_verify() {
    let sig = sign_payload(FIXTURE_KEY, FIXTURE_PAYLOAD);
    assert!(
        !verify_payload(b"wrong-key", FIXTURE_PAYLOAD, &sig),
        "wrong key must not verify"
    );
}

#[test]
fn amqp_hmac_tampered_payload_fails_verify() {
    let sig = sign_payload(FIXTURE_KEY, FIXTURE_PAYLOAD);
    let tampered = b"{\"tenant_id\":\"...\",\"action\":\"write\"}";
    assert!(
        !verify_payload(FIXTURE_KEY, tampered, &sig),
        "tampered payload must not verify"
    );
}

#[test]
fn amqp_hmac_missing_signature_fails_verify() {
    // hex::decode("") yields an empty byte vec; verify_slice against an
    // empty expected MAC must fail closed, never panic or succeed.
    assert!(
        !verify_payload(FIXTURE_KEY, FIXTURE_PAYLOAD, ""),
        "an empty/invalid signature must never verify"
    );
}

#[test]
fn authz_request_hmac_signature_omitted_when_none() {
    let req = AuthzRequest {
        correlation_id: uuid::Uuid::nil(),
        tenant_id: uuid::Uuid::nil(),
        subject_id: uuid::Uuid::nil(),
        action: "read".into(),
        resource_id: uuid::Uuid::nil(),
        scope: None,
        key_version: 2,
        nonce: uuid::Uuid::nil(),
        issued_at: fixed_issued_at(),
        hmac_signature: None,
    };
    let json = serde_json::to_string(&req).expect("serialize");
    assert!(
        !json.contains("hmac_signature"),
        "hmac_signature must be omitted from JSON when None (matches server's \
         skip_serializing_if = \"Option::is_none\")"
    );
}

#[test]
fn authz_request_hmac_signature_present_when_some() {
    let req = AuthzRequest {
        correlation_id: uuid::Uuid::nil(),
        tenant_id: uuid::Uuid::nil(),
        subject_id: uuid::Uuid::nil(),
        action: "read".into(),
        resource_id: uuid::Uuid::nil(),
        scope: None,
        key_version: 2,
        nonce: uuid::Uuid::nil(),
        issued_at: fixed_issued_at(),
        hmac_signature: Some("abc123".into()),
    };
    let json = serde_json::to_string(&req).expect("serialize");
    assert!(
        json.contains("hmac_signature"),
        "hmac_signature must be present in JSON when Some"
    );
}

#[test]
fn authz_request_field_declaration_order_matches_server() {
    // The server struct declares fields in this exact order:
    // correlation_id, tenant_id, subject_id, action, resource_id, scope,
    // key_version, nonce, issued_at
    // (crates/axiam-amqp/src/messages.rs:166-197, NEW-4 v2). A derived
    // `Serialize` impl on a plain struct emits keys via `serialize_struct`,
    // which writes fields in declaration order regardless of the
    // `serde_json::Value` map representation used on the read side — so we
    // assert directly on the raw JSON text's key ordering rather than
    // round-tripping through `Value` (whose `Map` type may reorder keys
    // depending on the "preserve_order" feature).
    let req = AuthzRequest {
        correlation_id: uuid::Uuid::nil(),
        tenant_id: uuid::Uuid::nil(),
        subject_id: uuid::Uuid::nil(),
        action: "read".into(),
        resource_id: uuid::Uuid::nil(),
        scope: Some("sub".into()),
        key_version: 2,
        nonce: uuid::Uuid::nil(),
        issued_at: fixed_issued_at(),
        hmac_signature: None,
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let expected_order = [
        "correlation_id",
        "tenant_id",
        "subject_id",
        "action",
        "resource_id",
        "scope",
        "key_version",
        "nonce",
        "issued_at",
    ];
    let mut last_index = 0usize;
    for key in expected_order {
        let needle = format!("\"{key}\"");
        let idx = json
            .find(&needle)
            .unwrap_or_else(|| panic!("expected key {key} not found in {json}"));
        assert!(
            idx >= last_index,
            "field {key} appeared out of declaration order in {json}"
        );
        last_index = idx;
    }
}

#[test]
fn audit_event_message_hmac_signature_omitted_when_none() {
    let msg = AuditEventMessage {
        tenant_id: uuid::Uuid::nil(),
        actor_id: uuid::Uuid::nil(),
        actor_type: "user".into(),
        action: "login".into(),
        resource_id: None,
        outcome: "success".into(),
        ip_address: None,
        metadata: None,
        key_version: 2,
        nonce: uuid::Uuid::nil(),
        issued_at: fixed_issued_at(),
        hmac_signature: None,
    };
    let json = serde_json::to_string(&msg).expect("serialize");
    assert!(
        !json.contains("hmac_signature"),
        "hmac_signature must be omitted from JSON when None"
    );
}

#[test]
fn grep_gate_no_server_crate_import() {
    // Doc comments legitimately reference `crates/axiam-amqp/src/messages.rs`
    // as the file being mirrored (byte-identical wire format), so this gate
    // checks for actual Rust import syntax (`use axiam_amqp::...` /
    // `axiam_amqp::`) rather than any textual mention of the crate name —
    // it must catch a real dependency edge, not a doc-comment citation of
    // the reference implementation being mirrored.
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/amqp");
    for entry in std::fs::read_dir(src_dir).expect("read src/amqp") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let contents = std::fs::read_to_string(&path).expect("read file");
        for line in contents.lines() {
            let trimmed = line.trim_start();
            // Skip doc/regular comment lines entirely.
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("axiam_amqp::") && !trimmed.contains("use axiam_amqp"),
                "src/amqp/{:?} must never import the axiam-amqp server crate (mirror, never import): {line}",
                path.file_name().unwrap()
            );
            assert!(
                !trimmed.contains("axiam_core::") && !trimmed.contains("use axiam_core"),
                "src/amqp/{:?} must never import the axiam-core server crate: {line}",
                path.file_name().unwrap()
            );
        }
    }
}
