//! SA-15 (N2): reference vectors for the signed `AuthzResponse` (CONTRACT §8).
//!
//! The vectors answer the `AuthzRequest` of `v2_reference_vectors.json` (same
//! master key, tenant, `key_version`, `correlation_id` and `nonce`). Each pins
//! the canonical bytes and the signature byte for byte, as produced by the
//! server's own sign path (`AuthzResponse::sign`), and checks the result also
//! verifies through `verify_tenant_signature` — and fails for another tenant,
//! another `key_version` or a flipped decision. The same values are published
//! in CONTRACT §8 for the seven AMQP SDKs; if this test has to change, so does
//! the contract.

use axiam_amqp::messages::{
    AuthzResponse, CURRENT_KEY_VERSION, derive_tenant_key, split_trailing_signature,
    verify_tenant_signature,
};
use uuid::Uuid;

const MASTER_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TENANT_ID: &str = "11111111-1111-1111-1111-111111111111";
const CORRELATION_ID: &str = "22222222-2222-2222-2222-222222222222";
const NONCE: &str = "55555555-5555-5555-5555-555555555555";
const KEY_VERSION: u8 = 2;

struct Vector {
    name: &'static str,
    allowed: bool,
    reason: Option<&'static str>,
    reason_code: Option<&'static str>,
    canonical: &'static str,
    signature: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "allow",
        allowed: true,
        reason: None,
        reason_code: Some("allowed"),
        canonical: r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#,
        signature: "8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a",
    },
    Vector {
        name: "deny_no_grant",
        allowed: false,
        reason: Some("no permission grants action 'documents:read'"),
        reason_code: Some("no_grant"),
        canonical: r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'documents:read'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#,
        signature: "f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400",
    },
    Vector {
        name: "deny_denied_by_rule",
        allowed: false,
        reason: Some("an explicit deny rule refuses action 'documents:read'"),
        reason_code: Some("denied_by_rule"),
        canonical: r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"an explicit deny rule refuses action 'documents:read'","reason_code":"denied_by_rule","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#,
        signature: "4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc",
    },
    // SR1-6: a `reason` echoing a requester-chosen action with the characters
    // JSON encoders escape differently (`&`, `<`, `>`, `"`, `/`, non-ASCII).
    // serde_json writes `"` as `\"` and everything else here raw.
    Vector {
        name: "deny_escaping",
        allowed: false,
        reason: Some("no permission grants action 'docs:a&b</\"c\">/\u{e9}\u{20ac}'"),
        reason_code: Some("no_grant"),
        canonical: CANON4,
        signature: SIG4,
    },
];

fn master_key() -> Vec<u8> {
    hex::decode(MASTER_KEY_HEX).unwrap()
}

fn response(v: &Vector) -> AuthzResponse {
    AuthzResponse {
        correlation_id: Uuid::parse_str(CORRELATION_ID).unwrap(),
        allowed: v.allowed,
        reason: v.reason.map(str::to_owned),
        reason_code: v.reason_code.map(str::to_owned),
        tenant_id: Uuid::parse_str(TENANT_ID).unwrap(),
        nonce: Uuid::parse_str(NONCE).unwrap(),
        hmac_signature: None,
    }
}

/// The subkey the vectors are signed with, pinned so an SDK can check its
/// HKDF step on its own (it is the same subkey as in v2_reference_vectors.json).
#[test]
fn the_subkey_is_pinned() {
    let subkey = derive_tenant_key(
        &master_key(),
        Uuid::parse_str(TENANT_ID).unwrap(),
        KEY_VERSION,
    );
    assert_eq!(hex::encode(subkey), SUBKEY_HEX);
}

/// Vector 4's canonical bytes (`deny_escaping`).
const CANON4: &str = r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'docs:a&b</\"c\">/é€'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#;
/// Vector 4's signature.
const SIG4: &str = "5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff";

const SUBKEY_HEX: &str = "919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89";

#[test]
fn signed_authz_response_vectors_are_byte_exact() {
    assert_eq!(KEY_VERSION, CURRENT_KEY_VERSION);
    let master = master_key();
    for v in VECTORS {
        let mut r = response(v);
        let canonical = r.canonical_bytes();
        r.sign(&master, KEY_VERSION);
        let sig = r.hmac_signature.clone().unwrap();
        assert_eq!(
            String::from_utf8(canonical.clone()).unwrap(),
            v.canonical,
            "{}",
            v.name
        );
        assert_eq!(sig, v.signature, "{}", v.name);

        // The wire form is the canonical form with the signature appended.
        let wire = serde_json::to_string(&r).unwrap();
        assert_eq!(
            wire,
            format!(
                "{},\"hmac_signature\":\"{}\"}}",
                &v.canonical[..v.canonical.len() - 1],
                v.signature
            ),
            "{}",
            v.name
        );

        // CONTRACT §8: a verifier strips the trailing signature member from
        // the received bytes and gets the canonical bytes back exactly.
        let (stripped, sig_hex) = split_trailing_signature(wire.as_bytes()).unwrap();
        assert_eq!(stripped, canonical, "{}", v.name);
        assert_eq!(sig_hex, v.signature, "{}", v.name);

        // A verifier that parses the wire form and re-serializes it without the
        // signature (with serde_json) reproduces the canonical bytes and verifies.
        let parsed: AuthzResponse = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed.canonical_bytes(), canonical, "{}", v.name);
        assert!(parsed.verify(&master, KEY_VERSION), "{}", v.name);
        assert!(verify_tenant_signature(
            &master,
            parsed.tenant_id,
            KEY_VERSION,
            v.canonical.as_bytes(),
            Some(v.signature),
        ));

        // Another tenant's subkey, another key_version, or a flipped decision
        // does not verify.
        assert!(!verify_tenant_signature(
            &master,
            Uuid::parse_str("99999999-9999-9999-9999-999999999999").unwrap(),
            KEY_VERSION,
            v.canonical.as_bytes(),
            Some(v.signature),
        ));
        assert!(!parsed.verify(&master, KEY_VERSION + 1), "{}", v.name);
        let mut flipped = parsed.clone();
        flipped.allowed = !flipped.allowed;
        assert!(!flipped.verify(&master, KEY_VERSION), "{}", v.name);
    }
}
