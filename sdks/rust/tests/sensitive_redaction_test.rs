//! Proves `Sensitive<T>` never leaks a raw token via `Debug`/`Display`, and
//! that `AxiamError`'s HTTP status mapping produces the correct category
//! (CONTRACT.md §2 / §7).

use axiam_sdk::{AxiamError, Sensitive};

const FAKE_JWT: &str = "eyJabc.def.ghi";

#[test]
fn debug_redacts_token_and_never_contains_raw_value() {
    let sensitive = Sensitive::new(FAKE_JWT.to_string());
    let debug_str = format!("{sensitive:?}");

    assert!(
        debug_str.contains("redacted"),
        "Debug output should contain a redacted placeholder, got: {debug_str}"
    );
    assert!(
        !debug_str.contains("eyJ"),
        "Debug output must never contain the raw token, got: {debug_str}"
    );
}

#[test]
fn display_redacts_token_and_never_contains_raw_value() {
    let sensitive = Sensitive::new(FAKE_JWT.to_string());
    let display_str = format!("{sensitive}");

    assert_eq!(display_str, "[SENSITIVE]");
    assert!(
        !display_str.contains("eyJ"),
        "Display output must never contain the raw token, got: {display_str}"
    );
}

#[derive(Debug)]
struct HoldsToken {
    #[allow(dead_code)]
    token: Sensitive<String>,
    #[allow(dead_code)]
    label: &'static str,
}

#[test]
fn nested_debug_delegates_to_redacting_impl() {
    let holder = HoldsToken {
        token: Sensitive::new(FAKE_JWT.to_string()),
        label: "access",
    };
    let debug_str = format!("{holder:?}");

    assert!(
        debug_str.contains("redacted"),
        "Nested Debug output should delegate to the redacting impl, got: {debug_str}"
    );
    assert!(
        !debug_str.contains("eyJ"),
        "Nested Debug output must never contain the raw token, got: {debug_str}"
    );
    assert!(
        debug_str.contains("access"),
        "Non-sensitive fields should still print normally"
    );
}

#[test]
fn from_http_status_maps_to_correct_category_and_never_leaks() {
    let auth_err = AxiamError::from_http_status(401, "bad credentials");
    assert!(matches!(auth_err, AxiamError::Auth { .. }));

    let authz_err = AxiamError::from_http_status(403, "forbidden");
    assert!(matches!(authz_err, AxiamError::Authz { .. }));

    let network_429 = AxiamError::from_http_status(429, "rate limited");
    assert!(matches!(network_429, AxiamError::Network { .. }));

    let network_408 = AxiamError::from_http_status(408, "request timeout");
    assert!(matches!(network_408, AxiamError::Network { .. }));

    let network_500 = AxiamError::from_http_status(500, "internal server error");
    assert!(matches!(network_500, AxiamError::Network { .. }));

    for err in [auth_err, authz_err, network_429, network_408, network_500] {
        let display_str = format!("{err}");
        assert!(
            !display_str.contains("eyJ"),
            "AxiamError Display must never contain a raw token substring, got: {display_str}"
        );
    }
}

/// SDK-Q02: a 403 body with both `action` and `resource_id` populates both
/// fields on the `Authz` variant.
#[test]
fn from_http_status_403_extracts_action_and_resource_id() {
    let body = r#"{"error":"authorization_denied","message":"not allowed","action":"users:get","resource_id":"3f9e2b7a-9b1a-4e9d-8b0a-1c2d3e4f5a6b"}"#;
    let err = AxiamError::from_http_status(403, body);

    match err {
        AxiamError::Authz {
            action,
            resource_id,
            ..
        } => {
            assert_eq!(action.as_deref(), Some("users:get"));
            assert_eq!(
                resource_id.as_deref(),
                Some("3f9e2b7a-9b1a-4e9d-8b0a-1c2d3e4f5a6b")
            );
        }
        other => panic!("expected AxiamError::Authz, got: {other:?}"),
    }
}

/// SDK-Q02: a 403 body with only `action` (a global/nil-resource denial,
/// no `resource_id` key) populates `action` and leaves `resource_id` as
/// `None`.
#[test]
fn from_http_status_403_extracts_action_only_when_resource_id_absent() {
    let body = r#"{"error":"authorization_denied","message":"not allowed","action":"users:list"}"#;
    let err = AxiamError::from_http_status(403, body);

    match err {
        AxiamError::Authz {
            action,
            resource_id,
            ..
        } => {
            assert_eq!(action.as_deref(), Some("users:list"));
            assert_eq!(resource_id, None);
        }
        other => panic!("expected AxiamError::Authz, got: {other:?}"),
    }
}
