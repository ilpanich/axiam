//! REQ-14 AC-5 — Pagination limit clamp tests (SEC-010/CQ-B30).
//!
//! Verifies that Pagination deserialization clamps limit to [1, 200].

use axiam_core::repository::Pagination;

/// Deserialization must clamp an absurdly large limit to 200.
#[test]
fn pagination_limit_clamped_high() {
    let p: Pagination = serde_json::from_str(r#"{"offset":0,"limit":999999}"#).unwrap();
    assert_eq!(p.limit, 200, "limit=999999 should clamp to 200");
}

/// Deserialization must clamp limit=0 to 1 (zero pages is not useful).
#[test]
fn pagination_limit_clamped_low() {
    let p: Pagination = serde_json::from_str(r#"{"offset":0,"limit":0}"#).unwrap();
    assert_eq!(p.limit, 1, "limit=0 should clamp to 1");
}

/// A valid limit within range is passed through unchanged.
#[test]
fn pagination_limit_valid_passthrough() {
    let p: Pagination = serde_json::from_str(r#"{"offset":5,"limit":50}"#).unwrap();
    assert_eq!(p.limit, 50);
    assert_eq!(p.offset, 5);
}

/// Exactly at the maximum is allowed.
#[test]
fn pagination_limit_at_max() {
    let p: Pagination = serde_json::from_str(r#"{"offset":0,"limit":200}"#).unwrap();
    assert_eq!(p.limit, 200);
}

/// Exactly at the minimum is allowed.
#[test]
fn pagination_limit_at_min() {
    let p: Pagination = serde_json::from_str(r#"{"offset":0,"limit":1}"#).unwrap();
    assert_eq!(p.limit, 1);
}

/// Default construction (not deserialization) is unaffected — direct struct
/// construction must still work and may use any value the code needs.
#[test]
fn pagination_direct_construction_unaffected() {
    let p = Pagination {
        offset: 0,
        limit: 500,
    };
    assert_eq!(p.limit, 500, "direct struct construction is not clamped");
}
