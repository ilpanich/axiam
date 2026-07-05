//! Integration tests for CORR-02: SurrealDB root-token renewal/reconnect
//! resilience (`crates/axiam-db/src/connection.rs`).
//!
//! Two kinds of assertions:
//! - Pure-logic assertions (run by the default `cargo test`, no live server
//!   needed): the fraction-to-interval derivation math, and the
//!   auth-failure `health_check` classification.
//! - A live-SurrealDB-gated recovery test (`#[ignore]`) that proves the
//!   client survives a real token expiry without a process restart. Run via
//!   `just dev-up` then:
//!   `cargo test -p axiam-db --test connection_resilience_test -- --ignored`

use std::time::Duration;

use axiam_db::{DbConfig, DbError, DbManager};
use surrealdb::types::AuthError;

/// Four weeks in seconds, mirroring `connection.rs`'s private
/// `ROOT_TOKEN_DURATION` constant — kept in sync manually since the constant
/// itself is intentionally not part of the crate's public surface.
const FOUR_WEEKS_SECS: f64 = 4.0 * 7.0 * 24.0 * 3600.0;

#[test]
fn re_signin_interval_derives_from_ttl_and_fraction() {
    let interval = DbManager::re_signin_interval(0.6);
    let expected_secs = FOUR_WEEKS_SECS * 0.6;
    let diff = (interval.as_secs_f64() - expected_secs).abs();
    assert!(
        diff < 1.0,
        "expected ~{expected_secs}s (0.6 * 4 weeks), got {:?}",
        interval
    );
}

#[test]
fn re_signin_interval_clamps_fraction_below_band() {
    // fraction 0.0 must clamp up to the 0.05 floor, not produce a near-zero interval.
    let interval = DbManager::re_signin_interval(0.0);
    let expected_secs = FOUR_WEEKS_SECS * 0.05;
    let diff = (interval.as_secs_f64() - expected_secs).abs();
    assert!(
        diff < 1.0,
        "expected clamp to 0.05 ({expected_secs}s), got {:?}",
        interval
    );
}

#[test]
fn re_signin_interval_clamps_fraction_above_band() {
    // fraction 1.0 must clamp down to the 0.95 ceiling, never equal the full TTL
    // (re-signin must fire strictly before actual expiry).
    let interval = DbManager::re_signin_interval(1.0);
    let expected_secs = FOUR_WEEKS_SECS * 0.95;
    let diff = (interval.as_secs_f64() - expected_secs).abs();
    assert!(
        diff < 1.0,
        "expected clamp to 0.95 ({expected_secs}s), got {:?}",
        interval
    );
}

#[test]
fn health_classification_maps_token_expiry_to_unhealthy() {
    let err = surrealdb::Error::not_allowed("token expired".to_string(), AuthError::TokenExpired);
    let classified = DbManager::classify_query_error(err);
    assert!(
        matches!(classified, DbError::Unhealthy(_)),
        "expected DbError::Unhealthy for a token-expiry auth failure, got {classified:?}"
    );
}

#[test]
fn health_classification_maps_revoked_credentials_to_unhealthy_too() {
    // T-26-02-02 / ASVS V3: a genuinely revoked/invalid credential must ALSO
    // alarm as Unhealthy — health_check must not silently treat every auth
    // failure as "just expiry" and pretend it is transient/recoverable.
    let err =
        surrealdb::Error::not_allowed("invalid credentials".to_string(), AuthError::InvalidAuth);
    let classified = DbManager::classify_query_error(err);
    assert!(
        matches!(classified, DbError::Unhealthy(_)),
        "expected DbError::Unhealthy for a revoked/invalid-credential auth failure, got {classified:?}"
    );
}

#[test]
fn health_classification_leaves_non_auth_errors_as_ordinary_surreal_errors() {
    let err = surrealdb::Error::internal("some unrelated failure".to_string());
    let classified = DbManager::classify_query_error(err);
    assert!(
        matches!(classified, DbError::Surreal(_)),
        "expected a non-auth error to classify as DbError::Surreal, got {classified:?}"
    );
}

/// Live-broker-gated recovery proof (CORR-02 acceptance criterion): connects
/// with a short, test-only root-token TTL override, waits past several
/// proactive-refresh cycles (and past the raw TTL itself), then asserts:
/// - `health_check` is still healthy (the proactive re-signin task kept the
///   session alive well before the short TTL actually expired), and
/// - the reactive reconnect seam (`DbManager::reconnect`) independently
///   builds a fresh, working connection against the same server (the
///   "missed window" safety net).
///
/// Requires a running SurrealDB (`just dev-up`). Run explicitly:
/// `cargo test -p axiam-db --test connection_resilience_test -- --ignored`
#[tokio::test]
#[ignore = "requires a live SurrealDB instance (just dev-up)"]
async fn recovers_from_token_expiry_without_restart() {
    let config = DbConfig {
        url: std::env::var("AXIAM_TEST_DB_URL").unwrap_or_else(|_| "127.0.0.1:8000".into()),
        namespace: "axiam_test_corr02".into(),
        database: "resilience".into(),
        username: "root".into(),
        password: "root".into(),
        token_refresh_fraction: 0.5,
    };

    // Short TTL: a 4s token, proactive re-signin at 0.5 * 4s = 2s — well
    // before the token actually expires, so the client should never even
    // observe an Unhealthy state in the steady state.
    let short_ttl = Duration::from_secs(4);
    let db = DbManager::connect_with_ttl(&config, short_ttl)
        .await
        .expect("connect_with_ttl should succeed against a live SurrealDB");

    // Wait well past several proactive-refresh cycles and past the raw TTL.
    tokio::time::sleep(Duration::from_secs(10)).await;

    db.health_check().await.expect(
        "health_check should still be healthy — the proactive re-signin task \
         kept the session alive without a process restart",
    );

    // Reactive-path proof: an independent from-scratch reconnect (the
    // "missed window" safety net) also succeeds against the same server.
    let reconnected = DbManager::reconnect(&config)
        .await
        .expect("reconnect() should build a fresh, authenticated connection");
    reconnected
        .query("RETURN 1")
        .await
        .and_then(|r| r.check())
        .expect("a query on the freshly-reconnected handle should succeed");
}
