//! REQ-14 AC-5 — TOTP replay rejection tests (SEC-008).
//!
//! Tests that a TOTP code used once cannot be replayed within the same
//! time step.

use axiam_auth::totp;
use totp_rs::{Algorithm, Secret, TOTP};

/// Helper to build a TOTP and get the current code + current step.
fn make_totp(secret_bytes: &[u8]) -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes.to_vec(),
        Some("AXIAM".into()),
        "test@test.com".into(),
    )
    .unwrap()
}

/// Verifying a valid code once succeeds; replaying the same code with the
/// same step stored as last_used_step returns false (rejected).
#[test]
fn totp_replay_rejected() {
    let secret = Secret::generate_secret();
    let secret_bytes = secret.to_bytes().unwrap();
    let totp = make_totp(&secret_bytes);

    let code = totp.generate_current().unwrap();
    let current_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;

    // First use succeeds (no prior step recorded).
    let result = totp::verify_code_with_replay_check(
        &secret_bytes,
        &code,
        "AXIAM",
        "test@test.com",
        None, // no last_used_step
    );
    assert!(
        result.is_ok(),
        "first verification should succeed: {result:?}"
    );
    let (valid, used_step) = result.unwrap();
    assert!(valid, "first verification should return true");
    assert_eq!(
        used_step, current_step,
        "used step should match current step"
    );

    // Replay the same code with the same step → rejected.
    let replay_result = totp::verify_code_with_replay_check(
        &secret_bytes,
        &code,
        "AXIAM",
        "test@test.com",
        Some(used_step), // last_used_step = step just used
    );
    assert!(
        replay_result.is_ok(),
        "replay check should not error: {replay_result:?}"
    );
    let (replay_valid, _) = replay_result.unwrap();
    assert!(!replay_valid, "replayed code in same step must be rejected");
}

/// A code from a strictly later step is accepted even if last_used_step is set.
#[test]
fn totp_new_step_accepted() {
    let secret = Secret::generate_secret();
    let secret_bytes = secret.to_bytes().unwrap();
    let totp = make_totp(&secret_bytes);

    let code = totp.generate_current().unwrap();
    let current_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;

    // Simulate that a previous step was recorded.
    let old_step = current_step.saturating_sub(2);

    let result = totp::verify_code_with_replay_check(
        &secret_bytes,
        &code,
        "AXIAM",
        "test@test.com",
        Some(old_step), // last used was 2 steps ago
    );
    assert!(
        result.is_ok(),
        "verify with old step should not error: {result:?}"
    );
    let (valid, used_step) = result.unwrap();
    assert!(
        valid,
        "code from current step should be accepted when last_used < current"
    );
    assert_eq!(used_step, current_step);
}

/// Legacy verify_code (no replay check) still works for backward compatibility.
#[test]
fn verify_code_legacy_api_unchanged() {
    let secret = Secret::generate_secret();
    let secret_bytes = secret.to_bytes().unwrap();
    let totp = make_totp(&secret_bytes);
    let code = totp.generate_current().unwrap();

    assert!(
        totp::verify_code(&secret_bytes, &code, "AXIAM", "test@test.com").unwrap(),
        "legacy verify_code should still work"
    );
}
