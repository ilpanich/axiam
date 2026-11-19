//! QR12-2 (SA-06 / N7): a password reset whose session revocation fails after
//! the credential write still emits the SSF `credential-change` event, then
//! answers the error (500). The password HAS changed at that point; a receiver
//! that is not told would keep trusting sessions it should drop.
//!
//! The fixtures are the D-55 world (`ssf_shared_issuer_support`): the real
//! route table, real repositories on an in-memory database, a recording
//! outbox. The revocation failure is a `DEFINE EVENT … THEN THROW` on the
//! `session` DELETE, the same seam the session repository's own OBS-3 tests use.

#[macro_use]
mod ssf_shared_issuer_support;

use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::session::CreateSession;
use axiam_core::repository::{PasswordResetTokenRepository, SessionRepository};
use axiam_db::repository::{SurrealPasswordResetTokenRepository, SurrealSessionRepository};
use chrono::Duration;
use ssf_shared_issuer_support::*;

const NEW_PASSWORD: &str = "AnotherStr0ngPassword77"; // gitleaks:allow

async fn confirm(w: &World, poison: bool) -> (u16, String) {
    w.stream(SsfDeliveryMethod::Push).await;
    SurrealSessionRepository::new(w.db.clone())
        .create(CreateSession {
            tenant_id: w.tenant_id,
            user_id: w.user,
            token_hash: "qr12-2-session".into(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            amr: vec![],
            browser_token_hash: None,
            lineage_id: None,
        })
        .await
        .unwrap();
    if poison {
        w.db.query(
            "DEFINE EVENT session_delete_poison ON TABLE session \
             WHEN $event = 'DELETE' THEN { THROW 'poisoned delete' }",
        )
        .await
        .unwrap()
        .check()
        .unwrap();
    }
    let raw_token = generate_refresh_token();
    SurrealPasswordResetTokenRepository::new(w.db.clone())
        .create(CreatePasswordResetToken {
            tenant_id: w.tenant_id,
            user_id: w.user,
            token_hash: hash_refresh_token(&raw_token),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();
    let state = w.state();
    let app = app!(state, w);
    let req = request(Method::POST, "/api/v1/auth/reset/confirm", None).set_json(json!({
        "tenant_id": w.tenant_id,
        "token": raw_token,
        "new_password": NEW_PASSWORD,
    }));
    send(&app, req).await
}

/// Control: with nothing failing the reset answers 200 and the event is sent.
#[actix_rt::test]
async fn reset_emits_credential_change_when_revocation_succeeds() {
    let w = world(1, false).await;
    let (status, _) = confirm(&w, false).await;
    assert_eq!(status, 200);
    assert!(w.told() >= 1, "the credential-change event is emitted");
}

#[actix_rt::test]
async fn qr12_2_reset_emits_credential_change_even_when_revocation_fails() {
    let w = world(1, false).await;
    let (status, _) = confirm(&w, true).await;
    assert_eq!(status, 500, "the revocation failure is still answered");
    let sent = w.outbox.submitted.lock().unwrap();
    assert_eq!(
        sent.len(),
        1,
        "the password was changed, so the credential-change event is emitted"
    );
}
