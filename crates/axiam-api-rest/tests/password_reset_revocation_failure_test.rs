//! QR12-2 (SA-06 / N7): a password reset whose session revocation fails after
//! the credential write still emits the SSF `credential-change` event, then
//! answers the error (500). The password HAS changed at that point; a receiver
//! that is not told would keep trusting sessions it should drop.
//!
//! The fixtures are the D-55 world (`ssf_shared_issuer_support`): the real
//! route table, real repositories on an in-memory database, a recording
//! outbox. The revocation failure is a `DEFINE EVENT … THEN THROW` on the
//! `session` DELETE, the same seam the session repository's own OBS-3 tests use.
//!
//! QR13-1 / QR13-2: on that path the credential change is also recorded (a
//! tenant-attributed audit row) and offered to the notification rules, for the
//! password reset and for the self-service password change alike. The audit
//! middleware and a recording notification sink are wrapped around the real
//! route table, so both are observed as the server runs them.

// The shared support also defines `app!`, which wraps no audit middleware; these
// tests use `audited_app!` below.
#[allow(unused_macros)]
#[macro_use]
mod ssf_shared_issuer_support;

use axiam_audit::{AuditEvent, AuditEventSink, AuditMiddleware};
use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
use axiam_core::models::notification_rule::NotificationEventType;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::session::CreateSession;
use axiam_core::repository::{PasswordResetTokenRepository, SessionRepository};
use axiam_db::repository::{SurrealPasswordResetTokenRepository, SurrealSessionRepository};
use chrono::Duration;
use ssf_shared_issuer_support::*;

const NEW_PASSWORD: &str = "AnotherStr0ngPassword77"; // gitleaks:allow

/// What the notification rules would be offered.
#[derive(Default)]
struct RecordingSink(Mutex<Vec<AuditEvent>>);

impl AuditEventSink for RecordingSink {
    fn on_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move { self.0.lock().unwrap().push(event.clone()) })
    }
}

/// The route table with the audit middleware and `sink` around it.
macro_rules! audited_app {
    ($state:expr, $w:expr, $sink:expr) => {
        test::init_service(
            App::new()
                .wrap(AuditMiddleware::spawn_with_sink(
                    SurrealAuditLogRepository::new($w.db.clone()),
                    Some($sink.clone() as Arc<dyn AuditEventSink>),
                ))
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.authz.clone()))
                .app_data(web::Data::new($state))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(
                        cfg,
                        &permissive_limits(),
                        RouteOptions {
                            tenant_issuer_paths: $w.auth.tenant_issuer_paths,
                            ..RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    };
}

async fn poison_session_deletes(w: &World) {
    w.db.query(
        "DEFINE EVENT session_delete_poison ON TABLE session \
         WHEN $event = 'DELETE' THEN { THROW 'poisoned delete' }",
    )
    .await
    .unwrap()
    .check()
    .unwrap();
}

async fn seed_session(w: &World, token_hash: &str) -> Uuid {
    SurrealSessionRepository::new(w.db.clone())
        .create(CreateSession {
            tenant_id: w.tenant_id,
            user_id: w.user,
            token_hash: token_hash.into(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            amr: vec![],
            browser_token_hash: None,
            lineage_id: None,
        })
        .await
        .unwrap()
        .id
}

/// The tenant's audit rows once the row for `request_action` has been written
/// (the worker is asynchronous) and the rows queued behind it have had time to
/// follow.
async fn audit_rows_after(w: &World, request_action: &str) -> Vec<AuditLogEntry> {
    let repo = SurrealAuditLogRepository::new(w.db.clone());
    for _ in 0..120 {
        let rows = repo
            .list(w.tenant_id, AuditLogFilter::default(), all_pages())
            .await
            .unwrap()
            .items;
        if rows.iter().any(|r| r.action == request_action) {
            settle().await;
            return repo
                .list(w.tenant_id, AuditLogFilter::default(), all_pages())
                .await
                .unwrap()
                .items;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("no `{request_action}` row was written");
}

fn maps_to_password_changed(action: &str, outcome: &str) -> bool {
    NotificationEventType::from_audit_action(action, outcome)
        .contains(&NotificationEventType::PasswordChanged)
}

/// A row recording that the credential write committed and the revocation did
/// not: tenant-attributed, `Success`, a notification-eligible action.
fn is_revocation_failure_row(entry: &AuditLogEntry, tenant_id: Uuid) -> bool {
    entry.tenant_id == tenant_id
        && format!("{:?}", entry.outcome) == "Success"
        && entry.metadata["revocation"] == "failed"
        && entry.metadata["credential_written"] == true
        && maps_to_password_changed(&entry.action, "Success")
}

/// The submitted events that are credential changes of a password.
fn password_credential_changes(w: &World) -> usize {
    w.outbox
        .submitted
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, e)| {
            e.event_uri == SsfEventType::CredentialChange.uri()
                && e.event["credential_type"] == "password"
        })
        .count()
}

async fn confirm(w: &World, poison: bool, sink: &Arc<RecordingSink>) -> (u16, Vec<AuditLogEntry>) {
    w.stream(SsfDeliveryMethod::Push).await;
    seed_session(w, "qr12-2-session").await;
    if poison {
        poison_session_deletes(w).await;
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
    let app = audited_app!(state, w, sink);
    let req = request(Method::POST, "/api/v1/auth/reset/confirm", None).set_json(json!({
        "tenant_id": w.tenant_id,
        "token": raw_token,
        "new_password": NEW_PASSWORD,
    }));
    let (status, _) = send(&app, req).await;
    (
        status,
        audit_rows_after(w, "POST /api/v1/auth/reset/confirm").await,
    )
}

/// The notification-eligible events the sink was offered for the tenant.
fn offered_password_changed(sink: &RecordingSink, w: &World) -> Vec<AuditEvent> {
    sink.0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| {
            e.entry.tenant_id == w.tenant_id
                && maps_to_password_changed(&e.entry.action, &format!("{:?}", e.entry.outcome))
        })
        .cloned()
        .collect()
}

/// Control: with nothing failing the reset answers 200, the event is sent, and
/// the one `PasswordChanged` notification is the request row's. No
/// revocation-failure row is written on the success path.
#[actix_rt::test]
async fn reset_emits_credential_change_when_revocation_succeeds() {
    let w = world(1, false).await;
    let sink = Arc::new(RecordingSink::default());
    let (status, rows) = confirm(&w, false, &sink).await;
    assert_eq!(status, 200);
    assert_eq!(
        password_credential_changes(&w),
        1,
        "exactly one credential-change event, of a password"
    );
    assert!(
        !rows.iter().any(|r| r.metadata["revocation"] == "failed"),
        "the success path writes no revocation-failure row"
    );
    assert_eq!(
        offered_password_changed(&sink, &w).len(),
        1,
        "one PasswordChanged notification, the request row's"
    );
}

#[actix_rt::test]
async fn qr12_2_reset_emits_credential_change_even_when_revocation_fails() {
    let w = world(1, false).await;
    let sink = Arc::new(RecordingSink::default());
    let (status, rows) = confirm(&w, true, &sink).await;
    assert_eq!(status, 500, "the revocation failure is still answered");
    {
        let sent = w.outbox.submitted.lock().unwrap();
        assert_eq!(
            sent.len(),
            1,
            "the password was changed, so the credential-change event is emitted"
        );
        assert_eq!(
            sent[0].1.event_uri,
            SsfEventType::CredentialChange.uri(),
            "the submitted event is a credential-change"
        );
        assert_eq!(sent[0].1.event["credential_type"], "password");
    }

    // QR13-1: the credential change is on the record, in the tenant's partition,
    // and the notification rules are offered it.
    assert!(
        rows.iter()
            .any(|r| is_revocation_failure_row(r, w.tenant_id)),
        "a tenant-attributed audit row records the committed credential write \
         and the failed revocation: {rows:?}"
    );
    assert!(
        offered_password_changed(&sink, &w).iter().any(|e| e
            .entry
            .metadata
            .as_ref()
            .is_some_and(|m| m["revocation"] == "failed")),
        "the PasswordChanged notification fires on the revocation-failure path"
    );
}

// ---------------------------------------------------------------------------
// QR13-2: the same for a self-service password change
// ---------------------------------------------------------------------------

async fn change(w: &World, poison: bool, sink: &Arc<RecordingSink>) -> (u16, Vec<AuditLogEntry>) {
    w.stream(SsfDeliveryMethod::Push).await;
    let current = seed_session(w, "qr13-2-current").await;
    seed_session(w, "qr13-2-other").await;
    if poison {
        poison_session_deletes(w).await;
    }
    let token = issue_access_token(
        w.user,
        w.tenant_id,
        w.org_id,
        &[],
        &w.auth,
        current.to_string(),
        AUD_USER,
    )
    .unwrap();
    let state = w.state();
    let app = audited_app!(state, w, sink);
    let req = request(Method::POST, "/api/v1/auth/password/change", Some(&token)).set_json(json!({
        "current_password": test_password(),
        "new_password": NEW_PASSWORD,
    }));
    let (status, _) = send(&app, req).await;
    (
        status,
        audit_rows_after(w, "POST /api/v1/auth/password/change").await,
    )
}

/// Control: a change whose revocation succeeds answers 204, emits one password
/// credential-change event and writes no revocation-failure row.
#[actix_rt::test]
async fn change_emits_credential_change_when_revocation_succeeds() {
    let w = world(1, false).await;
    let sink = Arc::new(RecordingSink::default());
    let (status, rows) = change(&w, false, &sink).await;
    assert_eq!(status, 204);
    assert_eq!(password_credential_changes(&w), 1);
    assert!(!rows.iter().any(|r| r.metadata["revocation"] == "failed"));
}

#[actix_rt::test]
async fn qr13_2_change_emits_credential_change_even_when_revocation_fails() {
    let w = world(1, false).await;
    let sink = Arc::new(RecordingSink::default());
    let (status, rows) = change(&w, true, &sink).await;
    assert_eq!(status, 500, "the revocation failure is still answered");
    {
        let sent = w.outbox.submitted.lock().unwrap();
        assert_eq!(
            sent.len(),
            1,
            "the new password is stored, so the credential-change event is emitted"
        );
        assert_eq!(sent[0].1.event_uri, SsfEventType::CredentialChange.uri());
        assert_eq!(sent[0].1.event["credential_type"], "password");
    }
    assert!(
        rows.iter()
            .any(|r| is_revocation_failure_row(r, w.tenant_id)),
        "a tenant-attributed audit row records the committed credential write \
         and the failed revocation: {rows:?}"
    );
    assert!(
        offered_password_changed(&sink, &w).iter().any(|e| e
            .entry
            .metadata
            .as_ref()
            .is_some_and(|m| m["revocation"] == "failed")),
        "the PasswordChanged notification fires on the revocation-failure path"
    );
}
