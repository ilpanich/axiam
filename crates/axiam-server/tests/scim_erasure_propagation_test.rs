//! **T23.6.3** — GDPR erasure propagates to a downstream SCIM service provider
//! (G-6, D-58), end to end.
//!
//! A provisioned user (linked on the loopback SCIM server of `axiam-scim`'s
//! harness, shared here by path) goes through the **real** erasure pipeline
//! (`run_erasure_pipeline`, the public entry that runs `erasure_steps`: audit
//! scrub, `anonymize_user`, proof) or the real `DELETE /api/v1/users/{id}`
//! handler, over repositories that report to a `ScimProvisioner` on an
//! in-process dispatcher. The deliverer then sends `DELETE` through the link
//! row, which survives the erasure until that `DELETE` succeeds:
//!
//! * the downstream answers → `DELETE /Users/{downstream id}`, the link is gone;
//! * it answers `500` then `200` → retried, then gone;
//! * it answers `403` → the link is kept, `deprovisioned` + `erase_pending`;
//!   a reconciliation run with a healthy downstream sends the `DELETE` and the
//!   link goes.
//!
//! Passwords and keys are generated at run time; no assertion message formats a
//! credential.

#[path = "../../axiam-scim/tests/support/mod.rs"]
mod support;

use std::sync::{Arc, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::scim_target::{ScimLinkState, ScimResourceType, ScimTarget};
use axiam_core::models::user::{User, UserStatus};
use axiam_core::outbound::{DeliveryOutcome, OutboundDeliverer};
use axiam_core::repository::{GroupRepository, ScimTargetLinkRepository, UserRepository};
use axiam_db::{SurrealAuditLogRepository, SurrealErasureProofRepository};
use axiam_scim::outbound::ReconcileOutcome;
use axiam_server::cleanup::run_erasure_pipeline;
use support::{World, all_delivered, only};
use uuid::Uuid;

/// A user already provisioned downstream, with the queue and the request log
/// cleared: the state an erasure starts from.
async fn provisioned(w: &World) -> (ScimTarget, User, String) {
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    let downstream_id = w
        .links
        .get(w.tenant_id, target.id, ScimResourceType::User, user.id)
        .await
        .unwrap()
        .expect("linked")
        .downstream_id;
    w.server.clear_requests();
    w.queue.clear();
    (target, user, downstream_id)
}

/// The erasure the purge sweep runs for one account.
async fn erase(w: &World, user: &User) {
    let audit = SurrealAuditLogRepository::new(w.db.clone());
    let proofs = SurrealErasureProofRepository::new(w.db.clone());
    // The graph step of the purge (b3), which also reports to the sink.
    for group in w
        .groups
        .get_user_groups(w.tenant_id, user.id)
        .await
        .unwrap()
    {
        w.groups
            .remove_member(w.tenant_id, user.id, group.id)
            .await
            .unwrap();
    }
    run_erasure_pipeline(
        &audit,
        &proofs,
        &w.users,
        w.tenant_id,
        user.id,
        "DELETED_USER_0123456789abcdef",
        &Uuid::new_v4().simple().to_string(),
    )
    .await
    .expect("the erasure pipeline");
}

async fn link(
    w: &World,
    target: &ScimTarget,
    user: &User,
) -> Option<axiam_core::models::scim_target::ScimTargetLink> {
    w.links
        .get(w.tenant_id, target.id, ScimResourceType::User, user.id)
        .await
        .unwrap()
}

fn deletes(w: &World, downstream_id: &str) -> usize {
    w.server
        .requests_of("DELETE", &format!("/scim/v2/Users/{downstream_id}"))
        .len()
}

#[actix_rt::test]
async fn an_erased_user_is_deleted_downstream_and_only_then_loses_the_link() {
    let w = World::new().await;
    let (target, user, downstream_id) = provisioned(&w).await;
    let group = w.group("staff").await;
    w.groups
        .add_member(w.tenant_id, user.id, group)
        .await
        .unwrap();
    w.queue.clear();

    erase(&w, &user).await;

    // The cascade ran: the row is a tombstone, and the link — ids and a digest
    // only — is still there, because it is what addresses the DELETE.
    let erased = w.users.get_by_id(w.tenant_id, user.id).await.unwrap();
    assert_eq!(erased.status, UserStatus::Anonymized);
    assert!(link(&w, &target, &user).await.is_some(), "link survives");
    assert_eq!(deletes(&w, &downstream_id), 0, "nothing was sent yet");

    // What the erasure enqueued is a reference, never a person.
    for message in w.queue.all() {
        let payload = message.payload.to_string();
        assert!(!payload.contains("alice"), "no attribute is queued");
    }

    assert!(all_delivered(&w.sync().await));
    assert_eq!(deletes(&w, &downstream_id), 1);
    assert!(w.server.user(&downstream_id).is_none());
    assert!(link(&w, &target, &user).await.is_none(), "link removed");
}

#[actix_rt::test]
async fn a_failing_downstream_is_retried_and_the_link_goes_when_the_delete_succeeds() {
    let w = World::new().await;
    let (target, user, downstream_id) = provisioned(&w).await;
    w.server.fail_next_on("DELETE", "/scim/v2/Users/", 1, 500);

    erase(&w, &user).await;
    let attempts = w.queue.drain(&w.deliverer).await;
    let (message, first) = attempts
        .into_iter()
        .find(|(_, result)| {
            !matches!(
                result,
                Ok(DeliveryOutcome::Delivered { .. }) | Ok(DeliveryOutcome::DeadLetter { .. })
            )
        })
        .expect("the 500 is not a delivery");
    assert!(matches!(first, Ok(DeliveryOutcome::Retry { .. })));
    let pending = link(&w, &target, &user).await.expect("kept for the retry");
    assert!(pending.erase_pending);
    assert!(w.server.user(&downstream_id).is_some());

    // The dispatcher redelivers the same message after its backoff.
    let mut again = message.clone();
    again.attempt += 1;
    let outcome = w.deliverer.deliver_attempt(&again).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Delivered { .. }));
    assert_eq!(deletes(&w, &downstream_id), 2, "once refused, once done");
    assert!(w.server.user(&downstream_id).is_none());
    assert!(link(&w, &target, &user).await.is_none());
}

#[actix_rt::test]
async fn a_refused_erasure_keeps_the_link_pending_until_reconciliation_succeeds() {
    let w = World::new().await;
    let (target, user, downstream_id) = provisioned(&w).await;
    w.server.fail_next_on("DELETE", "/scim/v2/Users/", 1, 403);

    erase(&w, &user).await;
    let outcome = only(w.sync().await);
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));

    let kept = link(&w, &target, &user).await.expect("the link is kept");
    assert_eq!(kept.state, ScimLinkState::Deprovisioned);
    assert!(kept.erase_pending);
    assert!(w.server.user(&downstream_id).is_some(), "still downstream");

    // The downstream is healthy again; the reconciliation run retries it.
    w.queue.clear();
    w.server.clear_requests();
    let ran = w
        .deliverer
        .reconcile_now(w.tenant_id, target.id)
        .await
        .unwrap();
    let ReconcileOutcome::Ran(report) = ran else {
        panic!("a run was expected");
    };
    assert_eq!(report.erase_retried, 1);
    assert!(all_delivered(&w.sync().await));
    assert_eq!(deletes(&w, &downstream_id), 1);
    assert!(w.server.user(&downstream_id).is_none());
    assert!(link(&w, &target, &user).await.is_none());
}

// ---------------------------------------------------------------------------
// The administrator's DELETE /api/v1/users/{id}
// ---------------------------------------------------------------------------

const CSRF_VALUE: &str = "csrf-double-submit";

fn auth_config() -> AuthConfig {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    let (private, public) = PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    });
    AuthConfig {
        jwt_private_key_pem: private.clone(),
        jwt_public_key_pem: public.clone(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

#[actix_rt::test]
async fn the_admin_delete_endpoint_anonymises_and_deletes_downstream() {
    let w = World::new().await;
    let (target, user, downstream_id) = provisioned(&w).await;
    let auth = auth_config();
    // The application state carries the world's reporting user repository.
    let mut state = AppState::for_test(w.db.clone(), auth.clone());
    state.user_repo = w.users.clone();
    state.group_repo = w.groups.clone();
    let access = issue_access_token(
        Uuid::new_v4(),
        w.tenant_id,
        Uuid::new_v4(),
        &[],
        &auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(state))
            .app_data(web::Data::new(
                Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
            ))
            .configure(|cfg| {
                register_api_v1_routes::<surrealdb::engine::local::Db>(
                    cfg,
                    &RateLimitConfig::default(),
                )
            }),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .insert_header(("X-Forwarded-For", "127.0.0.1"))
            .uri(&format!("/api/v1/users/{}", user.id))
            .insert_header(("Authorization", format!("Bearer {access}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_VALUE}")))
            .insert_header(("X-CSRF-Token", CSRF_VALUE))
            .to_request(),
    )
    .await;
    assert_eq!(response.status().as_u16(), 204);

    // Tombstoned (`Deleted`, the status the repository's `delete` leaves; the
    // purge sweep's is `Anonymized`), with the link still there until the
    // DELETE is sent.
    let erased = w.users.get_by_id(w.tenant_id, user.id).await.unwrap();
    assert_eq!(erased.status, UserStatus::Deleted);
    assert_ne!(erased.email, "alice@example.com", "the address is erased");
    assert!(link(&w, &target, &user).await.is_some());

    assert!(all_delivered(&w.sync().await));
    assert_eq!(deletes(&w, &downstream_id), 1);
    assert!(w.server.user(&downstream_id).is_none());
    assert!(link(&w, &target, &user).await.is_none());
}
