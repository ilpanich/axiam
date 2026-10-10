//! #517 — `delete_all_for_client` on the authorization-code and pushed-request
//! stores: what removing a client voids, and the two scopes it must not cross.
//!
//! A `managed_by: cimd` client re-materialises under the same `client_id`
//! after it is deleted, so whatever the old row was granted must be gone
//! rather than merely orphaned. The deletion is scoped to one client in one
//! tenant: a client's id is unique only within its tenant, and another
//! client's codes are not this client's to void.

use axiam_core::models::oauth2_client::{
    CreateAuthorizationCode, CreatePushedAuthRequest, PushedAuthParams,
};
use axiam_core::repository::{AuthorizationCodeRepository, PushedAuthRequestRepository};
use axiam_db::repository::{
    SurrealAuthorizationCodeRepository, SurrealPushedAuthRequestRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const REDIRECT: &str = "https://rp.example.com/callback";

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn code(tenant_id: Uuid, client_id: &str, code_hash: &str) -> CreateAuthorizationCode {
    CreateAuthorizationCode {
        tenant_id,
        client_id: client_id.into(),
        user_id: Uuid::new_v4(),
        code_hash: code_hash.into(),
        redirect_uri: REDIRECT.into(),
        scopes: vec!["openid".into()],
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        session_id: Some(Uuid::new_v4()),
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        dpop_jkt: None,
        requested_userinfo_claims: Vec::new(),
        resource: None,
        expires_at: Utc::now() + Duration::minutes(10),
    }
}

fn pushed(tenant_id: Uuid, client_id: &str, hash: &str) -> CreatePushedAuthRequest {
    CreatePushedAuthRequest {
        tenant_id,
        client_id: client_id.into(),
        request_uri_hash: hash.into(),
        params: PushedAuthParams::default(),
        expires_at: Utc::now() + Duration::seconds(60),
    }
}

/// Every code of the client goes — redeemed or not — and a voided code reads
/// as one that never existed, **not** as a replay: `replayed_session` finding
/// it would make the token endpoint revoke the user's session for presenting
/// a code whose only fault is that its client was deleted.
#[tokio::test]
async fn deleting_a_clients_codes_voids_them_all_and_nobody_elses() {
    let db = setup().await;
    let repo = SurrealAuthorizationCodeRepository::new(db);
    let tenant = Uuid::new_v4();
    let other_tenant = Uuid::new_v4();

    repo.create(code(tenant, "client-x", "x-live"))
        .await
        .unwrap();
    repo.create(code(tenant, "client-x", "x-spent"))
        .await
        .unwrap();
    repo.consume(tenant, "x-spent", "client-x", REDIRECT)
        .await
        .unwrap();
    repo.create(code(tenant, "client-y", "y-live"))
        .await
        .unwrap();
    repo.create(code(other_tenant, "client-x", "x-elsewhere"))
        .await
        .unwrap();

    assert_eq!(
        repo.delete_all_for_client(tenant, "client-x")
            .await
            .unwrap(),
        2,
        "the client's live and redeemed codes"
    );

    assert!(
        repo.get_by_hash(tenant, "x-live", "client-x", REDIRECT)
            .await
            .is_err(),
        "a voided code cannot be redeemed"
    );
    assert_eq!(
        repo.replayed_session(tenant, "x-spent", "client-x", REDIRECT)
            .await
            .unwrap(),
        None,
        "a voided code is not a replay"
    );
    assert!(
        repo.get_by_hash(tenant, "y-live", "client-y", REDIRECT)
            .await
            .is_ok(),
        "another client's code is untouched"
    );
    assert!(
        repo.get_by_hash(other_tenant, "x-elsewhere", "client-x", REDIRECT)
            .await
            .is_ok(),
        "the same client_id in another tenant is another client"
    );
    assert_eq!(
        repo.delete_all_for_client(tenant, "client-x")
            .await
            .unwrap(),
        0,
        "idempotent"
    );
}

/// The same for pushed requests, spent or not.
#[tokio::test]
async fn deleting_a_clients_pushed_requests_voids_them_all_and_nobody_elses() {
    let db = setup().await;
    let repo = SurrealPushedAuthRequestRepository::new(db);
    let tenant = Uuid::new_v4();
    let other_tenant = Uuid::new_v4();

    repo.create(pushed(tenant, "client-x", "x-live"))
        .await
        .unwrap();
    repo.create(pushed(tenant, "client-x", "x-spent"))
        .await
        .unwrap();
    assert!(repo.consume(tenant, "x-spent").await.unwrap().is_some());
    repo.create(pushed(tenant, "client-y", "y-live"))
        .await
        .unwrap();
    repo.create(pushed(other_tenant, "client-x", "x-elsewhere"))
        .await
        .unwrap();

    assert_eq!(
        repo.delete_all_for_client(tenant, "client-x")
            .await
            .unwrap(),
        2
    );

    assert!(
        repo.find_unconsumed(tenant, "x-live")
            .await
            .unwrap()
            .is_none(),
        "a voided request_uri cannot be spent"
    );
    assert!(
        repo.find_unconsumed(tenant, "y-live")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.find_unconsumed(other_tenant, "x-elsewhere")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        repo.delete_all_for_client(tenant, "client-x")
            .await
            .unwrap(),
        0
    );
}
