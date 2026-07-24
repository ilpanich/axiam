//! Broker-free tests for `process_authz_request` — the pure
//! decode/verify/replay/evaluate logic factored out of the authz AMQP consumer
//! loop (R1). Each test calls `process_authz_request` directly with a real
//! kv-mem `AuthorizationEngine`, a real `SurrealAmqpNonceRepository`, and the
//! HMAC signing helpers from `axiam_amqp::messages` — no live RabbitMQ broker.
//!
//! Covered branches: valid Allow, valid Deny, malformed JSON, unsigned/invalid
//! HMAC, key_version below minimum, stale/future `issued_at`, nonce replay,
//! and a nonce-store error (via a mock nonce repo).

use axiam_amqp::authz_consumer::{AuthzOutcome, process_authz_request};
use axiam_amqp::messages::{AuthzRequest, CURRENT_KEY_VERSION, derive_tenant_key, sign_payload};
use axiam_authz::AuthorizationEngine;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AmqpNonceRepository, OrganizationRepository, PermissionRepository, ResourceRepository,
    RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::SurrealAmqpNonceRepository;
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{DateTime, Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<Db>,
    SurrealPermissionRepository<Db>,
    SurrealResourceRepository<Db>,
    SurrealScopeRepository<Db>,
    SurrealGroupRepository<Db>,
>;

const MASTER: &[u8] = b"test-amqp-master-signing-key-for-authz";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Runtime-generated throwaway password for the fixture user, which never
/// authenticates (this test drives the authz consumer, not login). Deriving it
/// at runtime avoids a hard-coded credential flowing into the `password` field.
fn fixture_password() -> String {
    format!("Fx1!{}", Uuid::new_v4().simple())
}

async fn setup_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn make_engine(db: &Surreal<Db>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

/// Create org + tenant + user, returning (tenant_id, user_id).
async fn seed_tenant_user(db: &Surreal<Db>) -> (Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();
    (tenant.id, user.id)
}

/// Seed a resource + role + permission and grant it to the user, so the engine
/// returns `Allow` for `action` on the returned resource.
async fn grant(db: &Surreal<Db>, tenant_id: Uuid, user_id: Uuid, action: &str) -> Uuid {
    let resource = SurrealResourceRepository::new(db.clone())
        .create(CreateResource {
            tenant_id,
            name: "svc".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "reader".into(),
            description: "reader".into(),
            is_global: false,
        })
        .await
        .unwrap();
    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: action.into(),
            description: "act".into(),
        })
        .await
        .unwrap();
    perm_repo
        .grant_to_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();
    role_repo
        .assign_to_user(tenant_id, user_id, role.id, Some(resource.id))
        .await
        .unwrap();
    resource.id
}

/// Build a fully-populated request for `tenant_id`, then sign it with the
/// per-tenant subkey exactly as a real producer would and return the wire bytes.
fn signed_request(
    tenant_id: Uuid,
    subject_id: Uuid,
    resource_id: Uuid,
    action: &str,
    key_version: u8,
    issued_at: DateTime<Utc>,
    nonce: Uuid,
) -> Vec<u8> {
    let mut req = AuthzRequest {
        correlation_id: Uuid::new_v4(),
        tenant_id,
        subject_id,
        action: action.into(),
        resource_id,
        scope: None,
        key_version,
        nonce,
        issued_at,
        hmac_signature: None,
    };
    // Canonical bytes are the body with hmac_signature = None (omitted).
    let canonical = serde_json::to_vec(&req).unwrap();
    let subkey = derive_tenant_key(MASTER, tenant_id, key_version);
    req.hmac_signature = Some(sign_payload(&subkey, &canonical));
    serde_json::to_vec(&req).unwrap()
}

fn skew() -> Duration {
    Duration::seconds(300)
}

// Mock nonce repo that always fails with a non-replay DB error, to exercise the
// generic `Err(e)` arm of the nonce-store match.
struct FailingNonceRepo;
impl AmqpNonceRepository for FailingNonceRepo {
    async fn insert_nonce(
        &self,
        _tenant_id: Uuid,
        _nonce: Uuid,
        _expires_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        Err(AxiamError::Database("nonce store unavailable".into()))
    }
    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        Ok(0)
    }
}

fn allowed_field(payload: &[u8]) -> bool {
    let v: serde_json::Value = serde_json::from_slice(payload).unwrap();
    v["allowed"].as_bool().unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_request_with_grant_publishes_allow() {
    let db = setup_db().await;
    let (tenant_id, user_id) = seed_tenant_user(&db).await;
    let resource_id = grant(&db, tenant_id, user_id, "read").await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());

    let now = Utc::now();
    let raw = signed_request(
        tenant_id,
        user_id,
        resource_id,
        "read",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );

    let outcome = process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), now).await;
    match outcome {
        AuthzOutcome::Publish(payload) => {
            assert!(allowed_field(&payload), "granted access must be allowed");
        }
        other => panic!("expected Publish(Allow), got {other:?}"),
    }
}

#[tokio::test]
async fn valid_request_without_grant_publishes_deny() {
    let db = setup_db().await;
    let (tenant_id, user_id) = seed_tenant_user(&db).await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());

    let now = Utc::now();
    // No grant seeded → engine denies.
    let raw = signed_request(
        tenant_id,
        user_id,
        Uuid::new_v4(),
        "read",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );

    let outcome = process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), now).await;
    match outcome {
        AuthzOutcome::Publish(payload) => {
            assert!(!allowed_field(&payload), "ungranted access must be denied");
        }
        other => panic!("expected Publish(Deny), got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_json_is_nackdropped() {
    let db = setup_db().await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let outcome = process_authz_request(
        b"this is not json",
        &engine,
        MASTER,
        &nonce_repo,
        skew(),
        Utc::now(),
    )
    .await;
    assert!(matches!(outcome, AuthzOutcome::NackDrop));
}

#[tokio::test]
async fn unsigned_request_is_nackdropped() {
    let db = setup_db().await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let (tenant_id, user_id) = seed_tenant_user(&db).await;

    // Build a valid-looking request but strip the signature.
    let mut raw_val: serde_json::Value = serde_json::from_slice(&signed_request(
        tenant_id,
        user_id,
        Uuid::new_v4(),
        "read",
        CURRENT_KEY_VERSION,
        Utc::now(),
        Uuid::new_v4(),
    ))
    .unwrap();
    raw_val.as_object_mut().unwrap().remove("hmac_signature");
    let raw = serde_json::to_vec(&raw_val).unwrap();

    let outcome =
        process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), Utc::now()).await;
    assert!(matches!(outcome, AuthzOutcome::NackDrop));
}

#[tokio::test]
async fn wrong_signature_is_nackdropped() {
    let db = setup_db().await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let (tenant_id, user_id) = seed_tenant_user(&db).await;

    let mut raw_val: serde_json::Value = serde_json::from_slice(&signed_request(
        tenant_id,
        user_id,
        Uuid::new_v4(),
        "read",
        CURRENT_KEY_VERSION,
        Utc::now(),
        Uuid::new_v4(),
    ))
    .unwrap();
    // Overwrite with a syntactically-valid but wrong signature.
    raw_val["hmac_signature"] = serde_json::Value::String("deadbeef".into());
    let raw = serde_json::to_vec(&raw_val).unwrap();

    let outcome =
        process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), Utc::now()).await;
    assert!(matches!(outcome, AuthzOutcome::NackDrop));
}

#[tokio::test]
async fn key_version_below_minimum_is_nackdropped() {
    let db = setup_db().await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let (tenant_id, user_id) = seed_tenant_user(&db).await;

    // key_version 1 < MIN(2). Sign under kv1 so the signature itself is VALID —
    // this isolates the key_version gate from the signature gate.
    let now = Utc::now();
    let raw = signed_request(
        tenant_id,
        user_id,
        Uuid::new_v4(),
        "read",
        1,
        now,
        Uuid::new_v4(),
    );

    let outcome = process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuthzOutcome::NackDrop));
}

#[tokio::test]
async fn stale_issued_at_is_nackdropped() {
    let db = setup_db().await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let (tenant_id, user_id) = seed_tenant_user(&db).await;

    let issued = Utc::now();
    let raw = signed_request(
        tenant_id,
        user_id,
        Uuid::new_v4(),
        "read",
        CURRENT_KEY_VERSION,
        issued,
        Uuid::new_v4(),
    );

    // Evaluate with a clock one hour ahead → outside the ±300s window.
    let now = issued + Duration::hours(1);
    let outcome = process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuthzOutcome::NackDrop));
}

#[tokio::test]
async fn future_issued_at_is_nackdropped() {
    let db = setup_db().await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let (tenant_id, user_id) = seed_tenant_user(&db).await;

    let issued = Utc::now() + Duration::hours(1);
    let raw = signed_request(
        tenant_id,
        user_id,
        Uuid::new_v4(),
        "read",
        CURRENT_KEY_VERSION,
        issued,
        Uuid::new_v4(),
    );
    let now = Utc::now();
    let outcome = process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuthzOutcome::NackDrop));
}

#[tokio::test]
async fn duplicate_nonce_replay_is_nackdropped() {
    let db = setup_db().await;
    let (tenant_id, user_id) = seed_tenant_user(&db).await;
    let resource_id = grant(&db, tenant_id, user_id, "read").await;
    let engine = make_engine(&db);
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());

    let now = Utc::now();
    let nonce = Uuid::new_v4();
    let raw = signed_request(
        tenant_id,
        user_id,
        resource_id,
        "read",
        CURRENT_KEY_VERSION,
        now,
        nonce,
    );

    // First delivery consumes the nonce and publishes.
    let first = process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(first, AuthzOutcome::Publish(_)));

    // Exact same signed bytes again → replay → NackDrop.
    let second = process_authz_request(&raw, &engine, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(second, AuthzOutcome::NackDrop));
}

#[tokio::test]
async fn nonce_store_error_is_nackdropped() {
    let db = setup_db().await;
    let engine = make_engine(&db);
    let (tenant_id, user_id) = seed_tenant_user(&db).await;

    let now = Utc::now();
    let raw = signed_request(
        tenant_id,
        user_id,
        Uuid::new_v4(),
        "read",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );

    // A non-replay nonce-store error must also reject (dead-letter), never
    // fall through to evaluation.
    let outcome =
        process_authz_request(&raw, &engine, MASTER, &FailingNonceRepo, skew(), now).await;
    assert!(matches!(outcome, AuthzOutcome::NackDrop));
}
