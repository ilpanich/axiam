//! §13.4 observation 9 — user mutations must invalidate cached decisions.
//!
//! `users::update` and `users::delete` did not call `invalidate_*`, so a
//! deleted or disabled user's cached `Allow` survived on every replica until the
//! decision-cache TTL expired. Nothing on the session-authenticated request path
//! re-reads user status either — `AuthenticatedUser::from_request` calls only
//! `is_session_active`, which checks the session row's `expires_at` and nothing
//! else — so the cache was the only thing holding the stale grant, and the only
//! place it could be cleared.
//!
//! These tests assert the handler *drives the invalidation seam*, which is the
//! part that was missing. Whether the cache then drops the entry is already
//! covered by `axiam-authz`'s own `decision_cache` tests and, cross-replica, by
//! `axiam-amqp`'s `cache_invalidation_test`.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use actix_web::web;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AccessTokenClaims, SubjectKind, ValidatedClaims};
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::error::AxiamResult;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::UserRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

use crate::authz::{AuthzChecker, AuthzData};
use crate::extractors::auth::AuthenticatedUser;
use crate::handlers::users::{UpdateUserRequest, delete, update};
use crate::state::AppState;

type TestDb = surrealdb::engine::local::Db;

/// Records every invalidation the handler drives. Allows all checks, so the test
/// is about the invalidation, not about the permission gate.
#[derive(Default)]
struct RecordingChecker {
    subjects: Mutex<Vec<(Uuid, Uuid)>>,
    tenants: Mutex<Vec<Uuid>>,
}

impl RecordingChecker {
    fn subjects(&self) -> Vec<(Uuid, Uuid)> {
        self.subjects.lock().unwrap().clone()
    }
}

impl AuthzChecker for RecordingChecker {
    fn check_access<'a>(
        &'a self,
        _request: &'a AccessRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<AccessDecision>> + Send + 'a>> {
        Box::pin(async { Ok(AccessDecision::Allow) })
    }

    fn invalidate_tenant<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>> {
        self.tenants.lock().unwrap().push(tenant_id);
        Box::pin(async { Ok(()) })
    }

    fn invalidate_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>> {
        self.subjects.lock().unwrap().push((tenant_id, subject_id));
        Box::pin(async { Ok(()) })
    }
}

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory db");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    axiam_db::run_migrations(&db).await.expect("run migrations");
    db
}

fn make_admin(tenant_id: Uuid) -> AuthenticatedUser {
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    AuthenticatedUser {
        user_id,
        tenant_id,
        org_id: Uuid::nil(),
        session_id,
        claims: ValidatedClaims(AccessTokenClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            org_id: Uuid::nil().to_string(),
            iss: "test".into(),
            iat: 0,
            exp: i64::MAX,
            jti: session_id.to_string(),
            aud: Some("axiam:user".into()),
            scope: None,
            sub_kind: SubjectKind::User,
        }),
    }
}

/// Create a target user to mutate, returning its id.
async fn seed_target(state: &AppState<TestDb>, tenant_id: Uuid) -> Uuid {
    state
        .user_repo
        .create(CreateUser {
            tenant_id,
            username: format!("target-{}", Uuid::new_v4()),
            email: format!("{}@example.test", Uuid::new_v4()),
            password: "Sup3rSecret!pass".into(),
            metadata: None,
        })
        .await
        .expect("seed target user")
        .id
}

/// Deleting a user must flush that subject: every cached `Allow` naming it is
/// now a decision about a principal that no longer exists.
#[actix_web::test]
async fn deleting_a_user_invalidates_that_subject() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let state = web::Data::new(AppState::for_test(db, AuthConfig::default()));
    let target = seed_target(&state, tenant_id).await;

    let checker = Arc::new(RecordingChecker::default());
    let authz: AuthzData = web::Data::new(checker.clone() as Arc<dyn AuthzChecker>);
    let admin = make_admin(tenant_id);

    delete(admin, authz, state, web::Path::from(target))
        .await
        .expect("delete succeeds");

    assert_eq!(
        checker.subjects(),
        vec![(tenant_id, target)],
        "a deleted user's cached decisions must be flushed for THAT subject, \
         scoped to the caller's tenant"
    );
}

/// Updating a user must flush that subject: an update can narrow access, most
/// directly by setting `status` away from Active.
#[actix_web::test]
async fn updating_a_user_invalidates_that_subject() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let state = web::Data::new(AppState::for_test(db, AuthConfig::default()));
    let target = seed_target(&state, tenant_id).await;

    let checker = Arc::new(RecordingChecker::default());
    let authz: AuthzData = web::Data::new(checker.clone() as Arc<dyn AuthzChecker>);
    let admin = make_admin(tenant_id);

    update(
        admin,
        authz,
        state,
        web::Path::from(target),
        web::Json(UpdateUserRequest {
            username: None,
            email: None,
            // Inactive is the narrowing transition: the user keeps its roles but
            // must stop being able to act on them.
            status: Some(axiam_core::models::user::UserStatus::Inactive),
            metadata: None,
        }),
    )
    .await
    .expect("update succeeds");

    assert_eq!(
        checker.subjects(),
        vec![(tenant_id, target)],
        "deactivating a user must not leave its cached allows live until the TTL"
    );
}

/// The flush must name the **target**, not the caller. Getting this backwards
/// would be worse than no flush at all: the suspended user keeps its cached
/// allows while an unrelated admin loses theirs, and the bug looks like a
/// performance blip rather than a revocation failure.
#[actix_web::test]
async fn the_invalidated_subject_is_the_target_not_the_caller() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let state = web::Data::new(AppState::for_test(db, AuthConfig::default()));
    let target = seed_target(&state, tenant_id).await;

    let checker = Arc::new(RecordingChecker::default());
    let authz: AuthzData = web::Data::new(checker.clone() as Arc<dyn AuthzChecker>);
    let admin = make_admin(tenant_id);
    let caller_id = admin.user_id;

    delete(admin, authz, state, web::Path::from(target))
        .await
        .expect("delete succeeds");

    let recorded = checker.subjects();
    assert!(
        recorded.iter().any(|(_, s)| *s == target),
        "the target must be invalidated"
    );
    assert!(
        !recorded.iter().any(|(_, s)| *s == caller_id),
        "the caller's own cached decisions must be left alone"
    );
}
