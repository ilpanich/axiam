//! Unit tests for `handlers::authz_check` (FND-04).
//!
//! Tests cover:
//! (a) Self-check — no subject_id → uses caller identity, returns a decision.
//! (b) Override denied — subject_id present but caller lacks authz:check_as → 403.
//! (c) Override allowed — subject_id present, caller holds authz:check_as → decision + audit row.
//! (d) Batch — results have same length and order as input checks.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::web;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::AccessTokenClaims;
use axiam_auth::token::SubjectKind;
use axiam_auth::token::ValidatedClaims;
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::error::AxiamResult;
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, Pagination};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

use crate::authz::{AllowAllAuthzChecker, AuthzChecker, AuthzData, DenyAllAuthzChecker};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::handlers::authz_check::{
    BatchCheckAccessBody, CheckAccessBody, batch_check_access, check_access,
};
use crate::state::AppState;

type TestDb = surrealdb::engine::local::Db;

/// Build a full `AppState<TestDb>` (QUAL-01) from a test `db` handle.
fn make_state(db: Surreal<TestDb>) -> web::Data<AppState<TestDb>> {
    web::Data::new(AppState::for_test(db, AuthConfig::default()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory db");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    axiam_db::run_migrations(&db).await.expect("run migrations");
    db
}

fn make_user(tenant_id: Uuid, user_id: Uuid) -> AuthenticatedUser {
    let session_id = Uuid::new_v4();
    let claims = ValidatedClaims(AccessTokenClaims {
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
    });
    AuthenticatedUser {
        user_id,
        tenant_id,
        org_id: Uuid::nil(),
        session_id,
        claims,
    }
}

fn make_authz<C: AuthzChecker + 'static>(checker: C) -> AuthzData {
    web::Data::new(Arc::new(checker) as Arc<dyn AuthzChecker>)
}

/// Unwrap HTTP status code from a handler result.
fn status_code(result: &Result<actix_web::HttpResponse, AxiamApiError>) -> u16 {
    match result {
        Ok(r) => r.status().as_u16(),
        Err(e) => {
            use actix_web::ResponseError;
            e.status_code().as_u16()
        }
    }
}

/// Read body JSON from a successful HTTP response.
async fn read_body_json(response: actix_web::HttpResponse) -> serde_json::Value {
    use actix_http::body::to_bytes;

    let bytes = to_bytes(response.into_body()).await.expect("body to bytes");
    serde_json::from_slice(&bytes).expect("valid JSON body")
}

// ---------------------------------------------------------------------------
// (a) Self-check — caller's own identity, AllowAll → allowed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn self_check_returns_allow() {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let resource_id = Uuid::new_v4();

    let db = setup_db().await;
    let state = make_state(db);
    let authz = make_authz(AllowAllAuthzChecker);
    let user = make_user(tenant_id, user_id);

    let body = web::Json(CheckAccessBody {
        action: "users:get".into(),
        resource_id,
        scope: None,
        subject_id: None, // self-check
    });

    let result = check_access(user, authz, state, body).await;
    assert_eq!(status_code(&result), 200, "self-check should return 200");

    let json = read_body_json(result.unwrap()).await;
    assert_eq!(json["allowed"], true, "AllowAll should return allowed=true");
    assert!(
        json.get("reason").is_none() || json["reason"].is_null(),
        "reason should be absent on allow"
    );
}

// ---------------------------------------------------------------------------
// (b) Override denied — subject_id but no authz:check_as → 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn override_without_check_as_permission_returns_403() {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let other_subject = Uuid::new_v4();
    let resource_id = Uuid::new_v4();

    let db = setup_db().await;
    let state = make_state(db);
    // DenyAll will deny the authz:check_as permission check → 403
    let authz = make_authz(DenyAllAuthzChecker);
    let user = make_user(tenant_id, user_id);

    let body = web::Json(CheckAccessBody {
        action: "users:get".into(),
        resource_id,
        scope: None,
        subject_id: Some(other_subject), // override attempt
    });

    let result = check_access(user, authz, state, body).await;
    assert_eq!(
        status_code(&result),
        403,
        "override without authz:check_as must return 403"
    );
}

// ---------------------------------------------------------------------------
// (c) Override allowed — admin holds authz:check_as → decision + audit row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn override_with_check_as_permission_returns_decision_and_audits() {
    let tenant_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let queried_subject = Uuid::new_v4();
    let resource_id = Uuid::new_v4();

    let db = setup_db().await;
    let state = make_state(db);
    // AllowAll grants both authz:check_as AND the engine's access decision
    let authz = make_authz(AllowAllAuthzChecker);
    let user = make_user(tenant_id, admin_id);

    let body = web::Json(CheckAccessBody {
        action: "users:get".into(),
        resource_id,
        scope: None,
        subject_id: Some(queried_subject),
    });

    let result = check_access(user, authz, state.clone(), body).await;
    assert_eq!(
        status_code(&result),
        200,
        "override with authz:check_as should return 200"
    );

    let json = read_body_json(result.unwrap()).await;
    assert_eq!(
        json["allowed"], true,
        "AllowAll engine should return allowed=true"
    );

    // Verify the audit row was written (T-15-04).
    // Small delay to ensure the fire-and-forget append completes.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let filter = AuditLogFilter {
        action: Some("authz.check_as".into()),
        ..Default::default()
    };
    let page = Pagination::default();
    let audit_result = state
        .audit_repo
        .list(tenant_id, filter, page)
        .await
        .expect("audit list");
    assert!(
        !audit_result.items.is_empty(),
        "authz.check_as audit row must be written for cross-subject override"
    );
    let row = &audit_result.items[0];
    assert_eq!(row.action, "authz.check_as");
    assert_eq!(row.actor_id, admin_id);
}

// ---------------------------------------------------------------------------
// (d) Batch — results have same length and order as input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_check_returns_results_in_input_order() {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let db = setup_db().await;
    let state = make_state(db);
    // AllowAll engine — all checks return allowed
    let authz = make_authz(AllowAllAuthzChecker);
    let user = make_user(tenant_id, user_id);

    let checks = vec![
        CheckAccessBody {
            action: "users:get".into(),
            resource_id: Uuid::new_v4(),
            scope: None,
            subject_id: None,
        },
        CheckAccessBody {
            action: "roles:list".into(),
            resource_id: Uuid::new_v4(),
            scope: None,
            subject_id: None,
        },
        CheckAccessBody {
            action: "groups:create".into(),
            resource_id: Uuid::new_v4(),
            scope: None,
            subject_id: None,
        },
    ];
    let input_len = checks.len();

    let body = web::Json(BatchCheckAccessBody { checks });

    let result = batch_check_access(user, authz, state, body).await;
    assert_eq!(status_code(&result), 200, "batch check should return 200");

    let json = read_body_json(result.unwrap()).await;
    let results = json["results"].as_array().expect("results array");
    assert_eq!(
        results.len(),
        input_len,
        "batch results must have same length as input"
    );
    // AllowAll engine: all should be allowed
    for (i, res) in results.iter().enumerate() {
        assert_eq!(res["allowed"], true, "batch result[{i}] should be allowed");
    }
}

// ---------------------------------------------------------------------------
// (e) Batch with DenyAll — override attempt returns 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_override_without_check_as_returns_403() {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let other_subject = Uuid::new_v4();

    let db = setup_db().await;
    let state = make_state(db);
    // DenyAll will deny the authz:check_as permission → 403
    let authz = make_authz(DenyAllAuthzChecker);
    let user = make_user(tenant_id, user_id);

    let body = web::Json(BatchCheckAccessBody {
        checks: vec![CheckAccessBody {
            action: "users:get".into(),
            resource_id: Uuid::new_v4(),
            scope: None,
            subject_id: Some(other_subject),
        }],
    });

    let result = batch_check_access(user, authz, state, body).await;
    assert_eq!(
        status_code(&result),
        403,
        "batch override without authz:check_as must return 403"
    );
}

// ---------------------------------------------------------------------------
// (f) D-06 correctness gate — batch == per-item check_access, same order
// ---------------------------------------------------------------------------

/// Test-only [`AuthzChecker`] whose decision depends on `resource_id`, so a
/// batch of mixed allow/deny results can prove `sort_by_key` genuinely
/// restores input order (not just a common allow-all/deny-all path).
struct PerResourceAuthzChecker {
    allowed: HashMap<Uuid, bool>,
}

impl AuthzChecker for PerResourceAuthzChecker {
    fn check_access<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<AccessDecision>> + Send + 'a>> {
        let allow = self
            .allowed
            .get(&request.resource_id)
            .copied()
            .unwrap_or(false);
        Box::pin(async move {
            Ok(if allow {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny("denied by PerResourceAuthzChecker".into())
            })
        })
    }
}

/// D-06/T-27-10 correctness gate: `batch_check_access` results must be
/// identical, in the same order, to calling `check_access` once per item
/// and collecting into a `Vec` — proves the concurrent
/// `buffer_unordered` + `sort_by_key` refactor introduces no ordering or
/// decision bug.
#[tokio::test]
async fn batch_check_access_matches_sequential_per_item_check_access() {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let resources: Vec<Uuid> = (0..6).map(|_| Uuid::new_v4()).collect();
    // Alternate allow/deny per resource so ordering actually matters.
    let allowed: HashMap<Uuid, bool> = resources
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, i % 2 == 0))
        .collect();

    let checks: Vec<CheckAccessBody> = resources
        .iter()
        .map(|resource_id| CheckAccessBody {
            action: "read".into(),
            resource_id: *resource_id,
            scope: None,
            subject_id: None,
        })
        .collect();

    // Sequential per-item baseline via the single-check handler.
    let db = setup_db().await;
    let seq_state = make_state(db);
    let mut sequential_allowed = Vec::with_capacity(checks.len());
    for check in &checks {
        let authz = make_authz(PerResourceAuthzChecker {
            allowed: allowed.clone(),
        });
        let user = make_user(tenant_id, user_id);
        let body = web::Json(CheckAccessBody {
            action: check.action.clone(),
            resource_id: check.resource_id,
            scope: check.scope.clone(),
            subject_id: None,
        });
        let result = check_access(user, authz, seq_state.clone(), body)
            .await
            .expect("sequential check_access must succeed");
        let json = read_body_json(result).await;
        sequential_allowed.push(json["allowed"].as_bool().expect("allowed bool"));
    }

    // Concurrent batch path via the real batch_check_access handler, with a
    // small concurrency bound to force actual interleaving.
    let batch_db = setup_db().await;
    let mut batch_state_inner = AppState::for_test(batch_db, AuthConfig::default());
    batch_state_inner.authz_config = axiam_authz::AuthzConfig {
        batch_max_concurrency: 2,
    };
    let batch_state = web::Data::new(batch_state_inner);
    let batch_authz = make_authz(PerResourceAuthzChecker { allowed });
    let batch_user = make_user(tenant_id, user_id);
    let batch_body = web::Json(BatchCheckAccessBody { checks });

    let batch_result = batch_check_access(batch_user, batch_authz, batch_state, batch_body)
        .await
        .expect("batch_check_access must succeed");
    let batch_json = read_body_json(batch_result).await;
    let batch_results = batch_json["results"].as_array().expect("results array");

    assert_eq!(
        batch_results.len(),
        sequential_allowed.len(),
        "batch and sequential result counts must match"
    );
    for (i, (batch_res, seq_allowed)) in batch_results
        .iter()
        .zip(sequential_allowed.iter())
        .enumerate()
    {
        assert_eq!(
            batch_res["allowed"].as_bool().expect("allowed bool"),
            *seq_allowed,
            "result[{i}] mismatch between concurrent batch and sequential per-item check_access"
        );
    }
}
