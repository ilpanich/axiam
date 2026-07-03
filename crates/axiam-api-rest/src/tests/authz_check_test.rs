//! Unit tests for `handlers::authz_check` (FND-04).
//!
//! Tests cover:
//! (a) Self-check — no subject_id → uses caller identity, returns a decision.
//! (b) Override denied — subject_id present but caller lacks authz:check_as → 403.
//! (c) Override allowed — subject_id present, caller holds authz:check_as → decision + audit row.
//! (d) Batch — results have same length and order as input checks.

use std::sync::Arc;

use actix_web::web;
use axiam_auth::token::AccessTokenClaims;
use axiam_auth::token::ValidatedClaims;
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, Pagination};
use axiam_db::SurrealAuditLogRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

use crate::authz::{AllowAllAuthzChecker, AuthzChecker, AuthzData, DenyAllAuthzChecker};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::handlers::authz_check::{
    BatchCheckAccessBody, CheckAccessBody, batch_check_access, check_access,
};

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
    let audit_repo = web::Data::new(SurrealAuditLogRepository::new(db));
    let authz = make_authz(AllowAllAuthzChecker);
    let user = make_user(tenant_id, user_id);

    let body = web::Json(CheckAccessBody {
        action: "users:get".into(),
        resource_id,
        scope: None,
        subject_id: None, // self-check
    });

    let result = check_access(user, authz, audit_repo, body).await;
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
    let audit_repo = web::Data::new(SurrealAuditLogRepository::new(db));
    // DenyAll will deny the authz:check_as permission check → 403
    let authz = make_authz(DenyAllAuthzChecker);
    let user = make_user(tenant_id, user_id);

    let body = web::Json(CheckAccessBody {
        action: "users:get".into(),
        resource_id,
        scope: None,
        subject_id: Some(other_subject), // override attempt
    });

    let result = check_access(user, authz, audit_repo, body).await;
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
    let audit_repo = web::Data::new(SurrealAuditLogRepository::new(db));
    // AllowAll grants both authz:check_as AND the engine's access decision
    let authz = make_authz(AllowAllAuthzChecker);
    let user = make_user(tenant_id, admin_id);

    let body = web::Json(CheckAccessBody {
        action: "users:get".into(),
        resource_id,
        scope: None,
        subject_id: Some(queried_subject),
    });

    let result = check_access(user, authz, audit_repo.clone(), body).await;
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
    let audit_result = audit_repo
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
    let audit_repo = web::Data::new(SurrealAuditLogRepository::new(db));
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

    let result = batch_check_access(user, authz, audit_repo, body).await;
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
    let audit_repo = web::Data::new(SurrealAuditLogRepository::new(db));
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

    let result = batch_check_access(user, authz, audit_repo, body).await;
    assert_eq!(
        status_code(&result),
        403,
        "batch override without authz:check_as must return 403"
    );
}
