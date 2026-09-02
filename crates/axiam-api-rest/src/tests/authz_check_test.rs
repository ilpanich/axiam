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
use crate::extractors::auth::AuthenticatedPrincipal;
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

/// A human principal (`aud = axiam:user`) for these handlers.
///
/// The authorization-check endpoints take [`AuthenticatedPrincipal`] since
/// §17.2 residual 1, because they are the one REST surface a machine token is
/// allowed to reach. `is_machine: false` here keeps every pre-existing test
/// asserting exactly what it did before; `make_machine` below covers the new
/// branch.
fn make_user(tenant_id: Uuid, user_id: Uuid) -> AuthenticatedPrincipal {
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
        act: None,
        permissions: None,
        ext_exchange: None,
        cnf: None,
        ext: None,
    });
    AuthenticatedPrincipal {
        subject_id: user_id,
        tenant_id,
        // An ordinary tenant principal: the tenant it acts on is the one it
        // lives in, and it has not been verified as organization-level.
        principal_tenant_id: tenant_id,
        organization_level: false,
        org_id: Uuid::nil(),
        is_machine: false,
        claims,
    }
}

/// A machine principal (`aud = axiam:m2m`) — a certificate-authenticated
/// device or a service account holding a client-credentials token.
fn make_machine(tenant_id: Uuid, service_account_id: Uuid) -> AuthenticatedPrincipal {
    let claims = ValidatedClaims(AccessTokenClaims {
        sub: service_account_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: Uuid::nil().to_string(),
        iss: "test".into(),
        iat: 0,
        exp: i64::MAX,
        jti: Uuid::new_v4().to_string(),
        aud: Some("axiam:m2m".into()),
        scope: None,
        sub_kind: axiam_auth::token::SubjectKind::ServiceAccount,
        act: None,
        permissions: None,
        ext_exchange: None,
        cnf: None,
        ext: None,
    });

    AuthenticatedPrincipal {
        subject_id: service_account_id,
        tenant_id,
        principal_tenant_id: tenant_id,
        organization_level: false,
        org_id: Uuid::nil(),
        is_machine: true,
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
// ---------------------------------------------------------------------------
// (e2) The tenant the check is evaluated in
// ---------------------------------------------------------------------------

/// Records the [`AccessRequest`] it was handed, so a test can assert *what was
/// asked* rather than only what came back. Allows everything: the decision is
/// not the subject here.
#[derive(Default)]
struct RecordingAuthzChecker {
    seen: std::sync::Mutex<Vec<AccessRequest>>,
}

impl AuthzChecker for RecordingAuthzChecker {
    fn check_access<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<AccessDecision>> + Send + 'a>> {
        self.seen.lock().unwrap().push(request.clone());
        Box::pin(async move { Ok(AccessDecision::Allow) })
    }
}

/// The reported defect: an organization-level administrator with a tenant
/// selected in the admin UI got `no roles assigned` from the effective-access
/// preview, for rule sets that were correct.
///
/// `AuthenticatedPrincipal::tenant_id` is the tenant being **acted upon** —
/// what the active-tenant header resolved to. It used to be the raw
/// `tenant_id` claim, i.e. the caller's own, so the engine was asked about the
/// organization's tenant, where the subject has no role assignments at all and
/// evaluation stops at step 1.
#[tokio::test]
async fn a_check_is_evaluated_in_the_tenant_being_acted_upon() {
    let org_scope = Uuid::new_v4();
    let acting_on = Uuid::new_v4();
    let subject = Uuid::new_v4();

    // An organization-level caller: living in the organization's tenant,
    // acting on one of its tenants.
    let mut caller = make_user(org_scope, Uuid::new_v4());
    caller.tenant_id = acting_on;
    caller.principal_tenant_id = org_scope;
    caller.organization_level = true;

    let recorder = Arc::new(RecordingAuthzChecker::default());
    let authz: AuthzData = web::Data::new(recorder.clone() as Arc<dyn AuthzChecker>);
    let state = make_state(setup_db().await);

    let result = check_access(
        caller,
        authz,
        state,
        web::Json(CheckAccessBody {
            action: "sites:read".into(),
            resource_id: Uuid::new_v4(),
            scope: None,
            subject_id: Some(subject),
        }),
    )
    .await;
    assert_eq!(status_code(&result), 200);

    let seen = recorder.seen.lock().unwrap();
    // Two requests: the `authz:check_as` guard, then the check itself.
    let checked = seen
        .iter()
        .find(|r| r.action == "sites:read")
        .expect("the requested check must reach the engine");
    assert_eq!(
        checked.tenant_id, acting_on,
        "the check must be evaluated in the tenant being acted upon, not the \
         one the caller lives in",
    );
    assert_eq!(
        checked.subject_id, subject,
        "the checked-as subject, not the caller",
    );

    // And the guard reads the CALLER's grants, which for an organization-level
    // principal live in its own tenant. With a fixed `SubjectScope::Tenant` it
    // looked for `authz:check_as` in the tenant being acted upon and would
    // refuse a caller that holds it.
    let guard = seen
        .iter()
        .find(|r| r.action == "authz:check_as")
        .expect("the check_as guard must run");
    assert_eq!(
        guard.subject_scope,
        axiam_authz::types::SubjectScope::Organization {
            tenant_id: org_scope
        },
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
        ..Default::default()
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

// ---------------------------------------------------------------------------
// §17.2 residual 1 — a machine principal reaches the authz-check endpoints
// ---------------------------------------------------------------------------

/// A certificate-authenticated device (now `aud = axiam:m2m`) can still run an
/// authorization check.
///
/// This is the test that makes the audience flip safe to ship. `aud` moved
/// from `axiam:user` to `axiam:m2m` so a device stops passing *user*-facing
/// route guards — but the check endpoints are the surface a device actually
/// needs, so they must keep working. Without the `AuthenticatedPrincipal`
/// widening this request would 401, and the narrowing would have been an
/// outage rather than a fix.
#[tokio::test]
async fn a_machine_principal_can_run_an_authz_check() {
    let tenant_id = Uuid::new_v4();
    let service_account_id = Uuid::new_v4();
    let resource_id = Uuid::new_v4();

    let db = setup_db().await;
    let state = make_state(db);
    let authz = make_authz(AllowAllAuthzChecker);
    let machine = make_machine(tenant_id, service_account_id);

    let body = web::Json(CheckAccessBody {
        action: "devices:report".into(),
        resource_id,
        scope: None,
        subject_id: None,
    });

    let result = check_access(machine, authz, state, body).await;
    assert_eq!(
        status_code(&result),
        200,
        "a machine token must be accepted on the authz-check endpoint"
    );
    let json = read_body_json(result.unwrap()).await;
    assert_eq!(json["allowed"], true);
}

/// The `authz:check_as` gate applies to machines exactly as it does to users.
///
/// Widening the accepted audience must not widen *authorization*: a device
/// asking about another subject is subject to the same permission check, and
/// the deny-all checker means it does not have it.
#[tokio::test]
async fn a_machine_principal_still_needs_check_as_to_query_another_subject() {
    let tenant_id = Uuid::new_v4();
    let service_account_id = Uuid::new_v4();
    let other_subject = Uuid::new_v4();
    let resource_id = Uuid::new_v4();

    let db = setup_db().await;
    let state = make_state(db);
    let authz = make_authz(DenyAllAuthzChecker);
    let machine = make_machine(tenant_id, service_account_id);

    let body = web::Json(CheckAccessBody {
        action: "users:get".into(),
        resource_id,
        scope: None,
        subject_id: Some(other_subject),
    });

    let result = check_access(machine, authz, state, body).await;
    assert_eq!(
        status_code(&result),
        403,
        "a machine without authz:check_as must not query another subject"
    );
}

/// The audit trail must record a device as a service account, not as a user.
///
/// `authz.check_as` is legally significant, so attributing a machine's
/// cross-subject query to `ActorType::User` would be a false record. Before
/// the principal widening the actor type was hardcoded.
#[test]
fn a_machine_principal_audits_as_a_service_account() {
    use axiam_core::models::audit::ActorType;

    let machine = make_machine(Uuid::new_v4(), Uuid::new_v4());
    let human = make_user(Uuid::new_v4(), Uuid::new_v4());

    assert!(matches!(machine.actor_type(), ActorType::ServiceAccount));
    assert!(matches!(human.actor_type(), ActorType::User));
}
