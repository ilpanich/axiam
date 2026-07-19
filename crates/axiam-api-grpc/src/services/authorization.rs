//! AuthorizationService gRPC implementation.

use axiam_auth::token::ValidatedClaims;
use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::authorization_service_server::AuthorizationService;
use crate::proto::{
    BatchCheckAccessRequest, BatchCheckAccessResponse, CheckAccessRequest, CheckAccessResponse,
};

pub struct AuthorizationServiceImpl<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    engine: AuthorizationEngine<R, P, Res, S, G>,
    /// Retained from the pre-D1 concurrent-fan-out design and still accepted by
    /// [`Self::new`] for call-site/config compatibility (`AuthzConfig::
    /// batch_max_concurrency`, default 16). The D1 coalesced batch path issues
    /// a small fixed number of DB round-trips per batch rather than one
    /// per-item future, so the concurrency bound is no longer applied here.
    #[allow(dead_code)]
    batch_max_concurrency: usize,
}

impl<R, P, Res, S, G> AuthorizationServiceImpl<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    pub fn new(engine: AuthorizationEngine<R, P, Res, S, G>, batch_max_concurrency: usize) -> Self {
        Self {
            engine,
            batch_max_concurrency,
        }
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    value
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}

fn to_check_response(decision: AccessDecision) -> CheckAccessResponse {
    match decision {
        AccessDecision::Allow => CheckAccessResponse {
            allowed: true,
            deny_reason: String::new(),
        },
        AccessDecision::Deny(reason) => CheckAccessResponse {
            allowed: false,
            deny_reason: reason,
        },
    }
}

#[tonic::async_trait]
impl<R, P, Res, S, G> AuthorizationService for AuthorizationServiceImpl<R, P, Res, S, G>
where
    R: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
{
    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        // SEC-003: derive authoritative identity from verified JWT claims.
        // The body fields are cross-validated and rejected on mismatch.
        let claims = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .clone();

        let claims_tenant_id = parse_uuid(&claims.0.tenant_id, "claims.tenant_id")?;
        let claims_subject_id = parse_uuid(&claims.0.sub, "claims.sub")?;

        let req = request.into_inner();

        // Cross-validate body fields against verified claims (reject on mismatch).
        let body_tenant_id = parse_uuid(&req.tenant_id, "tenant_id")?;
        let body_subject_id = parse_uuid(&req.subject_id, "subject_id")?;

        if body_tenant_id != claims_tenant_id {
            return Err(Status::permission_denied(
                "tenant_id mismatch: body does not match token claims",
            ));
        }
        if body_subject_id != claims_subject_id {
            return Err(Status::permission_denied(
                "subject_id mismatch: body does not match token claims",
            ));
        }

        let access_req = AccessRequest {
            tenant_id: claims_tenant_id,
            subject_id: claims_subject_id,
            action: req.action,
            resource_id: parse_uuid(&req.resource_id, "resource_id")?,
            scope: req.scope,
        };

        let decision = self
            .engine
            .check_access(&access_req)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(to_check_response(decision)))
    }

    async fn batch_check_access(
        &self,
        request: Request<BatchCheckAccessRequest>,
    ) -> Result<Response<BatchCheckAccessResponse>, Status> {
        // SEC-003: derive authoritative identity from verified JWT claims.
        let claims = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .clone();

        let claims_tenant_id = parse_uuid(&claims.0.tenant_id, "claims.tenant_id")?;
        let claims_subject_id = parse_uuid(&claims.0.sub, "claims.sub")?;

        let req = request.into_inner();

        // T-27-12: validate ALL cross-request identity checks synchronously
        // up front. Any single tenant_id/subject_id mismatch rejects the
        // WHOLE batch (permission_denied) before any check_access fires —
        // preserves today's sequential first-error short-circuit semantics.
        let mut access_requests = Vec::with_capacity(req.requests.len());
        for check_req in req.requests {
            let body_tenant_id = parse_uuid(&check_req.tenant_id, "tenant_id")?;
            let body_subject_id = parse_uuid(&check_req.subject_id, "subject_id")?;

            if body_tenant_id != claims_tenant_id {
                return Err(Status::permission_denied(
                    "tenant_id mismatch: body does not match token claims",
                ));
            }
            if body_subject_id != claims_subject_id {
                return Err(Status::permission_denied(
                    "subject_id mismatch: body does not match token claims",
                ));
            }

            access_requests.push(AccessRequest {
                tenant_id: claims_tenant_id,
                subject_id: claims_subject_id,
                action: check_req.action,
                resource_id: parse_uuid(&check_req.resource_id, "resource_id")?,
                scope: check_req.scope,
            });
        }

        // D1: route the whole batch through the engine's coalesced path. Items
        // sharing a subject/resource (every item in the bench's batch shares
        // both) resolve their role-assignment + ancestor + grant lookups ONCE
        // instead of once per item, and input order is preserved by the engine.
        let decisions = self
            .engine
            .check_access_batch(&access_requests)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let results = decisions.into_iter().map(to_check_response).collect();

        Ok(Response::new(BatchCheckAccessResponse { results }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::organization::CreateOrganization;
    use axiam_core::models::permission::CreatePermission;
    use axiam_core::models::resource::CreateResource;
    use axiam_core::models::role::CreateRole;
    use axiam_core::models::tenant::CreateTenant;
    use axiam_core::models::user::CreateUser;
    use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
    use axiam_db::repository::{
        SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
        SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
        SurrealTenantRepository, SurrealUserRepository,
    };
    use surrealdb::Surreal;
    use surrealdb::engine::local::{Db, Mem};

    type TestEngine = AuthorizationEngine<
        SurrealRoleRepository<Db>,
        SurrealPermissionRepository<Db>,
        SurrealResourceRepository<Db>,
        SurrealScopeRepository<Db>,
        SurrealGroupRepository<Db>,
    >;

    async fn setup() -> (Surreal<Db>, Uuid, Uuid) {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();

        let org_repo = SurrealOrganizationRepository::new(db.clone());
        let org = org_repo
            .create(CreateOrganization {
                name: "Test Org".into(),
                slug: "test-org".into(),
                metadata: None,
            })
            .await
            .unwrap();

        let tenant_repo = SurrealTenantRepository::new(db.clone());
        let tenant = tenant_repo
            .create(CreateTenant {
                organization_id: org.id,
                name: "Test Tenant".into(),
                slug: "test-tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();

        let user_repo = SurrealUserRepository::new(db.clone());
        let user = user_repo
            .create(CreateUser {
                tenant_id: tenant.id,
                username: "alice".into(),
                email: "alice@example.com".into(),
                password: "pass123456789".into(),
                metadata: None,
            })
            .await
            .unwrap();

        (db, tenant.id, user.id)
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

    async fn create_resource(db: &Surreal<Db>, tenant_id: Uuid, name: &str) -> Uuid {
        let repo = SurrealResourceRepository::new(db.clone());
        let res = repo
            .create(CreateResource {
                tenant_id,
                name: name.into(),
                resource_type: "service".into(),
                parent_id: None,
                metadata: None,
            })
            .await
            .unwrap();
        res.id
    }

    async fn grant_user_role_permission(
        db: &Surreal<Db>,
        tenant_id: Uuid,
        user_id: Uuid,
        role_name: &str,
        action: &str,
        resource_id: Option<Uuid>,
    ) {
        let role_repo = SurrealRoleRepository::new(db.clone());
        let perm_repo = SurrealPermissionRepository::new(db.clone());

        let role = role_repo
            .create(CreateRole {
                tenant_id,
                name: role_name.into(),
                description: format!("Role: {role_name}"),
                is_global: false,
            })
            .await
            .unwrap();

        let perm = perm_repo
            .create(CreatePermission {
                tenant_id,
                action: action.into(),
                description: format!("Can {action}"),
            })
            .await
            .unwrap();

        perm_repo
            .grant_to_role(tenant_id, role.id, perm.id)
            .await
            .unwrap();

        role_repo
            .assign_to_user(tenant_id, user_id, role.id, resource_id)
            .await
            .unwrap();
    }

    /// D-06 correctness gate (T-27-10): `batch_check_access` must yield
    /// byte-identical results, in the same order, as calling
    /// `AuthorizationEngine::check_access` per-item and collecting into a
    /// `Vec` — proving concurrency introduces no ordering or decision bug.
    #[tokio::test]
    async fn batch_check_access_matches_sequential_per_item_check_access() {
        let (db, tenant_id, user_id) = setup().await;
        let resource_a = create_resource(&db, tenant_id, "svc-a").await;
        let resource_b = create_resource(&db, tenant_id, "svc-b").await;
        let resource_c = create_resource(&db, tenant_id, "svc-c").await;

        grant_user_role_permission(&db, tenant_id, user_id, "viewer", "read", Some(resource_a))
            .await;

        let requests = vec![
            AccessRequest {
                tenant_id,
                subject_id: user_id,
                action: "read".into(),
                resource_id: resource_a,
                scope: None,
            },
            AccessRequest {
                tenant_id,
                subject_id: user_id,
                action: "read".into(),
                resource_id: resource_b,
                scope: None,
            },
            AccessRequest {
                tenant_id,
                subject_id: user_id,
                action: "delete".into(),
                resource_id: resource_c,
                scope: None,
            },
            AccessRequest {
                tenant_id,
                subject_id: user_id,
                action: "read".into(),
                resource_id: resource_a,
                scope: None,
            },
        ];

        // Sequential per-item baseline: AuthorizationEngine::check_access
        // called directly, one at a time, collected into a Vec.
        let seq_engine = make_engine(&db);
        let mut sequential_results = Vec::with_capacity(requests.len());
        for req in &requests {
            sequential_results.push(seq_engine.check_access(req).await.unwrap());
        }

        // Concurrent batch path: drive the REAL AuthorizationService trait
        // method (small concurrency bound to force actual overlap across
        // buffer_unordered), not a re-implementation of its internals.
        let claims = ValidatedClaims(axiam_auth::token::AccessTokenClaims {
            sub: user_id.to_string(),
            sub_kind: axiam_auth::token::SubjectKind::User,
            tenant_id: tenant_id.to_string(),
            org_id: Uuid::nil().to_string(),
            iss: "axiam-test".into(),
            iat: 0,
            exp: i64::MAX,
            jti: Uuid::new_v4().to_string(),
            aud: None,
            scope: None,
        });

        let svc = AuthorizationServiceImpl::new(make_engine(&db), 2);
        let mut tonic_req = Request::new(BatchCheckAccessRequest {
            requests: requests
                .iter()
                .map(|r| CheckAccessRequest {
                    tenant_id: r.tenant_id.to_string(),
                    subject_id: r.subject_id.to_string(),
                    action: r.action.clone(),
                    resource_id: r.resource_id.to_string(),
                    scope: r.scope.clone(),
                })
                .collect(),
        });
        tonic_req.extensions_mut().insert(claims);

        let batch_response = svc
            .batch_check_access(tonic_req)
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            batch_response.results.len(),
            sequential_results.len(),
            "batch and sequential result counts must match"
        );
        for (i, (batch, seq)) in batch_response
            .results
            .iter()
            .zip(sequential_results.iter())
            .enumerate()
        {
            let expected = to_check_response(seq.clone());
            assert_eq!(
                batch.allowed, expected.allowed,
                "result[{i}] allowed mismatch between concurrent batch and sequential per-item check_access"
            );
            assert_eq!(
                batch.deny_reason, expected.deny_reason,
                "result[{i}] deny_reason mismatch between concurrent batch and sequential per-item check_access"
            );
        }
    }
}
