//! AuthorizationService gRPC implementation.

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
}

impl<R, P, Res, S, G> AuthorizationServiceImpl<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    pub fn new(engine: AuthorizationEngine<R, P, Res, S, G>) -> Self {
        Self { engine }
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
        let req = request.into_inner();

        let access_req = AccessRequest {
            tenant_id: parse_uuid(&req.tenant_id, "tenant_id")?,
            subject_id: parse_uuid(&req.subject_id, "subject_id")?,
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
        let req = request.into_inner();
        let mut results = Vec::with_capacity(req.requests.len());

        for check_req in req.requests {
            let access_req = AccessRequest {
                tenant_id: parse_uuid(&check_req.tenant_id, "tenant_id")?,
                subject_id: parse_uuid(&check_req.subject_id, "subject_id")?,
                action: check_req.action,
                resource_id: parse_uuid(&check_req.resource_id, "resource_id")?,
                scope: check_req.scope,
            };

            let decision = self
                .engine
                .check_access(&access_req)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            results.push(to_check_response(decision));
        }

        Ok(Response::new(BatchCheckAccessResponse { results }))
    }
}
