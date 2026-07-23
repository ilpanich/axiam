//! UserInfoService gRPC implementation.
//!
//! Low-latency gRPC counterpart of the REST `GET /oauth2/userinfo` endpoint
//! (`crates/axiam-api-rest/src/handlers/oauth2.rs`). Identity is derived
//! entirely from the interceptor-verified bearer token (`ValidatedClaims` in
//! request extensions) — the request body is empty. The returned claim set and
//! its OIDC scope gating mirror the REST handler exactly.

use axiam_auth::token::ValidatedClaims;
use axiam_core::error::AxiamError;
use axiam_core::repository::UserRepository;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::user_info_service_server::UserInfoService;
use crate::proto::{GetUserInfoRequest, GetUserInfoResponse};

pub struct UserInfoServiceImpl<U: UserRepository> {
    user_repo: U,
}

impl<U: UserRepository> UserInfoServiceImpl<U> {
    pub fn new(user_repo: U) -> Self {
        Self { user_repo }
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    value
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}

#[tonic::async_trait]
impl<U: UserRepository + 'static> UserInfoService for UserInfoServiceImpl<U> {
    async fn get_user_info(
        &self,
        request: Request<GetUserInfoRequest>,
    ) -> Result<Response<GetUserInfoResponse>, Status> {
        // Identity is authoritative from the interceptor-verified JWT claims;
        // the request body carries nothing (mirrors GetMyUser / REST userinfo).
        let claims = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .0
            .clone();

        let tenant_id = parse_uuid(&claims.tenant_id, "claims.tenant_id")?;
        let user_id = parse_uuid(&claims.sub, "claims.sub")?;

        // Parse space-delimited scopes exactly like the REST handler.
        let scopes: Vec<&str> = claims
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        let has_scope = |s: &str| scopes.contains(&s);

        // Fetch user details only when email/profile scope requires them.
        let (email, preferred_username) = if has_scope("email") || has_scope("profile") {
            match self.user_repo.get_by_id(tenant_id, user_id).await {
                Ok(u) => (
                    has_scope("email").then_some(u.email),
                    has_scope("profile").then_some(u.username),
                ),
                // Subject not found (never provisioned, or hard-removed): the
                // token no longer maps to a live user, so report UNAUTHENTICATED.
                // Any other repo error is INTERNAL, without leaking backend
                // detail (mirrors the REST handler's fail-closed posture,
                // adapted to gRPC status codes). Note: the standard `delete` is a
                // soft-delete (status→Inactive, row retained), so a soft-deleted
                // user still resolves here — matching REST userinfo, which also
                // does not status-gate.
                Err(AxiamError::NotFound { .. }) => {
                    return Err(Status::unauthenticated("subject not found"));
                }
                Err(_) => {
                    return Err(Status::internal("failed to retrieve user claims"));
                }
            }
        } else {
            (None, None)
        };

        Ok(Response::new(GetUserInfoResponse {
            sub: claims.sub,
            tenant_id: claims.tenant_id,
            org_id: claims.org_id,
            email,
            preferred_username,
        }))
    }
}
