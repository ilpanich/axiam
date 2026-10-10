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

/// The one UNAUTHENTICATED message for a subject that may not act, whether it
/// was suspended or removed.
const ACCOUNT_MAY_NOT_ACT: &str = "the token's subject may no longer sign in";

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

        // The account is read on every call and must still be allowed to act
        // (#520, P23W1-12) — the rule REST UserInfo, every OAuth2 grant and
        // `/oauth2/authorize` apply (`axiam_auth::service::account_may_act`).
        // A locked, inactive, anonymized or deleted account, or a subject that
        // no longer exists, is UNAUTHENTICATED with one message, so the answer
        // does not say which. Any other repo error is INTERNAL, without
        // leaking backend detail. One indexed read per call: identity reads
        // are not the authorization hot path (`CheckAccess` is).
        let user = match self.user_repo.get_by_id(tenant_id, user_id).await {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => {
                return Err(Status::unauthenticated(ACCOUNT_MAY_NOT_ACT));
            }
            Err(_) => {
                return Err(Status::internal("failed to retrieve user claims"));
            }
        };
        if let Err(reason) = axiam_auth::service::account_may_act(&user) {
            tracing::info!(
                %tenant_id,
                %user_id,
                reason = %reason,
                "grpc userinfo: refusing a token whose account may no longer sign in"
            );
            return Err(Status::unauthenticated(ACCOUNT_MAY_NOT_ACT));
        }
        let email = has_scope("email").then_some(user.email);
        let preferred_username = has_scope("profile").then_some(user.username);

        Ok(Response::new(GetUserInfoResponse {
            sub: claims.sub,
            tenant_id: claims.tenant_id,
            org_id: claims.org_id,
            email,
            preferred_username,
        }))
    }
}
