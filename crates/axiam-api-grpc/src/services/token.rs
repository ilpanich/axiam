//! TokenService gRPC implementation.

use axiam_auth::config::AuthConfig;
use axiam_auth::error::AuthError;
use axiam_auth::token::validate_access_token;
use tonic::{Request, Response, Status};

use axiam_auth::token::ValidatedClaims;

use crate::proto::token_service_server::TokenService;
use crate::proto::{
    IntrospectTokenRequest, IntrospectTokenResponse, ValidateTokenRequest, ValidateTokenResponse,
};

pub struct TokenServiceImpl {
    config: AuthConfig,
}

impl TokenServiceImpl {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }
}

#[tonic::async_trait]
impl TokenService for TokenServiceImpl {
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        // SEC-068: the caller's tenant comes from the interceptor-verified JWT.
        let caller_tenant = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .0
            .tenant_id
            .clone();
        let req = request.into_inner();

        match validate_access_token(&req.access_token, &self.config) {
            // SEC-068: refuse to introspect a token belonging to a different
            // tenant — report it as invalid (not merely denied) so a mesh peer
            // in tenant A cannot read a tenant-B token's claims by observing the
            // difference between "denied" and "invalid".
            Ok(validated) if validated.0.tenant_id == caller_tenant => {
                let claims = validated.0;
                Ok(Response::new(ValidateTokenResponse {
                    valid: true,
                    subject_id: claims.sub,
                    tenant_id: claims.tenant_id,
                    org_id: claims.org_id,
                    exp: claims.exp,
                }))
            }
            Err(AuthError::Crypto(msg)) => {
                Err(Status::internal(format!("token validation error: {msg}")))
            }
            // Invalid token OR a cross-tenant token (guard above failed) — both
            // report inactive so the two are indistinguishable to the caller.
            _ => Ok(Response::new(ValidateTokenResponse {
                valid: false,
                subject_id: String::new(),
                tenant_id: String::new(),
                org_id: String::new(),
                exp: 0,
            })),
        }
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        // SEC-068: the caller's tenant comes from the interceptor-verified JWT.
        let caller_tenant = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .0
            .tenant_id
            .clone();
        let req = request.into_inner();

        match validate_access_token(&req.access_token, &self.config) {
            // SEC-068: only introspect a token from the caller's own tenant; a
            // cross-tenant token reports inactive (indistinguishable from an
            // invalid one) so its sub/org/jti claims are not disclosed.
            Ok(validated) if validated.0.tenant_id == caller_tenant => {
                let claims = validated.0;
                Ok(Response::new(IntrospectTokenResponse {
                    active: true,
                    sub: claims.sub,
                    tenant_id: claims.tenant_id,
                    org_id: claims.org_id,
                    iss: claims.iss,
                    iat: claims.iat,
                    exp: claims.exp,
                    jti: claims.jti,
                }))
            }
            Err(AuthError::Crypto(msg)) => {
                Err(Status::internal(format!("token validation error: {msg}")))
            }
            _ => Ok(Response::new(IntrospectTokenResponse {
                active: false,
                sub: String::new(),
                tenant_id: String::new(),
                org_id: String::new(),
                iss: String::new(),
                iat: 0,
                exp: 0,
                jti: String::new(),
            })),
        }
    }
}
