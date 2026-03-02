//! TokenService gRPC implementation.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::validate_access_token;
use tonic::{Request, Response, Status};

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
        let req = request.into_inner();

        match validate_access_token(&req.access_token, &self.config) {
            Ok(validated) => {
                let claims = validated.0;
                Ok(Response::new(ValidateTokenResponse {
                    valid: true,
                    subject_id: claims.sub,
                    tenant_id: claims.tenant_id,
                    org_id: claims.org_id,
                    exp: claims.exp,
                }))
            }
            Err(_) => Ok(Response::new(ValidateTokenResponse {
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
        let req = request.into_inner();

        match validate_access_token(&req.access_token, &self.config) {
            Ok(validated) => {
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
            Err(_) => Ok(Response::new(IntrospectTokenResponse {
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
