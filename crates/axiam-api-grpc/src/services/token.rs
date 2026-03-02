//! TokenService gRPC implementation.

use tonic::{Request, Response, Status};

use crate::proto::token_service_server::TokenService;
use crate::proto::{
    IntrospectTokenRequest, IntrospectTokenResponse, ValidateTokenRequest, ValidateTokenResponse,
};

pub struct TokenServiceImpl;

#[tonic::async_trait]
impl TokenService for TokenServiceImpl {
    async fn validate_token(
        &self,
        _request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn introspect_token(
        &self,
        _request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }
}
