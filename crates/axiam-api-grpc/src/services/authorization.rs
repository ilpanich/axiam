//! AuthorizationService gRPC implementation.

use tonic::{Request, Response, Status};

use crate::proto::authorization_service_server::AuthorizationService;
use crate::proto::{
    BatchCheckAccessRequest, BatchCheckAccessResponse, CheckAccessRequest, CheckAccessResponse,
};

pub struct AuthorizationServiceImpl;

#[tonic::async_trait]
impl AuthorizationService for AuthorizationServiceImpl {
    async fn check_access(
        &self,
        _request: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn batch_check_access(
        &self,
        _request: Request<BatchCheckAccessRequest>,
    ) -> Result<Response<BatchCheckAccessResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }
}
