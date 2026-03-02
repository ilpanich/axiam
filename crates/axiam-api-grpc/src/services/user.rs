//! UserService gRPC implementation.

use tonic::{Request, Response, Status};

use crate::proto::user_service_server::UserService;
use crate::proto::{
    GetUserRequest, UserResponse, ValidateCredentialsRequest, ValidateCredentialsResponse,
};

pub struct UserServiceImpl;

#[tonic::async_trait]
impl UserService for UserServiceImpl {
    async fn get_user(
        &self,
        _request: Request<GetUserRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn validate_credentials(
        &self,
        _request: Request<ValidateCredentialsRequest>,
    ) -> Result<Response<ValidateCredentialsResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }
}
