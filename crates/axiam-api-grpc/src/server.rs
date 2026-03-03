//! Tonic gRPC server setup.

use std::net::SocketAddr;

use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
    UserRepository,
};
use tonic::transport::Server;

use crate::proto::authorization_service_server::AuthorizationServiceServer;
use crate::proto::token_service_server::TokenServiceServer;
use crate::proto::user_service_server::UserServiceServer;
use crate::services::{AuthorizationServiceImpl, TokenServiceImpl, UserServiceImpl};

/// Start the gRPC server with all registered services.
pub async fn start_grpc_server<R, P, Res, S, G, U>(
    addr: SocketAddr,
    engine: AuthorizationEngine<R, P, Res, S, G>,
    user_repo: U,
    auth_config: AuthConfig,
) -> Result<(), tonic::transport::Error>
where
    R: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
    U: UserRepository + 'static,
{
    tracing::info!(bind = %addr, "Starting gRPC server");

    let authz_svc = AuthorizationServiceServer::new(AuthorizationServiceImpl::new(engine));
    let user_svc = UserServiceServer::new(UserServiceImpl::new(user_repo, auth_config.clone()));
    let token_svc = TokenServiceServer::new(TokenServiceImpl::new(auth_config));

    Server::builder()
        .add_service(authz_svc)
        .add_service(user_svc)
        .add_service(token_svc)
        .serve(addr)
        .await
}
