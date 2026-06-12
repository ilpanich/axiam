//! Tonic gRPC server setup.

use std::net::SocketAddr;

use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
    UserRepository,
};
use tonic::transport::Server;

use crate::config::GrpcConfig;
use crate::middleware::auth::AuthInterceptor;
use crate::middleware::rate_limit::build_grpc_governor_layer;
use crate::proto::authorization_service_server::AuthorizationServiceServer;
use crate::proto::token_service_server::TokenServiceServer;
use crate::proto::user_service_server::UserServiceServer;
use crate::services::{AuthorizationServiceImpl, TokenServiceImpl, UserServiceImpl};

/// Start the gRPC server with all registered services.
///
/// Applies a tower-governor rate limiting layer (per D-10) using the
/// `grpc_authz_per_sec` setting from `GrpcConfig`.
pub async fn start_grpc_server<R, P, Res, S, G, U>(
    addr: SocketAddr,
    engine: AuthorizationEngine<R, P, Res, S, G>,
    user_repo: U,
    auth_config: AuthConfig,
    grpc_config: &GrpcConfig,
) -> Result<(), tonic::transport::Error>
where
    R: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
    U: UserRepository + 'static,
{
    tracing::info!(
        bind = %addr,
        grpc_authz_per_sec = grpc_config.grpc_authz_per_sec,
        "Starting gRPC server",
    );

    let governor_layer = build_grpc_governor_layer(grpc_config.grpc_authz_per_sec);

    let authz_svc = AuthorizationServiceServer::with_interceptor(
        AuthorizationServiceImpl::new(engine),
        AuthInterceptor::new(auth_config.clone()),
    );
    let user_svc = UserServiceServer::new(UserServiceImpl::new(user_repo, auth_config.clone()));
    let token_svc = TokenServiceServer::new(TokenServiceImpl::new(auth_config));

    Server::builder()
        .layer(governor_layer)
        .add_service(authz_svc)
        .add_service(user_svc)
        .add_service(token_svc)
        .serve(addr)
        .await
}
