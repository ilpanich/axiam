//! Tonic gRPC server setup.

use std::net::SocketAddr;

use tonic::transport::Server;

use crate::proto::authorization_service_server::AuthorizationServiceServer;
use crate::proto::token_service_server::TokenServiceServer;
use crate::proto::user_service_server::UserServiceServer;
use crate::services::{AuthorizationServiceImpl, TokenServiceImpl, UserServiceImpl};

/// Start the gRPC server with all registered services.
pub async fn start_grpc_server(addr: SocketAddr) -> Result<(), tonic::transport::Error> {
    tracing::info!(bind = %addr, "Starting gRPC server");

    Server::builder()
        .add_service(AuthorizationServiceServer::new(AuthorizationServiceImpl))
        .add_service(UserServiceServer::new(UserServiceImpl))
        .add_service(TokenServiceServer::new(TokenServiceImpl))
        .serve(addr)
        .await
}
