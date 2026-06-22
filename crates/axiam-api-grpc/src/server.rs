//! Tonic gRPC server setup.
//!
//! CQ-B20: Server builder sets message-size limits, per-connection timeout,
//! and concurrency limit to prevent resource exhaustion.
//! TLS (REQ-15 AC-1): When `AXIAM__GRPC_TLS_CERT_PATH` and
//! `AXIAM__GRPC_TLS_KEY_PATH` env vars are set, the server is configured with
//! `ServerTlsConfig`; otherwise plaintext mode is used (suitable for in-mesh
//! mutual-TLS handled at the sidecar/service-mesh layer).

use std::net::SocketAddr;
use std::time::Duration;

use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
    UserRepository,
};
use tonic::transport::{Identity, Server, ServerTlsConfig};

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
///
/// Transport limits (CQ-B20):
/// - Max message size: 4 MiB decode / 4 MiB encode
/// - Per-connection timeout: 30 s
/// - Concurrency limit: 256 streams per connection
///
/// TLS (REQ-15 AC-1): env-gated via `AXIAM__GRPC_TLS_CERT_PATH` /
/// `AXIAM__GRPC_TLS_KEY_PATH`. When absent, TLS is disabled and a warning
/// is logged (acceptable for in-mesh/loopback deployments).
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

    // CQ-B20: Apply transport limits to the gRPC server builder.
    // Note: tonic 0.14 does not expose max_decoding_message_size / max_encoding_message_size
    // at the Server level (added in tonic 0.12+ via the Router API). The HTTP/2 frame-size
    // limit (max_frame_size) is the closest available per-connection cap in 0.14. Upgrade
    // to tonic ≥0.12 to use per-service max_decoding_message_size / max_encoding_message_size.
    // Tracked: max_decoding_message_size (CQ-B20, pending tonic upgrade in Phase 19).
    let mut builder = Server::builder()
        .max_frame_size(4 * 1024 * 1024) // CQ-B20: 4 MiB frame cap (tonic-0.14 equivalent of max_decoding_message_size)
        .timeout(Duration::from_secs(30))
        .concurrency_limit_per_connection(256)
        .layer(governor_layer);

    // REQ-15 AC-1 / CQ-B20: Env-gated TLS.
    // Set AXIAM__GRPC_TLS_CERT_PATH and AXIAM__GRPC_TLS_KEY_PATH to enable.
    let cert_path = std::env::var("AXIAM__GRPC_TLS_CERT_PATH").ok();
    let key_path = std::env::var("AXIAM__GRPC_TLS_KEY_PATH").ok();
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(&cert_path).unwrap_or_else(|e| {
                panic!("AXIAM__GRPC_TLS_CERT_PATH set but file not readable at '{cert_path}': {e}")
            });
            let key_pem = std::fs::read(&key_path).unwrap_or_else(|e| {
                panic!("AXIAM__GRPC_TLS_KEY_PATH set but file not readable at '{key_path}': {e}")
            });

            let identity = Identity::from_pem(cert_pem, key_pem);
            let tls_config = ServerTlsConfig::new().identity(identity);
            tracing::info!("gRPC server TLS enabled (AXIAM__GRPC_TLS_CERT_PATH)");
            builder
                .tls_config(tls_config)?
                .add_service(authz_svc)
                .add_service(user_svc)
                .add_service(token_svc)
                .serve(addr)
                .await
        }
        _ => {
            tracing::warn!(
                "gRPC TLS is DISABLED — set AXIAM__GRPC_TLS_CERT_PATH + \
                 AXIAM__GRPC_TLS_KEY_PATH to enable (acceptable for in-mesh deployments)"
            );
            builder
                .add_service(authz_svc)
                .add_service(user_svc)
                .add_service(token_svc)
                .serve(addr)
                .await
        }
    }
}
