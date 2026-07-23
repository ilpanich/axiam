//! Tonic gRPC server setup.
//!
//! CQ-B20: Server builder sets message-size limits, per-connection timeout,
//! and concurrency limit to prevent resource exhaustion.
//! TLS (REQ-15 AC-1): When `AXIAM__GRPC_TLS_CERT_PATH` and
//! `AXIAM__GRPC_TLS_KEY_PATH` env vars are set, the server is configured with
//! `ServerTlsConfig`; otherwise plaintext mode is used (suitable for in-mesh
//! mutual-TLS handled at the sidecar/service-mesh layer).
//!
//! D2 (benchmark plan — native gRPC TLS termination): this is the same
//! mechanism the p2-tls13 native-TLS bench overlay
//! (`benchmarks/targets/axiam/docker-compose.native-tls.yml`) turns on,
//! pointed at the SAME server cert/key files the REST listener uses
//! (`crates/axiam-server/src/tls.rs` / `AXIAM__SERVER__TLS__CERT_PATH`+
//! `KEY_PATH`) so the two protocols present identical PKI material. No new
//! `TlsConfig`-style struct was introduced here — the existing flat
//! `AXIAM__GRPC_TLS_CERT_PATH`/`KEY_PATH` env-var pair (already shipped in
//! phase 11) is reused as-is per D2's "least invasive" guidance, rather than
//! adding a parallel `AXIAM__GRPC__TLS__*` nested config surface.
//!
//! Caveat vs. the REST listener: `crates/axiam-server/src/tls.rs` builds a
//! custom rustls `ServerConfig` restricted to TLS 1.3 only
//! (`with_protocol_versions(&[&rustls::version::TLS13])`). Tonic 0.14's
//! `ServerTlsConfig` (see `tonic::transport::server::tls`) does not expose a
//! protocol-version knob — it always builds `rustls::ServerConfig::builder()`
//! with the crate's default versions (TLS 1.2 negotiable in addition to 1.3).
//! There is no way to force TLS-1.3-only through tonic's public API without
//! hand-rolling the accept loop, which is out of scope here; the gRPC
//! listener is TLS 1.3-*capable* (matching REST posture) but not TLS
//! 1.3-*exclusive*.

use std::net::SocketAddr;
use std::time::Duration;

use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
    UserRepository,
};
use surrealdb::{Connection, Surreal};
use tonic::transport::{Identity, Server, ServerTlsConfig};

use crate::config::GrpcConfig;
use crate::middleware::auth::AuthInterceptor;
use crate::middleware::rate_limit::{
    GrpcSharedRateLimitLayer, build_grpc_governor_layer, trusted_hops_from_env,
};
use crate::proto::authorization_service_server::AuthorizationServiceServer;
use crate::proto::token_service_server::TokenServiceServer;
use crate::proto::user_info_service_server::UserInfoServiceServer;
use crate::proto::user_service_server::UserServiceServer;
use crate::services::{
    AuthorizationServiceImpl, TokenServiceImpl, UserInfoServiceImpl, UserServiceImpl,
};

/// Start the gRPC server with all registered services.
///
/// Applies two cooperating rate-limit layers (SECHRD-03, D-01a/b/c — gap
/// closure for 24-07): the SurrealDB-backed [`GrpcSharedRateLimitLayer`]
/// shared-store pre-check runs FIRST (outermost), failing OPEN on any DB
/// error to the per-replica in-memory `GovernorLayer` (per D-10) built via
/// `grpc_authz_per_sec` from `GrpcConfig`. Both layers derive their client-IP
/// key from the SAME `trusted_hops` value so gRPC keying stays in lockstep
/// across the shared store and the in-memory fallback.
///
/// Transport limits (CQ-B20):
/// - Max message size: 4 MiB decode / 4 MiB encode
/// - Per-connection timeout: 30 s
/// - Concurrency limit: 256 streams per connection
///
/// TLS (REQ-15 AC-1): env-gated via `AXIAM__GRPC_TLS_CERT_PATH` /
/// `AXIAM__GRPC_TLS_KEY_PATH`. When absent, TLS is disabled and a warning
/// is logged (acceptable for in-mesh/loopback deployments).
pub async fn start_grpc_server<R, P, Res, S, G, U, C>(
    addr: SocketAddr,
    engine: AuthorizationEngine<R, P, Res, S, G>,
    user_repo: U,
    auth_config: AuthConfig,
    grpc_config: &GrpcConfig,
    db: Surreal<C>,
    batch_max_concurrency: usize,
) -> Result<(), tonic::transport::Error>
where
    R: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
    U: UserRepository + Clone + 'static,
    C: Connection + 'static,
{
    tracing::info!(
        bind = %addr,
        grpc_authz_per_sec = grpc_config.grpc_authz_per_sec,
        "Starting gRPC server",
    );

    // SECHRD-03 gap closure (24-07 follow-up): the shared-store pre-check
    // MUST use the same trusted_hops value as the in-memory governor's key
    // extractor (both ultimately key off GrpcTrustedHopsKeyExtractor logic)
    // so a rotating XFF cannot mint a fresh bucket in one layer while being
    // correctly collapsed in the other.
    let trusted_hops = trusted_hops_from_env();
    let shared_rate_limit_layer = GrpcSharedRateLimitLayer::new(
        db,
        "grpc_authz",
        grpc_config.grpc_authz_per_sec,
        trusted_hops,
    );
    let governor_layer = build_grpc_governor_layer(grpc_config.grpc_authz_per_sec);

    let authz_svc = AuthorizationServiceServer::with_interceptor(
        AuthorizationServiceImpl::new(engine, batch_max_concurrency),
        AuthInterceptor::new(auth_config.clone()),
    );
    // SECFIX-01: UserService and TokenService previously had zero auth —
    // any unauthenticated mesh peer could call GetUser/ValidateCredentials/
    // IntrospectToken. Wrap them with the same AuthInterceptor chokepoint
    // as AuthorizationService so every gRPC call requires a verified bearer JWT.
    let user_svc = UserServiceServer::with_interceptor(
        UserServiceImpl::new(user_repo.clone(), auth_config.clone()),
        AuthInterceptor::new(auth_config.clone()),
    );
    // UserInfoService: OIDC-style self lookup — identity derived entirely from
    // the interceptor-verified bearer token (no request body), mirroring the
    // REST `/oauth2/userinfo` endpoint. Guarded by the same AuthInterceptor.
    let user_info_svc = UserInfoServiceServer::with_interceptor(
        UserInfoServiceImpl::new(user_repo),
        AuthInterceptor::new(auth_config.clone()),
    );
    let token_svc = TokenServiceServer::with_interceptor(
        TokenServiceImpl::new(auth_config.clone()),
        AuthInterceptor::new(auth_config),
    );

    // CQ-B20: Apply transport limits to the gRPC server builder.
    // Note: tonic 0.14 does not expose max_decoding_message_size / max_encoding_message_size
    // at the Server level (added in tonic 0.12+ via the Router API). The HTTP/2 frame-size
    // limit (max_frame_size) is the closest available per-connection cap in 0.14. Upgrade
    // to tonic ≥0.12 to use per-service max_decoding_message_size / max_encoding_message_size.
    // Tracked: max_decoding_message_size (CQ-B20, pending tonic upgrade in Phase 19).
    // SECHRD-03 (D-01a/b/c): the shared-store pre-check is `.layer()`'d
    // FIRST so it is OUTERMOST (tower's ServiceBuilder/Server::builder()
    // convention — first `.layer()` call = outermost = runs first, the
    // opposite of actix's last-`.wrap()`-is-outermost rule). It fails OPEN
    // to `governor_layer` on any SurrealDB error or missing key, so a DB
    // blip degrades to the in-memory limiter rather than hard-blocking.
    let mut builder = Server::builder()
        .max_frame_size(4 * 1024 * 1024) // CQ-B20: 4 MiB frame cap (tonic-0.14 equivalent of max_decoding_message_size)
        .timeout(Duration::from_secs(30))
        .concurrency_limit_per_connection(256)
        .layer(shared_rate_limit_layer)
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
                .add_service(user_info_svc)
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
                .add_service(user_info_svc)
                .add_service(token_svc)
                .serve(addr)
                .await
        }
    }
}
