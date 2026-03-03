//! AXIAM Server — Application entry point.

use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use axiam_api_grpc::{GrpcConfig, start_grpc_server};
use axiam_api_rest::{
    HealthChecker, ServerConfig, api_v1_routes, build_cors, health_routes, openapi_routes,
};
use axiam_auth::AuthService;
use axiam_auth::config::AuthConfig;
use axiam_db::{
    DbConfig, DbManager, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealServiceAccountRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use serde::Deserialize;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

/// Top-level configuration aggregating all sub-configs.
#[derive(Debug, Deserialize)]
struct AppConfig {
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    db: DbConfig,
    #[serde(default)]
    auth: AuthConfig,
    #[serde(default)]
    grpc: GrpcConfig,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("axiam=info".parse().unwrap()))
        .json()
        .init();

    tracing::info!("Starting AXIAM server...");

    let mut config = load_config();

    // Load MFA encryption key from env (skipped by serde on AuthConfig).
    if let Ok(hex) = std::env::var("AXIAM__AUTH__MFA_ENCRYPTION_KEY") {
        let bytes = hex::decode(&hex).expect(
            "AXIAM__AUTH__MFA_ENCRYPTION_KEY must be a 64-char hex string (32 bytes / 256 bits)",
        );
        let key: [u8; 32] = bytes
            .try_into()
            .expect("AXIAM__AUTH__MFA_ENCRYPTION_KEY must be exactly 32 bytes (256 bits)");
        config.auth.mfa_encryption_key = Some(key);
        tracing::info!("MFA encryption key loaded");
    } else {
        tracing::warn!(
            "AXIAM__AUTH__MFA_ENCRYPTION_KEY not set — MFA enrollment will be unavailable"
        );
    }

    // Connect to SurrealDB
    let db = DbManager::connect(&config.db)
        .await
        .expect("Failed to connect to SurrealDB");

    // Run schema migrations
    axiam_db::run_migrations(db.client())
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database connected and migrations applied");

    let org_repo = SurrealOrganizationRepository::new(db.client().clone());
    let tenant_repo = SurrealTenantRepository::new(db.client().clone());
    let user_repo = SurrealUserRepository::new(db.client().clone());
    let group_repo = SurrealGroupRepository::new(db.client().clone());
    let role_repo = SurrealRoleRepository::new(db.client().clone());
    let permission_repo = SurrealPermissionRepository::new(db.client().clone());
    let resource_repo = SurrealResourceRepository::new(db.client().clone());
    let scope_repo = SurrealScopeRepository::new(db.client().clone());
    let service_account_repo = SurrealServiceAccountRepository::new(db.client().clone());
    let session_repo = SurrealSessionRepository::new(db.client().clone());
    let auth_service = AuthService::new(user_repo.clone(), session_repo, config.auth.clone());

    let bind_addr = config.server.bind_address();
    let server_config = config.server.clone();
    let auth_config = config.auth.clone();
    let health_checker: Arc<dyn HealthChecker> = Arc::new(db);

    tracing::info!(bind = %bind_addr, "Starting REST API server");

    // Build gRPC services and spawn server on a background task.
    let grpc_addr = config.grpc.bind_address();
    let grpc_engine = axiam_authz::AuthorizationEngine::new(
        role_repo.clone(),
        permission_repo.clone(),
        resource_repo.clone(),
        scope_repo.clone(),
        group_repo.clone(),
    );
    let grpc_user_repo = user_repo.clone();
    let grpc_auth_config = config.auth.clone();
    tokio::spawn(async move {
        if let Err(e) =
            start_grpc_server(grpc_addr, grpc_engine, grpc_user_repo, grpc_auth_config).await
        {
            tracing::error!(error = %e, "gRPC server failed — shutting down process");
            std::process::exit(1);
        }
    });

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .wrap(build_cors(&server_config.cors_allowed_origins))
            .app_data(web::Data::new(auth_config.clone()))
            .app_data(web::Data::new(health_checker.clone()))
            .app_data(web::Data::new(org_repo.clone()))
            .app_data(web::Data::new(tenant_repo.clone()))
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(group_repo.clone()))
            .app_data(web::Data::new(role_repo.clone()))
            .app_data(web::Data::new(permission_repo.clone()))
            .app_data(web::Data::new(resource_repo.clone()))
            .app_data(web::Data::new(scope_repo.clone()))
            .app_data(web::Data::new(service_account_repo.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .configure(health_routes)
            .configure(api_v1_routes)
            .configure(openapi_routes)
    })
    .bind(&bind_addr)?
    .run()
    .await
}

fn load_config() -> AppConfig {
    let builder = config::Config::builder()
        .add_source(config::File::with_name("config/default").required(false))
        .add_source(config::Environment::with_prefix("AXIAM").separator("__"));

    let config: AppConfig = builder
        .build()
        .and_then(|c| c.try_deserialize())
        .expect("Failed to load configuration — check config/default.toml or AXIAM__* env vars");

    // Validate critical fields to fail fast instead of booting an insecure/broken server.
    assert!(
        !config.auth.jwt_private_key_pem.is_empty(),
        "AXIAM__AUTH__JWT_PRIVATE_KEY_PEM must be set (Ed25519 PEM)"
    );
    assert!(
        !config.auth.jwt_public_key_pem.is_empty(),
        "AXIAM__AUTH__JWT_PUBLIC_KEY_PEM must be set (Ed25519 PEM)"
    );

    config
}
