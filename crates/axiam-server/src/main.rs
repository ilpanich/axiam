//! AXIAM Server — Application entry point.

use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use axiam_api_rest::{HealthChecker, ServerConfig, api_v1_routes, build_cors, health_routes};
use axiam_auth::AuthService;
use axiam_auth::config::AuthConfig;
use axiam_db::{
    DbConfig, DbManager, SurrealOrganizationRepository, SurrealSessionRepository,
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
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("axiam=info".parse().unwrap()))
        .json()
        .init();

    tracing::info!("Starting AXIAM server...");

    let config = load_config();

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
    let session_repo = SurrealSessionRepository::new(db.client().clone());
    let auth_service = AuthService::new(user_repo.clone(), session_repo, config.auth.clone());

    let bind_addr = config.server.bind_address();
    let server_config = config.server.clone();
    let auth_config = config.auth.clone();
    let health_checker: Arc<dyn HealthChecker> = Arc::new(db);

    tracing::info!(bind = %bind_addr, "Starting REST API server");

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .wrap(build_cors(&server_config.cors_allowed_origins))
            .app_data(web::Data::new(auth_config.clone()))
            .app_data(web::Data::new(health_checker.clone()))
            .app_data(web::Data::new(org_repo.clone()))
            .app_data(web::Data::new(tenant_repo.clone()))
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .configure(health_routes)
            .configure(api_v1_routes)
    })
    .bind(&bind_addr)?
    .run()
    .await
}

fn load_config() -> AppConfig {
    let builder = config::Config::builder()
        .add_source(config::File::with_name("config/default").required(false))
        .add_source(config::Environment::with_prefix("AXIAM").separator("__"));

    match builder.build().and_then(|c| c.try_deserialize()) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!(error = %e, "Config load failed, using defaults");
            AppConfig {
                server: ServerConfig::default(),
                db: DbConfig::default(),
                auth: AuthConfig::default(),
            }
        }
    }
}
