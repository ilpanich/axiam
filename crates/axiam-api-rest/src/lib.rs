//! AXIAM REST API — HTTP extractors, authorization guards, server bootstrap,
//! and error handling.

pub mod authz;
pub mod config;
pub mod error;
pub mod extractors;
pub mod handlers;
pub mod health;
pub mod openapi;
pub mod server;

pub use authz::{AuthzChecker, AuthzData, RequirePermission};
pub use config::ServerConfig;
pub use error::AxiamApiError;
pub use extractors::auth::AuthenticatedUser;
pub use extractors::tenant::TenantContext;
pub use health::HealthChecker;
pub use openapi::ApiDoc;
pub use server::{
    api_v1_routes, build_cors, health_routes, openapi_routes, register_api_v1_routes,
};
