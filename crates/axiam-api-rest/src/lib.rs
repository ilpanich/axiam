//! AXIAM REST API — HTTP extractors, authorization guards, server bootstrap,
//! and error handling.

pub mod authz;
pub mod config;
pub mod error;
pub mod extractors;
pub mod handlers;
pub mod health;
pub mod middleware;
pub mod openapi;
pub mod permissions;
pub mod server;
pub mod webhook;
pub mod webhook_consumer;

pub use authz::{AuthzChecker, AuthzData, RequirePermission};
pub use config::{RateLimitConfig, ServerConfig};
pub use error::AxiamApiError;
pub use extractors::auth::{AuthenticatedUser, SessionValidator};
pub use extractors::cert_auth::CertificateAuthenticated;
pub use extractors::tenant::TenantContext;
pub use health::HealthChecker;
pub use openapi::ApiDoc;
pub use server::{
    api_v1_routes, build_cors, health_routes, openapi_routes, register_api_v1_routes,
};

#[cfg(test)]
mod tests;
