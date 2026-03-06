//! AXIAM Database — SurrealDB connection management and repository
//! implementations.
//!
//! This crate provides:
//! - Connection management ([`DbManager`], [`DbConfig`])
//! - Schema initialization and migrations ([`run_migrations`])
//! - Repository implementations for `axiam-core` traits
//! - Error types ([`DbError`])

mod connection;
mod error;
pub mod repository;
mod schema;

pub use connection::{DbConfig, DbManager};
pub use error::DbError;
pub use repository::{
    SurrealAuditLogRepository, SurrealCaCertificateRepository, SurrealCertificateRepository,
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealServiceAccountRepository, SurrealSessionRepository, SurrealTenantRepository,
    SurrealUserRepository, hash_client_secret, verify_password,
};
pub use schema::{run_migrations, schema_v1};
/// Re-export SurrealDB connection types for use in repository type aliases.
pub use surrealdb::Connection;
pub use surrealdb::engine::remote::ws::Client as WsClient;
