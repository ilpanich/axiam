//! AXIAM Database — SurrealDB connection management and repository
//! implementations.
//!
//! This crate provides:
//! - Connection management ([`DbManager`], [`DbConfig`])
//! - Schema initialization and migrations ([`run_migrations`])
//! - Error types ([`DbError`])
//!
//! Repository trait implementations (for `axiam-core` traits) will be
//! added in subsequent tasks.

mod connection;
mod error;
mod schema;

pub use connection::{DbConfig, DbManager};
pub use error::DbError;
pub use schema::{run_migrations, schema_v1};
