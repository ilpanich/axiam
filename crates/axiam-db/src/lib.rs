//! AXIAM Database — SurrealDB connection management and repository
//! implementations.
//!
//! This crate provides:
//! - Connection management ([`DbManager`], [`DbConfig`], [`DbPool`])
//! - [`DbHandle`] — the LIVE pooled-connection reference repositories bind to,
//!   so a reconnect-loop handle swap is observed on the next query rather than
//!   leaving them pinned to an evicted connection
//! - Schema initialization and migrations ([`run_migrations`])
//! - Repository implementations for `axiam-core` traits
//! - Error types ([`DbError`])
//! - The process-wide write-behind shared rate-limit counter
//!   ([`SharedRateLimitCounter`]), used by BOTH the REST and gRPC
//!   shared-store rate-limit layers

mod connection;
mod error;
mod handle;
pub mod helpers;
pub mod metrics;
mod pool;
pub mod rate_limit_counter;
pub mod repository;
mod schema;
pub mod seeder;
pub mod session_validation_cache;

pub use connection::{DbConfig, DbManager};
pub use error::DbError;
pub use handle::DbHandle;
pub use helpers::{CountRow, parse_uuid, take_first_or_not_found};
pub use pool::{DbCheckout, DbPool};
pub use rate_limit_counter::{
    SharedRateLimitConfig, SharedRateLimitCounter, SharedRateLimitStore, StoreIncrementFuture,
};
pub use repository::{
    SurrealAccountDeletionRepository, SurrealAmqpNonceRepository, SurrealAssertionReplayRepository,
    SurrealAuditLogRepository, SurrealAuthorizationCodeRepository, SurrealCaCertificateRepository,
    SurrealCertificateRepository, SurrealConsentRepository, SurrealEmailConfigRepository,
    SurrealEmailTemplateRepository, SurrealEmailVerificationTokenRepository,
    SurrealErasureProofRepository, SurrealExportJobRepository, SurrealFederationConfigRepository,
    SurrealFederationLinkRepository, SurrealFederationLoginStateRepository, SurrealGroupRepository,
    SurrealNotificationRuleRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository,
    SurrealPasswordResetTokenRepository, SurrealPermissionRepository, SurrealPgpKeyRepository,
    SurrealRateLimitBucketRepository, SurrealRefreshTokenRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealServiceAccountRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebauthnCredentialRepository, SurrealWebhookRepository,
};

/// Client-secret hashing (OBS-1). Re-exported at the `axiam_db` root because
/// every stored `client_secret_hash` in this crate is produced by it, and
/// because it replaces the former `axiam_db::hash_client_secret` free
/// function — which could hash without a key and is therefore gone.
pub use axiam_auth::client_secret::{self, ClientSecretHasher, ClientSecretVerdict};
pub use schema::{run_migrations, schema_v1};
pub use seeder::{
    SeedRolesResult, SeederStateRow, mint_bootstrap_setup_token_if_needed,
    reconcile_default_role_grants, seed_default_roles, seed_permissions,
};
pub use session_validation_cache::SessionValidationCache;
/// Re-export SurrealDB connection types for use in repository type aliases.
pub use surrealdb::Connection;
/// Production SurrealDB client type — the stateless HTTP engine (see `connection.rs`
/// for why HTTP over WebSocket). Named `DbClient` (engine-neutral) since it is no
/// longer the WebSocket client.
pub use surrealdb::engine::remote::http::Client as DbClient;
