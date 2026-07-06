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
pub mod helpers;
pub mod repository;
mod schema;
pub mod seeder;

pub use connection::{DbConfig, DbManager};
pub use error::DbError;
pub use helpers::{CountRow, parse_uuid, take_first_or_not_found};
pub use repository::{
    SurrealAccountDeletionRepository, SurrealAssertionReplayRepository, SurrealAuditLogRepository,
    SurrealAuthorizationCodeRepository, SurrealCaCertificateRepository,
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
    hash_client_secret,
};
pub use schema::{run_migrations, schema_v1};
pub use seeder::{
    SeedRolesResult, SeederStateRow, mint_bootstrap_setup_token_if_needed,
    reconcile_default_role_grants, seed_default_roles, seed_permissions,
};
/// Re-export SurrealDB connection types for use in repository type aliases.
pub use surrealdb::Connection;
/// Production SurrealDB client type — the stateless HTTP engine (see `connection.rs`
/// for why HTTP over WebSocket). Named `DbClient` (engine-neutral) since it is no
/// longer the WebSocket client.
pub use surrealdb::engine::remote::http::Client as DbClient;
