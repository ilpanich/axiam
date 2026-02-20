//! Schema definitions and migration runner for SurrealDB.
//!
//! All table definitions use SCHEMAFULL mode for data integrity.
//! UUIDs are stored as strings. Enums are stored as strings with
//! ASSERT constraints for validation.

use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use tracing::info;

use crate::error::DbError;

// -----------------------------------------------------------------------
// Migration tracking
// -----------------------------------------------------------------------

const MIGRATION_TABLE_DDL: &str = "\
DEFINE TABLE IF NOT EXISTS _migration SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS version ON TABLE _migration TYPE int;
DEFINE FIELD IF NOT EXISTS name ON TABLE _migration TYPE string;
DEFINE FIELD IF NOT EXISTS applied_at ON TABLE _migration TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_migration_version ON TABLE _migration \
    COLUMNS version UNIQUE;
";

#[derive(Debug, SurrealValue)]
struct MigrationRecord {
    version: u32,
    #[allow(dead_code)]
    name: String,
}

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_schema",
    sql: SCHEMA_V1,
}];

// -----------------------------------------------------------------------
// Schema v1 — initial table definitions
// -----------------------------------------------------------------------

const SCHEMA_V1: &str = "\
-- =======================================================================
-- Organizations (global scope)
-- =======================================================================
DEFINE TABLE organization SCHEMAFULL;
DEFINE FIELD name ON TABLE organization TYPE string;
DEFINE FIELD slug ON TABLE organization TYPE string;
DEFINE FIELD metadata ON TABLE organization TYPE object FLEXIBLE \
    DEFAULT {};
DEFINE FIELD created_at ON TABLE organization TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE organization TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_organization_slug ON TABLE organization \
    COLUMNS slug UNIQUE;

-- =======================================================================
-- Tenants (global scope, scoped to organization)
-- =======================================================================
DEFINE TABLE tenant SCHEMAFULL;
DEFINE FIELD organization_id ON TABLE tenant TYPE string;
DEFINE FIELD name ON TABLE tenant TYPE string;
DEFINE FIELD slug ON TABLE tenant TYPE string;
DEFINE FIELD metadata ON TABLE tenant TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD created_at ON TABLE tenant TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE tenant TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_tenant_org_slug ON TABLE tenant \
    COLUMNS organization_id, slug UNIQUE;

-- =======================================================================
-- CA Certificates (organization scope)
-- =======================================================================
DEFINE TABLE ca_certificate SCHEMAFULL;
DEFINE FIELD organization_id ON TABLE ca_certificate TYPE string;
DEFINE FIELD subject ON TABLE ca_certificate TYPE string;
DEFINE FIELD public_cert_pem ON TABLE ca_certificate TYPE string;
DEFINE FIELD fingerprint ON TABLE ca_certificate TYPE string;
DEFINE FIELD key_algorithm ON TABLE ca_certificate TYPE string \
    ASSERT $value IN ['Rsa4096', 'Ed25519'];
DEFINE FIELD not_before ON TABLE ca_certificate TYPE datetime;
DEFINE FIELD not_after ON TABLE ca_certificate TYPE datetime;
DEFINE FIELD status ON TABLE ca_certificate TYPE string \
    ASSERT $value IN ['Active', 'Revoked', 'Expired'];
DEFINE FIELD encrypted_private_key ON TABLE ca_certificate \
    TYPE option<bytes>;
DEFINE FIELD created_at ON TABLE ca_certificate TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_ca_cert_org_fingerprint ON TABLE ca_certificate \
    COLUMNS organization_id, fingerprint UNIQUE;

-- =======================================================================
-- Users (tenant scope)
-- =======================================================================
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE user TYPE string;
DEFINE FIELD username ON TABLE user TYPE string;
DEFINE FIELD email ON TABLE user TYPE string;
DEFINE FIELD password_hash ON TABLE user TYPE string;
DEFINE FIELD status ON TABLE user TYPE string \
    ASSERT $value IN ['Active', 'Inactive', 'Locked', \
    'PendingVerification'];
DEFINE FIELD mfa_enabled ON TABLE user TYPE bool DEFAULT false;
DEFINE FIELD mfa_secret ON TABLE user TYPE option<string>;
DEFINE FIELD metadata ON TABLE user TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD created_at ON TABLE user TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE user TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_user_tenant_username ON TABLE user \
    COLUMNS tenant_id, username UNIQUE;
DEFINE INDEX idx_user_tenant_email ON TABLE user \
    COLUMNS tenant_id, email UNIQUE;

-- =======================================================================
-- Roles (tenant scope)
-- =======================================================================
DEFINE TABLE role SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE role TYPE string;
DEFINE FIELD name ON TABLE role TYPE string;
DEFINE FIELD description ON TABLE role TYPE string;
DEFINE FIELD is_global ON TABLE role TYPE bool DEFAULT false;
DEFINE FIELD created_at ON TABLE role TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE role TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_role_tenant_name ON TABLE role \
    COLUMNS tenant_id, name UNIQUE;

-- =======================================================================
-- Permissions (tenant scope)
-- =======================================================================
DEFINE TABLE permission SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE permission TYPE string;
DEFINE FIELD action ON TABLE permission TYPE string;
DEFINE FIELD description ON TABLE permission TYPE string;
DEFINE FIELD created_at ON TABLE permission TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE permission TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_permission_tenant_action ON TABLE permission \
    COLUMNS tenant_id, action UNIQUE;

-- =======================================================================
-- Resources (tenant scope, hierarchical)
-- =======================================================================
DEFINE TABLE resource SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE resource TYPE string;
DEFINE FIELD name ON TABLE resource TYPE string;
DEFINE FIELD resource_type ON TABLE resource TYPE string;
DEFINE FIELD parent_id ON TABLE resource TYPE option<string>;
DEFINE FIELD metadata ON TABLE resource TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD created_at ON TABLE resource TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE resource TYPE datetime \
    DEFAULT time::now();

-- =======================================================================
-- Scopes (tenant scope, per-resource)
-- =======================================================================
DEFINE TABLE scope SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE scope TYPE string;
DEFINE FIELD resource_id ON TABLE scope TYPE string;
DEFINE FIELD name ON TABLE scope TYPE string;
DEFINE FIELD description ON TABLE scope TYPE string;
DEFINE FIELD created_at ON TABLE scope TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE scope TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_scope_resource_name ON TABLE scope \
    COLUMNS tenant_id, resource_id, name UNIQUE;

-- =======================================================================
-- Service Accounts (tenant scope)
-- =======================================================================
DEFINE TABLE service_account SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE service_account TYPE string;
DEFINE FIELD name ON TABLE service_account TYPE string;
DEFINE FIELD client_id ON TABLE service_account TYPE string;
DEFINE FIELD client_secret_hash ON TABLE service_account TYPE string;
DEFINE FIELD status ON TABLE service_account TYPE string \
    ASSERT $value IN ['Active', 'Inactive', 'Locked', \
    'PendingVerification'];
DEFINE FIELD created_at ON TABLE service_account TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE service_account TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_sa_tenant_client_id ON TABLE service_account \
    COLUMNS tenant_id, client_id UNIQUE;

-- =======================================================================
-- Groups (tenant scope)
-- =======================================================================
DEFINE TABLE group SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE group TYPE string;
DEFINE FIELD name ON TABLE group TYPE string;
DEFINE FIELD description ON TABLE group TYPE string;
DEFINE FIELD metadata ON TABLE group TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD created_at ON TABLE group TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE group TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_group_tenant_name ON TABLE group \
    COLUMNS tenant_id, name UNIQUE;

-- =======================================================================
-- Sessions (tenant scope)
-- =======================================================================
DEFINE TABLE session SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE session TYPE string;
DEFINE FIELD user_id ON TABLE session TYPE string;
DEFINE FIELD token_hash ON TABLE session TYPE string;
DEFINE FIELD ip_address ON TABLE session TYPE option<string>;
DEFINE FIELD user_agent ON TABLE session TYPE option<string>;
DEFINE FIELD expires_at ON TABLE session TYPE datetime;
DEFINE FIELD created_at ON TABLE session TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_session_token ON TABLE session \
    COLUMNS tenant_id, token_hash UNIQUE;
DEFINE INDEX idx_session_user ON TABLE session \
    COLUMNS tenant_id, user_id;

-- =======================================================================
-- Audit Log (tenant scope, append-only)
-- =======================================================================
DEFINE TABLE audit_log SCHEMAFULL
    PERMISSIONS
        FOR create FULL
        FOR select FULL
        FOR update NONE
        FOR delete NONE;
DEFINE FIELD tenant_id ON TABLE audit_log TYPE string;
DEFINE FIELD actor_id ON TABLE audit_log TYPE string;
DEFINE FIELD actor_type ON TABLE audit_log TYPE string \
    ASSERT $value IN ['User', 'ServiceAccount', 'System'];
DEFINE FIELD action ON TABLE audit_log TYPE string;
DEFINE FIELD resource_id ON TABLE audit_log TYPE option<string>;
DEFINE FIELD outcome ON TABLE audit_log TYPE string \
    ASSERT $value IN ['Success', 'Failure', 'Denied'];
DEFINE FIELD ip_address ON TABLE audit_log TYPE option<string>;
DEFINE FIELD metadata ON TABLE audit_log TYPE object FLEXIBLE \
    DEFAULT {};
DEFINE FIELD timestamp ON TABLE audit_log TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_audit_tenant_time ON TABLE audit_log \
    COLUMNS tenant_id, timestamp;
DEFINE INDEX idx_audit_tenant_actor ON TABLE audit_log \
    COLUMNS tenant_id, actor_id;

-- =======================================================================
-- OAuth2 Clients (tenant scope)
-- =======================================================================
DEFINE TABLE oauth2_client SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE oauth2_client TYPE string;
DEFINE FIELD client_id ON TABLE oauth2_client TYPE string;
DEFINE FIELD client_secret_hash ON TABLE oauth2_client TYPE string;
DEFINE FIELD name ON TABLE oauth2_client TYPE string;
DEFINE FIELD redirect_uris ON TABLE oauth2_client TYPE array;
DEFINE FIELD redirect_uris.* ON TABLE oauth2_client TYPE string;
DEFINE FIELD grant_types ON TABLE oauth2_client TYPE array;
DEFINE FIELD grant_types.* ON TABLE oauth2_client TYPE string;
DEFINE FIELD scopes ON TABLE oauth2_client TYPE array;
DEFINE FIELD scopes.* ON TABLE oauth2_client TYPE string;
DEFINE FIELD created_at ON TABLE oauth2_client TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE oauth2_client TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_oauth2_tenant_client_id ON TABLE oauth2_client \
    COLUMNS tenant_id, client_id UNIQUE;

-- =======================================================================
-- Federation Config (tenant scope)
-- =======================================================================
DEFINE TABLE federation_config SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE federation_config TYPE string;
DEFINE FIELD provider ON TABLE federation_config TYPE string;
DEFINE FIELD protocol ON TABLE federation_config TYPE string \
    ASSERT $value IN ['OidcConnect', 'Saml'];
DEFINE FIELD metadata_url ON TABLE federation_config \
    TYPE option<string>;
DEFINE FIELD client_id ON TABLE federation_config TYPE string;
DEFINE FIELD client_secret ON TABLE federation_config TYPE string;
DEFINE FIELD attribute_map ON TABLE federation_config \
    TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD enabled ON TABLE federation_config TYPE bool \
    DEFAULT true;
DEFINE FIELD created_at ON TABLE federation_config TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE federation_config TYPE datetime \
    DEFAULT time::now();

-- =======================================================================
-- Certificates (tenant scope)
-- =======================================================================
DEFINE TABLE certificate SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE certificate TYPE string;
DEFINE FIELD issuer_ca_id ON TABLE certificate TYPE string;
DEFINE FIELD subject ON TABLE certificate TYPE string;
DEFINE FIELD public_cert_pem ON TABLE certificate TYPE string;
DEFINE FIELD fingerprint ON TABLE certificate TYPE string;
DEFINE FIELD cert_type ON TABLE certificate TYPE string \
    ASSERT $value IN ['User', 'Service', 'Device'];
DEFINE FIELD key_algorithm ON TABLE certificate TYPE string \
    ASSERT $value IN ['Rsa4096', 'Ed25519'];
DEFINE FIELD not_before ON TABLE certificate TYPE datetime;
DEFINE FIELD not_after ON TABLE certificate TYPE datetime;
DEFINE FIELD status ON TABLE certificate TYPE string \
    ASSERT $value IN ['Active', 'Revoked', 'Expired'];
DEFINE FIELD metadata ON TABLE certificate TYPE object FLEXIBLE \
    DEFAULT {};
DEFINE FIELD created_at ON TABLE certificate TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_cert_tenant_fingerprint ON TABLE certificate \
    COLUMNS tenant_id, fingerprint UNIQUE;

-- =======================================================================
-- Webhooks (tenant scope)
-- =======================================================================
DEFINE TABLE webhook SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE webhook TYPE string;
DEFINE FIELD url ON TABLE webhook TYPE string;
DEFINE FIELD events ON TABLE webhook TYPE array;
DEFINE FIELD events.* ON TABLE webhook TYPE string;
DEFINE FIELD secret_hash ON TABLE webhook TYPE string;
DEFINE FIELD enabled ON TABLE webhook TYPE bool DEFAULT true;
DEFINE FIELD retry_policy ON TABLE webhook TYPE object;
DEFINE FIELD retry_policy.max_retries ON TABLE webhook TYPE int \
    DEFAULT 5;
DEFINE FIELD retry_policy.initial_delay_secs ON TABLE webhook \
    TYPE int DEFAULT 10;
DEFINE FIELD retry_policy.backoff_multiplier ON TABLE webhook \
    TYPE float DEFAULT 2.0;
DEFINE FIELD created_at ON TABLE webhook TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE webhook TYPE datetime \
    DEFAULT time::now();

-- =======================================================================
-- Graph Edge Tables (relations)
-- =======================================================================

-- Organization -> Tenant membership
DEFINE TABLE has_tenant TYPE RELATION SCHEMAFULL;

-- User -> Group membership
DEFINE TABLE member_of TYPE RELATION SCHEMAFULL;

-- User/ServiceAccount/Group -> Role assignment (optionally scoped to resource)
DEFINE TABLE has_role TYPE RELATION SCHEMAFULL;
DEFINE FIELD resource_id ON TABLE has_role TYPE option<string>;

-- Role -> Permission grants
DEFINE TABLE grants TYPE RELATION SCHEMAFULL;

-- Permission -> Resource association
DEFINE TABLE on_resource TYPE RELATION SCHEMAFULL;

-- Resource -> Resource parent/child hierarchy
DEFINE TABLE child_of TYPE RELATION SCHEMAFULL;

-- Certificate -> CA Certificate signing chain
DEFINE TABLE signed_by TYPE RELATION SCHEMAFULL;
";

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

/// Run all pending migrations against the given SurrealDB client.
///
/// Creates a `_migration` tracking table on first run, then applies
/// each migration whose version exceeds the current maximum.
/// All DEFINE statements are idempotent so re-running is safe.
pub async fn run_migrations<C: Connection>(db: &Surreal<C>) -> Result<(), DbError> {
    // Ensure migration tracking table exists (idempotent).
    db.query(MIGRATION_TABLE_DDL)
        .await?
        .check()
        .map_err(|e| DbError::Migration(e.to_string()))?;

    // Determine current schema version.
    let mut result = db
        .query("SELECT * FROM _migration ORDER BY version DESC LIMIT 1")
        .await?;
    let records: Vec<MigrationRecord> = result.take(0)?;
    let current_version = records.first().map(|m| m.version).unwrap_or(0);

    for migration in MIGRATIONS {
        if migration.version > current_version {
            info!(
                version = migration.version,
                name = migration.name,
                "Applying migration"
            );
            db.query(migration.sql).await?.check().map_err(|e| {
                DbError::Migration(format!(
                    "Migration v{} '{}' failed: {}",
                    migration.version, migration.name, e,
                ))
            })?;

            // Record the applied migration.
            db.query(
                "CREATE _migration SET version = $version, \
                 name = $name",
            )
            .bind(("version", migration.version))
            .bind(("name", migration.name))
            .await?
            .check()
            .map_err(|e| {
                DbError::Migration(format!(
                    "Failed to record migration v{}: {}",
                    migration.version, e,
                ))
            })?;

            info!(
                version = migration.version,
                "Migration applied successfully"
            );
        }
    }

    Ok(())
}

/// Returns the raw schema DDL for version 1.
///
/// Exposed for testing with in-memory SurrealDB instances that
/// bypass the migration runner.
pub fn schema_v1() -> &'static str {
    SCHEMA_V1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_v1_is_nonempty() {
        assert!(!SCHEMA_V1.is_empty());
    }

    #[test]
    fn migrations_are_ordered() {
        for window in MIGRATIONS.windows(2) {
            assert!(
                window[0].version < window[1].version,
                "Migrations must be in ascending version order"
            );
        }
    }
}
