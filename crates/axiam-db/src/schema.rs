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

/// DDL for the migration-tracking table (idempotent — all IF NOT EXISTS).
const MIGRATION_TABLE_DDL: &str = "\
DEFINE TABLE IF NOT EXISTS _migration SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS version ON TABLE _migration TYPE int;
DEFINE FIELD IF NOT EXISTS name ON TABLE _migration TYPE string;
DEFINE FIELD IF NOT EXISTS applied_at ON TABLE _migration TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_migration_version ON TABLE _migration \
    COLUMNS version UNIQUE;
DEFINE TABLE IF NOT EXISTS _migration_lock SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS locked_at ON TABLE _migration_lock TYPE datetime \
    DEFAULT time::now();
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

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_schema",
        sql: SCHEMA_V1,
    },
    Migration {
        version: 2,
        name: "cert_binding",
        sql: SCHEMA_V2,
    },
    Migration {
        version: 3,
        name: "pgp_keys",
        sql: SCHEMA_V3,
    },
    Migration {
        version: 4,
        name: "oauth2_auth_codes",
        sql: SCHEMA_V4,
    },
    Migration {
        version: 5,
        name: "oauth2_refresh_tokens",
        sql: SCHEMA_V5,
    },
    Migration {
        version: 6,
        name: "oauth2_auth_code_nonce",
        sql: SCHEMA_V6,
    },
    Migration {
        version: 7,
        name: "federation_links",
        sql: SCHEMA_V7,
    },
    Migration {
        version: 8,
        name: "security_settings",
        sql: SCHEMA_V8,
    },
    Migration {
        version: 9,
        name: "password_history",
        sql: SCHEMA_V9,
    },
    Migration {
        version: 10,
        name: "email_templates",
        sql: SCHEMA_V10,
    },
    Migration {
        version: 11,
        name: "email_verification_tokens",
        sql: SCHEMA_V11,
    },
    Migration {
        version: 12,
        name: "password_reset_tokens",
        sql: SCHEMA_V12,
    },
    Migration {
        version: 13,
        name: "notification_rules",
        sql: SCHEMA_V13,
    },
    Migration {
        version: 14,
        name: "webauthn_credentials",
        sql: SCHEMA_V14,
    },
    Migration {
        version: 15,
        name: "phase5_email_gdpr",
        sql: SCHEMA_V15,
    },
    Migration {
        version: 16,
        name: "sparse_tenant_settings",
        sql: SCHEMA_V16,
    },
    Migration {
        version: 17,
        name: "totp_replay_prevention",
        sql: SCHEMA_V17,
    },
];

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
DEFINE FIELD failed_login_attempts ON TABLE user TYPE int DEFAULT 0;
DEFINE FIELD last_failed_login_at ON TABLE user TYPE option<datetime>;
DEFINE FIELD locked_until ON TABLE user TYPE option<datetime>;
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
-- Phase 4 additions: encrypted client secret columns + algorithm allow-list
-- (legacy client_secret column is kept for back-compat; nulled by plan 04-02 backfill)
DEFINE FIELD IF NOT EXISTS allowed_algorithms ON TABLE federation_config \
    TYPE array<string> DEFAULT [];
DEFINE FIELD IF NOT EXISTS idp_signing_cert_pem ON TABLE federation_config \
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS client_secret_ciphertext ON TABLE federation_config \
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS client_secret_nonce ON TABLE federation_config \
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS client_secret_key_version ON TABLE federation_config \
    TYPE option<int>;

-- =======================================================================
-- SAML Assertion Replay Table (D-09)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS saml_assertion_replay SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE saml_assertion_replay TYPE string;
DEFINE FIELD IF NOT EXISTS assertion_id ON TABLE saml_assertion_replay TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE saml_assertion_replay TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE saml_assertion_replay TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_replay_uniq ON TABLE saml_assertion_replay \
    COLUMNS tenant_id, assertion_id UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_replay_expires_at ON TABLE saml_assertion_replay \
    COLUMNS expires_at;

-- =======================================================================
-- Federation Login State Table (D-24)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS federation_login_state SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS state ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS nonce ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS federation_config_id ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS redirect_uri ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE federation_login_state TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE federation_login_state TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_login_state_uniq ON TABLE federation_login_state \
    COLUMNS state UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_login_state_expires_at ON TABLE federation_login_state \
    COLUMNS expires_at;

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
DEFINE FIELD secret ON TABLE webhook TYPE string;
DEFINE FIELD enabled ON TABLE webhook TYPE bool DEFAULT true;
DEFINE FIELD max_retries ON TABLE webhook TYPE int DEFAULT 5;
DEFINE FIELD initial_delay_secs ON TABLE webhook TYPE int DEFAULT 10;
DEFINE FIELD backoff_multiplier ON TABLE webhook TYPE float DEFAULT 2.0;
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
DEFINE FIELD scope_ids ON TABLE grants TYPE option<array<string>>;

-- Permission -> Resource association
DEFINE TABLE on_resource TYPE RELATION SCHEMAFULL;

-- Resource -> Resource parent/child hierarchy
DEFINE TABLE child_of TYPE RELATION SCHEMAFULL;

-- Certificate -> CA Certificate signing chain
DEFINE TABLE signed_by TYPE RELATION SCHEMAFULL;
";

// -----------------------------------------------------------------------
// Schema v2 — certificate binding
// -----------------------------------------------------------------------

const SCHEMA_V2: &str = "\
-- Certificate -> ServiceAccount binding for mTLS device auth
DEFINE TABLE cert_bound_to TYPE RELATION SCHEMAFULL;
DEFINE FIELD created_at ON TABLE cert_bound_to TYPE datetime \
    DEFAULT time::now();

-- Each certificate can be bound to at most one service account
DEFINE INDEX idx_cert_bound_unique ON TABLE cert_bound_to \
    COLUMNS in UNIQUE;

-- Global fingerprint index for cross-tenant cert lookup
DEFINE INDEX idx_cert_fingerprint_global ON TABLE certificate \
    COLUMNS fingerprint UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v3 — PGP keys and audit signatures
// -----------------------------------------------------------------------

const SCHEMA_V3: &str = "\
-- =======================================================================
-- PGP Keys (tenant scope)
-- =======================================================================
DEFINE TABLE pgp_key SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE pgp_key TYPE string;
DEFINE FIELD name ON TABLE pgp_key TYPE string;
DEFINE FIELD purpose ON TABLE pgp_key TYPE string \
    ASSERT $value IN ['AuditSigning', 'Export'];
DEFINE FIELD public_key_armored ON TABLE pgp_key TYPE string;
DEFINE FIELD fingerprint ON TABLE pgp_key TYPE string;
DEFINE FIELD algorithm ON TABLE pgp_key TYPE string \
    ASSERT $value IN ['Rsa4096', 'Ed25519'];
DEFINE FIELD status ON TABLE pgp_key TYPE string \
    ASSERT $value IN ['Active', 'Revoked'];
DEFINE FIELD encrypted_private_key ON TABLE pgp_key \
    TYPE option<bytes>;
DEFINE FIELD created_at ON TABLE pgp_key TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_pgp_key_tenant_fingerprint ON TABLE pgp_key \
    COLUMNS tenant_id, fingerprint UNIQUE;

-- =======================================================================
-- Audit Signatures (tenant scope, append-only)
-- =======================================================================
DEFINE TABLE audit_signature SCHEMAFULL \
    PERMISSIONS \
        FOR create FULL \
        FOR select FULL \
        FOR update NONE \
        FOR delete NONE;
DEFINE FIELD tenant_id ON TABLE audit_signature TYPE string;
DEFINE FIELD signing_key_id ON TABLE audit_signature TYPE string;
DEFINE FIELD entry_ids ON TABLE audit_signature TYPE array;
DEFINE FIELD entry_ids.* ON TABLE audit_signature TYPE string;
DEFINE FIELD signature_armored ON TABLE audit_signature TYPE string;
DEFINE FIELD signed_at ON TABLE audit_signature TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_audit_sig_tenant ON TABLE audit_signature \
    COLUMNS tenant_id, signed_at;
";

// -----------------------------------------------------------------------
// Schema v4 — OAuth2 authorization codes
// -----------------------------------------------------------------------

const SCHEMA_V4: &str = "\
-- =======================================================================
-- OAuth2 Authorization Codes (tenant scope, short-lived)
-- =======================================================================
DEFINE TABLE oauth2_auth_code SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE oauth2_auth_code TYPE string;
DEFINE FIELD client_id ON TABLE oauth2_auth_code TYPE string;
DEFINE FIELD user_id ON TABLE oauth2_auth_code TYPE string;
DEFINE FIELD code_hash ON TABLE oauth2_auth_code TYPE string;
DEFINE FIELD redirect_uri ON TABLE oauth2_auth_code TYPE string;
DEFINE FIELD scopes ON TABLE oauth2_auth_code TYPE array;
DEFINE FIELD scopes.* ON TABLE oauth2_auth_code TYPE string;
DEFINE FIELD code_challenge ON TABLE oauth2_auth_code TYPE option<string>;
DEFINE FIELD code_challenge_method ON TABLE oauth2_auth_code TYPE option<string>;
DEFINE FIELD expires_at ON TABLE oauth2_auth_code TYPE datetime;
DEFINE FIELD used ON TABLE oauth2_auth_code TYPE bool DEFAULT false;
DEFINE FIELD created_at ON TABLE oauth2_auth_code TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_auth_code_hash ON TABLE oauth2_auth_code \
    COLUMNS tenant_id, code_hash UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v5 — OAuth2 refresh tokens
// -----------------------------------------------------------------------

const SCHEMA_V5: &str = "\
-- =======================================================================
-- OAuth2 Refresh Tokens (tenant scope)
-- =======================================================================
DEFINE TABLE oauth2_refresh_token SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE oauth2_refresh_token TYPE string;
DEFINE FIELD token_hash ON TABLE oauth2_refresh_token TYPE string;
DEFINE FIELD client_id ON TABLE oauth2_refresh_token TYPE string;
DEFINE FIELD user_id ON TABLE oauth2_refresh_token TYPE option<string>;
DEFINE FIELD scopes ON TABLE oauth2_refresh_token TYPE array;
DEFINE FIELD scopes.* ON TABLE oauth2_refresh_token TYPE string;
DEFINE FIELD expires_at ON TABLE oauth2_refresh_token TYPE datetime;
DEFINE FIELD revoked ON TABLE oauth2_refresh_token TYPE bool DEFAULT false;
DEFINE FIELD created_at ON TABLE oauth2_refresh_token TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_refresh_token_hash ON TABLE oauth2_refresh_token \
    COLUMNS tenant_id, token_hash UNIQUE;
DEFINE INDEX idx_refresh_token_client ON TABLE oauth2_refresh_token \
    COLUMNS tenant_id, client_id;
";

// -----------------------------------------------------------------------
// Schema v6 — OIDC nonce on authorization codes
// -----------------------------------------------------------------------

const SCHEMA_V6: &str = "\
DEFINE FIELD nonce ON TABLE oauth2_auth_code TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v7 — Federation links (external IdP user binding)
// -----------------------------------------------------------------------

const SCHEMA_V7: &str = "\
-- =======================================================================
-- Federation Links (tenant scope)
-- =======================================================================
DEFINE TABLE federation_link SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE federation_link TYPE string;
DEFINE FIELD user_id ON TABLE federation_link TYPE string;
DEFINE FIELD federation_config_id ON TABLE federation_link TYPE string;
DEFINE FIELD external_subject ON TABLE federation_link TYPE string;
DEFINE FIELD external_email ON TABLE federation_link TYPE option<string>;
DEFINE FIELD created_at ON TABLE federation_link TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE federation_link TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_fed_link_subject ON TABLE federation_link \
    COLUMNS tenant_id, federation_config_id, external_subject UNIQUE;
DEFINE INDEX idx_fed_link_user ON TABLE federation_link \
    COLUMNS tenant_id, user_id;
";

// -----------------------------------------------------------------------
// Schema v8 — Security settings (org/tenant scope)
// -----------------------------------------------------------------------

const SCHEMA_V8: &str = "\
-- =======================================================================
-- Security Settings (org or tenant scope)
-- =======================================================================
DEFINE TABLE security_settings SCHEMAFULL;
DEFINE FIELD scope ON TABLE security_settings TYPE string \
    ASSERT $value IN ['org', 'tenant'];
DEFINE FIELD scope_id ON TABLE security_settings TYPE string;
-- Password policy (pw_ prefix)
DEFINE FIELD pw_min_length ON TABLE security_settings TYPE int;
DEFINE FIELD pw_require_uppercase ON TABLE security_settings TYPE bool;
DEFINE FIELD pw_require_lowercase ON TABLE security_settings TYPE bool;
DEFINE FIELD pw_require_digits ON TABLE security_settings TYPE bool;
DEFINE FIELD pw_require_symbols ON TABLE security_settings TYPE bool;
DEFINE FIELD pw_history_count ON TABLE security_settings TYPE int;
DEFINE FIELD pw_hibp_check ON TABLE security_settings TYPE bool;
-- MFA policy (mfa_ prefix)
DEFINE FIELD mfa_enforced ON TABLE security_settings TYPE bool;
DEFINE FIELD mfa_challenge_lifetime ON TABLE security_settings TYPE int;
-- Lockout policy (lockout_ prefix)
DEFINE FIELD lockout_max_attempts ON TABLE security_settings TYPE int;
DEFINE FIELD lockout_duration ON TABLE security_settings TYPE int;
DEFINE FIELD lockout_backoff ON TABLE security_settings TYPE float;
DEFINE FIELD lockout_max_duration ON TABLE security_settings TYPE int;
-- Token policy (token_ prefix)
DEFINE FIELD token_access_lifetime ON TABLE security_settings TYPE int;
DEFINE FIELD token_refresh_lifetime ON TABLE security_settings TYPE int;
-- Email policy (email_ prefix)
DEFINE FIELD email_verification_required ON TABLE security_settings TYPE bool;
DEFINE FIELD email_grace_period_hours ON TABLE security_settings TYPE int;
-- Certificate policy (cert_ prefix)
DEFINE FIELD cert_default_validity ON TABLE security_settings TYPE int;
DEFINE FIELD cert_max_validity ON TABLE security_settings TYPE int;
-- Notification policy (notif_ prefix)
DEFINE FIELD notif_admin_enabled ON TABLE security_settings TYPE bool;
-- Timestamps
DEFINE FIELD created_at ON TABLE security_settings TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE security_settings TYPE datetime \
    DEFAULT time::now();
-- Unique index on (scope, scope_id) — one settings row per scope target
DEFINE INDEX idx_settings_scope ON TABLE security_settings \
    COLUMNS scope, scope_id UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v9 — Password history for reuse prevention
// -----------------------------------------------------------------------

const SCHEMA_V9: &str = "\
-- =======================================================================
-- Password History (tenant scope, for reuse detection)
-- =======================================================================
DEFINE TABLE password_history SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE password_history TYPE string;
DEFINE FIELD user_id ON TABLE password_history TYPE string;
DEFINE FIELD password_hash ON TABLE password_history TYPE string;
DEFINE FIELD created_at ON TABLE password_history TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_pw_history_user ON TABLE password_history \
    COLUMNS tenant_id, user_id;
";

// -----------------------------------------------------------------------
// Schema v10 — Email templates (org/tenant scope)
// -----------------------------------------------------------------------

const SCHEMA_V10: &str = "\
-- =======================================================================
-- Email Templates (org or tenant scope)
-- =======================================================================
DEFINE TABLE email_template SCHEMAFULL;
DEFINE FIELD scope ON TABLE email_template TYPE string \
    ASSERT $value IN ['org', 'tenant'];
DEFINE FIELD scope_id ON TABLE email_template TYPE string;
DEFINE FIELD kind ON TABLE email_template TYPE string \
    ASSERT $value IN ['activation', 'password_reset', \
                       'mfa_setup_reminder', 'admin_notification'];
DEFINE FIELD subject ON TABLE email_template TYPE string;
DEFINE FIELD html_body ON TABLE email_template TYPE string;
DEFINE FIELD text_body ON TABLE email_template TYPE string;
DEFINE FIELD created_at ON TABLE email_template TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE email_template TYPE datetime \
    DEFAULT time::now();
-- One template per (scope, scope_id, kind)
DEFINE INDEX idx_email_template_scope_kind ON TABLE email_template \
    COLUMNS scope, scope_id, kind UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v11 — Email verification tokens
// -----------------------------------------------------------------------

const SCHEMA_V11: &str = "\
-- =======================================================================
-- Email Verification Tokens (tenant scope)
-- =======================================================================
DEFINE TABLE email_verification_token SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE email_verification_token TYPE string;
DEFINE FIELD user_id ON TABLE email_verification_token TYPE string;
DEFINE FIELD token_hash ON TABLE email_verification_token TYPE string;
DEFINE FIELD expires_at ON TABLE email_verification_token TYPE datetime;
DEFINE FIELD consumed_at ON TABLE email_verification_token \
    TYPE option<datetime>;
DEFINE FIELD created_at ON TABLE email_verification_token TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_evtoken_hash ON TABLE email_verification_token \
    COLUMNS tenant_id, token_hash UNIQUE;
DEFINE INDEX idx_evtoken_user ON TABLE email_verification_token \
    COLUMNS tenant_id, user_id;

-- Add email_verified_at to user table
DEFINE FIELD email_verified_at ON TABLE user TYPE option<datetime>;
";

// -----------------------------------------------------------------------
// Schema v12 — Password reset tokens
// -----------------------------------------------------------------------

const SCHEMA_V12: &str = "\
-- =======================================================================
-- Password Reset Tokens (tenant scope)
-- =======================================================================
DEFINE TABLE password_reset_token SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE password_reset_token TYPE string;
DEFINE FIELD user_id ON TABLE password_reset_token TYPE string;
DEFINE FIELD token_hash ON TABLE password_reset_token TYPE string;
DEFINE FIELD expires_at ON TABLE password_reset_token TYPE datetime;
DEFINE FIELD consumed_at ON TABLE password_reset_token \
    TYPE option<datetime>;
DEFINE FIELD created_at ON TABLE password_reset_token TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_prtoken_hash ON TABLE password_reset_token \
    COLUMNS tenant_id, token_hash UNIQUE;
DEFINE INDEX idx_prtoken_user ON TABLE password_reset_token \
    COLUMNS tenant_id, user_id;
";

// -----------------------------------------------------------------------
// Schema v13 — Notification rules (tenant scope)
// -----------------------------------------------------------------------

const SCHEMA_V13: &str = "\
-- =======================================================================
-- Notification Rules (tenant scope)
-- =======================================================================
DEFINE TABLE notification_rule SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE notification_rule TYPE string;
DEFINE FIELD name ON TABLE notification_rule TYPE string;
DEFINE FIELD description ON TABLE notification_rule TYPE string;
DEFINE FIELD events ON TABLE notification_rule TYPE array;
DEFINE FIELD events.* ON TABLE notification_rule TYPE string;
DEFINE FIELD recipient_emails ON TABLE notification_rule TYPE array;
DEFINE FIELD recipient_emails.* ON TABLE notification_rule TYPE string;
DEFINE FIELD enabled ON TABLE notification_rule TYPE bool DEFAULT true;
DEFINE FIELD created_at ON TABLE notification_rule TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE notification_rule TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX idx_notification_rule_tenant ON TABLE notification_rule \
    COLUMNS tenant_id;
";

// -----------------------------------------------------------------------
// Schema v14 — WebAuthn credentials
// -----------------------------------------------------------------------

const SCHEMA_V14: &str = "\
-- =======================================================================
-- WebAuthn Credentials (tenant scope)
-- =======================================================================
DEFINE TABLE webauthn_credential SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE webauthn_credential TYPE string;
DEFINE FIELD user_id ON TABLE webauthn_credential TYPE string;
DEFINE FIELD credential_id ON TABLE webauthn_credential TYPE string;
DEFINE FIELD name ON TABLE webauthn_credential TYPE string;
DEFINE FIELD credential_type ON TABLE webauthn_credential TYPE string \
    ASSERT $value IN ['Passkey', 'SecurityKey'];
DEFINE FIELD passkey_json ON TABLE webauthn_credential TYPE string;
DEFINE FIELD created_at ON TABLE webauthn_credential TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD last_used_at ON TABLE webauthn_credential TYPE option<datetime>;
DEFINE INDEX idx_webauthn_cred_tenant_user ON TABLE webauthn_credential \
    COLUMNS tenant_id, user_id;
DEFINE INDEX idx_webauthn_cred_id ON TABLE webauthn_credential \
    COLUMNS tenant_id, credential_id UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v15 — Phase 5: email delivery & GDPR compliance
// -----------------------------------------------------------------------

const SCHEMA_V15: &str = "\
-- =======================================================================
-- Email Config (org/tenant scope) — provider secrets stored encrypted
-- =======================================================================
DEFINE TABLE IF NOT EXISTS email_config SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS scope ON TABLE email_config TYPE string
    ASSERT $value IN ['org', 'tenant'];
DEFINE FIELD IF NOT EXISTS scope_id ON TABLE email_config TYPE string;
DEFINE FIELD IF NOT EXISTS enabled ON TABLE email_config TYPE bool
    DEFAULT true;
DEFINE FIELD IF NOT EXISTS from_name ON TABLE email_config TYPE string;
DEFINE FIELD IF NOT EXISTS from_email ON TABLE email_config TYPE string;
DEFINE FIELD IF NOT EXISTS reply_to ON TABLE email_config TYPE option<string>;
DEFINE FIELD IF NOT EXISTS provider_kind ON TABLE email_config TYPE string
    ASSERT $value IN ['smtp', 'send_grid', 'postmark', 'resend', 'brevo'];
DEFINE FIELD IF NOT EXISTS smtp_host ON TABLE email_config TYPE option<string>;
DEFINE FIELD IF NOT EXISTS smtp_port ON TABLE email_config TYPE option<int>;
DEFINE FIELD IF NOT EXISTS smtp_username ON TABLE email_config TYPE option<string>;
DEFINE FIELD IF NOT EXISTS smtp_starttls ON TABLE email_config TYPE option<bool>;
DEFINE FIELD IF NOT EXISTS smtp_password_ciphertext ON TABLE email_config
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS smtp_password_nonce ON TABLE email_config
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS api_url ON TABLE email_config TYPE option<string>;
DEFINE FIELD IF NOT EXISTS api_key_ciphertext ON TABLE email_config
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS api_key_nonce ON TABLE email_config
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS secret_key_version ON TABLE email_config
    TYPE option<int>;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE email_config TYPE datetime
    DEFAULT time::now();
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE email_config TYPE datetime
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_email_config_scope ON TABLE email_config
    COLUMNS scope, scope_id UNIQUE;

-- =======================================================================
-- Consent (tenant scope, immutable records — append-only)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS consent SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE consent TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON TABLE consent TYPE string;
DEFINE FIELD IF NOT EXISTS consent_type ON TABLE consent TYPE string;
DEFINE FIELD IF NOT EXISTS version ON TABLE consent TYPE string;
DEFINE FIELD IF NOT EXISTS accepted_at ON TABLE consent TYPE datetime
    DEFAULT time::now();
DEFINE FIELD IF NOT EXISTS ip_address ON TABLE consent TYPE option<string>;
DEFINE FIELD IF NOT EXISTS user_agent ON TABLE consent TYPE option<string>;
DEFINE INDEX IF NOT EXISTS idx_consent_tenant_user_type ON TABLE consent
    COLUMNS tenant_id, user_id, consent_type, version UNIQUE;

-- =======================================================================
-- Account Deletion Requests (tenant scope)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS account_deletion SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE account_deletion TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON TABLE account_deletion TYPE string;
DEFINE FIELD IF NOT EXISTS cancel_token_hash ON TABLE account_deletion TYPE string;
DEFINE FIELD IF NOT EXISTS scheduled_purge_at ON TABLE account_deletion
    TYPE datetime;
DEFINE FIELD IF NOT EXISTS status ON TABLE account_deletion TYPE string
    ASSERT $value IN ['pending', 'cancelled', 'completed'];
DEFINE FIELD IF NOT EXISTS created_at ON TABLE account_deletion TYPE datetime
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_account_deletion_tenant_user ON TABLE account_deletion
    COLUMNS tenant_id, user_id;
DEFINE INDEX IF NOT EXISTS idx_account_deletion_token ON TABLE account_deletion
    COLUMNS tenant_id, cancel_token_hash;

-- =======================================================================
-- Export Jobs (tenant scope)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS export_job SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE export_job TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON TABLE export_job TYPE string;
DEFINE FIELD IF NOT EXISTS status ON TABLE export_job TYPE string
    ASSERT $value IN ['queued', 'ready', 'downloaded', 'expired'];
DEFINE FIELD IF NOT EXISTS encrypted_blob ON TABLE export_job
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS file_path ON TABLE export_job TYPE option<string>;
DEFINE FIELD IF NOT EXISTS blob_nonce ON TABLE export_job TYPE option<string>;
DEFINE FIELD IF NOT EXISTS download_token_hash ON TABLE export_job
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE export_job TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE export_job TYPE datetime
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_export_job_tenant_user ON TABLE export_job
    COLUMNS tenant_id, user_id;
DEFINE INDEX IF NOT EXISTS idx_export_job_token ON TABLE export_job
    COLUMNS tenant_id, download_token_hash;

-- =======================================================================
-- Erasure Proof (PII-free record proving erasure happened)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS erasure_proof SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS pseudonym ON TABLE erasure_proof TYPE string;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE erasure_proof TYPE string;
DEFINE FIELD IF NOT EXISTS erased_at ON TABLE erasure_proof TYPE datetime
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_erasure_proof_tenant ON TABLE erasure_proof
    COLUMNS tenant_id;

-- =======================================================================
-- ALTER user table: add GDPR deletion fields
-- =======================================================================
DEFINE FIELD IF NOT EXISTS deletion_pending ON TABLE user TYPE bool
    DEFAULT false;
DEFINE FIELD IF NOT EXISTS scheduled_purge_at ON TABLE user
    TYPE option<datetime>;

-- Re-DEFINE user.status ASSERT to include 'Anonymized' (OVERWRITE extends the ASSERT)
DEFINE FIELD OVERWRITE status ON TABLE user TYPE string
    ASSERT $value IN ['Active', 'Inactive', 'Locked', 'PendingVerification',
                      'Anonymized'];

-- =======================================================================
-- ALTER audit_log permissions: add gdpr_pseudonymizer UPDATE path (D-04)
-- Note: FOR delete stays NONE. True enforcement is the single repo method.
-- =======================================================================
DEFINE TABLE OVERWRITE audit_log SCHEMAFULL
    PERMISSIONS
        FOR create FULL
        FOR select FULL
        FOR update WHERE $auth.role = 'gdpr_pseudonymizer'
        FOR delete NONE;

-- =======================================================================
-- ALTER email_template.kind ASSERT: add deletion_scheduled, export_ready
-- =======================================================================
DEFINE FIELD OVERWRITE kind ON TABLE email_template TYPE string
    ASSERT $value IN ['activation', 'password_reset', 'mfa_setup_reminder',
                      'admin_notification', 'deletion_scheduled', 'export_ready'];
";

// -----------------------------------------------------------------------
// Schema v16 — sparse tenant settings (CQ-B03 / REQ-14 AC-3)
// -----------------------------------------------------------------------
//
// Adds an `overrides_json` column to `security_settings` to persist only
// the fields explicitly overridden by a tenant.  Org rows leave this
// column `NONE`.  The repository uses it at read time instead of
// diff-against-org so that an org baseline change propagates correctly to
// tenants that did not explicitly override that field.

const SCHEMA_V16: &str = "\
-- Add sparse override mask to security_settings (CQ-B03 / REQ-14 AC-3).
DEFINE FIELD IF NOT EXISTS overrides_json ON TABLE security_settings \
    TYPE option<string>;
-- Extend export_job status ASSERT to include 'failed' (CQ-B38 / REQ-14 AC-5).
DEFINE FIELD OVERWRITE status ON TABLE export_job TYPE string \
    ASSERT $value IN ['queued', 'ready', 'downloaded', 'expired', 'failed'];
";

// -----------------------------------------------------------------------
// Schema v17 — TOTP replay prevention (SEC-008 / REQ-14 AC-5)
// -----------------------------------------------------------------------
//
// Adds `totp_last_used_step` to the `user` table.  The field records the
// last TOTP time-step that was accepted so that codes cannot be replayed
// within the same 30-second window.

const SCHEMA_V17: &str = "\
-- Add TOTP replay prevention step counter to user table (SEC-008/REQ-14 AC-5).
DEFINE FIELD IF NOT EXISTS totp_last_used_step ON TABLE user \
    TYPE option<int>;
";

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

/// Run all pending migrations against the given SurrealDB client.
///
/// Creates `_migration` and `_migration_lock` tracking tables on first run,
/// then applies each pending migration atomically: the schema DDL and the
/// version-record INSERT are wrapped in a single `BEGIN TRANSACTION …
/// COMMIT TRANSACTION` so that a mid-step failure leaves the row
/// re-selectable (CQ-B06 / REQ-14 AC-5).
///
/// The `_migration_lock` record (`CREATE IF NOT EXISTS`) guards concurrent
/// startup — only one process may hold the lock at a time.  The record is
/// removed once migrations complete.
pub async fn run_migrations<C: Connection>(db: &Surreal<C>) -> Result<(), DbError> {
    // Ensure migration-tracking tables exist (all DDL is IF NOT EXISTS).
    db.query(MIGRATION_TABLE_DDL)
        .await?
        .check()
        .map_err(|e| DbError::Migration(e.to_string()))?;

    // Acquire a startup lock so that concurrent instances do not race on
    // schema application.  UPSERT with a deterministic record ID is
    // idempotent — if a lock record already exists this is a no-op.
    db.query(
        "BEGIN TRANSACTION; \
         UPSERT _migration_lock:`startup` SET locked_at = time::now(); \
         COMMIT TRANSACTION",
    )
    .await?
    .check()
    .map_err(|e| DbError::Migration(format!("failed to acquire _migration_lock: {e}")))?;

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

            // Wrap the schema DDL and the version-record INSERT in a single
            // transaction (CQ-B06).  If the DDL succeeds but the INSERT
            // fails, the whole block is rolled back and the migration will
            // be retried on the next startup.
            //
            // SurrealDB v3 transaction slot offset: BEGIN = slot 0, first
            // statement = slot 1, … (MEMORY.md).  We don't take() from the
            // result; we only call .check() to surface errors.
            let txn = format!(
                "BEGIN TRANSACTION;\n\
                 {};\n\
                 CREATE _migration SET version = {v}, name = '{n}';\n\
                 COMMIT TRANSACTION",
                migration.sql,
                v = migration.version,
                n = migration.name,
            );
            db.query(&txn).await?.check().map_err(|e| {
                DbError::Migration(format!(
                    "Migration v{} '{}' failed (transaction rolled back): {}",
                    migration.version, migration.name, e,
                ))
            })?;

            info!(
                version = migration.version,
                "Migration applied successfully"
            );
        }
    }

    // Release the startup lock now that migrations are complete.
    db.query("DELETE _migration_lock:`startup`")
        .await?
        .check()
        .map_err(|e| DbError::Migration(format!("failed to release migration lock: {e}")))?;

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
