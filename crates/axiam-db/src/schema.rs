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
    Migration {
        version: 18,
        name: "federation_login_state_request_id",
        sql: SCHEMA_V18,
    },
    Migration {
        version: 19,
        name: "edge_unique_indexes",
        sql: SCHEMA_V19,
    },
    Migration {
        version: 20,
        name: "seeder_state",
        sql: SCHEMA_V20,
    },
    Migration {
        version: 21,
        name: "rate_limit_bucket",
        sql: SCHEMA_V21,
    },
    Migration {
        version: 22,
        name: "bootstrap_atomicity_gate",
        sql: SCHEMA_V22,
    },
    Migration {
        version: 23,
        name: "email_config_provider_kind_optional",
        sql: SCHEMA_V23,
    },
    Migration {
        version: 24,
        name: "tenant_status_and_sa_description",
        sql: SCHEMA_V24,
    },
    Migration {
        version: 25,
        name: "grant_effect_deny_override",
        sql: SCHEMA_V25,
    },
    Migration {
        version: 26,
        name: "device_grant_rfc8628",
        sql: SCHEMA_V26,
    },
    Migration {
        version: 27,
        name: "oidc_logout_and_par",
        sql: SCHEMA_V27,
    },
    Migration {
        version: 28,
        name: "session_client_participation",
        sql: SCHEMA_V28,
    },
    Migration {
        version: 29,
        name: "reactor_registrations",
        sql: SCHEMA_V29,
    },
    Migration {
        version: 30,
        name: "uma_permission_tickets",
        sql: SCHEMA_V30,
    },
    Migration {
        version: 31,
        name: "uma_permission_ticket_redemption_nonce",
        sql: SCHEMA_V31,
    },
    Migration {
        version: 32,
        name: "single_use_redemption_nonce_device_grant_and_par",
        sql: SCHEMA_V32,
    },
    Migration {
        version: 33,
        name: "uma_resource_registration_provenance",
        sql: SCHEMA_V33,
    },
    Migration {
        version: 34,
        name: "resource_child_epoch_delete_race",
        sql: SCHEMA_V34,
    },
    Migration {
        version: 35,
        name: "webauthn_attestation_policy_and_mds",
        sql: SCHEMA_V35,
    },
    Migration {
        version: 36,
        name: "federation_external_token_exchange_trust",
        sql: SCHEMA_V36,
    },
    Migration {
        version: 37,
        name: "authorization_code_redemption_nonce",
        sql: SCHEMA_V37,
    },
    Migration {
        version: 38,
        name: "fapi2_client_profile_and_mtls_client_auth",
        sql: SCHEMA_V38,
    },
    Migration {
        version: 39,
        name: "private_key_jwt_dpop_and_proof_replay",
        sql: SCHEMA_V39,
    },
    Migration {
        version: 40,
        name: "scim_provisioning_tokens",
        sql: SCHEMA_V40,
    },
    Migration {
        version: 41,
        name: "srp_credentials_and_policy",
        sql: SCHEMA_V41,
    },
    Migration {
        version: 42,
        name: "opaque_replaces_srp",
        sql: SCHEMA_V42,
    },
    Migration {
        version: 43,
        name: "email_config_tenant_override_tristate",
        sql: SCHEMA_V43,
    },
    Migration {
        version: 44,
        name: "configurable_deletion_grace_period",
        sql: SCHEMA_V44,
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
-- AMQP Nonce Replay Table (NEW-4)
-- =======================================================================
-- Durable per-tenant nonce store for AMQP message replay protection. The
-- authz/audit consumers insert (tenant_id, nonce) after a valid HMAC + fresh
-- issued_at; the UNIQUE index turns a replayed nonce into a conflict that the
-- repository maps to ReplayDetected. Rows expire at issued_at + skew and are
-- swept by the periodic cleanup task (no native SurrealDB TTL, RESEARCH §7).
DEFINE TABLE IF NOT EXISTS amqp_nonce_replay SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE amqp_nonce_replay TYPE string;
DEFINE FIELD IF NOT EXISTS nonce ON TABLE amqp_nonce_replay TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE amqp_nonce_replay TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE amqp_nonce_replay TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_amqp_nonce_uniq ON TABLE amqp_nonce_replay \
    COLUMNS tenant_id, nonce UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_amqp_nonce_expires_at ON TABLE amqp_nonce_replay \
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
DEFINE FIELD IF NOT EXISTS user_id ON TABLE erasure_proof TYPE string;
DEFINE FIELD IF NOT EXISTS erased_at ON TABLE erasure_proof TYPE datetime
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_erasure_proof_tenant ON TABLE erasure_proof
    COLUMNS tenant_id;
-- Erasure proofs are tenant-scoped (like every other domain entity in this
-- codebase — e.g. idx_user_tenant_username above), so uniqueness is defined
-- on (tenant_id, user_id) rather than a bare user_id: a retried erasure's
-- duplicate proof CREATE for the same user in the same tenant no-ops/fails
-- idempotently at the schema level (D-03b/SECHRD-06).
DEFINE INDEX IF NOT EXISTS idx_erasure_proof_tenant_user ON TABLE erasure_proof
    COLUMNS tenant_id, user_id UNIQUE;

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
// Schema v18 — SAML InResponseTo / Destination tracking (SEC-005/REQ-14 AC-5)
// -----------------------------------------------------------------------
//
// Adds `request_id` to `federation_login_state` to track the SAML
// AuthnRequest ID so the ACS handler can verify InResponseTo.

const SCHEMA_V18: &str = "\
-- Add SAML AuthnRequest ID to federation_login_state (SEC-005/REQ-14 AC-5).
DEFINE FIELD IF NOT EXISTS request_id ON TABLE federation_login_state \
    TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v19 — unique (in, out) indexes on edge tables (CQ-B17)
// -----------------------------------------------------------------------
//
// Without unique constraints, duplicate edges (e.g. user → role assigned
// twice) could be silently inserted.  A duplicate edge now surfaces as a
// SurrealDB unique-index violation which the repository layer maps to
// DbError::AlreadyExists → AxiamError::AlreadyExists → HTTP 409 (ASVS V5).

const SCHEMA_V19: &str = "\
-- Unique (in, out) composite indexes for all edge tables (CQ-B17).
-- IF NOT EXISTS guards idempotent re-runs.
DEFINE INDEX IF NOT EXISTS idx_has_tenant_unique \
    ON TABLE has_tenant FIELDS in, out UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_member_of_unique \
    ON TABLE member_of FIELDS in, out UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_has_role_unique \
    ON TABLE has_role FIELDS in, out UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_grants_unique \
    ON TABLE grants FIELDS in, out UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_on_resource_unique \
    ON TABLE on_resource FIELDS in, out UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_child_of_unique \
    ON TABLE child_of FIELDS in, out UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_signed_by_unique \
    ON TABLE signed_by FIELDS in, out UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v20 — seeder_state (CQ-B42 hash-guard skip)
// -----------------------------------------------------------------------
//
// Persists the sha256 hash of the permission registry per tenant so that
// repeated restarts with an unchanged registry skip the UPSERT storm.

const SCHEMA_V20: &str = "\
-- =======================================================================
-- Seeder state (tenant scope) — hash-guard for permission seeder (CQ-B42)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS seeder_state SCHEMAFULL TYPE NORMAL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE seeder_state TYPE string;
DEFINE FIELD IF NOT EXISTS hash ON TABLE seeder_state TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE seeder_state TYPE datetime
    DEFAULT time::now();
";

// -----------------------------------------------------------------------
// Schema v21 — rate_limit_bucket (SECHRD-03 / D-01a shared rate-limit store)
// -----------------------------------------------------------------------
//
// Backs the multi-replica shared rate-limit counter (windowed CAS via
// UPSERT ... RETURN AFTER). Record IDs are `format!("{endpoint}:{ip}")` so
// per-endpoint limits are preserved across replicas under HPA. This table
// is read/written ONLY by the REST shared-store pre-check middleware
// (`axiam-api-rest::middleware::rate_limit_shared`), which fails OPEN to
// the existing per-replica in-memory Governor on any error (D-01b) — never
// a hard block on auth traffic.

const SCHEMA_V21: &str = "\
-- =======================================================================
-- Rate limit bucket (global scope) — shared multi-replica counter
-- =======================================================================
DEFINE TABLE IF NOT EXISTS rate_limit_bucket SCHEMAFULL TYPE NORMAL;
DEFINE FIELD IF NOT EXISTS count ON TABLE rate_limit_bucket TYPE int DEFAULT 0;
DEFINE FIELD IF NOT EXISTS window_start ON TABLE rate_limit_bucket TYPE datetime;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE rate_limit_bucket TYPE datetime
    DEFAULT time::now();
";

// -----------------------------------------------------------------------
// Schema v22 — bootstrap atomicity + mandatory gate (SECHRD-04 / SEC-049)
// -----------------------------------------------------------------------
//
// Three additive tables backing the atomic single-super-admin invariant
// and the mandatory first-run gate:
//
// - `bootstrap_lock`: record ID = tenant_id. The bootstrap transaction
//   CREATEs a lock record for the target tenant; a concurrent second
//   request racing on the SAME tenant_id hits a UNIQUE-index violation on
//   this CREATE (the record ID itself IS the uniqueness constraint) and
//   its whole transaction rolls back — no partial admin, no orphan role
//   RELATE (D-03c).
// - `bootstrap_setup_token`: record ID = sha256(token) hex. Stores ONLY
//   the token hash — the plaintext token is never persisted, only logged
//   once at first boot (D-03b).
// - `bootstrap_setup_token_consumed`: record ID = sha256(token) hex.
//   Consumption-by-existence: the bootstrap transaction CREATEs this
//   record in the SAME transaction as the admin user, so a replay of the
//   same token also loses to the same UNIQUE-index violation.

const SCHEMA_V22: &str = "\
-- =======================================================================
-- Bootstrap atomicity + mandatory gate (SECHRD-04 / SEC-049)
-- =======================================================================
DEFINE TABLE IF NOT EXISTS bootstrap_lock SCHEMAFULL TYPE NORMAL;
DEFINE FIELD IF NOT EXISTS locked_at ON TABLE bootstrap_lock TYPE datetime
    DEFAULT time::now();

DEFINE TABLE IF NOT EXISTS bootstrap_setup_token SCHEMAFULL TYPE NORMAL;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE bootstrap_setup_token TYPE datetime
    DEFAULT time::now();

DEFINE TABLE IF NOT EXISTS bootstrap_setup_token_consumed SCHEMAFULL TYPE NORMAL;
DEFINE FIELD IF NOT EXISTS consumed_at ON TABLE bootstrap_setup_token_consumed TYPE datetime
    DEFAULT time::now();
";

// -----------------------------------------------------------------------
// Schema v23 — email_config.provider_kind becomes optional (28-04/FUNC-03)
// -----------------------------------------------------------------------
//
// `SurrealEmailConfigRepository::set_tenant_override` has always written
// `provider_kind = ''` when the caller's override does not touch the
// provider (a tenant may override only `from_name`/`enabled`, leaving the
// provider inherited from the org baseline — `get_tenant_override` already
// treats an empty `provider_kind` as "no provider override" on the read
// side). The original v15 ASSERT only allowed the five real provider-kind
// values, so this legitimate partial-override write path always violated
// the schema constraint. `OVERWRITE` extends the ASSERT to also accept the
// empty-string sentinel, matching the read-side contract, without touching
// scope='org' rows (org config always sets a real provider_kind).

const SCHEMA_V23: &str = "\
-- Allow empty provider_kind (sentinel: tenant override does not touch the
-- provider) alongside the five real provider kinds (28-04).
DEFINE FIELD OVERWRITE provider_kind ON TABLE email_config TYPE string
    ASSERT $value IN ['', 'smtp', 'send_grid', 'postmark', 'resend', 'brevo'];
";

// -----------------------------------------------------------------------
// Schema v24 — tenant.status + service_account.description
// -----------------------------------------------------------------------
//
// Two additive fields flagged as pre-MVP polish:
//
// - `tenant.status`: a lifecycle enum (Active/Suspended) mirroring the
//   existing `service_account.status` string-enum pattern. `tenant` is
//   SCHEMAFULL and this field is a required `string`, so any pre-existing
//   tenant row (which physically lacks the column) would fail read-side
//   deserialization; the backfill UPDATE sets every existing row to
//   'Active' before it can be read. New rows created by the repository set
//   status = 'Active' explicitly.
// - `service_account.description`: an OPTIONAL free-text field
//   (`option<string>`), so absent rows simply read back as NONE and need
//   no backfill.
//
// `IF NOT EXISTS` keeps both DEFINE FIELDs idempotent.

const SCHEMA_V24: &str = "\
-- Tenant lifecycle status (new required field; backfill existing rows).
DEFINE FIELD IF NOT EXISTS status ON TABLE tenant TYPE string
    ASSERT $value IN ['Active', 'Suspended'] DEFAULT 'Active';
UPDATE tenant SET status = 'Active' WHERE status = NONE;
-- Service account optional description (no backfill: option<string> reads
-- back as NONE when absent).
DEFINE FIELD IF NOT EXISTS description ON TABLE service_account TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v25 — grants.effect (B1, deny-override)
// -----------------------------------------------------------------------
//
// `grants` is the role->permission edge and is SCHEMAFULL, so the new
// `effect` column has to be declared before the repository can project it —
// SurrealDB rejects an unknown field on a SCHEMAFULL table outright, which is
// exactly what this migration exists to stop.
//
// **`option<string>`, and therefore no backfill.** An absent effect reads back
// as NONE, which the row mapper turns into `PermissionEffect::Allow` — the
// meaning every pre-B1 grant already had. Making the field required and
// backfilling it would work too, but it would touch every grant edge in the
// deployment to write a value that changes nothing, and a migration that
// rewrites the authorization tables is a migration that can fail halfway
// through the authorization tables.
//
// The ASSERT is the load-bearing half. `effect` decides whether a grant
// permits or refuses, so a value that is neither 'allow' nor 'deny' has no
// defined meaning; the read path defaults such a value to 'allow' rather than
// erroring (it must not take authorization down over one bad row), which means
// the *write* path is the only place that can keep the column honest. Rejecting
// it here makes "a grant edge always says allow, deny, or nothing" an invariant
// of the datastore rather than a convention of the code above it.
const SCHEMA_V25: &str = "\
DEFINE FIELD IF NOT EXISTS effect ON TABLE grants TYPE option<string>
    ASSERT $value = NONE OR $value IN ['allow', 'deny'];
";

// -----------------------------------------------------------------------
// Schema v26 — device_grant (B2, RFC 8628 Device Authorization Grant)
// -----------------------------------------------------------------------
//
// SCHEMAFULL like every other table, so the shape is enforced rather than
// conventional.
//
// Two indexes, and both are load-bearing rather than merely helpful:
//
// - `idx_device_grant_user_code` is UNIQUE per tenant. The user code is the
//   short string a human types on a second device, so it is *guessable* by
//   construction — 8 characters from a 20-letter alphabet. A collision would
//   mean one user's approval landing on another user's device, which is the
//   worst failure this feature can have, so uniqueness is a datastore
//   invariant rather than a retry loop's good intentions.
// - `idx_device_grant_code_hash` is UNIQUE globally. The device code is a
//   256-bit CSPRNG value stored as a SHA-256 hash; the index exists so the
//   poll path — which runs every few seconds per device, forever, by design —
//   is an index lookup rather than a scan over every pending grant in the
//   deployment.
//
// `status` is ASSERTed to the four states rather than left free-form. The read
// path refuses to deserialize an unrecognised status (guessing which state a
// row is in is the one unacceptable answer when the states differ by whether
// they grant access), so the ASSERT is what stops such a row existing.
const SCHEMA_V26: &str = "\
DEFINE TABLE IF NOT EXISTS device_grant SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE device_grant TYPE string;
DEFINE FIELD IF NOT EXISTS client_id ON TABLE device_grant TYPE string;
DEFINE FIELD IF NOT EXISTS device_code_hash ON TABLE device_grant TYPE string;
DEFINE FIELD IF NOT EXISTS user_code ON TABLE device_grant TYPE string;
DEFINE FIELD IF NOT EXISTS scopes ON TABLE device_grant TYPE array<string> DEFAULT [];
DEFINE FIELD IF NOT EXISTS status ON TABLE device_grant TYPE string
    ASSERT $value IN ['pending', 'approved', 'denied', 'redeemed'] DEFAULT 'pending';
DEFINE FIELD IF NOT EXISTS user_id ON TABLE device_grant TYPE option<string>;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE device_grant TYPE datetime;
DEFINE FIELD IF NOT EXISTS interval_secs ON TABLE device_grant TYPE int DEFAULT 5;
DEFINE FIELD IF NOT EXISTS last_polled_at ON TABLE device_grant TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE device_grant TYPE datetime DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_device_grant_user_code
    ON TABLE device_grant FIELDS tenant_id, user_code UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_device_grant_code_hash
    ON TABLE device_grant FIELDS device_code_hash UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v27 — RP-initiated logout, back-channel logout, PAR (B5)
// -----------------------------------------------------------------------
//
// Three additive client-registration fields and one new table. Every
// existing client keeps working: the two arrays default empty, the URI is
// optional, and `require_par` defaults false, so a registration that
// predates this migration behaves exactly as it did.
//
// `post_logout_redirect_uris` is deliberately a SEPARATE list from
// `redirect_uris` rather than a reuse of it. They are allow-lists for
// different things — one receives an authorization code, the other receives
// a browser after a session ended — and deployments routinely want the
// second to be a marketing page that must never be a code destination.
// Reusing one list would silently widen the code allow-list the first time
// an operator added a post-logout landing page.
//
// `pushed_auth_request` mirrors `device_grant`'s shape for the same reasons:
// the lookup key is a hash of a 256-bit CSPRNG value (the `request_uri` is a
// bearer credential for the 60 s it lives, so the plaintext is never
// stored), and the index on it is UNIQUE globally because the authorize
// path resolves it on every PAR-initiated login.
//
// `consumed` exists rather than deleting the row on use: RFC 9126 requires
// single-use, and the difference between "never existed" and "already used"
// is worth having in an audit trail even though both answer
// `invalid_request` on the wire.
const SCHEMA_V27: &str = "\
DEFINE FIELD IF NOT EXISTS post_logout_redirect_uris ON TABLE oauth2_client
    TYPE array DEFAULT [];
DEFINE FIELD IF NOT EXISTS post_logout_redirect_uris.* ON TABLE oauth2_client TYPE string;
DEFINE FIELD IF NOT EXISTS backchannel_logout_uri ON TABLE oauth2_client TYPE option<string>;
DEFINE FIELD IF NOT EXISTS require_par ON TABLE oauth2_client TYPE bool DEFAULT false;

DEFINE TABLE IF NOT EXISTS pushed_auth_request SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE pushed_auth_request TYPE string;
DEFINE FIELD IF NOT EXISTS client_id ON TABLE pushed_auth_request TYPE string;
DEFINE FIELD IF NOT EXISTS request_uri_hash ON TABLE pushed_auth_request TYPE string;
DEFINE FIELD IF NOT EXISTS params ON TABLE pushed_auth_request TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD IF NOT EXISTS consumed ON TABLE pushed_auth_request TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE pushed_auth_request TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE pushed_auth_request TYPE datetime DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_pushed_auth_request_uri_hash
    ON TABLE pushed_auth_request FIELDS request_uri_hash UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v28 — session/client participation for back-channel logout (B5)
// -----------------------------------------------------------------------
//
// Back-channel logout notifies "every client that participated in the session
// that just ended". Two things have to exist for that sentence to be
// implementable, and neither did.
//
// **`session_client` is a table, not a column on `session`.** One AXIAM
// session serves many relying parties — that is what SSO *is* — so a single
// `client_id` on the session would record only whichever RP happened to log
// in last, and back-channel logout would silently skip every other RP the
// user was signed into. The row is written when an authorization code is
// issued, which is the moment a client actually joins the session.
//
// The index is on `(tenant_id, session_id)` rather than UNIQUE across the
// triple: a client legitimately re-authorizes within one session (a second
// tab, a refreshed consent), and making that a constraint violation would
// turn a normal flow into an error. Duplicates are deduplicated at fan-out
// time, where the cost is a small in-memory set rather than a write failure.
//
// **`oauth2_auth_code.session_id`** carries the session through to the
// token endpoint so the ID token can assert `sid`. Without it the ID token
// names a user but not a session, and both halves of B5 need session
// precision: RP-initiated logout must end *one* session (a user with a phone
// and a laptop expects the other to survive), and a logout token carrying
// only `sub` tells an RP to end every session it holds for that user, which
// is not what happened.
//
// `option<string>` rather than a required field: codes issued before this
// migration have no session, and a device-grant or client-credentials path
// legitimately has none either.
const SCHEMA_V28: &str = "\
DEFINE FIELD IF NOT EXISTS session_id ON TABLE oauth2_auth_code TYPE option<string>;
DEFINE FIELD IF NOT EXISTS session_id ON TABLE oauth2_refresh_token TYPE option<string>;

DEFINE TABLE IF NOT EXISTS session_client SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE session_client TYPE string;
DEFINE FIELD IF NOT EXISTS session_id ON TABLE session_client TYPE string;
DEFINE FIELD IF NOT EXISTS client_id ON TABLE session_client TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON TABLE session_client TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE session_client TYPE datetime DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_session_client_session
    ON TABLE session_client FIELDS tenant_id, session_id;
";

// -----------------------------------------------------------------------
// Schema v29 — reactor registrations (X1)
// -----------------------------------------------------------------------
//
// A `reactor` row is a registration, not a secret: it says which events an
// external actor subscribes to and what happens when it does not answer. The
// signing key it authenticates with is the tenant's existing AMQP subkey
// (HKDF-derived per §8), so nothing key-shaped is stored here.
//
// Two ASSERTs are load-bearing, for the same reason the v25 `effect` ASSERT
// is. `mode` and `failure_policy` both decide behaviour on the security path —
// whether a reply can veto, and whether an unreachable veto passes — and the
// read path defaults an unparseable value to the *safe* side rather than
// erroring (it must not take token issuance down over one bad row). That makes
// the write path the only place the column can be kept honest.
//
// `timeout_ms` is asserted at the same 5000 ms ceiling `MAX_TIMEOUT_MS`
// enforces in `axiam-core`, so a row written outside the API cannot make the
// dispatcher wait longer than the API would ever allow. The two constants have
// to move together; the repository tests pin that.
//
// `events` is NOT constrained here. The valid set lives in `EVENT_REGISTRY`
// and grows with the code; encoding it in an ASSERT would mean a schema
// migration every time a hook is added, and a mismatch between the two would
// be resolved in favour of whichever was edited last. The registry validates
// on write and the dispatcher ignores an unknown name on read.
const SCHEMA_V29: &str = "\
DEFINE TABLE IF NOT EXISTS reactor SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE reactor TYPE string;
DEFINE FIELD IF NOT EXISTS name ON TABLE reactor TYPE string;
DEFINE FIELD IF NOT EXISTS description ON TABLE reactor TYPE string DEFAULT '';
DEFINE FIELD IF NOT EXISTS events ON TABLE reactor TYPE array<string>;
DEFINE FIELD IF NOT EXISTS mode ON TABLE reactor TYPE string
    ASSERT $value IN ['intercept', 'listen'];
DEFINE FIELD IF NOT EXISTS priority ON TABLE reactor TYPE int DEFAULT 0;
DEFINE FIELD IF NOT EXISTS timeout_ms ON TABLE reactor TYPE int
    ASSERT $value > 0 AND $value <= 5000;
DEFINE FIELD IF NOT EXISTS failure_policy ON TABLE reactor TYPE string
    ASSERT $value IN ['fail_open', 'fail_closed'];
DEFINE FIELD IF NOT EXISTS enabled ON TABLE reactor TYPE bool DEFAULT true;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE reactor TYPE datetime DEFAULT time::now();
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE reactor TYPE datetime DEFAULT time::now();
DEFINE FIELD IF NOT EXISTS last_seen_at ON TABLE reactor TYPE option<datetime>;
-- The dispatcher's hot lookup is 'the enabled reactors for this tenant',
-- resolved once per interceptable event and then held in the routing table.
DEFINE INDEX IF NOT EXISTS idx_reactor_tenant_enabled
    ON TABLE reactor FIELDS tenant_id, enabled;
-- A tenant's reactor names are unique, so a re-registration updates rather
-- than silently doubling the interceptor chain for an event.
DEFINE INDEX IF NOT EXISTS idx_reactor_tenant_name
    ON TABLE reactor FIELDS tenant_id, name UNIQUE;
";

// -----------------------------------------------------------------------
// Schema v30 — UMA 2.0 permission tickets (X2)
// -----------------------------------------------------------------------
//
// A permission ticket is a short-lived, single-use bearer credential, so the
// table mirrors `pushed_auth_request` rather than inventing a shape: only the
// SHA-256 of the handle is stored, `consumed` marks redemption instead of
// deleting the row, and expiry is a column the consuming statement can test.
//
// `consumed` is marked rather than the row deleted for the same reason PAR
// does it: "already used" and "never existed" both answer `invalid_grant` on
// the wire, and the audit trail is the only place the difference survives.
//
// The unique index is on `ticket_hash` alone, not (tenant, hash). The handle
// carries 256 bits of entropy, so a collision across tenants is not a
// practical event — but if one ever occurred, a per-tenant index would let the
// same handle exist twice and the `consume` statement would then depend on
// which row the planner reached first. A global unique makes that
// unrepresentable.
//
// `permissions` is FLEXIBLE for the same reason PAR's `params` is: it is an
// array of `(resource_id, resource_scopes)` objects whose shape belongs to the
// domain model, and pinning it here would mean a migration to add a field the
// engine already validates on write.
//
// No ASSERT constrains the scope names. Which names are legal is a property of
// the resource's declared `scope` rows, which change at runtime; an ASSERT
// would freeze that into the schema and be resolved in favour of whichever was
// edited last.
const SCHEMA_V30: &str = "\
DEFINE TABLE IF NOT EXISTS permission_ticket SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE permission_ticket TYPE string;
DEFINE FIELD IF NOT EXISTS client_id ON TABLE permission_ticket TYPE string;
DEFINE FIELD IF NOT EXISTS ticket_hash ON TABLE permission_ticket TYPE string;
DEFINE FIELD IF NOT EXISTS permissions ON TABLE permission_ticket TYPE array<object> FLEXIBLE DEFAULT [];
DEFINE FIELD IF NOT EXISTS consumed ON TABLE permission_ticket TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE permission_ticket TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE permission_ticket TYPE datetime DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_permission_ticket_hash
    ON TABLE permission_ticket FIELDS ticket_hash UNIQUE;
-- The sweeper deletes by (tenant, expiry); without this it is a table scan on
-- the one table that turns over fastest.
DEFINE INDEX IF NOT EXISTS idx_permission_ticket_tenant_expiry
    ON TABLE permission_ticket FIELDS tenant_id, expires_at;
";

// -----------------------------------------------------------------------
// Schema v31 — redemption nonce, so single-use stops depending on the engine
// -----------------------------------------------------------------------
//
// READ THE TWO ADDENDA AT THE END OF THIS COMMENT FIRST — the 2026-08
// re-measurement, then the X6 note, which is the current state. The premise
// below — "SurrealDB does not detect the write-write conflict" — was measured
// on `kv-mem`, which is the TEST engine and not one AXIAM deploys. On the two
// persistent engines the conflict IS detected, and this mechanism is now
// layered ON TOP of an explicit transaction rather than instead of one.
//
// v30 relied on SurrealDB detecting the write-write conflict between two
// concurrent redemptions. Measured, it does not: 8 rounds in 1200 (8 racers
// each) saw two transactions both commit, with zero errors, both returning the
// pre-transition row — two RPTs from one authorization decision.
//
// Three repairs were measured before this one, and the two obvious ones are
// worse than the bug they fix:
//
//   mechanism                                    wrong (this consume path)
//   ------------------------------------------   -------------------------
//   v30: transaction + WHERE consumed = false     1 / 320
//   claim keyed on a record ID                   30 / 1200  (isolated probe)
//   claim on a UNIQUE INDEX, in a transaction     3 / 320
//   this: per-attempt nonce, write then read      1 / 640
//
// Read that table honestly: only the UNIQUE-index result is clearly bad. One
// failure in 640 against one in 320 is a single event either way, and does
// **not** establish that the nonce is less likely to double-redeem than what it
// replaces. What it does establish is that the nonce is not *worse*, and the
// reason to prefer it is mechanical rather than statistical.
//
// The nonce does not ask the engine to arbitrate. Every racer writes its own;
// the last write persists; each racer reads the row back and only the one whose
// nonce survived reports a redemption. Nothing depends on conflict detection or
// constraint enforcement — the two guarantees this engine was measured not to
// provide — and the one remaining window is at least nameable: a racer's write
// can land after another racer's read-back. An opaque failure to detect a
// conflict is not analysable in that way.
//
// No mechanism tested at this layer reaches zero, and closing the window needs
// a guarantee from below it — a storage engine that serialises, or
// single-writer serialisation in front of it. (X6 took the first of those; see
// the second addendum.)
//
// The read-back is deliberately NOT inside a transaction. Under snapshot
// isolation a racer would see its own write and every racer would believe it
// won — the failure would be total rather than occasional.
//
// -----------------------------------------------------------------------
// ADDENDUM, 2026-08 — everything above was measured on the wrong engine
// -----------------------------------------------------------------------
//
// The measurements above, and the ones in #302, were taken against `kv-mem`.
// Every integration test in this crate opened `Surreal::new::<Mem>(())`, so
// `kv-mem` is what "measured" meant. AXIAM does not deploy it: dev and prod
// compose run `surrealkv:`, and so does the k8s StatefulSet.
//
// Re-measured with `tools/surreal-race-probe` on SurrealDB 3.2.3, running the
// v30 shape (one guarded UPDATE inside BEGIN/COMMIT) with 8 racers released
// through a barrier:
//
//   engine          rounds x racers   admitted two winners   attempts aborted
//   -------------   ---------------   --------------------   ----------------
//   kv-mem          1200 x 8          23  (10 on a re-run)   5229 / 9600
//   kv-surrealkv    5000 x 8           0                     21613 / 40000
//   kv-rocksdb      1200 x 8           0                     8154 / 9600
//
// The abort column matters more than the winners column. `kv-mem` is not
// failing to arbitrate — it aborts contended attempts at 54%, the same rate
// `surrealkv` does. It arbitrates and then occasionally misses, silently, both
// callers receiving the pre-transition row. The persistent engines did not miss
// once, so on the engine AXIAM ships, v30 was already correct.
//
// What that means for this mechanism, and what it does not:
//
//   * The nonce is KEPT. It costs one extra write and one extra read on a rare
//     operation, it measured no worse than v30 on every engine, and conflict
//     detection is not a documented SurrealDB guarantee — so a version bump
//     could take it away silently. Removing working defence to reclaim two
//     statements is a bad trade.
//   * The nonce is NOT the thing standing between AXIAM and a double
//     redemption on a deployed system. The engine is. Do not read the presence
//     of this field as licence to run `memory` anywhere real; `kv-mem` leaks
//     with the nonce in place too (6 rounds in 1200).
//   * "Single-use is not guaranteed" above is still the correct posture, but
//     for a narrower reason than it says: 0 in 40 000 is strong evidence, not
//     proof, and no probe run reproduces the coverage-instrumented, saturated
//     conditions #302 describes.
//
// `WHERE consumed = false` is still required: it is what makes a later,
// non-concurrent redemption match nothing and leave the first winner's nonce
// undisturbed.
//
// -----------------------------------------------------------------------
// ADDENDUM 2, X6 (#302 closed) — the current state of this mechanism
// -----------------------------------------------------------------------
//
// Everything above describes a choice between the transaction and the nonce.
// X6 stopped choosing. All three consume paths now run BOTH:
//
//   1. the guarded `UPDATE` inside an explicit `BEGIN`/`COMMIT`, so the
//      deployed engine arbitrates and aborts the loser (54% of contended
//      attempts on `surrealkv`, 0 double winners in 40 000); and
//   2. the per-attempt nonce, read back in a SEPARATE QUERY AFTER THE COMMIT,
//      which asks the engine for nothing and therefore still catches a
//      conflict the engine silently missed.
//
// The read-back's position is the load-bearing detail and the reason this is
// two queries rather than one transaction: inside the transaction, snapshot
// isolation shows every racer its own write, so every racer reads back its own
// nonce and believes it won. Folding the read-back inside would convert an
// occasional double redemption into a certain one. Do not "simplify" it.
//
// So the posture changes, and this is the wording #302 was holding open until
// the fix landed: **single-use is guaranteed, conditional on an attested
// persistent storage engine** — the transaction arbitrating, the nonce
// auditing. A double redemption now requires two independent failures rather
// than one. On `kv-mem` it remains explicitly NOT guaranteed (the nonce leaks
// there too, 6 rounds in 1200), which is why `axiam-server` attests the engine
// at startup and refuses a positively-identified `memory` datastore unless
// `AXIAM__DB__ALLOW_MEMORY_ENGINE=true` — see
// `crate::engine_attestation`, including its finding that SurrealDB 3.2.4
// exposes no engine identity over the wire, so today that attestation is a
// WARN plus a MUST-level operator requirement in `docs/deployment/README.md`.
//
// The escalation path if a future engine bump breaks this, recorded and
// deliberately NOT built: single-writer serialisation in front of the
// datastore via a RabbitMQ single-active-consumer redemption queue. It is
// disproportionate against 0/40 000 plus a layered mechanism; build it when
// the measurement says to.
//
// Re-run the probe on any SurrealDB bump — README.md in that directory says
// why and how, `RESULTS.md` records what each pinned version measured, and
// `.github/workflows/surreal-race-probe.yml` makes it a required check
// whenever `Cargo.lock` moves `surrealdb`, `surrealdb-core` or `surrealkv`, so
// a bump can no longer change this silently.
const SCHEMA_V31: &str = "\
DEFINE FIELD IF NOT EXISTS redemption_id ON TABLE permission_ticket TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v32 — the same nonce for the other two single-use consumes
// -----------------------------------------------------------------------
//
// v31 fixed `permission_ticket.consume`. `device_grant.redeem` and
// `pushed_auth_request.consume` were written in the same shape, at the same
// time, on the same understanding — that `BEGIN`/`COMMIT` makes SurrealDB
// detect the write-write conflict and abort every loser. On `kv-mem` it does
// not, so on that engine those two carried the same defect.
//
// They were not measured failing. That is not evidence they are sound: the
// permission-ticket race needed coverage instrumentation *plus* a saturated
// machine to show up at roughly 1 in 320, and these two are tested exactly the
// same way the ticket was when its own test was passing. "Not yet observed" and
// "cannot happen" are different statements, and the mechanism is shared.
//
// What each protects, if it does fail:
//
//   device_grant.redeem          — one user approval minting two token sets
//                                  (RFC 8628 §3.4 polls on a short interval and
//                                  retries, so concurrency here is the normal
//                                  shape of the flow, not an exotic case)
//   pushed_auth_request.consume  — a replayable RFC 9126 `request_uri`, which
//                                  is a replayable authorization request
//
// See `SCHEMA_V31` for the mechanism and the measurements behind choosing it,
// including the two repairs that turned out worse than the defect; its 2026-08
// addendum, which re-measured all of it on the engine AXIAM actually deploys
// and found the premise engine-specific; and its X6 addendum, which is the
// current state. The short version: these two paths are in exactly the same
// position as the ticket. All three now run the transaction AND the nonce, and
// single-use is guaranteed on an attested persistent engine — not on `kv-mem`,
// which `axiam-server` refuses when it can identify it.
const SCHEMA_V32: &str = "\
DEFINE FIELD IF NOT EXISTS redemption_id ON TABLE device_grant TYPE option<string>;
DEFINE FIELD IF NOT EXISTS redemption_id ON TABLE pushed_auth_request TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v33 — which client registered a resource through the UMA
// Protection API (X2)
// -----------------------------------------------------------------------
//
// X2 asks for a read-only "UMA" badge on resources registered via the
// Protection API. The obvious place to put that is `metadata`, which already
// exists on `resource` and is already returned by the API — no migration, no
// new field.
//
// It is the wrong place. `metadata` is writable through the ordinary resource
// endpoints, so any caller who may edit a resource could set the marker on a
// resource the Protection API never touched. A badge that asserts provenance
// and can be written by anyone is not a provenance record; it is decoration
// that reads like evidence.
//
// So it is its own field, written only by the resource-registration handler
// and never by `UpdateResource`. `None` means "not registered through UMA",
// which is also what every pre-existing row means — the migration adds a field
// rather than backfilling a claim about resources nobody registered.
const SCHEMA_V33: &str = "\
DEFINE FIELD IF NOT EXISTS uma_registered_by ON TABLE resource TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v34 — a key for resource-delete and child-create to collide on (#308)
// -----------------------------------------------------------------------
//
// `resource.delete` refuses to delete a resource that has children, and folds
// the check into its own transaction:
//
//     BEGIN;
//     LET $children = (SELECT VALUE id FROM child_of WHERE out = resource:<id>);
//     IF array::len($children) > 0 { THROW ... };
//     DELETE ...; DELETE type::record('resource', $id) ...;
//     COMMIT;
//
// D-13/CQ-B46 introduced that shape to close a TOCTOU window and described it
// as making the read-then-decide-then-delete atomic. It does make the
// statements atomic. That is not the property the guard needs, and #308 is the
// proof: on `surrealkv` a concurrent child-create beats it on trial 0 of every
// run, leaving a deleted parent with a live `child_of` edge pointing at it.
//
// The guard is a RANGE READ — every edge whose `out` is this parent — and the
// racing create INSERTS INTO THAT RANGE. Excluding that is the definition of a
// phantom, and preventing phantoms takes serialisable isolation. These engines
// give snapshot isolation: they detect write-write conflicts on the same key
// (measured doing exactly that, 21613 aborts in 40000 contended attempts — see
// `tools/surreal-race-probe`), and they let this through because the two
// transactions have no key in common. The delete writes the parent row and the
// edges it could see; the create writes a NEW edge the delete never saw.
//
// No query can fix that, because the guard cannot read a row that does not
// exist yet. What fixes it is giving the two transactions a shared key, so the
// conflict the engine already detects reliably is the one that decides the
// race. That is what this field is for:
//
//   * `resource.delete` already writes the parent row — it deletes it.
//   * Every path that adds a child edge now also writes the parent row, by
//     bumping `child_epoch`, inside the same transaction as the RELATE.
//
// One of the two must now lose. If the create commits first, the delete's write
// to the parent conflicts and it aborts, leaving parent and child intact. If
// the delete commits first, the create's bump matches no row, its guard throws,
// and no edge is written. Neither order produces an orphan.
//
// The counter's VALUE is not used for anything and deliberately so — reading it
// would be a second way to get this wrong. Its only job is to be a write to the
// parent's key. It is `option<int>` rather than `int DEFAULT 0` so that rows
// predating this migration need no backfill: `child_epoch ?? 0` treats absent
// and zero alike, and nothing distinguishes "never had a child" from "has had
// exactly zero".
const SCHEMA_V34: &str = "\
DEFINE FIELD IF NOT EXISTS child_epoch ON TABLE resource TYPE option<int>;
";

// -----------------------------------------------------------------------
// Schema v35 — WebAuthn attestation policy + FIDO MDS3 storage (X3 wave 2)
// -----------------------------------------------------------------------
//
// Three additive, brand-new tables — no existing table's shape changes here
// except the additive `webauthn_credential` columns at the bottom (D6), which
// are all `option<..>`/`DEFAULT false` so every pre-X3 row keeps reading back
// unchanged (no backfill, same reasoning as v25's `grants.effect`).
//
// - `webauthn_attestation_policy` (D5): tenant-scoped, **one row per tenant**.
//   `idx_webauthn_attestation_policy_tenant` is UNIQUE on `tenant_id` so a
//   double-write can never leave two rows for the same tenant (the repository
//   upserts via a v5-UUID deterministic record id derived from tenant_id, the
//   same pattern `security_settings` already uses — this index is the
//   datastore-level backstop, not the only guard). An absent row means
//   `WebauthnAttestationPolicy::default()` (D5) — there is no "empty policy"
//   row ever written for that case, so the table only ever holds tenants that
//   explicitly opted into a non-default policy.
// - `mds_entry` (D10): **server-global**, not tenant-scoped — every tenant
//   looks up the same AAGUID against the same FIDO Alliance BLOB. Keyed by a
//   generated record id (house convention — every other table in this schema
//   uses a generated id rather than a domain value as the primary key), with
//   `aaguid` as an indexed, UNIQUE field so the registration-time lookup
//   (`MdsRepository::get_by_aaguid`) is a single index seek. `status_reports`
//   is stored as a JSON string (`status_reports_json`) rather than a nested
//   SurrealDB array-of-objects — it is opaque, read-only-as-a-whole audit/
//   policy data (never queried by sub-field), so a JSON blob column avoids
//   modelling FIDO's `StatusReport` schema a second time in DDL.
// - `mds_blob_meta` (D10): **server-global, single row**. Record id is the
//   fixed sentinel `mds_blob_meta:singleton` — the same "deterministic
//   record id as the uniqueness constraint" pattern `_migration_lock:startup`
//   already uses, so there is structurally never more than one row.
//
// `min_certification` and `unknown_aaguid` follow v25's `option<string>
// ASSERT $value = NONE OR $value IN [...]` pattern for an optional enum-like
// column.
const SCHEMA_V35: &str = "\
-- =======================================================================
-- WebAuthn attestation policy (tenant scope, one row per tenant) — D5
-- =======================================================================
DEFINE TABLE webauthn_attestation_policy SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE webauthn_attestation_policy TYPE string;
DEFINE FIELD mode ON TABLE webauthn_attestation_policy TYPE string
    ASSERT $value IN ['none', 'indirect', 'direct_required'];
DEFINE FIELD require_fido_certified ON TABLE webauthn_attestation_policy TYPE bool
    DEFAULT false;
DEFINE FIELD min_certification ON TABLE webauthn_attestation_policy TYPE option<string>
    ASSERT $value = NONE OR $value IN ['L1', 'L1plus', 'L2', 'L2plus', 'L3', 'L3plus'];
DEFINE FIELD allowed_aaguids ON TABLE webauthn_attestation_policy TYPE option<array<string>>;
DEFINE FIELD blocked_aaguids ON TABLE webauthn_attestation_policy TYPE array<string>
    DEFAULT [];
DEFINE FIELD block_revoked_status ON TABLE webauthn_attestation_policy TYPE bool
    DEFAULT true;
DEFINE FIELD unknown_aaguid ON TABLE webauthn_attestation_policy TYPE option<string>
    ASSERT $value = NONE OR $value IN ['allow', 'deny'];
DEFINE FIELD created_at ON TABLE webauthn_attestation_policy TYPE datetime
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE webauthn_attestation_policy TYPE datetime
    DEFAULT time::now();
DEFINE INDEX idx_webauthn_attestation_policy_tenant
    ON TABLE webauthn_attestation_policy COLUMNS tenant_id UNIQUE;

-- =======================================================================
-- FIDO MDS3 metadata (server-global, NOT tenant-scoped) — D10
-- =======================================================================
DEFINE TABLE mds_entry SCHEMAFULL;
DEFINE FIELD aaguid ON TABLE mds_entry TYPE string;
DEFINE FIELD description ON TABLE mds_entry TYPE option<string>;
DEFINE FIELD attestation_root_certificates ON TABLE mds_entry TYPE array<string>
    DEFAULT [];
DEFINE FIELD status_reports_json ON TABLE mds_entry TYPE string DEFAULT '[]';
DEFINE FIELD time_of_last_status_change ON TABLE mds_entry TYPE option<string>;
DEFINE INDEX idx_mds_entry_aaguid ON TABLE mds_entry COLUMNS aaguid UNIQUE;

DEFINE TABLE mds_blob_meta SCHEMAFULL;
DEFINE FIELD no ON TABLE mds_blob_meta TYPE int;
DEFINE FIELD next_update ON TABLE mds_blob_meta TYPE string;
DEFINE FIELD entry_count ON TABLE mds_blob_meta TYPE int;
DEFINE FIELD last_refreshed_at ON TABLE mds_blob_meta TYPE datetime;
DEFINE FIELD stale ON TABLE mds_blob_meta TYPE bool DEFAULT false;

-- =======================================================================
-- WebAuthn credential attestation metadata (additive, no migration) — D6
-- =======================================================================
DEFINE FIELD IF NOT EXISTS aaguid ON TABLE webauthn_credential TYPE option<string>;
DEFINE FIELD IF NOT EXISTS attestation_format ON TABLE webauthn_credential TYPE option<string>;
DEFINE FIELD IF NOT EXISTS attested ON TABLE webauthn_credential TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS authenticator_name ON TABLE webauthn_credential TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v36 — external-IdP token-exchange trust on federation providers (X4)
// -----------------------------------------------------------------------
//
// Purely additive columns on the existing `federation_config` table. Every
// pre-X4 row reads back as `TokenExchangeTrust::default()` — the repository
// maps a missing/NONE column to the default rather than relying on a DB
// DEFAULT, so there is no backfill and no window in which a row is half-X4.
//
// `token_exchange_enabled` DEFAULTs to **false**, which is the whole safety
// story of this migration: turning on X4 for a provider is an explicit act,
// never a consequence of upgrading. An operator who configured Okta for login
// did not thereby agree to accept Okta tokens as API credentials.
//
// `token_exchange_scope_map` is a JSON string rather than a nested SurrealDB
// object, for the same reason `mds_entry.status_reports_json` is (v35): it is
// read and written whole, never queried by sub-field, and modelling a
// map-of-arrays in DDL a second time buys nothing. `accepted_audiences` IS a
// native array — it is a list of scalars, and an operator reading the row
// should be able to see at a glance which audiences a provider trusts.
//
// `subject_mapping` follows v25/v35's `option<string> ASSERT $value = NONE OR
// $value IN [...]` pattern for an optional enum-like column; NONE means
// `linked_only`, the stricter of the two.
const SCHEMA_V36: &str = "\
DEFINE FIELD IF NOT EXISTS token_exchange_enabled ON TABLE federation_config
    TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS token_exchange_accepted_audiences ON TABLE federation_config
    TYPE array<string> DEFAULT [];
DEFINE FIELD IF NOT EXISTS token_exchange_subject_mapping ON TABLE federation_config
    TYPE option<string>
    ASSERT $value = NONE OR $value IN ['linked_only', 'jit_provision'];
DEFINE FIELD IF NOT EXISTS token_exchange_scope_map_json ON TABLE federation_config
    TYPE string DEFAULT '{}';
DEFINE FIELD IF NOT EXISTS token_exchange_max_token_age_secs ON TABLE federation_config
    TYPE option<int>;
DEFINE FIELD IF NOT EXISTS token_exchange_max_lifetime_secs ON TABLE federation_config
    TYPE option<int>;
DEFINE INDEX IF NOT EXISTS idx_federation_config_tenant_tx ON TABLE federation_config
    COLUMNS tenant_id, token_exchange_enabled;
";

// -----------------------------------------------------------------------
// Schema v37 — the fourth single-use consume joins the layered mechanism
// -----------------------------------------------------------------------
//
// v31 and v32 gave `permission_ticket.consume`, `device_grant.redeem` and
// `pushed_auth_request.consume` a per-attempt redemption nonce, and X6 layered
// an explicit transaction underneath all three. `oauth2_auth_code.consume` is
// the fourth single-use consume in this crate and did not get either.
//
// It was never in #302's scope, and it is not broken: its redemption is ONE
// statement, so it already runs in the engine's own transaction and two
// concurrent callers conflict on one key. That is the same first layer the
// other three now have — it just arrives implicitly rather than by writing
// `BEGIN`/`COMMIT`.
//
// What it did not have is the second layer. Every argument in `SCHEMA_V31`'s
// X6 addendum for keeping the nonce applies here unchanged: conflict detection
// is not a documented SurrealDB guarantee, a version bump could take it away
// silently, and the cost is one extra write and one extra read on an operation
// that happens once per login. A code redeemed twice is two token pairs from
// one authorization — the same class of outcome as the ticket path's two RPTs,
// and the reason T-54/T-164 in the threat model rate it High.
//
// So this field is the ticket's `redemption_id` for authorization codes, and
// `consume` is rewritten to the same shape as the other three: guarded UPDATE
// inside an explicit transaction, nonce read back in a SEPARATE QUERY AFTER
// THE COMMIT. The read-back's position is load-bearing for the same reason it
// is there — inside the transaction, snapshot isolation shows every racer its
// own write and every racer believes it won.
//
// `option<string>` rather than `string DEFAULT ''` so rows predating this
// migration need no backfill: an authorization code created before v37 and
// redeemed after it simply has no prior nonce to disturb.
const SCHEMA_V37: &str = "\
DEFINE FIELD IF NOT EXISTS redemption_id ON TABLE oauth2_auth_code TYPE option<string>;
";

// -----------------------------------------------------------------------
// Schema v38 — FAPI 2.0 client profile and mTLS client credentials (X5.1)
// -----------------------------------------------------------------------
//
// Seven additive client-registration fields, and every one of them defaults to
// the behaviour a pre-v38 client already had. That is the whole point of the
// design: the FAPI posture is ONE switch (`profile`), and a deployment that
// never touches it cannot be changed by this migration.
//
// - `profile` defaults to `'standard'`, so every existing row keeps the exact
//   constraint set it was registered under. It is a string rather than a bool
//   because the next profile (FAPI Message Signing, or a national variant)
//   should be a new value here, not a second boolean that can contradict the
//   first.
// - `token_endpoint_auth_method` defaults to `'client_secret_post'`, which is
//   what every client did before this migration and what the discovery
//   document advertised.
// - The three `tls_client_auth_*` fields are `option<string>` and mutually
//   exclusive per RFC 8705 §2.1.2. The exclusivity is enforced in the
//   application layer (`OAuth2Client::mtls_binding_count`) rather than by a
//   SurrealDB assertion, because the check spans three fields and needs to
//   produce a caller-facing error message naming which ones collided.
// - `self_signed_tls_client_auth_thumbprints` defaults to `[]`, which reads
//   correctly as "no self-signed certificate is accepted for this client" —
//   the same fail-closed reading as an empty `post_logout_redirect_uris`.
// - `tls_client_certificate_bound_access_tokens` defaults false, so no
//   existing token gains a `cnf` claim and no existing resource server starts
//   seeing a confirmation it does not know how to check.
//
// No backfill and no index. These fields are read on the client-authentication
// path, which already loads the whole row by `(tenant_id, client_id)` through
// `idx_oauth2_tenant_client_id`; indexing a field that is only ever read
// alongside that lookup would cost writes and buy nothing.
const SCHEMA_V38: &str = "\
DEFINE FIELD IF NOT EXISTS profile ON TABLE oauth2_client TYPE string DEFAULT 'standard';
DEFINE FIELD IF NOT EXISTS token_endpoint_auth_method ON TABLE oauth2_client
    TYPE string DEFAULT 'client_secret_post';
DEFINE FIELD IF NOT EXISTS tls_client_auth_subject_dn ON TABLE oauth2_client
    TYPE option<string>;
DEFINE FIELD IF NOT EXISTS tls_client_auth_san_dns ON TABLE oauth2_client TYPE option<string>;
DEFINE FIELD IF NOT EXISTS tls_client_auth_san_uri ON TABLE oauth2_client TYPE option<string>;
DEFINE FIELD IF NOT EXISTS self_signed_tls_client_auth_thumbprints ON TABLE oauth2_client
    TYPE array DEFAULT [];
DEFINE FIELD IF NOT EXISTS self_signed_tls_client_auth_thumbprints.* ON TABLE oauth2_client
    TYPE string;
DEFINE FIELD IF NOT EXISTS tls_client_certificate_bound_access_tokens ON TABLE oauth2_client
    TYPE bool DEFAULT false;
";

// -----------------------------------------------------------------------
// Schema v39 — private_key_jwt client auth and DPoP binding (X5.1)
// -----------------------------------------------------------------------
//
// The second half of two X5.1 rows: the `private_key_jwt` client-authentication
// family (RFC 7523 §2.2) and DPoP sender-constraining (RFC 9449). Same rule v38
// set and this migration keeps: **every new field defaults to pre-v39
// behaviour.**
//
// - `jwks` / `jwks_uri` are `option<string>`, absent for every existing row.
//   Mutually exclusive per RFC 7591 §2, enforced in the application layer
//   (`OAuth2Client::jwks_source_count`) for the same reason the
//   `tls_client_auth_*` exclusivity is: the check spans two fields and owes the
//   caller an error naming which ones collided.
// - `jwks` holds the raw JSON document rather than a parsed structure. A client
//   may legitimately publish a key type this build does not implement, and the
//   right place to discover that is the authentication path — where it is one
//   client failing to authenticate — not row decoding, where it is a client
//   that cannot be read at all.
// - `dpop_bound_access_tokens` defaults false, so no existing token gains a
//   `cnf.jkt` and no resource server starts seeing a confirmation it cannot
//   check.
// - `dpop_require_nonce` defaults false, so enabling DPoP does not silently
//   turn every first request into two round trips.
//
// The replay table is new, and is the reason this migration is not purely
// additive-to-`oauth2_client`. It carries a UNIQUE index over
// `(tenant_id, kind, scope, jti)` and that index is the entire replay
// mechanism: `CREATE` either succeeds — first sighting — or violates the index,
// which the repository reads as `ReplayDetected`. There is deliberately no
// SELECT anywhere in that path. A read-then-write check would leave a window in
// which two concurrent copies of one proof both pass, which is the race #316
// and #318 closed for authorization codes and which a proof-of-possession
// credential can afford even less.
//
// `idx_proof_replay_expires_at` exists for the cleanup sweep only. Without it
// the sweep is a full table scan over a table whose whole purpose is to be
// written to on every authenticated request.
const SCHEMA_V39: &str = "\
DEFINE FIELD IF NOT EXISTS jwks ON TABLE oauth2_client TYPE option<string>;
DEFINE FIELD IF NOT EXISTS jwks_uri ON TABLE oauth2_client TYPE option<string>;
DEFINE FIELD IF NOT EXISTS dpop_bound_access_tokens ON TABLE oauth2_client
    TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS dpop_require_nonce ON TABLE oauth2_client
    TYPE bool DEFAULT false;
DEFINE TABLE IF NOT EXISTS oauth2_proof_replay SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE oauth2_proof_replay TYPE string;
DEFINE FIELD IF NOT EXISTS kind ON TABLE oauth2_proof_replay TYPE string
    ASSERT $value IN ['client_assertion', 'dpop_proof'];
DEFINE FIELD IF NOT EXISTS scope ON TABLE oauth2_proof_replay TYPE string;
DEFINE FIELD IF NOT EXISTS jti ON TABLE oauth2_proof_replay TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE oauth2_proof_replay TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE oauth2_proof_replay TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_proof_replay_uniq ON TABLE oauth2_proof_replay \
    COLUMNS tenant_id, kind, scope, jti UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_proof_replay_expires_at ON TABLE oauth2_proof_replay \
    COLUMNS expires_at;
";

// -----------------------------------------------------------------------
// Schema v40 — SCIM provisioning tokens
// -----------------------------------------------------------------------
//
// The long-lived credential an IdP pastes into its SCIM connector — see
// `claude_dev/scim-provisioning-token-design.md`.
//
// `idx_scim_token_hash` is the one index that is not optional. A presented
// handle is looked up by hash on **every** `/scim/v2/*` request, and it is
// looked up without a tenant (there is no authenticated tenant yet — the row
// is what establishes one), so without this the hot authentication path is a
// full scan of every token in the deployment. UNIQUE additionally makes a hash
// collision a write error rather than an ambiguous lookup that silently
// resolves to whichever row came back first.
//
// `idx_scim_token_tenant` serves the admin list, and `idx_scim_token_user`
// serves the delete-on-user-deletion sweep — without it, removing one user's
// tokens scans the table.
//
// `revoked_at` and `last_used_at` are `option<datetime>` rather than nullable
// datetimes with a sentinel: "never used" and "used at the epoch" are
// different facts, and a sentinel would make them the same one.
const SCHEMA_V40: &str = "\
DEFINE TABLE IF NOT EXISTS scim_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE scim_token TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON TABLE scim_token TYPE string;
DEFINE FIELD IF NOT EXISTS name ON TABLE scim_token TYPE string;
DEFINE FIELD IF NOT EXISTS token_hash ON TABLE scim_token TYPE string;
DEFINE FIELD IF NOT EXISTS created_by ON TABLE scim_token TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE scim_token TYPE datetime;
DEFINE FIELD IF NOT EXISTS last_used_at ON TABLE scim_token TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS revoked_at ON TABLE scim_token TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE scim_token TYPE datetime \
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_scim_token_hash ON TABLE scim_token \
    COLUMNS token_hash UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_scim_token_tenant ON TABLE scim_token \
    COLUMNS tenant_id;
DEFINE INDEX IF NOT EXISTS idx_scim_token_user ON TABLE scim_token \
    COLUMNS tenant_id, user_id;
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

// -----------------------------------------------------------------------
// Schema v41 — Secure Remote Password (SRP-6a)
// -----------------------------------------------------------------------
//
// Two additions:
//
// 1. `srp_credential` — at most one verifier per user. There is deliberately
//    no history table: a verifier is a password equivalent under a slow KDF,
//    and keeping superseded ones would keep superseded passwords crackable for
//    no operational benefit.
//
// 2. Three columns on `security_settings`. They carry `DEFAULT` values *and*
//    an explicit backfill, because a SCHEMAFULL SELECT over a row written
//    before this migration would otherwise yield NONE for them. The Rust side
//    also treats them as optional (see `decode_srp`), so a partially applied
//    migration degrades to "SRP disabled" rather than to a settings read that
//    fails for the whole organization.

const SCHEMA_V41: &str = "\
-- =======================================================================
-- SRP verifiers (tenant scope)
-- =======================================================================
DEFINE TABLE srp_credential SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE srp_credential TYPE string;
DEFINE FIELD user_id ON TABLE srp_credential TYPE string;
-- The canonical identity bound into the client-side KDF that derives x.
-- Always the
-- username; a user may sign in with their email but only one string can be
-- inside the KDF input.
DEFINE FIELD identity ON TABLE srp_credential TYPE string;
DEFINE FIELD srp_group ON TABLE srp_credential TYPE string \
    ASSERT $value IN ['rfc5054_2048', 'rfc5054_3072', 'rfc5054_4096'];
DEFINE FIELD kdf ON TABLE srp_credential TYPE string \
    ASSERT $value IN ['argon2id', 'pbkdf2_sha256'];
DEFINE FIELD kdf_memory_kib ON TABLE srp_credential TYPE option<int>;
DEFINE FIELD kdf_iterations ON TABLE srp_credential TYPE int;
DEFINE FIELD kdf_parallelism ON TABLE srp_credential TYPE option<int>;
DEFINE FIELD salt ON TABLE srp_credential TYPE string;
DEFINE FIELD verifier ON TABLE srp_credential TYPE string;
DEFINE FIELD created_at ON TABLE srp_credential TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE srp_credential TYPE datetime \
    DEFAULT time::now();
-- One verifier per user. UNIQUE is what makes upsert-by-user safe under
-- concurrent password changes.
DEFINE INDEX idx_srp_cred_user ON TABLE srp_credential \
    COLUMNS tenant_id, user_id UNIQUE;

-- =======================================================================
-- SRP policy on security_settings
-- =======================================================================
DEFINE FIELD IF NOT EXISTS srp_mode ON TABLE security_settings TYPE string \
    DEFAULT 'disabled' ASSERT $value IN ['disabled', 'optional', 'required'];
DEFINE FIELD IF NOT EXISTS srp_group ON TABLE security_settings TYPE string \
    DEFAULT 'rfc5054_4096' \
    ASSERT $value IN ['rfc5054_2048', 'rfc5054_3072', 'rfc5054_4096'];
DEFINE FIELD IF NOT EXISTS srp_kdf ON TABLE security_settings TYPE string \
    DEFAULT 'argon2id' ASSERT $value IN ['argon2id', 'pbkdf2_sha256'];
-- Backfill rows that predate the columns. DEFAULT only applies on write.
UPDATE security_settings SET srp_mode = 'disabled' WHERE srp_mode = NONE;
UPDATE security_settings SET srp_group = 'rfc5054_4096' WHERE srp_group = NONE;
UPDATE security_settings SET srp_kdf = 'argon2id' WHERE srp_kdf = NONE;
";

// -----------------------------------------------------------------------
// Schema v42 — OPAQUE (RFC 9807) replaces SRP-6a
// -----------------------------------------------------------------------
//
// v41 is left exactly as it was rather than rewritten in place. Migration
// history is linear and every developer and CI database that has already run
// v41 is sitting at that version; editing it would leave those databases with
// SRP tables and no path forward, because the migration runner would consider
// v41 already applied. A fresh install therefore creates the SRP table and
// drops it moments later, which is a small, one-off cost for a history that is
// true.
//
// Nothing is preserved across the change and nothing needs to be. An SRP
// verifier cannot be converted into an OPAQUE registration record — both are
// sealed against the plaintext password, which the server has never had — and
// AXIAM is unreleased, so no deployment holds verifiers worth carrying.
//
// Three parts:
//
// 1. Drop `srp_credential`, and the three SRP columns on `security_settings`.
//
// 2. `opaque_credential` — at most one record per user. There is deliberately
//    no history table: a record is a password equivalent, and keeping
//    superseded ones would keep superseded passwords attackable for no
//    operational benefit. Note the absence of an `identity` column, which
//    `srp_credential` had: OPAQUE binds to a random `credential_identifier`
//    instead, so renaming a user no longer invalidates their credential.
//
// 3. `opaque_server_setup` — per-tenant OPRF seed and AKE keypair, encrypted
//    at rest. One row per (tenant, suite), UNIQUE, which is what makes
//    `get_or_create` idempotent under two concurrent first logins.

const SCHEMA_V42: &str = "\
-- =======================================================================
-- Remove SRP
-- =======================================================================
REMOVE TABLE IF EXISTS srp_credential;
REMOVE FIELD IF EXISTS srp_mode ON TABLE security_settings;
REMOVE FIELD IF EXISTS srp_group ON TABLE security_settings;
REMOVE FIELD IF EXISTS srp_kdf ON TABLE security_settings;

-- =======================================================================
-- OPAQUE registration records (tenant scope)
-- =======================================================================
DEFINE TABLE opaque_credential SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE opaque_credential TYPE string;
DEFINE FIELD user_id ON TABLE opaque_credential TYPE string;
-- Random 32 bytes, hex. Keys the server's OPRF and is bound into the record.
-- Deliberately unrelated to the username: that is what makes a rename free,
-- where SRP's equivalent binding was the username itself.
DEFINE FIELD credential_identifier ON TABLE opaque_credential TYPE string;
DEFINE FIELD suite ON TABLE opaque_credential TYPE string \
    ASSERT $value IN ['ristretto255_sha512'];
DEFINE FIELD ksf ON TABLE opaque_credential TYPE string \
    ASSERT $value IN ['argon2id', 'scrypt'];
-- Argon2id costs.
DEFINE FIELD ksf_memory_kib ON TABLE opaque_credential TYPE option<int>;
DEFINE FIELD ksf_iterations ON TABLE opaque_credential TYPE option<int>;
DEFINE FIELD ksf_parallelism ON TABLE opaque_credential TYPE option<int>;
-- scrypt costs.
DEFINE FIELD ksf_log_n ON TABLE opaque_credential TYPE option<int>;
DEFINE FIELD ksf_r ON TABLE opaque_credential TYPE option<int>;
DEFINE FIELD ksf_p ON TABLE opaque_credential TYPE option<int>;
-- Serialized RFC 9807 RegistrationRecord, hex.
DEFINE FIELD record ON TABLE opaque_credential TYPE string;
DEFINE FIELD created_at ON TABLE opaque_credential TYPE datetime \
    DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE opaque_credential TYPE datetime \
    DEFAULT time::now();
-- One record per user. UNIQUE is what makes upsert-by-user safe under
-- concurrent password changes.
DEFINE INDEX idx_opaque_cred_user ON TABLE opaque_credential \
    COLUMNS tenant_id, user_id UNIQUE;

-- =======================================================================
-- OPAQUE server key material (tenant scope)
-- =======================================================================
DEFINE TABLE opaque_server_setup SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE opaque_server_setup TYPE string;
DEFINE FIELD suite ON TABLE opaque_server_setup TYPE string \
    ASSERT $value IN ['ristretto255_sha512'];
-- AES-256-GCM sealed. A database dump alone must not hand over the OPRF seed,
-- because that seed is the thing standing between a stolen record and an
-- offline dictionary attack.
DEFINE FIELD sealed_setup ON TABLE opaque_server_setup TYPE string;
DEFINE FIELD sealed_decoy_key ON TABLE opaque_server_setup TYPE string;
DEFINE FIELD created_at ON TABLE opaque_server_setup TYPE datetime \
    DEFAULT time::now();
-- One setup per (tenant, suite). UNIQUE is load-bearing: it is what decides
-- the race between two concurrent first logins, so a tenant cannot end up
-- with two seeds and records that only sometimes open.
DEFINE INDEX idx_opaque_setup_tenant ON TABLE opaque_server_setup \
    COLUMNS tenant_id, suite UNIQUE;

-- =======================================================================
-- OPAQUE policy on security_settings
-- =======================================================================
DEFINE FIELD IF NOT EXISTS opaque_mode ON TABLE security_settings TYPE string \
    DEFAULT 'disabled' ASSERT $value IN ['disabled', 'optional', 'required'];
DEFINE FIELD IF NOT EXISTS opaque_suite ON TABLE security_settings TYPE string \
    DEFAULT 'ristretto255_sha512' \
    ASSERT $value IN ['ristretto255_sha512'];
DEFINE FIELD IF NOT EXISTS opaque_ksf ON TABLE security_settings TYPE string \
    DEFAULT 'argon2id' ASSERT $value IN ['argon2id', 'scrypt'];
-- Backfill rows that predate the columns. DEFAULT only applies on write.
UPDATE security_settings SET opaque_mode = 'disabled' WHERE opaque_mode = NONE;
UPDATE security_settings SET opaque_suite = 'ristretto255_sha512' \
    WHERE opaque_suite = NONE;
UPDATE security_settings SET opaque_ksf = 'argon2id' WHERE opaque_ksf = NONE;
";

// -----------------------------------------------------------------------
// Schema v43 — a tenant email override says *which* fields it overrides
// -----------------------------------------------------------------------
//
// The tenant row reused the org row's columns, which have no way to say
// "inherit this one". `enabled` is the clearest case: every tenant write
// stored a bool, so the read path handed back `Some(..)` for a field the
// operator never touched and the merge treated it as a deliberate override.
// `reply_to` had the opposite problem — no tenant column at all, so a tenant
// could not override it even deliberately.
//
// Two columns, both meaningful only on `scope = 'tenant'` rows:
//
//   * `enabled_override` — NONE inherits the org's delivery switch.
//   * `reply_to_overridden` — when true, this row's `reply_to` is
//     authoritative, *including* a NONE that clears the org's reply-to.
//     Without the flag those two states are the same value.

const SCHEMA_V43: &str = "\
DEFINE FIELD IF NOT EXISTS enabled_override ON TABLE email_config \
    TYPE option<bool>;
DEFINE FIELD IF NOT EXISTS reply_to_overridden ON TABLE email_config \
    TYPE bool DEFAULT false;
-- Existing tenant rows stored `enabled` from `input.enabled.unwrap_or(true)`,
-- so an explicit override and an untouched field are indistinguishable now.
-- Carry the stored value forward as explicit: reading it as \"inherit\" would
-- silently switch delivery off for a tenant that had deliberately turned it on
-- while the organization's own switch was off.
UPDATE email_config SET enabled_override = enabled WHERE scope = 'tenant';
";

// -----------------------------------------------------------------------
// Schema v44 — the erasure grace window becomes a setting
// -----------------------------------------------------------------------
//
// `POST /api/v1/auth/account/delete` hard-coded 30 days, which made the admin
// UI's "cancel a pending deletion" control refer to a duration no operator
// could see, let alone change. It is now an org baseline a tenant may only
// lower — shorter is more restrictive, being less time holding data the
// subject has already asked to have erased.
//
// The DEFAULT is the same 30 days the handler used, and the backfill applies
// it to rows that predate the column, so an upgrade changes nothing anywhere.

const SCHEMA_V44: &str = "\
DEFINE FIELD IF NOT EXISTS privacy_deletion_grace_days ON TABLE \
    security_settings TYPE int DEFAULT 30 \
    ASSERT $value >= 1 AND $value <= 90;
-- DEFAULT only applies on write, so rows written before this migration need
-- the value put there explicitly.
UPDATE security_settings SET privacy_deletion_grace_days = 30 \
    WHERE privacy_deletion_grace_days = NONE;
";

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
