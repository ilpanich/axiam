//! SurrealDB implementation of [`EmailConfigRepository`].
//!
//! Provider secrets (SMTP password, API key) are encrypted at rest using
//! AES-256-GCM with a dedicated `AXIAM__EMAIL_ENCRYPTION_KEY` (D-17).
//! The repository stores `{field}_ciphertext`, `{field}_nonce`, and
//! `secret_key_version` columns; plaintext is only present in the returned
//! in-memory domain structs.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Generate, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::{
    ApiProviderConfig, EmailConfig, EmailConfigOverride, EmailProviderKind, ProviderConfig,
    SetOrgEmailConfig, SetTenantEmailOverride, SmtpConfig, email_config_from_org_input,
};
use axiam_core::models::settings::SettingsScope;
use axiam_core::repository::EmailConfigRepository;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::helpers::{CountRow, take_first_or_not_found};

// ---------------------------------------------------------------------------
// Crypto helpers (mirror of axiam-auth split-output variant — no circular dep)
// ---------------------------------------------------------------------------

fn encrypt_field(key: &[u8; 32], plaintext: &[u8]) -> Result<(String, String), AxiamError> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let nonce_bytes: [u8; 12] = Generate::generate();
    let nonce = Nonce::<U12>::from(nonce_bytes);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AxiamError::Internal(format!("email secret encrypt: {e}")))?;
    Ok((STANDARD.encode(nonce_bytes), STANDARD.encode(ct)))
}

fn decrypt_field(key: &[u8; 32], nonce_b64: &str, ct_b64: &str) -> Result<String, AxiamError> {
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| AxiamError::Internal(format!("nonce decode: {e}")))?;
    let ct = STANDARD
        .decode(ct_b64)
        .map_err(|e| AxiamError::Internal(format!("ct decode: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(AxiamError::Internal("nonce must be 12 bytes".into()));
    }
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice())
        .map_err(|_| AxiamError::Internal("nonce must be 12 bytes".into()))?;
    let plaintext = cipher
        .decrypt(&nonce, ct.as_slice())
        .map_err(|e| AxiamError::Internal(format!("email secret decrypt: {e}")))?;
    String::from_utf8(plaintext).map_err(|e| AxiamError::Internal(format!("utf8 decode: {e}")))
}

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct EmailConfigRow {
    scope: String,
    scope_id: String,
    enabled: bool,
    from_name: String,
    from_email: String,
    reply_to: Option<String>,
    provider_kind: String,
    // SMTP fields
    smtp_host: Option<String>,
    smtp_port: Option<i64>,
    smtp_username: Option<String>,
    smtp_starttls: Option<bool>,
    smtp_password_ciphertext: Option<String>,
    smtp_password_nonce: Option<String>,
    // API provider fields
    api_url: Option<String>,
    api_key_ciphertext: Option<String>,
    api_key_nonce: Option<String>,
    // Key version for future rotation
    secret_key_version: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct EmailConfigRowWithId {
    record_id: String,
    scope: String,
    scope_id: String,
    enabled: bool,
    from_name: String,
    from_email: String,
    reply_to: Option<String>,
    provider_kind: String,
    smtp_host: Option<String>,
    smtp_port: Option<i64>,
    smtp_username: Option<String>,
    smtp_starttls: Option<bool>,
    smtp_password_ciphertext: Option<String>,
    smtp_password_nonce: Option<String>,
    api_url: Option<String>,
    api_key_ciphertext: Option<String>,
    api_key_nonce: Option<String>,
    secret_key_version: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Row → domain conversion helpers
// ---------------------------------------------------------------------------

fn parse_scope(s: &str) -> Result<SettingsScope, DbError> {
    match s {
        "org" => Ok(SettingsScope::Org),
        "tenant" => Ok(SettingsScope::Tenant),
        other => Err(DbError::Migration(format!(
            "unknown email config scope: {other}"
        ))),
    }
}

// Note: scope_str is kept for completeness but may only be used
// when update methods are added (T19.20).
#[allow(dead_code)]
fn scope_str(s: &SettingsScope) -> &'static str {
    match s {
        SettingsScope::Org => "org",
        SettingsScope::Tenant => "tenant",
    }
}

fn provider_kind_str(k: &EmailProviderKind) -> &'static str {
    match k {
        EmailProviderKind::Smtp => "smtp",
        EmailProviderKind::SendGrid => "send_grid",
        EmailProviderKind::Postmark => "postmark",
        EmailProviderKind::Resend => "resend",
        EmailProviderKind::Brevo => "brevo",
    }
}

fn parse_provider_kind(s: &str) -> Result<EmailProviderKind, DbError> {
    match s {
        "smtp" => Ok(EmailProviderKind::Smtp),
        "send_grid" => Ok(EmailProviderKind::SendGrid),
        "postmark" => Ok(EmailProviderKind::Postmark),
        "resend" => Ok(EmailProviderKind::Resend),
        "brevo" => Ok(EmailProviderKind::Brevo),
        other => Err(DbError::Migration(format!(
            "unknown provider kind: {other}"
        ))),
    }
}

/// Bundled provider fields extracted from a row for decryption.
struct ProviderRowFields {
    kind: String,
    smtp_host: Option<String>,
    smtp_port: Option<i64>,
    smtp_username: Option<String>,
    smtp_starttls: Option<bool>,
    smtp_password_ciphertext: Option<String>,
    smtp_password_nonce: Option<String>,
    api_url: Option<String>,
    api_key_ciphertext: Option<String>,
    api_key_nonce: Option<String>,
}

/// Decrypt and reconstruct `ProviderConfig` from row data.
///
/// Returns a clear [`AxiamError::EmailConfig`] (D-08) when a row has a
/// configured provider but NULL/missing secret ciphertext or nonce, instead
/// of silently reconstructing an empty-string secret. An empty in-memory
/// secret would otherwise be indistinguishable from a deliberately-empty
/// credential and only fail later, at send time, with a confusing
/// provider-level error rather than a clear misconfiguration error here.
fn row_to_provider(
    fields: ProviderRowFields,
    key: &[u8; 32],
) -> Result<ProviderConfig, AxiamError> {
    match parse_provider_kind(&fields.kind)? {
        EmailProviderKind::Smtp => {
            let password = match (fields.smtp_password_ciphertext, fields.smtp_password_nonce) {
                (Some(ct), Some(nonce)) => decrypt_field(key, &nonce, &ct)?,
                _ => {
                    return Err(AxiamError::EmailConfig(
                        "email config has no usable credential: SMTP password ciphertext/nonce is missing"
                            .to_string(),
                    ));
                }
            };
            Ok(ProviderConfig::Smtp(SmtpConfig {
                host: fields.smtp_host.unwrap_or_default(),
                port: fields.smtp_port.unwrap_or(587) as u16,
                username: fields.smtp_username.unwrap_or_default(),
                password,
                starttls: fields.smtp_starttls.unwrap_or(true),
            }))
        }
        kind => {
            let api_key = match (fields.api_key_ciphertext, fields.api_key_nonce) {
                (Some(ct), Some(nonce)) => decrypt_field(key, &nonce, &ct)?,
                _ => {
                    return Err(AxiamError::EmailConfig(
                        "email config has no usable credential: API key ciphertext/nonce is missing"
                            .to_string(),
                    ));
                }
            };
            let config = ApiProviderConfig {
                api_key,
                api_url: fields.api_url,
            };
            Ok(match kind {
                EmailProviderKind::SendGrid => ProviderConfig::SendGrid(config),
                EmailProviderKind::Postmark => ProviderConfig::Postmark(config),
                EmailProviderKind::Resend => ProviderConfig::Resend(config),
                EmailProviderKind::Brevo => ProviderConfig::Brevo(config),
                EmailProviderKind::Smtp => unreachable!(),
            })
        }
    }
}

impl EmailConfigRowWithId {
    fn try_into_domain(self, key: &[u8; 32]) -> Result<EmailConfig, AxiamError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let scope_id = Uuid::parse_str(&self.scope_id)
            .map_err(|e| DbError::Migration(format!("invalid scope_id UUID: {e}")))?;
        let provider = row_to_provider(
            ProviderRowFields {
                kind: self.provider_kind,
                smtp_host: self.smtp_host,
                smtp_port: self.smtp_port,
                smtp_username: self.smtp_username,
                smtp_starttls: self.smtp_starttls,
                smtp_password_ciphertext: self.smtp_password_ciphertext,
                smtp_password_nonce: self.smtp_password_nonce,
                api_url: self.api_url,
                api_key_ciphertext: self.api_key_ciphertext,
                api_key_nonce: self.api_key_nonce,
            },
            key,
        )?;
        Ok(EmailConfig {
            id,
            scope: parse_scope(&self.scope)?,
            scope_id,
            enabled: self.enabled,
            from_name: self.from_name,
            from_email: self.from_email,
            reply_to: self.reply_to,
            provider,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Bind helpers — encrypt provider secrets for DB write
// ---------------------------------------------------------------------------

/// Existing secret ciphertext/nonce columns for an org's email_config row,
/// used by `set_org_config`'s D-02 preserve-on-omit merge.
#[derive(Debug, SurrealValue)]
struct ExistingSecretColumns {
    smtp_password_ciphertext: Option<String>,
    smtp_password_nonce: Option<String>,
    api_key_ciphertext: Option<String>,
    api_key_nonce: Option<String>,
}

struct EncryptedProviderBinds {
    provider_kind: String,
    smtp_host: Option<String>,
    smtp_port: Option<i64>,
    smtp_username: Option<String>,
    smtp_starttls: Option<bool>,
    smtp_password_ciphertext: Option<String>,
    smtp_password_nonce: Option<String>,
    api_url: Option<String>,
    api_key_ciphertext: Option<String>,
    api_key_nonce: Option<String>,
    secret_key_version: i64,
}

fn encrypt_provider(
    provider: &ProviderConfig,
    key: &[u8; 32],
) -> Result<EncryptedProviderBinds, AxiamError> {
    let kind_str = provider_kind_str(&provider.kind()).to_string();
    match provider {
        ProviderConfig::Smtp(smtp) => {
            let (nonce, ct) = encrypt_field(key, smtp.password.as_bytes())?;
            Ok(EncryptedProviderBinds {
                provider_kind: kind_str,
                smtp_host: Some(smtp.host.clone()),
                smtp_port: Some(smtp.port as i64),
                smtp_username: Some(smtp.username.clone()),
                smtp_starttls: Some(smtp.starttls),
                smtp_password_ciphertext: Some(ct),
                smtp_password_nonce: Some(nonce),
                api_url: None,
                api_key_ciphertext: None,
                api_key_nonce: None,
                secret_key_version: 1,
            })
        }
        ProviderConfig::SendGrid(api)
        | ProviderConfig::Postmark(api)
        | ProviderConfig::Resend(api)
        | ProviderConfig::Brevo(api) => {
            let (nonce, ct) = encrypt_field(key, api.api_key.as_bytes())?;
            Ok(EncryptedProviderBinds {
                provider_kind: kind_str,
                smtp_host: None,
                smtp_port: None,
                smtp_username: None,
                smtp_starttls: None,
                smtp_password_ciphertext: None,
                smtp_password_nonce: None,
                api_url: api.api_url.clone(),
                api_key_ciphertext: Some(ct),
                api_key_nonce: Some(nonce),
                secret_key_version: 1,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of [`EmailConfigRepository`].
///
/// The `key` field holds the 32-byte AES-256-GCM encryption key loaded from
/// `AXIAM__EMAIL_ENCRYPTION_KEY` at startup. Secrets are encrypted on write
/// and decrypted on read — never stored plaintext (D-17).
pub struct SurrealEmailConfigRepository<C: Connection> {
    db: Surreal<C>,
    key: [u8; 32],
}

impl<C: Connection> Clone for SurrealEmailConfigRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            key: self.key,
        }
    }
}

impl<C: Connection> SurrealEmailConfigRepository<C> {
    pub fn new(db: Surreal<C>, key: [u8; 32]) -> Self {
        Self { db, key }
    }

    /// Intentional, tested no-op (D-07): `email_config` has no plaintext
    /// secret to migrate, unlike `federation_config`.
    ///
    /// `federation_config` predates split-column encryption: it was created
    /// with a single plaintext `client_secret` column, so a real backfill
    /// path exists there (`list_with_legacy_plaintext_secret` +
    /// `set_encrypted_secret` in `federation_config.rs`) that reads the
    /// plaintext column, encrypts it, and nulls the plaintext out.
    ///
    /// `email_config` is different: it was introduced in Schema v15
    /// (Phase 5) with ciphertext-only columns (`smtp_password_ciphertext`,
    /// `api_key_ciphertext`) from the very first migration — there has
    /// never been a plaintext `smtp_password`/`api_key` source column in
    /// this schema to encrypt. There is therefore no UPDATE/encrypt path to
    /// implement here, and inventing one would be dishonest about what this
    /// function does. The "no unencrypted secrets at rest" intent is
    /// instead satisfied structurally: `SurrealEmailConfigRepository`
    /// only ever writes through `encrypt_provider` (see `set_org_config`),
    /// so no plaintext-secret row can be produced by this repository.
    ///
    /// What this function *does* do: it detects (and warns on, but does not
    /// mutate) any row with a configured provider but NULL/missing secret
    /// ciphertext — an anomalous state that should never occur via this
    /// repository's own write path, but could in principle arise from
    /// external tooling writing directly to the table. On a normal v15+
    /// database with no such anomalies, this always returns `Ok(0)`.
    pub async fn backfill_plaintext_secrets(&self) -> AxiamResult<u64> {
        let result = self
            .db
            .query(
                "SELECT count() AS total FROM email_config \
                 WHERE (provider_kind IN ['smtp'] AND smtp_password_ciphertext = NONE) \
                    OR (provider_kind IN ['send_grid','postmark','resend','brevo'] \
                        AND api_key_ciphertext = NONE) \
                 GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        let anomalous = rows.into_iter().next().map(|r| r.total).unwrap_or(0);

        // Expected steady state on a v15+ schema: nothing anomalous found,
        // nothing to do.
        if anomalous == 0 {
            return Ok(0);
        }

        // Anomalous rows exist (should not happen via this repository's own
        // write path). There is no plaintext source column to migrate from
        // (see doc comment above), so we can only detect and warn — an
        // operator must investigate how these rows were written and either
        // re-set the config (going through `set_org_config`/
        // `set_tenant_override`, which always encrypts) or remove them.
        tracing::warn!(
            anomalous_rows = anomalous,
            "email_config rows with a configured provider but NULL/missing secret \
             ciphertext found; email_config has no plaintext source column to \
             backfill from (D-07) — these rows must be re-set or removed manually"
        );
        Ok(anomalous)
    }

    /// Fetch the currently-stored secret ciphertext/nonce columns for an
    /// org's email_config row, if one exists. Used by `set_org_config`'s
    /// D-02 preserve-on-omit merge to keep the stored secret unchanged when
    /// a write omits it, instead of overwriting it with ciphertext of an
    /// empty value.
    async fn fetch_org_secret_columns(
        &self,
        org_id: Uuid,
    ) -> AxiamResult<Option<ExistingSecretColumns>> {
        let result = self
            .db
            .query(
                "SELECT smtp_password_ciphertext, smtp_password_nonce, \
                        api_key_ciphertext, api_key_nonce \
                 FROM email_config \
                 WHERE scope = 'org' AND scope_id = $scope_id",
            )
            .bind(("scope_id", org_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<ExistingSecretColumns> = result.take(0).map_err(DbError::from)?;
        Ok(rows.into_iter().next())
    }
}

impl<C: Connection> EmailConfigRepository for SurrealEmailConfigRepository<C> {
    async fn get_org_config(&self, org_id: Uuid) -> AxiamResult<Option<EmailConfig>> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM email_config \
                 WHERE scope = 'org' AND scope_id = $scope_id",
            )
            .bind(("scope_id", org_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<EmailConfigRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain(&self.key))
            .transpose()
    }

    async fn set_org_config(
        &self,
        org_id: Uuid,
        input: SetOrgEmailConfig,
    ) -> AxiamResult<EmailConfig> {
        // D-02: an empty secret on the write path means "no new secret
        // supplied" — preserve whatever ciphertext is already stored rather
        // than persisting ciphertext of an empty value.
        let secret_omitted = match &input.provider {
            ProviderConfig::Smtp(smtp) => smtp.password.is_empty(),
            ProviderConfig::SendGrid(api)
            | ProviderConfig::Postmark(api)
            | ProviderConfig::Resend(api)
            | ProviderConfig::Brevo(api) => api.api_key.is_empty(),
        };

        let mut encrypted = encrypt_provider(&input.provider, &self.key)?;

        if secret_omitted && let Some(existing) = self.fetch_org_secret_columns(org_id).await? {
            match &input.provider {
                ProviderConfig::Smtp(_) => {
                    if existing.smtp_password_ciphertext.is_some() {
                        encrypted.smtp_password_ciphertext = existing.smtp_password_ciphertext;
                        encrypted.smtp_password_nonce = existing.smtp_password_nonce;
                    }
                }
                ProviderConfig::SendGrid(_)
                | ProviderConfig::Postmark(_)
                | ProviderConfig::Resend(_)
                | ProviderConfig::Brevo(_) => {
                    if existing.api_key_ciphertext.is_some() {
                        encrypted.api_key_ciphertext = existing.api_key_ciphertext;
                        encrypted.api_key_nonce = existing.api_key_nonce;
                    }
                }
            }
        }

        // Clone fields we need post-move for the domain object reconstruction.
        let enabled = input.enabled;
        let from_name = input.from_name.clone();
        let from_email = input.from_email.clone();
        let reply_to = input.reply_to.clone();

        // CQ-B41: UPSERT keyed on (scope, scope_id) — idempotent whether or
        // not a row for this org already exists.  created_at is set only on
        // insert (IF created_at = NONE); updated_at is always refreshed.
        // Use a deterministic record ID derived from org_id to avoid
        // SurrealDB v3 auto-generated ULID IDs which fail UUID parsing in
        // the SDK response deserialization.
        let record_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("email_config:org:{org_id}").as_bytes(),
        )
        .to_string();
        let result = self
            .db
            .query(
                "UPSERT type::record('email_config', $record_id) SET \
                 scope = 'org', \
                 scope_id = $scope_id, \
                 enabled = $enabled, \
                 from_name = $from_name, \
                 from_email = $from_email, \
                 reply_to = $reply_to, \
                 provider_kind = $provider_kind, \
                 smtp_host = $smtp_host, \
                 smtp_port = $smtp_port, \
                 smtp_username = $smtp_username, \
                 smtp_starttls = $smtp_starttls, \
                 smtp_password_ciphertext = $smtp_password_ciphertext, \
                 smtp_password_nonce = $smtp_password_nonce, \
                 api_url = $api_url, \
                 api_key_ciphertext = $api_key_ciphertext, \
                 api_key_nonce = $api_key_nonce, \
                 secret_key_version = $secret_key_version, \
                 created_at = IF created_at = NONE THEN time::now() ELSE created_at END, \
                 updated_at = time::now()",
            )
            .bind(("record_id", record_id))
            .bind(("scope_id", org_id.to_string()))
            .bind(("enabled", enabled))
            .bind(("from_name", from_name.clone()))
            .bind(("from_email", from_email.clone()))
            .bind(("reply_to", reply_to.clone()))
            .bind(("provider_kind", encrypted.provider_kind))
            .bind(("smtp_host", encrypted.smtp_host))
            .bind(("smtp_port", encrypted.smtp_port))
            .bind(("smtp_username", encrypted.smtp_username))
            .bind(("smtp_starttls", encrypted.smtp_starttls))
            .bind((
                "smtp_password_ciphertext",
                encrypted.smtp_password_ciphertext,
            ))
            .bind(("smtp_password_nonce", encrypted.smtp_password_nonce))
            .bind(("api_url", encrypted.api_url))
            .bind(("api_key_ciphertext", encrypted.api_key_ciphertext))
            .bind(("api_key_nonce", encrypted.api_key_nonce))
            .bind(("secret_key_version", encrypted.secret_key_version))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<EmailConfigRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "email_config", &org_id.to_string())?;

        // Re-construct domain with original plaintext provider.
        // Use a placeholder UUID for the record id since UPSERT does not
        // return meta::id by default here; the id is opaque to callers.
        let config = email_config_from_org_input(Uuid::new_v4(), org_id, &input);
        // Carry timestamps from DB row.
        Ok(EmailConfig {
            created_at: row.created_at,
            updated_at: row.updated_at,
            ..config
        })
    }

    async fn delete_org_config(&self, org_id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "DELETE FROM email_config \
                 WHERE scope = 'org' AND scope_id = $scope_id",
            )
            .bind(("scope_id", org_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn get_tenant_override(
        &self,
        tenant_id: Uuid,
    ) -> AxiamResult<Option<EmailConfigOverride>> {
        // Tenant overrides stored as a JSON blob in a separate email_config row.
        // For the MVP we store only the override fields. A None result means
        // "no override — inherit everything from org."
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM email_config \
                 WHERE scope = 'tenant' AND scope_id = $scope_id",
            )
            .bind(("scope_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<EmailConfigRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = match rows.into_iter().next() {
            None => return Ok(None),
            Some(r) => r,
        };

        // Reconstruct an override object from the tenant row.
        let provider = if row.provider_kind.is_empty() {
            None
        } else {
            Some(row_to_provider(
                ProviderRowFields {
                    kind: row.provider_kind,
                    smtp_host: row.smtp_host,
                    smtp_port: row.smtp_port,
                    smtp_username: row.smtp_username,
                    smtp_starttls: row.smtp_starttls,
                    smtp_password_ciphertext: row.smtp_password_ciphertext,
                    smtp_password_nonce: row.smtp_password_nonce,
                    api_url: row.api_url,
                    api_key_ciphertext: row.api_key_ciphertext,
                    api_key_nonce: row.api_key_nonce,
                },
                &self.key,
            )?)
        };

        Ok(Some(EmailConfigOverride {
            enabled: Some(row.enabled),
            from_name: Some(row.from_name).filter(|s| !s.is_empty()),
            from_email: Some(row.from_email).filter(|s| !s.is_empty()),
            reply_to: None, // not stored per-tenant in current schema
            provider,
        }))
    }

    async fn set_tenant_override(
        &self,
        tenant_id: Uuid,
        input: SetTenantEmailOverride,
    ) -> AxiamResult<EmailConfigOverride> {
        let provider_kind;
        let encrypted;

        if let Some(ref p) = input.provider {
            let enc = encrypt_provider(p, &self.key)?;
            provider_kind = enc.provider_kind.clone();
            encrypted = Some(enc);
        } else {
            provider_kind = String::new();
            encrypted = None;
        }

        let enc = encrypted.unwrap_or_else(|| EncryptedProviderBinds {
            provider_kind: String::new(),
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_starttls: None,
            smtp_password_ciphertext: None,
            smtp_password_nonce: None,
            api_url: None,
            api_key_ciphertext: None,
            api_key_nonce: None,
            secret_key_version: 0,
        });

        // CQ-B41: UPSERT keyed on (scope, scope_id) — idempotent whether or
        // not a tenant override row already exists for this tenant.
        // Use a deterministic record ID derived from tenant_id to avoid
        // SurrealDB v3 auto-generated ULID IDs which fail UUID parsing in
        // the SDK response deserialization.
        let tenant_record_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("email_config:tenant:{tenant_id}").as_bytes(),
        )
        .to_string();
        self.db
            .query(
                "UPSERT type::record('email_config', $record_id) SET \
                 scope = 'tenant', \
                 scope_id = $scope_id, \
                 enabled = $enabled, \
                 from_name = $from_name, \
                 from_email = $from_email, \
                 reply_to = NONE, \
                 provider_kind = $provider_kind, \
                 smtp_host = $smtp_host, \
                 smtp_port = $smtp_port, \
                 smtp_username = $smtp_username, \
                 smtp_starttls = $smtp_starttls, \
                 smtp_password_ciphertext = $smtp_password_ciphertext, \
                 smtp_password_nonce = $smtp_password_nonce, \
                 api_url = $api_url, \
                 api_key_ciphertext = $api_key_ciphertext, \
                 api_key_nonce = $api_key_nonce, \
                 secret_key_version = $secret_key_version, \
                 created_at = IF created_at = NONE THEN time::now() ELSE created_at END, \
                 updated_at = time::now()",
            )
            .bind(("record_id", tenant_record_id))
            .bind(("scope_id", tenant_id.to_string()))
            .bind(("enabled", input.enabled.unwrap_or(true)))
            .bind(("from_name", input.from_name.clone().unwrap_or_default()))
            .bind(("from_email", input.from_email.clone().unwrap_or_default()))
            .bind(("provider_kind", provider_kind))
            .bind(("smtp_host", enc.smtp_host))
            .bind(("smtp_port", enc.smtp_port))
            .bind(("smtp_username", enc.smtp_username))
            .bind(("smtp_starttls", enc.smtp_starttls))
            .bind(("smtp_password_ciphertext", enc.smtp_password_ciphertext))
            .bind(("smtp_password_nonce", enc.smtp_password_nonce))
            .bind(("api_url", enc.api_url))
            .bind(("api_key_ciphertext", enc.api_key_ciphertext))
            .bind(("api_key_nonce", enc.api_key_nonce))
            .bind(("secret_key_version", enc.secret_key_version))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(input)
    }

    async fn delete_tenant_override(&self, tenant_id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "DELETE FROM email_config \
                 WHERE scope = 'tenant' AND scope_id = $scope_id",
            )
            .bind(("scope_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn get_effective_config(
        &self,
        org_id: Uuid,
        tenant_id: Uuid,
    ) -> AxiamResult<Option<EmailConfig>> {
        let org_cfg = match self.get_org_config(org_id).await? {
            None => return Ok(None),
            Some(c) => c,
        };

        let override_cfg = self.get_tenant_override(tenant_id).await?;
        let effective = match override_cfg {
            None => org_cfg,
            Some(ov) => axiam_core::models::email::effective_email_config(
                &org_cfg,
                &ov,
                tenant_id,
                Uuid::new_v4(),
            ),
        };
        Ok(Some(effective))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    fn test_key() -> [u8; 32] {
        [0xABu8; 32]
    }

    #[tokio::test]
    async fn round_trip_smtp() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();
        let input = SetOrgEmailConfig {
            enabled: true,
            from_name: "AXIAM".into(),
            from_email: "noreply@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Smtp(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 587,
                username: "user".into(),
                password: "supersecret".into(),
                starttls: true,
            }),
        };
        let created = repo.set_org_config(org_id, input.clone()).await.unwrap();
        assert_eq!(created.from_email, "noreply@example.com");

        let fetched = repo.get_org_config(org_id).await.unwrap().unwrap();
        if let ProviderConfig::Smtp(smtp) = &fetched.provider {
            assert_eq!(
                smtp.password, "supersecret",
                "SMTP password must decrypt correctly"
            );
            assert_eq!(smtp.host, "smtp.example.com");
            assert_eq!(smtp.port, 587);
            assert!(smtp.starttls);
        } else {
            panic!("expected Smtp provider");
        }
    }

    #[tokio::test]
    async fn round_trip_sendgrid() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();
        let input = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::SendGrid(ApiProviderConfig {
                api_key: "sg_secret_key".into(),
                api_url: None,
            }),
        };
        repo.set_org_config(org_id, input).await.unwrap();
        let fetched = repo.get_org_config(org_id).await.unwrap().unwrap();
        if let ProviderConfig::SendGrid(api) = &fetched.provider {
            assert_eq!(api.api_key, "sg_secret_key");
        } else {
            panic!("expected SendGrid provider");
        }
    }

    #[tokio::test]
    async fn round_trip_postmark() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();
        let input = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Postmark(ApiProviderConfig {
                api_key: "pm_secret_key".into(),
                api_url: Some("https://api.postmarkapp.com".into()),
            }),
        };
        repo.set_org_config(org_id, input).await.unwrap();
        let fetched = repo.get_org_config(org_id).await.unwrap().unwrap();
        if let ProviderConfig::Postmark(api) = &fetched.provider {
            assert_eq!(api.api_key, "pm_secret_key");
            assert_eq!(api.api_url.as_deref(), Some("https://api.postmarkapp.com"));
        } else {
            panic!("expected Postmark provider");
        }
    }

    #[tokio::test]
    async fn round_trip_resend() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();
        let input = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Resend(ApiProviderConfig {
                api_key: "re_secret_key".into(),
                api_url: None,
            }),
        };
        repo.set_org_config(org_id, input).await.unwrap();
        let fetched = repo.get_org_config(org_id).await.unwrap().unwrap();
        if let ProviderConfig::Resend(api) = &fetched.provider {
            assert_eq!(api.api_key, "re_secret_key");
        } else {
            panic!("expected Resend provider");
        }
    }

    #[tokio::test]
    async fn round_trip_brevo() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();
        let input = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Brevo(ApiProviderConfig {
                api_key: "brevo_secret_key".into(),
                api_url: None,
            }),
        };
        repo.set_org_config(org_id, input).await.unwrap();
        let fetched = repo.get_org_config(org_id).await.unwrap().unwrap();
        if let ProviderConfig::Brevo(api) = &fetched.provider {
            assert_eq!(api.api_key, "brevo_secret_key");
        } else {
            panic!("expected Brevo provider");
        }
    }

    #[tokio::test]
    async fn get_org_config_returns_none_when_not_set() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let result = repo.get_org_config(Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    // --- D-13: delete_org_config ---

    #[tokio::test]
    async fn delete_org_config_removes_row() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();
        let input = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Smtp(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 587,
                username: "user".into(),
                password: "supersecret".into(),
                starttls: true,
            }),
        };
        repo.set_org_config(org_id, input).await.unwrap();
        assert!(repo.get_org_config(org_id).await.unwrap().is_some());

        repo.delete_org_config(org_id).await.unwrap();

        assert!(repo.get_org_config(org_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_org_config_is_ok_when_nothing_to_delete() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        // No config was ever set for this org — must not error.
        repo.delete_org_config(Uuid::new_v4()).await.unwrap();
    }

    // --- D-02: preserve-on-omit / replace-on-supply ---

    #[tokio::test]
    async fn set_org_config_omitted_secret_preserves_stored_smtp_password() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();

        let with_secret = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Smtp(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 587,
                username: "user".into(),
                password: "original-secret".into(),
                starttls: true,
            }),
        };
        repo.set_org_config(org_id, with_secret).await.unwrap();

        // A second write that omits the password (empty string sentinel,
        // D-02) but changes an unrelated field (from_name).
        let omit_secret = SetOrgEmailConfig {
            enabled: true,
            from_name: "Renamed".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Smtp(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 587,
                username: "user".into(),
                password: String::new(),
                starttls: true,
            }),
        };
        repo.set_org_config(org_id, omit_secret).await.unwrap();

        let fetched = repo.get_org_config(org_id).await.unwrap().unwrap();
        assert_eq!(fetched.from_name, "Renamed");
        if let ProviderConfig::Smtp(smtp) = &fetched.provider {
            assert_eq!(
                smtp.password, "original-secret",
                "omitting the secret on update must preserve the previously stored ciphertext"
            );
        } else {
            panic!("expected Smtp provider");
        }
    }

    #[tokio::test]
    async fn set_org_config_supplied_secret_replaces_stored_value() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();

        let first = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::SendGrid(ApiProviderConfig {
                api_key: "original_key".into(),
                api_url: None,
            }),
        };
        repo.set_org_config(org_id, first).await.unwrap();

        let second = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::SendGrid(ApiProviderConfig {
                api_key: "replaced_key".into(),
                api_url: None,
            }),
        };
        repo.set_org_config(org_id, second).await.unwrap();

        let fetched = repo.get_org_config(org_id).await.unwrap().unwrap();
        if let ProviderConfig::SendGrid(api) = &fetched.provider {
            assert_eq!(
                api.api_key, "replaced_key",
                "supplying a non-empty secret on update must replace the stored value"
            );
        } else {
            panic!("expected SendGrid provider");
        }
    }

    // --- D-08: NULL-ciphertext row surfaces a clear error, not an empty secret ---

    #[tokio::test]
    async fn read_path_errors_on_null_ciphertext_row() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db.clone(), test_key());
        let org_id = Uuid::new_v4();

        // Insert a row directly (bypassing the repository's own encrypt-on-write
        // path) with a configured SMTP provider but NULL secret ciphertext/nonce —
        // simulating an anomalous/corrupted row that should never occur via the
        // repository's own write path, but must not silently decrypt to "".
        let record_id = Uuid::new_v4().to_string();
        db.query(
            "CREATE type::record('email_config', $record_id) SET \
             scope = 'org', scope_id = $scope_id, enabled = true, \
             from_name = 'Test', from_email = 'test@example.com', reply_to = NONE, \
             provider_kind = 'smtp', smtp_host = 'smtp.example.com', smtp_port = 587, \
             smtp_username = 'user', smtp_starttls = true, \
             smtp_password_ciphertext = NONE, smtp_password_nonce = NONE, \
             api_url = NONE, api_key_ciphertext = NONE, api_key_nonce = NONE, \
             secret_key_version = NONE, created_at = time::now(), updated_at = time::now()",
        )
        .bind(("record_id", record_id))
        .bind(("scope_id", org_id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();

        let err = repo.get_org_config(org_id).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no usable credential"),
            "expected a clear no-usable-credential error, got: {msg}"
        );
    }

    // --- D-07: backfill_plaintext_secrets is a documented no-op ---

    #[tokio::test]
    async fn backfill_plaintext_secrets_is_a_noop_on_v15_schema_with_data_present() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let org_id = Uuid::new_v4();

        // Seed a real org email_config row (encrypted, via the repository's
        // own write path) so the table is non-empty when the backfill runs.
        let input = SetOrgEmailConfig {
            enabled: true,
            from_name: "Test".into(),
            from_email: "test@example.com".into(),
            reply_to: None,
            provider: ProviderConfig::Smtp(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 587,
                username: "user".into(),
                password: "supersecret".into(),
                starttls: true,
            }),
        };
        repo.set_org_config(org_id, input).await.unwrap();

        let before = repo.get_org_config(org_id).await.unwrap().unwrap();

        let result = repo.backfill_plaintext_secrets().await.unwrap();
        assert_eq!(
            result, 0,
            "email_config has no plaintext source column (D-07); backfill must be a no-op"
        );

        // Mutates nothing: the seeded row's (decrypted) secret is unchanged.
        let after = repo.get_org_config(org_id).await.unwrap().unwrap();
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn backfill_plaintext_secrets_is_a_noop_on_empty_table() {
        let db = setup_db().await;
        let repo = SurrealEmailConfigRepository::new(db, test_key());
        let result = repo.backfill_plaintext_secrets().await.unwrap();
        assert_eq!(result, 0);
    }
}
