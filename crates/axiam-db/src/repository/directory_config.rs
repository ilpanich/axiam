//! SurrealDB implementation of [`DirectoryConfigRepository`] (G-3, D-15).
//!
//! One row per tenant. The bind secret is encrypted at rest with AES-256-GCM,
//! a fresh nonce per write, exactly as the per-tenant SMTP password is in
//! `email_config.rs`; the 256-bit key is fetched from the secret provider under
//! `directory_encryption_key` and handed to [`SurrealDirectoryConfigRepository::new`]
//! by the composition root. It is **optional**: a repository built without it
//! fails closed on `create`, `update` and `decrypt_bind_secret` with an error
//! naming the key, and still serves reads, `delete` and `list_enabled`.
//!
//! The secret is write-only. Every read projects the non-secret columns
//! explicitly, so the ciphertext never leaves the datastore except through
//! [`SurrealDirectoryConfigRepository::decrypt_bind_secret`], the single path
//! to the plaintext, which the bind path (T23.3.2) calls.

use axiam_auth::crypto::{decrypt_separate, encrypt_separate};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::directory::{
    DirectoryConfig, DirectoryKind, NewDirectoryConfig, UserAttributeMap,
};
use axiam_core::repository::DirectoryConfigRepository;
use axiam_core::secrets::{DIRECTORY_ENCRYPTION_KEY, env_var_name};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{classify_write_error, parse_uuid, take_first_or_not_found};

/// The key version written today. The column exists so a future rotation can
/// tell which key sealed a row; `email_config` writes the same constant.
const SECRET_KEY_VERSION: i64 = 1;

/// Every non-secret column, projected explicitly: a read of this table never
/// hydrates `bind_secret_ciphertext` or `bind_secret_nonce`.
const PUBLIC_COLUMNS: &str = "meta::id(id) AS record_id, tenant_id, enabled, kind, url, \
    start_tls, bind_dn, base_dn, user_filter, attr_username, attr_email, \
    attr_display_name, attr_external_id, group_base_dn, group_filter, \
    group_member_attribute, group_nesting_depth, sync_interval_secs, \
    jit_provisioning, trust_anchors_pem, created_at, updated_at";

/// A directory row without its secret columns.
#[derive(Debug, SurrealValue)]
struct DirectoryRow {
    record_id: String,
    tenant_id: String,
    enabled: bool,
    kind: String,
    url: String,
    start_tls: bool,
    bind_dn: String,
    base_dn: String,
    user_filter: String,
    attr_username: String,
    attr_email: String,
    attr_display_name: String,
    attr_external_id: String,
    group_base_dn: Option<String>,
    group_filter: Option<String>,
    group_member_attribute: String,
    group_nesting_depth: i64,
    sync_interval_secs: i64,
    jit_provisioning: bool,
    trust_anchors_pem: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// The two secret columns. Deliberately not `Debug`: there is nothing safe to
/// print, and no derive means nobody can `{:?}` it into a log by accident.
#[derive(SurrealValue)]
struct SecretRow {
    bind_secret_ciphertext: String,
    bind_secret_nonce: String,
}

impl DirectoryRow {
    fn into_domain(self) -> Result<DirectoryConfig, DbError> {
        let kind = DirectoryKind::from_wire(&self.kind).ok_or_else(|| {
            DbError::Serialization("directory_config row has an unknown kind".to_string())
        })?;
        let depth = u8::try_from(self.group_nesting_depth).map_err(|_| {
            DbError::Serialization("directory_config group_nesting_depth is out of range".into())
        })?;
        let interval = u64::try_from(self.sync_interval_secs).map_err(|_| {
            DbError::Serialization("directory_config sync_interval_secs is out of range".into())
        })?;
        Ok(DirectoryConfig {
            id: parse_uuid(&self.record_id, "directory_config")?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            enabled: self.enabled,
            kind,
            url: self.url,
            start_tls: self.start_tls,
            bind_dn: self.bind_dn,
            base_dn: self.base_dn,
            user_filter: self.user_filter,
            user_attribute_map: UserAttributeMap {
                username: self.attr_username,
                email: self.attr_email,
                display_name: self.attr_display_name,
                external_id: self.attr_external_id,
            },
            group_base_dn: self.group_base_dn,
            group_filter: self.group_filter,
            group_member_attribute: self.group_member_attribute,
            group_nesting_depth: depth,
            sync_interval_secs: interval,
            jit_provisioning: self.jit_provisioning,
            trust_anchors_pem: self.trust_anchors_pem,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of [`DirectoryConfigRepository`].
pub struct SurrealDirectoryConfigRepository<C: Connection> {
    db: DbHandle<C>,
    key: Option<[u8; 32]>,
}

impl<C: Connection> Clone for SurrealDirectoryConfigRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            key: self.key,
        }
    }
}

/// Redacting `Debug`: the key is the one thing in this struct worth protecting.
impl<C: Connection> std::fmt::Debug for SurrealDirectoryConfigRepository<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealDirectoryConfigRepository")
            .field("key_configured", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

impl<C: Connection> SurrealDirectoryConfigRepository<C> {
    /// Build the repository. `key` is the 256-bit key the secret provider holds
    /// as `directory_encryption_key`, or `None` when it is not configured, in
    /// which case the directory feature is unavailable (see the module docs).
    pub fn new(db: impl Into<DbHandle<C>>, key: Option<[u8; 32]>) -> Self {
        Self { db: db.into(), key }
    }

    /// The text every missing-key refusal carries: the logical name and the
    /// variable the default provider reads, so the operator can act on it.
    fn missing_key_message() -> String {
        format!(
            "the directory feature is unavailable: {DIRECTORY_ENCRYPTION_KEY} \
             ({}) is not configured",
            env_var_name(DIRECTORY_ENCRYPTION_KEY)
        )
    }

    /// The key for a write, or the fail-closed refusal.
    fn key_for_write(&self) -> AxiamResult<&[u8; 32]> {
        self.key.as_ref().ok_or_else(|| AxiamError::Validation {
            message: Self::missing_key_message(),
        })
    }

    async fn fetch_public(&self, tenant_id: Uuid) -> AxiamResult<Option<DirectoryConfig>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM directory_config WHERE tenant_id = $tenant_id"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<DirectoryRow> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.into_domain()?)),
            None => Ok(None),
        }
    }
}

/// Encrypt the bind secret, returning `(nonce_b64, ciphertext_b64)`.
///
/// The error carries no detail: whatever the cipher says, none of it belongs in
/// a response or a log next to a credential.
fn seal(key: &[u8; 32], secret: &str) -> AxiamResult<(String, String)> {
    encrypt_separate(key, secret.as_bytes())
        .map_err(|_| AxiamError::Crypto("the directory bind secret could not be encrypted".into()))
}

impl<C: Connection> DirectoryConfigRepository for SurrealDirectoryConfigRepository<C> {
    async fn create(&self, input: NewDirectoryConfig) -> AxiamResult<DirectoryConfig> {
        let key = self.key_for_write()?;
        let secret = input
            .bind_secret
            .as_ref()
            .ok_or_else(|| AxiamError::Validation {
                message: "a directory configuration requires a bind secret when it is created"
                    .into(),
            })?;
        let (nonce, ciphertext) = seal(key, secret)?;

        let id = new_id();
        let tenant_id = input.tenant_id;
        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('directory_config', $id) SET \
                 tenant_id = $tenant_id, enabled = $enabled, kind = $kind, \
                 url = $url, start_tls = $start_tls, bind_dn = $bind_dn, \
                 bind_secret_ciphertext = $ciphertext, bind_secret_nonce = $nonce, \
                 secret_key_version = $key_version, base_dn = $base_dn, \
                 user_filter = $user_filter, attr_username = $attr_username, \
                 attr_email = $attr_email, attr_display_name = $attr_display_name, \
                 attr_external_id = $attr_external_id, \
                 group_base_dn = $group_base_dn, group_filter = $group_filter, \
                 group_member_attribute = $group_member_attribute, \
                 group_nesting_depth = $group_nesting_depth, \
                 sync_interval_secs = $sync_interval_secs, \
                 jit_provisioning = $jit_provisioning, \
                 trust_anchors_pem = $trust_anchors_pem, \
                 created_at = time::now(), updated_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("enabled", input.enabled))
            .bind(("kind", input.kind.as_str().to_string()))
            .bind(("url", input.url))
            .bind(("start_tls", input.start_tls))
            .bind(("bind_dn", input.bind_dn))
            .bind(("ciphertext", ciphertext))
            .bind(("nonce", nonce))
            .bind(("key_version", SECRET_KEY_VERSION))
            .bind(("base_dn", input.base_dn))
            .bind(("user_filter", input.user_filter))
            .bind(("attr_username", input.user_attribute_map.username))
            .bind(("attr_email", input.user_attribute_map.email))
            .bind(("attr_display_name", input.user_attribute_map.display_name))
            .bind(("attr_external_id", input.user_attribute_map.external_id))
            .bind(("group_base_dn", input.group_base_dn))
            .bind(("group_filter", input.group_filter))
            .bind(("group_member_attribute", input.group_member_attribute))
            .bind(("group_nesting_depth", i64::from(input.group_nesting_depth)))
            .bind((
                "sync_interval_secs",
                i64::try_from(input.sync_interval_secs).map_err(|_| AxiamError::Validation {
                    message: "sync_interval_secs is out of range".into(),
                })?,
            ))
            .bind(("jit_provisioning", input.jit_provisioning))
            .bind(("trust_anchors_pem", input.trust_anchors_pem))
            .await
            .map_err(DbError::from)?;
        // The unique index on `tenant_id` is what makes a second create for the
        // same tenant an `AlreadyExists` rather than a second configuration.
        result
            .check()
            .map_err(|e| classify_write_error(e, "directory_config"))?;

        let created = self.fetch_public(tenant_id).await?;
        Ok(take_first_or_not_found(
            created.into_iter().collect(),
            "directory_config",
            &tenant_id.to_string(),
        )?)
    }

    async fn update(&self, input: NewDirectoryConfig) -> AxiamResult<DirectoryConfig> {
        let key = self.key_for_write()?;
        // `None` keeps the stored ciphertext and nonce untouched; `Some` writes
        // both, under a fresh nonce.
        let sealed = match &input.bind_secret {
            Some(secret) => Some(seal(key, secret)?),
            None => None,
        };
        let secret_sets = if sealed.is_some() {
            "bind_secret_ciphertext = $ciphertext, bind_secret_nonce = $nonce, \
             secret_key_version = $key_version, "
        } else {
            ""
        };

        let tenant_id = input.tenant_id;
        let interval =
            i64::try_from(input.sync_interval_secs).map_err(|_| AxiamError::Validation {
                message: "sync_interval_secs is out of range".into(),
            })?;
        let db = self.db.current();
        let mut query = db
            .query(format!(
                "UPDATE directory_config SET {secret_sets}\
                 enabled = $enabled, kind = $kind, url = $url, \
                 start_tls = $start_tls, bind_dn = $bind_dn, base_dn = $base_dn, \
                 user_filter = $user_filter, attr_username = $attr_username, \
                 attr_email = $attr_email, attr_display_name = $attr_display_name, \
                 attr_external_id = $attr_external_id, \
                 group_base_dn = $group_base_dn, group_filter = $group_filter, \
                 group_member_attribute = $group_member_attribute, \
                 group_nesting_depth = $group_nesting_depth, \
                 sync_interval_secs = $sync_interval_secs, \
                 jit_provisioning = $jit_provisioning, \
                 trust_anchors_pem = $trust_anchors_pem, \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("enabled", input.enabled))
            .bind(("kind", input.kind.as_str().to_string()))
            .bind(("url", input.url))
            .bind(("start_tls", input.start_tls))
            .bind(("bind_dn", input.bind_dn))
            .bind(("base_dn", input.base_dn))
            .bind(("user_filter", input.user_filter))
            .bind(("attr_username", input.user_attribute_map.username))
            .bind(("attr_email", input.user_attribute_map.email))
            .bind(("attr_display_name", input.user_attribute_map.display_name))
            .bind(("attr_external_id", input.user_attribute_map.external_id))
            .bind(("group_base_dn", input.group_base_dn))
            .bind(("group_filter", input.group_filter))
            .bind(("group_member_attribute", input.group_member_attribute))
            .bind(("group_nesting_depth", i64::from(input.group_nesting_depth)))
            .bind(("sync_interval_secs", interval))
            .bind(("jit_provisioning", input.jit_provisioning))
            .bind(("trust_anchors_pem", input.trust_anchors_pem));
        if let Some((nonce, ciphertext)) = sealed {
            query = query
                .bind(("ciphertext", ciphertext))
                .bind(("nonce", nonce))
                .bind(("key_version", SECRET_KEY_VERSION));
        }
        let result = query.await.map_err(DbError::from)?;
        result
            .check()
            .map_err(|e| classify_write_error(e, "directory_config"))?;

        let updated = self.fetch_public(tenant_id).await?;
        Ok(take_first_or_not_found(
            updated.into_iter().collect(),
            "directory_config",
            &tenant_id.to_string(),
        )?)
    }

    async fn get_by_tenant(&self, tenant_id: Uuid) -> AxiamResult<Option<DirectoryConfig>> {
        self.fetch_public(tenant_id).await
    }

    async fn decrypt_bind_secret(&self, tenant_id: Uuid) -> AxiamResult<Zeroizing<String>> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| AxiamError::ServiceUnavailable(Self::missing_key_message()))?;

        let mut result = self
            .db
            .current()
            .query(
                "SELECT bind_secret_ciphertext, bind_secret_nonce \
                 FROM directory_config WHERE tenant_id = $tenant_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SecretRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "directory_config", &tenant_id.to_string())?;

        let plaintext = decrypt_separate(key, &row.bind_secret_nonce, &row.bind_secret_ciphertext)
            .map_err(|_| {
                // No detail on purpose: "wrong key" and "corrupt row" are both
                // an operator problem, and neither belongs next to a secret.
                AxiamError::Crypto(
                    "the directory bind secret could not be decrypted: the stored value \
                     does not match the configured directory_encryption_key"
                        .into(),
                )
            })?;
        let text = String::from_utf8(plaintext).map_err(|_| {
            AxiamError::Crypto("the decrypted directory bind secret is not valid UTF-8".into())
        })?;
        Ok(Zeroizing::new(text))
    }

    async fn delete(&self, tenant_id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query("DELETE directory_config WHERE tenant_id = $tenant_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        result.check().map_err(DbError::from)?;
        Ok(())
    }

    async fn list_enabled(&self) -> AxiamResult<Vec<DirectoryConfig>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM directory_config \
                 WHERE enabled = true ORDER BY created_at ASC"
            ))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<DirectoryRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect()
    }
}
