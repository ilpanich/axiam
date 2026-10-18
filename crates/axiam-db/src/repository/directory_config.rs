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
    CONNECTION_MOVED_WITHOUT_SECRET, DirectoryConfig, DirectoryKind, GROUP_MAPPINGS_MAX,
    GroupMapping, NewDirectoryConfig, UserAttributeMap,
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
use crate::helpers::{
    TxFail, classify_write_error, parse_uuid, retry_on_write_conflict, take_first_or_not_found,
};
use crate::repository::opaque_directory::{self, OpaqueDirectoryClaim};

/// The key version written today. The column exists so a future rotation can
/// tell which key sealed a row; `email_config` writes the same constant.
const SECRET_KEY_VERSION: i64 = 1;

/// Every non-secret column, projected explicitly: a read of this table never
/// hydrates `bind_secret_ciphertext` or `bind_secret_nonce`.
const PUBLIC_COLUMNS: &str = "meta::id(id) AS record_id, tenant_id, enabled, kind, url, \
    start_tls, bind_dn, base_dn, user_filter, attr_username, attr_email, \
    attr_display_name, attr_external_id, group_base_dn, group_filter, \
    group_member_attribute, group_nesting_depth, group_mappings, sync_interval_secs, \
    jit_provisioning, trust_anchors_pem, created_at, updated_at";

/// One stored row of the group-mapping table (v74).
#[derive(Debug, Clone, SurrealValue)]
struct GroupMappingRow {
    directory_group_dn: String,
    group_id: String,
}

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
    /// Absent on a row written before v74: reads as no mapping at all.
    group_mappings: Option<Vec<GroupMappingRow>>,
    sync_interval_secs: i64,
    jit_provisioning: bool,
    trust_anchors_pem: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Just the id of a group, for the same-tenant check on the mapping table.
#[derive(Debug, SurrealValue)]
struct GroupIdRow {
    #[allow(dead_code)] // counted, never read: the check is on how many came back
    record_id: String,
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
        let group_mappings = self
            .group_mappings
            .unwrap_or_default()
            .into_iter()
            .map(|row| {
                Ok(GroupMapping {
                    directory_group_dn: row.directory_group_dn,
                    group_id: parse_uuid(&row.group_id, "group")?,
                })
            })
            .collect::<Result<Vec<_>, DbError>>()?;
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
            group_mappings,
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

    /// Whether the encryption key is configured: the one fact a management
    /// route needs to answer "this deployment does not have the feature" before
    /// it validates anything, without learning or logging the key itself.
    #[must_use]
    pub fn has_encryption_key(&self) -> bool {
        self.key.is_some()
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

    /// The write-path rules of the mapping table that need the datastore
    /// (D-30): at most [`GROUP_MAPPINGS_MAX`] rows, and **every `group_id` a
    /// group of `tenant_id`**. A mapping naming another tenant's group, or none
    /// at all, is refused before the row is touched, so a tenant administrator
    /// can never point their directory at a group they do not own.
    ///
    /// The shape of each DN is `axiam-directory::config::validate`'s rule (this
    /// layer cannot reach it); the two together are what `T23.3.8` calls.
    async fn check_group_mappings(
        &self,
        tenant_id: Uuid,
        mappings: &[GroupMapping],
    ) -> AxiamResult<()> {
        if mappings.len() > GROUP_MAPPINGS_MAX {
            return Err(AxiamError::Validation {
                message: format!(
                    "directory group_mappings may hold at most {GROUP_MAPPINGS_MAX} entries"
                ),
            });
        }
        let mut wanted: Vec<String> = mappings.iter().map(|m| m.group_id.to_string()).collect();
        wanted.sort_unstable();
        wanted.dedup();
        if wanted.is_empty() {
            return Ok(());
        }
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id FROM group \
                 WHERE tenant_id = $tenant_id AND meta::id(id) IN $ids",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("ids", wanted.clone()))
            .await
            .map_err(DbError::from)?;
        let found: Vec<GroupIdRow> = result.take(0).map_err(DbError::from)?;
        if found.len() != wanted.len() {
            return Err(AxiamError::Validation {
                message: "directory group_mappings names a group that is not a group of this \
                          tenant"
                    .into(),
            });
        }
        Ok(())
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

/// The sealed secret a write stores: `(nonce_b64, ciphertext_b64)`.
type Sealed = (String, String);

impl<C: Connection> SurrealDirectoryConfigRepository<C> {
    /// [`DirectoryConfigRepository::create`] under the tenant's opaque/directory
    /// claim (item 10 of the 1.1.0 atomicity audit;
    /// `repository/opaque_directory.rs`): the create and the claim's compare
    /// are one transaction, and `Conflict` when the tenant's epoch moved since
    /// the claim was read — a settings write made `opaque_mode` `required`
    /// after the caller read the settings it decided on.
    pub async fn create_claimed(
        &self,
        input: NewDirectoryConfig,
        claim: OpaqueDirectoryClaim,
    ) -> AxiamResult<DirectoryConfig> {
        self.create_inner(input, Some(claim)).await
    }

    /// [`DirectoryConfigRepository::update`] under the tenant's claim, as
    /// [`Self::create_claimed`].
    pub async fn update_claimed(
        &self,
        input: NewDirectoryConfig,
        claim: OpaqueDirectoryClaim,
    ) -> AxiamResult<DirectoryConfig> {
        self.update_inner(input, Some(claim)).await
    }

    async fn create_inner(
        &self,
        input: NewDirectoryConfig,
        claim: Option<OpaqueDirectoryClaim>,
    ) -> AxiamResult<DirectoryConfig> {
        let key = self.key_for_write()?;
        let secret = input
            .bind_secret
            .as_ref()
            .ok_or_else(|| AxiamError::Validation {
                message: "a directory configuration requires a bind secret when it is created"
                    .into(),
            })?;
        let sealed = seal(key, secret)?;
        self.check_group_mappings(input.tenant_id, &input.group_mappings)
            .await?;
        let mapping_rows = mapping_rows(&input.group_mappings);
        let interval = sync_interval(&input)?;

        let id = new_id();
        let tenant_id = input.tenant_id;
        // A conflicted attempt committed nothing, so the replay cannot create
        // twice; the unique index on `tenant_id` is what makes a second create
        // for the same tenant an `AlreadyExists` rather than a second
        // configuration.
        retry_on_write_conflict(|| {
            self.create_tx(id, &input, &sealed, mapping_rows.clone(), interval, claim)
        })
        .await
        .map_err(AxiamError::from)?;

        let created = self.fetch_public(tenant_id).await?;
        Ok(take_first_or_not_found(
            created.into_iter().collect(),
            "directory_config",
            &tenant_id.to_string(),
        )?)
    }

    /// One attempt at the create, opened by the claim when there is one.
    async fn create_tx(
        &self,
        id: Uuid,
        input: &NewDirectoryConfig,
        sealed: &Sealed,
        mapping_rows: Vec<GroupMappingRow>,
        interval: i64,
        claim: Option<OpaqueDirectoryClaim>,
    ) -> Result<(), TxFail> {
        let create = "CREATE type::record('directory_config', $id) SET \
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
                 group_mappings = $group_mappings, \
                 sync_interval_secs = $sync_interval_secs, \
                 jit_provisioning = $jit_provisioning, \
                 trust_anchors_pem = $trust_anchors_pem, \
                 created_at = time::now(), updated_at = time::now()";
        let query = claimed_query(create, claim);
        let (nonce, ciphertext) = sealed.clone();
        let db = self.db.current();
        let mut q = db
            .query(query)
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("enabled", input.enabled))
            .bind(("kind", input.kind.as_str().to_string()))
            .bind(("url", input.url.clone()))
            .bind(("start_tls", input.start_tls))
            .bind(("bind_dn", input.bind_dn.clone()))
            .bind(("ciphertext", ciphertext))
            .bind(("nonce", nonce))
            .bind(("key_version", SECRET_KEY_VERSION))
            .bind(("base_dn", input.base_dn.clone()))
            .bind(("user_filter", input.user_filter.clone()))
            .bind(("attr_username", input.user_attribute_map.username.clone()))
            .bind(("attr_email", input.user_attribute_map.email.clone()))
            .bind((
                "attr_display_name",
                input.user_attribute_map.display_name.clone(),
            ))
            .bind((
                "attr_external_id",
                input.user_attribute_map.external_id.clone(),
            ))
            .bind(("group_base_dn", input.group_base_dn.clone()))
            .bind(("group_filter", input.group_filter.clone()))
            .bind((
                "group_member_attribute",
                input.group_member_attribute.clone(),
            ))
            .bind(("group_nesting_depth", i64::from(input.group_nesting_depth)))
            .bind(("group_mappings", mapping_rows))
            .bind(("sync_interval_secs", interval))
            .bind(("jit_provisioning", input.jit_provisioning))
            .bind(("trust_anchors_pem", input.trust_anchors_pem.clone()));
        if let Some(claim) = claim {
            q = q.bind(("opaque_claims", opaque_directory::bind_claims(&[claim])));
        }
        let result = q.await?;
        write_outcome(result, claim)
    }

    async fn update_inner(
        &self,
        input: NewDirectoryConfig,
        claim: Option<OpaqueDirectoryClaim>,
    ) -> AxiamResult<DirectoryConfig> {
        // `None` keeps the stored ciphertext and nonce untouched; `Some` writes
        // both, under a fresh nonce. **The key is needed only to seal**: an
        // update that carries no secret (enabling or disabling the directory,
        // editing a filter) neither reads nor writes one, so a deployment that
        // later lost its key can still switch its directory off (T23.3.8,
        // CONTRACT §30.3 rule 4: only a write that carries a secret is `503`).
        let sealed = match &input.bind_secret {
            Some(secret) => Some(seal(self.key_for_write()?, secret)?),
            None => None,
        };
        // D-30: before anything is written, so a refused table changes nothing.
        self.check_group_mappings(input.tenant_id, &input.group_mappings)
            .await?;
        let mapping_rows = mapping_rows(&input.group_mappings);
        let interval = sync_interval(&input)?;

        let moved = sealed.is_none().then(|| {
            (
                input.url.clone(),
                input.start_tls,
                input.bind_dn.clone(),
                input.trust_anchors_pem.clone(),
            )
        });

        let tenant_id = input.tenant_id;
        retry_on_write_conflict(|| {
            self.update_tx(
                &input,
                sealed.as_ref(),
                mapping_rows.clone(),
                interval,
                claim,
            )
        })
        .await
        .map_err(AxiamError::from)?;

        let updated = self.fetch_public(tenant_id).await?;
        let updated = take_first_or_not_found(
            updated.into_iter().collect(),
            "directory_config",
            &tenant_id.to_string(),
        )?;
        // The row exists; if the guard held it back, its connection still
        // differs from the one asked for. The message names the rule and none
        // of the values.
        if let Some((url, start_tls, bind_dn, anchors)) = moved
            && (updated.url != url
                || updated.start_tls != start_tls
                || updated.bind_dn != bind_dn
                || updated.trust_anchors_pem != anchors)
        {
            return Err(AxiamError::Validation {
                message: CONNECTION_MOVED_WITHOUT_SECRET.into(),
            });
        }
        Ok(updated)
    }

    /// One attempt at the update, opened by the claim when there is one.
    async fn update_tx(
        &self,
        input: &NewDirectoryConfig,
        sealed: Option<&Sealed>,
        mapping_rows: Vec<GroupMappingRow>,
        interval: i64,
        claim: Option<OpaqueDirectoryClaim>,
    ) -> Result<(), TxFail> {
        let secret_sets = if sealed.is_some() {
            "bind_secret_ciphertext = $ciphertext, bind_secret_nonce = $nonce, \
             secret_key_version = $key_version, "
        } else {
            ""
        };

        // P23W2-01: a stored secret is never sent to a server it was not
        // entered for. Without a new secret, the fields that decide where and
        // how the service bind goes — the URL, StartTLS, the bind DN and the
        // trust anchors — must equal the stored ones, or the update matches no
        // row. Otherwise whoever may edit the configuration could point it at a
        // host they control, with their own CA as the anchor, and receive the
        // write-only secret (D-15) in the next service bind. The guard is in
        // the `WHERE`, so the comparison and the write are one statement.
        let connection_guard = if sealed.is_some() {
            ""
        } else {
            " AND url = $url AND start_tls = $start_tls AND bind_dn = $bind_dn \
             AND trust_anchors_pem = $trust_anchors_pem"
        };

        let update = format!(
            "UPDATE directory_config SET {secret_sets}\
             enabled = $enabled, kind = $kind, url = $url, \
             start_tls = $start_tls, bind_dn = $bind_dn, base_dn = $base_dn, \
             user_filter = $user_filter, attr_username = $attr_username, \
             attr_email = $attr_email, attr_display_name = $attr_display_name, \
             attr_external_id = $attr_external_id, \
             group_base_dn = $group_base_dn, group_filter = $group_filter, \
             group_member_attribute = $group_member_attribute, \
             group_nesting_depth = $group_nesting_depth, \
             group_mappings = $group_mappings, \
             sync_interval_secs = $sync_interval_secs, \
             jit_provisioning = $jit_provisioning, \
             trust_anchors_pem = $trust_anchors_pem, \
             updated_at = time::now() \
             WHERE tenant_id = $tenant_id{connection_guard}"
        );
        let query = claimed_query(&update, claim);
        let db = self.db.current();
        let mut q = db
            .query(query)
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("enabled", input.enabled))
            .bind(("kind", input.kind.as_str().to_string()))
            .bind(("url", input.url.clone()))
            .bind(("start_tls", input.start_tls))
            .bind(("bind_dn", input.bind_dn.clone()))
            .bind(("base_dn", input.base_dn.clone()))
            .bind(("user_filter", input.user_filter.clone()))
            .bind(("attr_username", input.user_attribute_map.username.clone()))
            .bind(("attr_email", input.user_attribute_map.email.clone()))
            .bind((
                "attr_display_name",
                input.user_attribute_map.display_name.clone(),
            ))
            .bind((
                "attr_external_id",
                input.user_attribute_map.external_id.clone(),
            ))
            .bind(("group_base_dn", input.group_base_dn.clone()))
            .bind(("group_filter", input.group_filter.clone()))
            .bind((
                "group_member_attribute",
                input.group_member_attribute.clone(),
            ))
            .bind(("group_nesting_depth", i64::from(input.group_nesting_depth)))
            .bind(("group_mappings", mapping_rows))
            .bind(("sync_interval_secs", interval))
            .bind(("jit_provisioning", input.jit_provisioning))
            .bind(("trust_anchors_pem", input.trust_anchors_pem.clone()));
        if let Some((nonce, ciphertext)) = sealed.cloned() {
            q = q
                .bind(("ciphertext", ciphertext))
                .bind(("nonce", nonce))
                .bind(("key_version", SECRET_KEY_VERSION));
        }
        if let Some(claim) = claim {
            q = q.bind(("opaque_claims", opaque_directory::bind_claims(&[claim])));
        }
        let result = q.await?;
        write_outcome(result, claim)
    }
}

/// The stored form of a mapping table.
fn mapping_rows(mappings: &[GroupMapping]) -> Vec<GroupMappingRow> {
    mappings
        .iter()
        .map(|m| GroupMappingRow {
            directory_group_dn: m.directory_group_dn.clone(),
            group_id: m.group_id.to_string(),
        })
        .collect()
}

/// `sync_interval_secs` as the column stores it.
fn sync_interval(input: &NewDirectoryConfig) -> AxiamResult<i64> {
    i64::try_from(input.sync_interval_secs).map_err(|_| AxiamError::Validation {
        message: "sync_interval_secs is out of range".into(),
    })
}

/// A write statement alone, or — claimed — the claim and the write as one
/// transaction (BEGIN, the claim's slot, the write, COMMIT).
fn claimed_query(write: &str, claim: Option<OpaqueDirectoryClaim>) -> String {
    match claim {
        Some(_) => format!(
            "BEGIN TRANSACTION; {claim}{write}; COMMIT TRANSACTION",
            claim = opaque_directory::claim_statement(false),
        ),
        None => write.to_owned(),
    }
}

/// A write's statement errors, read: a claimed write's stale refusal first
/// (`opaque_directory::outcome`), otherwise classified — a UNIQUE violation is
/// `AlreadyExists`, an engine conflict is retried.
fn write_outcome(
    mut result: surrealdb::IndexedResults,
    claim: Option<OpaqueDirectoryClaim>,
) -> Result<(), TxFail> {
    match claim {
        Some(_) => opaque_directory::outcome(result.take_errors(), "directory_config"),
        None => result
            .check()
            .map(|_| ())
            .map_err(|e| TxFail::Db(classify_write_error(e, "directory_config"))),
    }
}

impl<C: Connection> DirectoryConfigRepository for SurrealDirectoryConfigRepository<C> {
    async fn create(&self, input: NewDirectoryConfig) -> AxiamResult<DirectoryConfig> {
        self.create_inner(input, None).await
    }

    async fn update(&self, input: NewDirectoryConfig) -> AxiamResult<DirectoryConfig> {
        self.update_inner(input, None).await
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
