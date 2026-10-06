//! SurrealDB implementations of [`ScimTargetRepository`],
//! [`ScimTargetLinkRepository`] and [`ScimTargetStateRepository`] (G-6,
//! T23.6.1, schema v79).
//!
//! # The credential
//!
//! Sealed with AES-256-GCM under `pki_encryption_key` — the key webhook secrets
//! and SSF push headers use, since it protects the same class of value: a
//! credential AXIAM presents to a tenant-registered outbound endpoint — with a
//! fresh nonce per write, nonce and ciphertext in their own columns and a key
//! version. The key is **optional**: a repository built without it refuses any
//! write that sets a credential (fail closed, naming the key; and `create`
//! always sets one) and serves everything else. Every read projects
//! [`PUBLIC_COLUMNS`], so the ciphertext never leaves the datastore except
//! through [`SurrealScimTargetRepository::decrypt_credential`].
//!
//! # Two writers, one version
//!
//! An administrator's update is conditional on the `updated_at` it read. The
//! repository reads the stored row itself first (to apply the URL-binding rule
//! against what is stored), and its write is conditional on **that** version,
//! so the rule is checked against the very row it replaces: a write racing it
//! matches nothing and is a `Conflict`, never a credential aimed at a URL the
//! rule did not see. The deliverer never writes the target row; its state lives
//! in `scim_target_state`, written only with atomic increments and plain sets.

use axiam_auth::crypto::{decrypt_separate, encrypt_separate};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::scim_target::{
    DeprovisionPolicy, NewScimTarget, NewScimTargetLink, ScimLinkState, ScimResourceType,
    ScimTarget, ScimTargetAuth, ScimTargetLink, ScimTargetScope, ScimTargetState, ScimTargetUpdate,
    UserNameSource,
};
use axiam_core::repository::{
    PaginatedResult, Pagination, ScimTargetLinkRepository, ScimTargetRepository,
    ScimTargetStateRepository,
};
use axiam_core::secrets::{PKI_ENCRYPTION_KEY, env_var_name};
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, DELETE_TARGET_MISSING, classify_write_error, delete_existence_guard,
    is_write_conflict, map_delete_errors, paginate, parse_uuid, search_bind, search_filter,
    take_first_or_not_found, write_conflict_backoff,
};

const ENTITY: &str = "scim_target";
const LINK_ENTITY: &str = "scim_target_link";

/// The key version written today, as `ssf_stream` writes its own.
const SECRET_KEY_VERSION: i64 = 1;

/// The longest failure reason kept, in characters. The deliverer's reasons are
/// a fixed vocabulary; the bound is a backstop for the column's `ASSERT`.
const MAX_REASON_CHARS: usize = 256;

/// Every non-secret column of `scim_target`, projected explicitly: a read of
/// this table never hydrates `cred_ciphertext` or `cred_nonce`.
const PUBLIC_COLUMNS: &str = "meta::id(id) AS record_id, tenant_id, name, base_url, enabled, \
    auth_kind, token_url, client_id, oauth_scope, scope_kind, scope_group_ids, push_groups, \
    user_name_from, deprovision, created_at, updated_at";

#[derive(Debug, SurrealValue)]
struct TargetRow {
    record_id: String,
    tenant_id: String,
    name: String,
    base_url: String,
    enabled: bool,
    auth_kind: String,
    token_url: Option<String>,
    client_id: Option<String>,
    oauth_scope: Option<String>,
    scope_kind: String,
    scope_group_ids: Vec<String>,
    push_groups: bool,
    user_name_from: String,
    deprovision: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TargetRow {
    fn into_domain(self) -> Result<ScimTarget, DbError> {
        let unknown =
            |what: &str| DbError::Serialization(format!("scim_target has an unknown {what}"));
        let malformed =
            |what: &str| DbError::Serialization(format!("scim_target has a malformed {what}"));
        let auth = match self.auth_kind.as_str() {
            "bearer" => ScimTargetAuth::Bearer,
            "oauth2_client_credentials" => ScimTargetAuth::OAuth2ClientCredentials {
                token_url: self.token_url.ok_or_else(|| malformed("token_url"))?,
                client_id: self.client_id.ok_or_else(|| malformed("client_id"))?,
                scope: self.oauth_scope,
            },
            _ => return Err(unknown("auth_kind")),
        };
        let scope = match self.scope_kind.as_str() {
            "all_users" => ScimTargetScope::AllUsers,
            "groups" => ScimTargetScope::Groups(
                self.scope_group_ids
                    .iter()
                    .map(|g| parse_uuid(g, "group"))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            _ => return Err(unknown("scope_kind")),
        };
        Ok(ScimTarget {
            id: parse_uuid(&self.record_id, ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            name: self.name,
            base_url: self.base_url,
            enabled: self.enabled,
            auth,
            scope,
            push_groups: self.push_groups,
            user_name_from: UserNameSource::from_wire(&self.user_name_from)
                .ok_or_else(|| unknown("user_name_from"))?,
            deprovision: DeprovisionPolicy::from_wire(&self.deprovision)
                .ok_or_else(|| unknown("deprovision"))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The two secret columns. Deliberately not `Debug`.
#[derive(SurrealValue)]
struct SecretRow {
    cred_ciphertext: Option<String>,
    cred_nonce: Option<String>,
}

/// The auth columns as they are written: `(auth_kind, token_url, client_id,
/// oauth_scope)`.
fn auth_columns(
    auth: &ScimTargetAuth,
) -> (&'static str, Option<String>, Option<String>, Option<String>) {
    match auth {
        ScimTargetAuth::Bearer => ("bearer", None, None, None),
        ScimTargetAuth::OAuth2ClientCredentials {
            token_url,
            client_id,
            scope,
        } => (
            "oauth2_client_credentials",
            Some(token_url.clone()),
            Some(client_id.clone()),
            scope.clone(),
        ),
    }
}

/// The scope columns as they are written: `(scope_kind, scope_group_ids)`.
/// Duplicate groups are dropped, first occurrence kept.
fn scope_columns(scope: &ScimTargetScope) -> (&'static str, Vec<String>) {
    match scope {
        ScimTargetScope::AllUsers => ("all_users", Vec::new()),
        ScimTargetScope::Groups(ids) => {
            let mut seen = std::collections::HashSet::new();
            let groups = ids
                .iter()
                .filter(|id| seen.insert(**id))
                .map(Uuid::to_string)
                .collect();
            ("groups", groups)
        }
    }
}

/// Whether `new` sends the stored credential — or what it yields — somewhere it
/// did not go before: a different authentication kind, a different `base_url`
/// for a bearer target, or a different `token_url` **or `base_url`** for a
/// client-credentials target (D-57, amended by the W5 F4 review, T-409: the
/// secret goes to `token_url`, and every access token minted with it goes to
/// `base_url`, so moving either moves what the secret is worth).
fn moves_credential(stored: &ScimTarget, new_base_url: &str, new_auth: &ScimTargetAuth) -> bool {
    match (&stored.auth, new_auth) {
        (ScimTargetAuth::Bearer, ScimTargetAuth::Bearer) => stored.base_url != new_base_url,
        (
            ScimTargetAuth::OAuth2ClientCredentials { token_url: old, .. },
            ScimTargetAuth::OAuth2ClientCredentials { token_url: new, .. },
        ) => old != new || stored.base_url != new_base_url,
        _ => true,
    }
}

fn truncate_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

/// Encrypt the credential, returning `(nonce_b64, ciphertext_b64)`. The error
/// carries no detail.
fn seal(key: &[u8; 32], credential: &str) -> AxiamResult<(String, String)> {
    encrypt_separate(key, credential.as_bytes())
        .map_err(|_| AxiamError::Crypto("the SCIM target credential could not be encrypted".into()))
}

/// SurrealDB implementation of [`ScimTargetRepository`].
pub struct SurrealScimTargetRepository<C: Connection> {
    db: DbHandle<C>,
    key: Option<[u8; 32]>,
}

impl<C: Connection> Clone for SurrealScimTargetRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            key: self.key,
        }
    }
}

/// Redacting `Debug`: the key is the one thing in this struct worth protecting.
impl<C: Connection> std::fmt::Debug for SurrealScimTargetRepository<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealScimTargetRepository")
            .field("key_configured", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

impl<C: Connection> SurrealScimTargetRepository<C> {
    /// Build the repository. `key` is the 256-bit `pki_encryption_key`, or
    /// `None` when it is not configured: then a write that sets a credential
    /// (every `create`, and an `update` that supplies one) is refused.
    pub fn new(db: impl Into<DbHandle<C>>, key: Option<[u8; 32]>) -> Self {
        Self { db: db.into(), key }
    }

    /// Whether the encryption key is configured, for a route that must answer
    /// `503` before it validates a credential it could not store.
    #[must_use]
    pub fn has_encryption_key(&self) -> bool {
        self.key.is_some()
    }

    fn missing_key_message() -> String {
        format!(
            "a SCIM target credential cannot be stored: {PKI_ENCRYPTION_KEY} ({}) is not \
             configured",
            env_var_name(PKI_ENCRYPTION_KEY)
        )
    }

    fn sealed(&self, credential: &str) -> AxiamResult<(String, String)> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| AxiamError::ServiceUnavailable(Self::missing_key_message()))?;
        seal(key, credential)
    }

    async fn fetch(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Option<ScimTarget>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM scim_target \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<TargetRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }
}

impl<C: Connection> ScimTargetRepository for SurrealScimTargetRepository<C> {
    async fn create(&self, input: NewScimTarget) -> AxiamResult<ScimTarget> {
        let (nonce, ciphertext) = self.sealed(&input.credential)?;
        let (auth_kind, token_url, client_id, oauth_scope) = auth_columns(&input.auth);
        let (scope_kind, scope_group_ids) = scope_columns(&input.scope);
        let id = new_id();
        let tenant_id = input.tenant_id;
        // The target and its (empty) delivery state land together, so a state
        // write never meets a target without its row.
        let result = self
            .db
            .current()
            .query(
                "BEGIN TRANSACTION; \
                 CREATE type::record('scim_target', $id) SET \
                   tenant_id = $tenant_id, name = $name, base_url = $base_url, \
                   enabled = $enabled, auth_kind = $auth_kind, token_url = $token_url, \
                   client_id = $client_id, oauth_scope = $oauth_scope, \
                   cred_ciphertext = $ciphertext, cred_nonce = $nonce, \
                   secret_key_version = $key_version, scope_kind = $scope_kind, \
                   scope_group_ids = $scope_group_ids, push_groups = $push_groups, \
                   user_name_from = $user_name_from, deprovision = $deprovision, \
                   created_at = time::now(), updated_at = time::now(); \
                 CREATE type::record('scim_target_state', $id) SET \
                   tenant_id = $tenant_id, target_id = $id, consecutive_failures = 0, \
                   dead_lettered_total = 0; \
                 COMMIT TRANSACTION",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("name", input.name))
            .bind(("base_url", input.base_url))
            .bind(("enabled", input.enabled))
            .bind(("auth_kind", auth_kind.to_owned()))
            .bind(("token_url", token_url))
            .bind(("client_id", client_id))
            .bind(("oauth_scope", oauth_scope))
            .bind(("ciphertext", ciphertext))
            .bind(("nonce", nonce))
            .bind(("key_version", SECRET_KEY_VERSION))
            .bind(("scope_kind", scope_kind.to_owned()))
            .bind(("scope_group_ids", scope_group_ids))
            .bind(("push_groups", input.push_groups))
            .bind(("user_name_from", input.user_name_from.as_str().to_owned()))
            .bind(("deprovision", input.deprovision.as_str().to_owned()))
            .await
            .map_err(DbError::from)?;
        result
            .check()
            .map_err(|e| classify_write_error(e, ENTITY))?;
        self.get(tenant_id, id).await
    }

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<ScimTarget> {
        let found = self.fetch(tenant_id, id).await?;
        Ok(take_first_or_not_found(
            found.into_iter().collect(),
            ENTITY,
            &id.to_string(),
        )?)
    }

    async fn list_page(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<ScimTarget>> {
        let search = search_filter(&pagination, &["name", "base_url"]);
        let search_term = search_bind(&pagination);
        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM scim_target \
                 WHERE tenant_id = $tenant_id{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM scim_target \
                 WHERE tenant_id = $tenant_id{search} \
                 ORDER BY created_at ASC, record_id ASC LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<TargetRow> = result.take(0).map_err(DbError::from)?;
        let items = rows
            .into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect::<AxiamResult<Vec<_>>>()?;
        Ok(paginate(items, count_rows, &pagination))
    }

    async fn list_enabled(&self, tenant_id: Uuid) -> AxiamResult<Vec<ScimTarget>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM scim_target \
                 WHERE tenant_id = $tenant_id AND enabled = true \
                 ORDER BY created_at ASC, record_id ASC"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<TargetRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect()
    }

    async fn list_all_enabled(&self) -> AxiamResult<Vec<ScimTarget>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM scim_target WHERE enabled = true \
                 ORDER BY created_at ASC, record_id ASC"
            ))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<TargetRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect()
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        update: ScimTargetUpdate,
    ) -> AxiamResult<ScimTarget> {
        // The stored row first: missing, or another tenant's, is `NotFound`.
        let stored = self
            .fetch(tenant_id, id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: ENTITY.into(),
                id: id.to_string(),
            })?;
        let conflict = || AxiamError::Conflict {
            reason: "the SCIM target changed since it was read; read it again and retry".into(),
        };
        if update
            .expected_updated_at
            .is_some_and(|expected| expected != stored.updated_at)
        {
            return Err(conflict());
        }

        // D-57: the credential stays bound to the URL it was registered for.
        if update.credential.is_none() && moves_credential(&stored, &update.base_url, &update.auth)
        {
            return Err(AxiamError::Validation {
                message: "changing the URL a SCIM target's credential is sent to, or its \
                          authentication kind, requires the credential in the same write"
                    .into(),
            });
        }

        let (secret_clause, ciphertext, nonce) = match &update.credential {
            None => ("", None, None),
            Some(credential) => {
                let (n, c) = self.sealed(credential)?;
                (
                    ", cred_ciphertext = $ciphertext, cred_nonce = $nonce, \
                     secret_key_version = $key_version",
                    Some(c),
                    Some(n),
                )
            }
        };
        let (auth_kind, token_url, client_id, oauth_scope) = auth_columns(&update.auth);
        let (scope_kind, scope_group_ids) = scope_columns(&update.scope);

        // The tenant guard and the version guard are in the `WHERE`: another
        // tenant's row, or a row written since the read above, matches
        // nothing. The version is the one this method read (and validated the
        // URL rule against), which equals `expected_updated_at` when that was
        // given.
        let result = self
            .db
            .current()
            .query(format!(
                "UPDATE type::record('scim_target', $id) SET \
                   name = $name, base_url = $base_url, enabled = $enabled, \
                   auth_kind = $auth_kind, token_url = $token_url, client_id = $client_id, \
                   oauth_scope = $oauth_scope, scope_kind = $scope_kind, \
                   scope_group_ids = $scope_group_ids, push_groups = $push_groups, \
                   user_name_from = $user_name_from, deprovision = $deprovision\
                   {secret_clause}, updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND updated_at = $stored_updated_at \
                 RETURN VALUE meta::id(id)"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("stored_updated_at", stored.updated_at))
            .bind(("name", update.name))
            .bind(("base_url", update.base_url))
            .bind(("enabled", update.enabled))
            .bind(("auth_kind", auth_kind.to_owned()))
            .bind(("token_url", token_url))
            .bind(("client_id", client_id))
            .bind(("oauth_scope", oauth_scope))
            .bind(("scope_kind", scope_kind.to_owned()))
            .bind(("scope_group_ids", scope_group_ids))
            .bind(("push_groups", update.push_groups))
            .bind(("user_name_from", update.user_name_from.as_str().to_owned()))
            .bind(("deprovision", update.deprovision.as_str().to_owned()))
            .bind(("ciphertext", ciphertext))
            .bind(("nonce", nonce))
            .bind(("key_version", SECRET_KEY_VERSION))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e, ENTITY))?;
        let written: Vec<String> = result.take(0).map_err(DbError::from)?;
        if written.is_empty() {
            // Present when read, gone or overtaken now: told apart by the read.
            self.get(tenant_id, id).await?;
            return Err(conflict());
        }
        self.get(tenant_id, id).await
    }

    async fn decrypt_credential(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AxiamResult<Option<Zeroizing<String>>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT cred_ciphertext, cred_nonce FROM scim_target \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SecretRow> = result.take(0).map_err(DbError::from)?;
        let Some(row) = rows.into_iter().next() else {
            return Err(DbError::NotFound {
                entity: ENTITY.into(),
                id: id.to_string(),
            }
            .into());
        };
        let (Some(ciphertext), Some(nonce)) = (row.cred_ciphertext, row.cred_nonce) else {
            return Ok(None);
        };
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| AxiamError::ServiceUnavailable(Self::missing_key_message()))?;
        let plaintext = decrypt_separate(key, &nonce, &ciphertext).map_err(|_| {
            AxiamError::Crypto(
                "the SCIM target credential could not be decrypted: the stored value does not \
                 match the configured pki_encryption_key"
                    .into(),
            )
        })?;
        let text = String::from_utf8(plaintext).map_err(|_| {
            AxiamError::Crypto("the decrypted SCIM target credential is not valid UTF-8".into())
        })?;
        Ok(Some(Zeroizing::new(text)))
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        // One transaction: the existence guard (a foreign or unknown id aborts
        // with `NotFound` before anything is removed), the target's links and
        // delivery state, then the target. Nothing is sent downstream.
        let guard = delete_existence_guard(ENTITY);
        let query = format!(
            "BEGIN TRANSACTION; \
             {guard} \
             DELETE scim_target_link WHERE tenant_id = $tenant_id AND target_id = $id; \
             DELETE type::record('scim_target_state', $id) WHERE tenant_id = $tenant_id; \
             DELETE type::record('scim_target', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        map_delete_errors(result.take_errors(), ENTITY, &id.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

const LINK_COLUMNS: &str = "tenant_id, target_id, resource_type, axiam_id, downstream_id, \
    synced_digest, state, erase_pending, created_at, updated_at";

#[derive(Debug, SurrealValue)]
struct LinkRow {
    tenant_id: String,
    target_id: String,
    resource_type: String,
    axiam_id: String,
    downstream_id: String,
    synced_digest: Option<String>,
    state: String,
    erase_pending: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl LinkRow {
    fn into_domain(self) -> Result<ScimTargetLink, DbError> {
        let unknown =
            |what: &str| DbError::Serialization(format!("scim_target_link has an unknown {what}"));
        Ok(ScimTargetLink {
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            target_id: parse_uuid(&self.target_id, ENTITY)?,
            resource_type: ScimResourceType::from_wire(&self.resource_type)
                .ok_or_else(|| unknown("resource_type"))?,
            axiam_id: parse_uuid(&self.axiam_id, "resource")?,
            downstream_id: self.downstream_id,
            synced_digest: self.synced_digest,
            state: ScimLinkState::from_wire(&self.state).ok_or_else(|| unknown("state"))?,
            erase_pending: self.erase_pending,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of [`ScimTargetLinkRepository`].
pub struct SurrealScimTargetLinkRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealScimTargetLinkRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealScimTargetLinkRepository<C> {
    /// Build the repository.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    async fn fetch_one(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: ScimResourceType,
        column: &str,
        value: String,
    ) -> AxiamResult<Option<ScimTargetLink>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {LINK_COLUMNS} FROM scim_target_link \
                 WHERE tenant_id = $tenant_id AND target_id = $target_id \
                   AND resource_type = $resource_type AND {column} = $value"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("target_id", target_id.to_string()))
            .bind(("resource_type", resource_type.as_str().to_owned()))
            .bind(("value", value))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<LinkRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }

    /// Run a link write behind the target's existence guard, mapping a
    /// missing target to `NotFound` and a unique-index hit to `AlreadyExists`.
    async fn guarded_write(
        &self,
        statements: &str,
        input: &NewScimTargetLink,
    ) -> Result<(), DbError> {
        let guard = delete_existence_guard(ENTITY);
        let mut result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; {guard} {statements} COMMIT TRANSACTION"
            ))
            .bind(("id", input.target_id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("target_id", input.target_id.to_string()))
            .bind(("link_id", new_id().to_string()))
            .bind(("resource_type", input.resource_type.as_str().to_owned()))
            .bind(("axiam_id", input.axiam_id.to_string()))
            .bind(("downstream_id", input.downstream_id.clone()))
            .await
            .map_err(DbError::from)?;
        let errors = result.take_errors();
        if errors.is_empty() {
            return Ok(());
        }
        let combined = errors
            .into_values()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        if combined.contains(DELETE_TARGET_MISSING) {
            return Err(DbError::NotFound {
                entity: ENTITY.into(),
                id: input.target_id.to_string(),
            });
        }
        Err(classify_write_error(combined, LINK_ENTITY))
    }
}

const CREATE_LINK: &str = "CREATE type::record('scim_target_link', $link_id) SET \
    tenant_id = $tenant_id, target_id = $target_id, resource_type = $resource_type, \
    axiam_id = $axiam_id, downstream_id = $downstream_id, synced_digest = NONE, \
    state = 'active', erase_pending = false, created_at = time::now(), \
    updated_at = time::now();";

impl<C: Connection> ScimTargetLinkRepository for SurrealScimTargetLinkRepository<C> {
    async fn get(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
    ) -> AxiamResult<Option<ScimTargetLink>> {
        self.fetch_one(
            tenant_id,
            target_id,
            resource_type,
            "axiam_id",
            axiam_id.to_string(),
        )
        .await
    }

    async fn get_by_downstream_id(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: ScimResourceType,
        downstream_id: &str,
    ) -> AxiamResult<Option<ScimTargetLink>> {
        self.fetch_one(
            tenant_id,
            target_id,
            resource_type,
            "downstream_id",
            downstream_id.to_owned(),
        )
        .await
    }

    async fn create(&self, input: NewScimTargetLink) -> AxiamResult<ScimTargetLink> {
        self.guarded_write(CREATE_LINK, &input).await?;
        self.get(
            input.tenant_id,
            input.target_id,
            input.resource_type,
            input.axiam_id,
        )
        .await?
        .ok_or_else(|| {
            DbError::NotFound {
                entity: LINK_ENTITY.into(),
                id: input.axiam_id.to_string(),
            }
            .into()
        })
    }

    async fn upsert(&self, input: NewScimTargetLink) -> AxiamResult<ScimTargetLink> {
        // Repoint an existing link, else create one; if a concurrent writer
        // created it between the two, the create is `AlreadyExists` and the
        // repoint is tried once more.
        let repoint = "LET $moved = (UPDATE scim_target_link SET \
                 downstream_id = $downstream_id, synced_digest = NONE, state = 'active', \
                 erase_pending = false, updated_at = time::now() \
               WHERE tenant_id = $tenant_id AND target_id = $target_id \
                 AND resource_type = $resource_type AND axiam_id = $axiam_id \
               RETURN VALUE meta::id(id)); \
             IF array::len($moved) == 0 { "
            .to_owned()
            + CREATE_LINK
            + " };";
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.guarded_write(&repoint, &input).await {
                Ok(()) => break,
                Err(DbError::AlreadyExists { .. })
                    if attempt < 2
                        && self
                            .get(
                                input.tenant_id,
                                input.target_id,
                                input.resource_type,
                                input.axiam_id,
                            )
                            .await?
                            .is_some() => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.get(
            input.tenant_id,
            input.target_id,
            input.resource_type,
            input.axiam_id,
        )
        .await?
        .ok_or_else(|| {
            DbError::NotFound {
                entity: LINK_ENTITY.into(),
                id: input.axiam_id.to_string(),
            }
            .into()
        })
    }

    async fn set_digest(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
        digest: Option<String>,
    ) -> AxiamResult<()> {
        self.update_link(
            tenant_id,
            target_id,
            resource_type,
            axiam_id,
            "synced_digest = $digest",
            vec![("digest", LinkBind::Text(digest))],
        )
        .await
    }

    async fn set_state(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
        state: ScimLinkState,
        erase_pending: bool,
    ) -> AxiamResult<()> {
        self.update_link(
            tenant_id,
            target_id,
            resource_type,
            axiam_id,
            "state = $state, erase_pending = $erase_pending",
            vec![
                ("state", LinkBind::Text(Some(state.as_str().to_owned()))),
                ("erase_pending", LinkBind::Flag(erase_pending)),
            ],
        )
        .await
    }

    async fn delete(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
    ) -> AxiamResult<bool> {
        let mut result = self
            .db
            .current()
            .query(
                "DELETE scim_target_link WHERE tenant_id = $tenant_id \
                   AND target_id = $target_id AND resource_type = $resource_type \
                   AND axiam_id = $axiam_id RETURN BEFORE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("target_id", target_id.to_string()))
            .bind(("resource_type", resource_type.as_str().to_owned()))
            .bind(("axiam_id", axiam_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let removed: Vec<LinkRow> = result.take(0).map_err(DbError::from)?;
        Ok(!removed.is_empty())
    }

    async fn list_by_target(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: Option<ScimResourceType>,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<ScimTargetLink>> {
        let type_filter = if resource_type.is_some() {
            " AND resource_type = $resource_type"
        } else {
            ""
        };
        let type_bind = resource_type.map(|t| t.as_str().to_owned());
        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM scim_target_link \
                 WHERE tenant_id = $tenant_id AND target_id = $target_id{type_filter} \
                 GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("target_id", target_id.to_string()))
            .bind(("resource_type", type_bind.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {LINK_COLUMNS} FROM scim_target_link \
                 WHERE tenant_id = $tenant_id AND target_id = $target_id{type_filter} \
                 ORDER BY created_at ASC, axiam_id ASC LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("target_id", target_id.to_string()))
            .bind(("resource_type", type_bind))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<LinkRow> = result.take(0).map_err(DbError::from)?;
        let items = rows
            .into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect::<AxiamResult<Vec<_>>>()?;
        Ok(paginate(items, count_rows, &pagination))
    }

    async fn delete_all_for_target(&self, tenant_id: Uuid, target_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "DELETE scim_target_link WHERE tenant_id = $tenant_id \
                   AND target_id = $target_id RETURN BEFORE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("target_id", target_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let removed: Vec<LinkRow> = result.take(0).map_err(DbError::from)?;
        Ok(removed.len() as u64)
    }
}

/// A value bound by [`SurrealScimTargetLinkRepository::update_link`].
enum LinkBind {
    Text(Option<String>),
    Flag(bool),
}

impl<C: Connection> SurrealScimTargetLinkRepository<C> {
    /// `UPDATE` one link's `set_clause` (plus `updated_at`), `NotFound` when no
    /// row of this tenant and target matches.
    async fn update_link(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
        set_clause: &str,
        binds: Vec<(&'static str, LinkBind)>,
    ) -> AxiamResult<()> {
        let db = self.db.current();
        let mut query = db
            .query(format!(
                "UPDATE scim_target_link SET {set_clause}, updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND target_id = $target_id \
                   AND resource_type = $resource_type AND axiam_id = $axiam_id \
                 RETURN VALUE axiam_id"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("target_id", target_id.to_string()))
            .bind(("resource_type", resource_type.as_str().to_owned()))
            .bind(("axiam_id", axiam_id.to_string()));
        for (name, value) in binds {
            query = match value {
                LinkBind::Text(v) => query.bind((name, v)),
                LinkBind::Flag(v) => query.bind((name, v)),
            };
        }
        let mut result = query
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| classify_write_error(e, LINK_ENTITY))?;
        let written: Vec<String> = result.take(0).map_err(DbError::from)?;
        if written.is_empty() {
            return Err(DbError::NotFound {
                entity: LINK_ENTITY.into(),
                id: axiam_id.to_string(),
            }
            .into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// State

/// How many attempts a write to the delivery-state row gets before its
/// conflict surfaces. The shared helper's four are sized for an occasional
/// collision; this row is hot by design — every delivery of every message of one
/// target, on every replica, increments it — so a burst of dead-letters needs
/// more patience. A conflicted transaction commits nothing, so replaying an
/// increment cannot double-count.
const STATE_MAX_WRITE_ATTEMPTS: u32 = 32;

/// Run `op`, retrying while it fails with a retryable write conflict, up to
/// [`STATE_MAX_WRITE_ATTEMPTS`] times with the shared backoff.
async fn retry_hot_row<T, F, Fut>(mut op: F) -> Result<T, DbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, DbError>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Err(e) if attempt < STATE_MAX_WRITE_ATTEMPTS && is_write_conflict(&e.to_string()) => {
                tokio::time::sleep(write_conflict_backoff(attempt)).await;
                attempt += 1;
            }
            outcome => return outcome,
        }
    }
}
// ---------------------------------------------------------------------------

const STATE_COLUMNS: &str = "tenant_id, target_id, last_success_at, last_failure_at, \
    last_failure_reason, consecutive_failures, dead_lettered_total, last_reconciled_at, \
    reconcile_claimed_at";

#[derive(Debug, SurrealValue)]
struct StateRow {
    tenant_id: String,
    target_id: String,
    last_success_at: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    last_failure_reason: Option<String>,
    consecutive_failures: i64,
    dead_lettered_total: i64,
    last_reconciled_at: Option<DateTime<Utc>>,
    reconcile_claimed_at: Option<DateTime<Utc>>,
}

impl StateRow {
    fn into_domain(self) -> Result<ScimTargetState, DbError> {
        Ok(ScimTargetState {
            target_id: parse_uuid(&self.target_id, ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            last_success_at: self.last_success_at,
            last_failure_at: self.last_failure_at,
            last_failure_reason: self.last_failure_reason,
            consecutive_failures: u64::try_from(self.consecutive_failures).unwrap_or(0),
            dead_lettered_total: u64::try_from(self.dead_lettered_total).unwrap_or(0),
            last_reconciled_at: self.last_reconciled_at,
            reconcile_claimed_at: self.reconcile_claimed_at,
        })
    }
}

/// SurrealDB implementation of [`ScimTargetStateRepository`].
pub struct SurrealScimTargetStateRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealScimTargetStateRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealScimTargetStateRepository<C> {
    /// Build the repository.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// Run one atomic `UPDATE` of the target's state row. The row id is the
    /// target id, so a foreign tenant's target matches nothing (`NotFound`).
    /// Retried on an optimistic-concurrency loss, which commits nothing, so the
    /// non-idempotent increments cannot double-count.
    async fn write(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        set_clause: &'static str,
        reason: Option<String>,
    ) -> AxiamResult<bool> {
        let written: Vec<String> = retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(format!(
                    "UPDATE type::record('scim_target_state', $id) SET {set_clause} \
                     WHERE tenant_id = $tenant_id RETURN VALUE meta::id(id)"
                ))
                .bind(("id", target_id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("reason", reason.clone()))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "scim_target_state"))?;
            result.take(0).map_err(DbError::from)
        })
        .await?;
        Ok(!written.is_empty())
    }

    async fn write_or_not_found(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        set_clause: &'static str,
        reason: Option<String>,
    ) -> AxiamResult<()> {
        if self.write(tenant_id, target_id, set_clause, reason).await? {
            Ok(())
        } else {
            Err(DbError::NotFound {
                entity: ENTITY.into(),
                id: target_id.to_string(),
            }
            .into())
        }
    }
}

impl<C: Connection> ScimTargetStateRepository for SurrealScimTargetStateRepository<C> {
    async fn get(&self, tenant_id: Uuid, target_id: Uuid) -> AxiamResult<ScimTargetState> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {STATE_COLUMNS} FROM scim_target_state \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id"
            ))
            .bind(("id", target_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<StateRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, ENTITY, &target_id.to_string())?;
        Ok(row.into_domain()?)
    }

    async fn record_success(&self, tenant_id: Uuid, target_id: Uuid) -> AxiamResult<()> {
        self.write_or_not_found(
            tenant_id,
            target_id,
            "last_success_at = time::now(), consecutive_failures = 0",
            None,
        )
        .await
    }

    async fn record_failure(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        reason: &str,
    ) -> AxiamResult<()> {
        self.write_or_not_found(
            tenant_id,
            target_id,
            "consecutive_failures += 1, last_failure_at = time::now(), \
             last_failure_reason = $reason",
            Some(truncate_reason(reason)),
        )
        .await
    }

    async fn record_dead_letter(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        reason: &str,
    ) -> AxiamResult<()> {
        self.write_or_not_found(
            tenant_id,
            target_id,
            "dead_lettered_total += 1, last_failure_at = time::now(), \
             last_failure_reason = $reason",
            Some(truncate_reason(reason)),
        )
        .await
    }

    async fn claim_reconciliation(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        now: DateTime<Utc>,
        min_interval_secs: i64,
    ) -> AxiamResult<bool> {
        // Existence first, so "too soon" and "not yours" are told apart.
        self.get(tenant_id, target_id).await?;
        let cutoff = now - Duration::seconds(min_interval_secs);
        // The interval is the precondition of the write: two concurrent
        // claimants cannot both pass it (the loser either matches nothing or
        // loses the optimistic write, and then sees the winner's stamp).
        retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(
                    "UPDATE type::record('scim_target_state', $id) SET \
                       last_reconciled_at = $now, reconcile_claimed_at = $now \
                     WHERE tenant_id = $tenant_id \
                       AND (last_reconciled_at = NONE OR last_reconciled_at <= $cutoff) \
                     RETURN VALUE meta::id(id)",
                )
                .bind(("id", target_id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("now", now))
                .bind(("cutoff", cutoff))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "scim_target_state"))?;
            let claimed: Vec<String> = result.take(0).map_err(DbError::from)?;
            Ok::<_, DbError>(!claimed.is_empty())
        })
        .await
        .map_err(Into::into)
    }

    async fn claim_failure_notification(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        now: DateTime<Utc>,
        min_interval_secs: i64,
    ) -> AxiamResult<bool> {
        let cutoff = now - Duration::seconds(min_interval_secs);
        // The interval is the precondition of the write (the
        // `claim_reconciliation` pattern): of two concurrent claimants one
        // matches nothing or loses the optimistic write and then sees the
        // winner's stamp. A target of another tenant, or one deleted since,
        // matches nothing: `false`, never an error.
        retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(
                    "UPDATE type::record('scim_target_state', $id) SET \
                       failure_notified_at = $now \
                     WHERE tenant_id = $tenant_id \
                       AND (failure_notified_at = NONE OR failure_notified_at <= $cutoff) \
                     RETURN VALUE meta::id(id)",
                )
                .bind(("id", target_id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("now", now))
                .bind(("cutoff", cutoff))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "scim_target_state"))?;
            let claimed: Vec<String> = result.take(0).map_err(DbError::from)?;
            Ok::<_, DbError>(!claimed.is_empty())
        })
        .await
        .map_err(Into::into)
    }
}
