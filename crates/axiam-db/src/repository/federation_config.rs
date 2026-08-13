//! SurrealDB implementation of [`FederationConfigRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::federation::{
    CreateFederationConfig, DEFAULT_MAX_TOKEN_AGE_SECS, FederationConfig, FederationProtocol,
    SubjectMapping, TokenExchangeTrust, UpdateFederationConfig,
};
use axiam_core::repository::{FederationConfigRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, paginate, take_first_or_not_found};

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct FederationConfigRow {
    tenant_id: String,
    provider: String,
    protocol: String,
    metadata_url: Option<String>,
    client_id: String,
    client_secret: String,
    attribute_map: serde_json::Value,
    enabled: bool,
    // Phase 4 fields (D-10 / D-11) — DB schema defaults to [] / None for legacy rows
    allowed_algorithms: Vec<String>,
    idp_signing_cert_pem: Option<String>,
    client_secret_ciphertext: Option<String>,
    client_secret_nonce: Option<String>,
    client_secret_key_version: Option<i64>,
    // X4 token-exchange trust (schema v36) — every column is optional or
    // DEFAULT-ed, so a pre-X4 row hydrates to `TokenExchangeTrust::default()`.
    token_exchange_enabled: Option<bool>,
    token_exchange_accepted_audiences: Option<Vec<String>>,
    token_exchange_subject_mapping: Option<String>,
    token_exchange_scope_map_json: Option<String>,
    token_exchange_max_token_age_secs: Option<i64>,
    token_exchange_max_lifetime_secs: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct FederationConfigRowWithId {
    record_id: String,
    tenant_id: String,
    provider: String,
    protocol: String,
    metadata_url: Option<String>,
    client_id: String,
    client_secret: String,
    attribute_map: serde_json::Value,
    enabled: bool,
    // Phase 4 fields (D-10 / D-11)
    allowed_algorithms: Vec<String>,
    idp_signing_cert_pem: Option<String>,
    client_secret_ciphertext: Option<String>,
    client_secret_nonce: Option<String>,
    client_secret_key_version: Option<i64>,
    // X4 token-exchange trust (schema v36) — every column is optional or
    // DEFAULT-ed, so a pre-X4 row hydrates to `TokenExchangeTrust::default()`.
    token_exchange_enabled: Option<bool>,
    token_exchange_accepted_audiences: Option<Vec<String>>,
    token_exchange_subject_mapping: Option<String>,
    token_exchange_scope_map_json: Option<String>,
    token_exchange_max_token_age_secs: Option<i64>,
    token_exchange_max_lifetime_secs: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Row shape for `list()` — deliberately narrower than
/// [`FederationConfigRowWithId`]: omits `client_secret`,
/// `client_secret_ciphertext`, `client_secret_nonce`, and
/// `client_secret_key_version` so list views never hydrate the encrypted
/// secret columns (SECHRD-09 / D-06).
#[derive(Debug, SurrealValue)]
struct FederationConfigListRow {
    record_id: String,
    tenant_id: String,
    provider: String,
    protocol: String,
    metadata_url: Option<String>,
    client_id: String,
    attribute_map: serde_json::Value,
    enabled: bool,
    allowed_algorithms: Vec<String>,
    idp_signing_cert_pem: Option<String>,
    // X4 token-exchange trust (schema v36) — every column is optional or
    // DEFAULT-ed, so a pre-X4 row hydrates to `TokenExchangeTrust::default()`.
    token_exchange_enabled: Option<bool>,
    token_exchange_accepted_audiences: Option<Vec<String>>,
    token_exchange_subject_mapping: Option<String>,
    token_exchange_scope_map_json: Option<String>,
    token_exchange_max_token_age_secs: Option<i64>,
    token_exchange_max_lifetime_secs: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Row -> Domain conversions
// ---------------------------------------------------------------------------

fn parse_protocol(s: &str) -> Result<FederationProtocol, DbError> {
    match s {
        "OidcConnect" => Ok(FederationProtocol::OidcConnect),
        "Saml" => Ok(FederationProtocol::Saml),
        other => Err(DbError::Migration(format!(
            "Unknown federation protocol: {other}"
        ))),
    }
}

fn protocol_to_string(p: &FederationProtocol) -> &'static str {
    match p {
        FederationProtocol::OidcConnect => "OidcConnect",
        FederationProtocol::Saml => "Saml",
    }
}

/// The six X4 columns, as they were read back, in row order.
type TrustColumns = (
    Option<bool>,
    Option<Vec<String>>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

/// Hydrate the X4 trust block from its columns.
///
/// Every failure mode here resolves **towards the default**, which is
/// `enabled: false` — a row whose `scope_map_json` no longer parses, or whose
/// `subject_mapping` holds a value this build does not know, must not become a
/// row that trusts *more* than intended. The one thing that is never inferred
/// is `enabled`: it is read straight from its own column, so a corrupt
/// neighbouring column can never switch external exchange on.
fn trust_from_columns(cols: TrustColumns) -> TokenExchangeTrust {
    let (enabled, audiences, mapping, scope_map_json, max_age, max_lifetime) = cols;
    let default = TokenExchangeTrust::default();
    TokenExchangeTrust {
        enabled: enabled.unwrap_or(false),
        accepted_audiences: audiences.unwrap_or_default(),
        subject_mapping: mapping
            .as_deref()
            .and_then(SubjectMapping::from_wire)
            .unwrap_or(default.subject_mapping),
        scope_map: scope_map_json
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default(),
        max_token_age_secs: max_age.unwrap_or(DEFAULT_MAX_TOKEN_AGE_SECS),
        max_lifetime_secs: max_lifetime,
    }
}

/// Serialize the scope map for storage.
///
/// Infallible by construction — the map is `BTreeMap<String, Vec<String>>`,
/// which has no un-serializable inhabitant — so a failure here would be a bug
/// in serde_json rather than bad data, and `{}` (trust nothing) is the safe
/// answer to a bug.
fn scope_map_json(trust: &TokenExchangeTrust) -> String {
    serde_json::to_string(&trust.scope_map).unwrap_or_else(|_| "{}".to_string())
}

impl FederationConfigRow {
    fn try_into_entry(self, id: Uuid) -> Result<FederationConfig, DbError> {
        Ok(FederationConfig {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            provider: self.provider,
            protocol: parse_protocol(&self.protocol)?,
            metadata_url: self.metadata_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            attribute_map: self.attribute_map,
            enabled: self.enabled,
            allowed_algorithms: self.allowed_algorithms,
            idp_signing_cert_pem: self.idp_signing_cert_pem,
            client_secret_ciphertext: self.client_secret_ciphertext,
            client_secret_nonce: self.client_secret_nonce,
            client_secret_key_version: self.client_secret_key_version,
            token_exchange: trust_from_columns((
                self.token_exchange_enabled,
                self.token_exchange_accepted_audiences,
                self.token_exchange_subject_mapping,
                self.token_exchange_scope_map_json,
                self.token_exchange_max_token_age_secs,
                self.token_exchange_max_lifetime_secs,
            )),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl FederationConfigListRow {
    /// Converts a narrowed list-view row into a `FederationConfig`, filling
    /// the never-selected secret columns with empty/`None` placeholders
    /// (list views never need the encrypted material; `get_by_id` is the
    /// legitimate decrypt-at-use path).
    fn try_into_entry(self) -> Result<FederationConfig, DbError> {
        let id = Uuid::parse_str(&self.record_id).map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(FederationConfig {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            provider: self.provider,
            protocol: parse_protocol(&self.protocol)?,
            metadata_url: self.metadata_url,
            client_id: self.client_id,
            client_secret: String::new(),
            attribute_map: self.attribute_map,
            enabled: self.enabled,
            allowed_algorithms: self.allowed_algorithms,
            idp_signing_cert_pem: self.idp_signing_cert_pem,
            client_secret_ciphertext: None,
            client_secret_nonce: None,
            client_secret_key_version: None,
            token_exchange: trust_from_columns((
                self.token_exchange_enabled,
                self.token_exchange_accepted_audiences,
                self.token_exchange_subject_mapping,
                self.token_exchange_scope_map_json,
                self.token_exchange_max_token_age_secs,
                self.token_exchange_max_lifetime_secs,
            )),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl FederationConfigRowWithId {
    fn try_into_entry(self) -> Result<FederationConfig, DbError> {
        let id = Uuid::parse_str(&self.record_id).map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(FederationConfig {
            id,
            tenant_id: Uuid::parse_str(&self.tenant_id)
                .map_err(|e| DbError::Migration(e.to_string()))?,
            provider: self.provider,
            protocol: parse_protocol(&self.protocol)?,
            metadata_url: self.metadata_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            attribute_map: self.attribute_map,
            enabled: self.enabled,
            allowed_algorithms: self.allowed_algorithms,
            idp_signing_cert_pem: self.idp_signing_cert_pem,
            client_secret_ciphertext: self.client_secret_ciphertext,
            client_secret_nonce: self.client_secret_nonce,
            client_secret_key_version: self.client_secret_key_version,
            token_exchange: trust_from_columns((
                self.token_exchange_enabled,
                self.token_exchange_accepted_audiences,
                self.token_exchange_subject_mapping,
                self.token_exchange_scope_map_json,
                self.token_exchange_max_token_age_secs,
                self.token_exchange_max_lifetime_secs,
            )),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealFederationConfigRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealFederationConfigRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealFederationConfigRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> FederationConfigRepository for SurrealFederationConfigRepository<C> {
    async fn create(&self, input: CreateFederationConfig) -> AxiamResult<FederationConfig> {
        let id = new_id();
        let protocol = protocol_to_string(&input.protocol);
        let attribute_map = input.attribute_map.unwrap_or_else(|| serde_json::json!({}));

        let allowed_algorithms = input
            .allowed_algorithms
            .unwrap_or_else(|| vec!["RS256".to_string()]);

        // X4: absent means "no external token exchange", which is also what
        // `TokenExchangeTrust::default()` means. The caller (the REST handler)
        // has already validated it; re-validating here would duplicate the
        // rule in a place that cannot report it usefully.
        let trust = input.token_exchange.unwrap_or_default();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('federation_config', $id) SET \
                 tenant_id = $tenant_id, \
                 provider = $provider, \
                 protocol = $protocol, \
                 metadata_url = $metadata_url, \
                 client_id = $client_id, \
                 client_secret = $client_secret, \
                 attribute_map = $attribute_map, \
                 idp_signing_cert_pem = $idp_signing_cert_pem, \
                 allowed_algorithms = $allowed_algorithms, \
                 token_exchange_enabled = $tx_enabled, \
                 token_exchange_accepted_audiences = $tx_audiences, \
                 token_exchange_subject_mapping = $tx_mapping, \
                 token_exchange_scope_map_json = $tx_scope_map, \
                 token_exchange_max_token_age_secs = $tx_max_age, \
                 token_exchange_max_lifetime_secs = $tx_max_lifetime, \
                 enabled = true, \
                 created_at = time::now(), \
                 updated_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("provider", input.provider))
            .bind(("protocol", protocol.to_string()))
            .bind(("metadata_url", input.metadata_url))
            .bind(("client_id", input.client_id))
            // TODO(T19.8): encrypt client_secret with AES-256-GCM before
            // storage (same pattern as MFA secrets and CA private keys).
            .bind(("client_secret", input.client_secret))
            .bind(("attribute_map", attribute_map))
            .bind(("idp_signing_cert_pem", input.idp_signing_cert_pem))
            .bind(("allowed_algorithms", allowed_algorithms))
            .bind(("tx_enabled", trust.enabled))
            .bind(("tx_audiences", trust.accepted_audiences.clone()))
            .bind((
                "tx_mapping",
                trust.subject_mapping.as_str().to_string(),
            ))
            .bind(("tx_scope_map", scope_map_json(&trust)))
            .bind(("tx_max_age", trust.max_token_age_secs))
            .bind(("tx_max_lifetime", trust.max_lifetime_secs))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "federation_config", &id.to_string())?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<FederationConfig> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM federation_config \
                 WHERE meta::id(id) = $id \
                 AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "federation_config", &id.to_string())?;
        row.try_into_entry().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateFederationConfig,
    ) -> AxiamResult<FederationConfig> {
        let mut set_clauses = vec!["updated_at = time::now()".to_string()];
        let mut binds: Vec<(String, serde_json::Value)> = Vec::new();

        if let Some(ref provider) = input.provider {
            set_clauses.push("provider = $provider".into());
            binds.push(("provider".into(), serde_json::json!(provider)));
        }
        if let Some(ref metadata_url) = input.metadata_url {
            set_clauses.push("metadata_url = $metadata_url".into());
            binds.push(("metadata_url".into(), serde_json::json!(metadata_url)));
        }
        if let Some(ref client_id) = input.client_id {
            set_clauses.push("client_id = $client_id".into());
            binds.push(("client_id".into(), serde_json::json!(client_id)));
        }
        if let Some(ref client_secret) = input.client_secret {
            // TODO(T19.8): encrypt client_secret before storage (see create()).
            set_clauses.push("client_secret = $client_secret".into());
            binds.push(("client_secret".into(), serde_json::json!(client_secret)));
        }
        if let Some(ref attribute_map) = input.attribute_map {
            set_clauses.push("attribute_map = $attribute_map".into());
            binds.push(("attribute_map".into(), serde_json::json!(attribute_map)));
        }
        if let Some(enabled) = input.enabled {
            set_clauses.push("enabled = $enabled".into());
            binds.push(("enabled".into(), serde_json::json!(enabled)));
        }
        if let Some(ref idp_signing_cert_pem) = input.idp_signing_cert_pem {
            set_clauses.push("idp_signing_cert_pem = $idp_signing_cert_pem".into());
            binds.push((
                "idp_signing_cert_pem".into(),
                serde_json::json!(idp_signing_cert_pem),
            ));
        }
        if let Some(ref allowed_algorithms) = input.allowed_algorithms {
            set_clauses.push("allowed_algorithms = $allowed_algorithms".into());
            binds.push((
                "allowed_algorithms".into(),
                serde_json::json!(allowed_algorithms),
            ));
        }
        // Replaced wholesale, never merged field-by-field: a partial merge of
        // a trust configuration is how an operator ends up keeping an
        // `accepted_audiences` entry they believed they had removed.
        if let Some(ref trust) = input.token_exchange {
            set_clauses.push("token_exchange_enabled = $tx_enabled".into());
            binds.push(("tx_enabled".into(), serde_json::json!(trust.enabled)));
            set_clauses.push("token_exchange_accepted_audiences = $tx_audiences".into());
            binds.push((
                "tx_audiences".into(),
                serde_json::json!(trust.accepted_audiences),
            ));
            set_clauses.push("token_exchange_subject_mapping = $tx_mapping".into());
            binds.push((
                "tx_mapping".into(),
                serde_json::json!(trust.subject_mapping.as_str()),
            ));
            set_clauses.push("token_exchange_scope_map_json = $tx_scope_map".into());
            binds.push((
                "tx_scope_map".into(),
                serde_json::json!(scope_map_json(trust)),
            ));
            set_clauses.push("token_exchange_max_token_age_secs = $tx_max_age".into());
            binds.push((
                "tx_max_age".into(),
                serde_json::json!(trust.max_token_age_secs),
            ));
            set_clauses.push("token_exchange_max_lifetime_secs = $tx_max_lifetime".into());
            binds.push((
                "tx_max_lifetime".into(),
                serde_json::json!(trust.max_lifetime_secs),
            ));
        }

        let sql = format!(
            "UPDATE type::record('federation_config', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            set_clauses.join(", ")
        );

        let db = self.db.current();
        let mut query = db.query(&sql);
        query = query
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()));

        for (key, val) in binds {
            query = query.bind((key, val));
        }

        let result = query.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "federation_config", &id.to_string())?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query(
                "DELETE type::record('federation_config', $id) \
                 WHERE tenant_id = $tenant_id RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "federation_config".into(),
                id: id.to_string(),
            }
            .into());
        }
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<FederationConfig>> {
        let tid = tenant_id.to_string();

        let count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM federation_config \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tid.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        // Narrowed projection (SECHRD-09 / D-06): explicitly excludes
        // client_secret / client_secret_ciphertext / client_secret_nonce /
        // client_secret_key_version — list views never need the encrypted
        // material, so `list()` no longer hydrates those columns per row.
        let data_result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, tenant_id, provider, protocol, \
                 metadata_url, client_id, attribute_map, enabled, allowed_algorithms, \
                 idp_signing_cert_pem, token_exchange_enabled, \
                 token_exchange_accepted_audiences, token_exchange_subject_mapping, \
                 token_exchange_scope_map_json, token_exchange_max_token_age_secs, \
                 token_exchange_max_lifetime_secs, created_at, updated_at \
                 FROM federation_config \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at DESC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tid))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let mut data_result = data_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigListRow> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<FederationConfig> = rows
            .into_iter()
            .map(|r| r.try_into_entry())
            .collect::<Result<_, _>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn list_token_exchange_enabled(
        &self,
        tenant_id: Uuid,
    ) -> AxiamResult<Vec<FederationConfig>> {
        // Both `enabled` flags are required, and they are different
        // statements: `enabled` is "this provider is live at all",
        // `token_exchange_enabled` is "…and its tokens may be exchanged".
        // Protocol is filtered too — a SAML row has no issuer to match and no
        // JWKS to verify against, so it can never be the answer here.
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, tenant_id, provider, protocol, \
                 metadata_url, client_id, attribute_map, enabled, allowed_algorithms, \
                 idp_signing_cert_pem, token_exchange_enabled, \
                 token_exchange_accepted_audiences, token_exchange_subject_mapping, \
                 token_exchange_scope_map_json, token_exchange_max_token_age_secs, \
                 token_exchange_max_lifetime_secs, created_at, updated_at \
                 FROM federation_config \
                 WHERE tenant_id = $tenant_id \
                 AND token_exchange_enabled = true \
                 AND enabled = true \
                 AND protocol = 'OidcConnect' \
                 ORDER BY created_at ASC",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigListRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn list_with_legacy_plaintext_secret(&self) -> AxiamResult<Vec<FederationConfig>> {
        // Return rows that have a non-empty plaintext secret but no ciphertext yet.
        // This is the predicate used by the boot backfill task (D-12).
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM federation_config \
                 WHERE client_secret_ciphertext IS NONE \
                 AND client_secret IS NOT NONE \
                 AND client_secret != \"\"",
            )
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationConfigRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn set_encrypted_secret(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        nonce_b64: String,
        ciphertext_b64: String,
        key_version: i64,
    ) -> AxiamResult<()> {
        // Write the split encrypted columns and null out the legacy plaintext.
        // Per MEMORY.md: bind() requires owned Strings.
        let result = self
            .db
            .current()
            .query(
                "UPDATE type::record('federation_config', $config_id) \
                 SET client_secret_nonce = $nonce, \
                     client_secret_ciphertext = $ciphertext, \
                     client_secret_key_version = $kv, \
                     client_secret = '' \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("config_id", config_id.to_string()))
            .bind(("nonce", nonce_b64))
            .bind(("ciphertext", ciphertext_b64))
            .bind(("kv", key_version))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }
}
