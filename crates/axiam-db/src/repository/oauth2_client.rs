//! SurrealDB implementation of [`OAuth2ClientRepository`].

use axiam_auth::client_secret;
use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_client::{
    ClientAuthMethod, ClientProfile, CreateOAuth2Client, OAuth2Client, UpdateOAuth2Client,
};
use axiam_core::repository::{OAuth2ClientRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use rand::RngExt;
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, paginate, take_first_or_not_found};

/// Generate a random client ID with the `oa_` prefix (32 hex chars).
fn generate_client_id() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    format!("oa_{}", hex::encode(bytes))
}

/// Collapse a blank string to `None` before it is stored.
///
/// An empty or whitespace-only `tls_client_auth_*` value must never reach the
/// matcher: `""` is not a DN anybody holds, but a matcher that compared it
/// literally would authenticate any certificate whose corresponding field is
/// also absent. Storing `None` makes the "registered nothing" case
/// unambiguous, and `mtls_client_auth` refuses to authenticate a client with
/// no registered expectation at all.
fn normalise_optional(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

/// Generate a random client secret (64 hex chars = 32 bytes of entropy).
fn generate_client_secret() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

#[derive(Debug, SurrealValue)]
struct OAuth2ClientRow {
    tenant_id: String,
    client_id: String,
    client_secret_hash: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    // B5. Rows written before schema v27 have none of these, so all three
    // must tolerate absence rather than fail the whole read.
    #[surreal(default)]
    post_logout_redirect_uris: Vec<String>,
    #[surreal(default)]
    backchannel_logout_uri: Option<String>,
    #[surreal(default)]
    require_par: bool,
    // X5.1. Rows written before schema v38 have none of these; every default
    // reproduces the pre-v38 behaviour exactly (see `SCHEMA_V38`).
    #[surreal(default)]
    profile: Option<String>,
    #[surreal(default)]
    token_endpoint_auth_method: Option<String>,
    #[surreal(default)]
    tls_client_auth_subject_dn: Option<String>,
    #[surreal(default)]
    tls_client_auth_san_dns: Option<String>,
    #[surreal(default)]
    tls_client_auth_san_uri: Option<String>,
    #[surreal(default)]
    self_signed_tls_client_auth_thumbprints: Vec<String>,
    #[surreal(default)]
    tls_client_certificate_bound_access_tokens: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct OAuth2ClientRowWithId {
    record_id: String,
    tenant_id: String,
    client_id: String,
    client_secret_hash: String,
    name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    // B5. Rows written before schema v27 have none of these, so all three
    // must tolerate absence rather than fail the whole read.
    #[surreal(default)]
    post_logout_redirect_uris: Vec<String>,
    #[surreal(default)]
    backchannel_logout_uri: Option<String>,
    #[surreal(default)]
    require_par: bool,
    // X5.1 — see `OAuth2ClientRow`.
    #[surreal(default)]
    profile: Option<String>,
    #[surreal(default)]
    token_endpoint_auth_method: Option<String>,
    #[surreal(default)]
    tls_client_auth_subject_dn: Option<String>,
    #[surreal(default)]
    tls_client_auth_san_dns: Option<String>,
    #[surreal(default)]
    tls_client_auth_san_uri: Option<String>,
    #[surreal(default)]
    self_signed_tls_client_auth_thumbprints: Vec<String>,
    #[surreal(default)]
    tls_client_certificate_bound_access_tokens: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Decode the stored `profile` string.
///
/// An **absent** value is a pre-v38 row and correctly reads as `Standard`. An
/// **unrecognised** value is not: it means this binary is older than the row
/// it is reading, and guessing `Standard` there would silently strip a client
/// of the constraint bundle it was registered under — a downgrade performed by
/// a rollback. That is refused, loudly, as a migration error.
fn decode_profile(raw: Option<&str>) -> Result<ClientProfile, DbError> {
    match raw {
        None => Ok(ClientProfile::default()),
        Some(s) => ClientProfile::from_wire(s).ok_or_else(|| {
            DbError::Migration(format!(
                "oauth2_client.profile holds an unrecognised value {s:?}; this binary cannot \
                 safely serve a client registered under a profile it does not implement"
            ))
        }),
    }
}

/// Decode the stored `token_endpoint_auth_method`. Fails closed for the same
/// reason [`decode_profile`] does — resolving an unknown method to
/// `client_secret_post` would let a certificate-authenticated client be
/// authenticated by a secret instead.
fn decode_auth_method(raw: Option<&str>) -> Result<ClientAuthMethod, DbError> {
    match raw {
        None => Ok(ClientAuthMethod::default()),
        Some(s) => ClientAuthMethod::from_wire(s).ok_or_else(|| {
            DbError::Migration(format!(
                "oauth2_client.token_endpoint_auth_method holds an unrecognised value {s:?}; \
                 this binary cannot authenticate a client by a method it does not implement"
            ))
        }),
    }
}

impl OAuth2ClientRow {
    fn try_into_client(self, id: Uuid) -> Result<OAuth2Client, DbError> {
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(OAuth2Client {
            id,
            tenant_id,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            name: self.name,
            redirect_uris: self.redirect_uris,
            grant_types: self.grant_types,
            scopes: self.scopes,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            backchannel_logout_uri: self.backchannel_logout_uri,
            require_par: self.require_par,
            profile: decode_profile(self.profile.as_deref())?,
            token_endpoint_auth_method: decode_auth_method(
                self.token_endpoint_auth_method.as_deref(),
            )?,
            tls_client_auth_subject_dn: self.tls_client_auth_subject_dn,
            tls_client_auth_san_dns: self.tls_client_auth_san_dns,
            tls_client_auth_san_uri: self.tls_client_auth_san_uri,
            self_signed_tls_client_auth_thumbprints: self.self_signed_tls_client_auth_thumbprints,
            tls_client_certificate_bound_access_tokens: self
                .tls_client_certificate_bound_access_tokens,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl OAuth2ClientRowWithId {
    fn try_into_client(self) -> Result<OAuth2Client, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(OAuth2Client {
            id,
            tenant_id,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            name: self.name,
            redirect_uris: self.redirect_uris,
            grant_types: self.grant_types,
            scopes: self.scopes,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            backchannel_logout_uri: self.backchannel_logout_uri,
            require_par: self.require_par,
            profile: decode_profile(self.profile.as_deref())?,
            token_endpoint_auth_method: decode_auth_method(
                self.token_endpoint_auth_method.as_deref(),
            )?,
            tls_client_auth_subject_dn: self.tls_client_auth_subject_dn,
            tls_client_auth_san_dns: self.tls_client_auth_san_dns,
            tls_client_auth_san_uri: self.tls_client_auth_san_uri,
            self_signed_tls_client_auth_thumbprints: self.self_signed_tls_client_auth_thumbprints,
            tls_client_certificate_bound_access_tokens: self
                .tls_client_certificate_bound_access_tokens,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of the OAuth2Client repository.
#[derive(Clone)]
pub struct SurrealOAuth2ClientRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealOAuth2ClientRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> OAuth2ClientRepository for SurrealOAuth2ClientRepository<C> {
    async fn create(&self, input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
        let id = new_id();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let client_id = generate_client_id();
        let raw_secret = generate_client_secret();
        let secret_hash = client_secret::global()?.hash(&raw_secret);

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('oauth2_client', $id) SET \
                 tenant_id = $tenant_id, \
                 client_id = $client_id, \
                 client_secret_hash = $secret_hash, \
                 name = $name, \
                 redirect_uris = $redirect_uris, \
                 grant_types = $grant_types, \
                 scopes = $scopes, \
                 post_logout_redirect_uris = $post_logout_redirect_uris, \
                 backchannel_logout_uri = $backchannel_logout_uri, \
                 require_par = $require_par, \
                 profile = $profile, \
                 token_endpoint_auth_method = $token_endpoint_auth_method, \
                 tls_client_auth_subject_dn = $tls_client_auth_subject_dn, \
                 tls_client_auth_san_dns = $tls_client_auth_san_dns, \
                 tls_client_auth_san_uri = $tls_client_auth_san_uri, \
                 self_signed_tls_client_auth_thumbprints = $self_signed_thumbprints, \
                 tls_client_certificate_bound_access_tokens = $cert_bound_tokens",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("client_id", client_id))
            .bind(("secret_hash", secret_hash))
            .bind(("name", input.name))
            .bind(("redirect_uris", input.redirect_uris))
            .bind(("grant_types", input.grant_types))
            .bind(("scopes", input.scopes))
            .bind(("post_logout_redirect_uris", input.post_logout_redirect_uris))
            .bind(("backchannel_logout_uri", input.backchannel_logout_uri))
            .bind(("require_par", input.require_par))
            .bind(("profile", input.profile.as_str()))
            .bind((
                "token_endpoint_auth_method",
                input.token_endpoint_auth_method.as_str(),
            ))
            .bind((
                "tls_client_auth_subject_dn",
                normalise_optional(input.tls_client_auth_subject_dn),
            ))
            .bind((
                "tls_client_auth_san_dns",
                normalise_optional(input.tls_client_auth_san_dns),
            ))
            .bind((
                "tls_client_auth_san_uri",
                normalise_optional(input.tls_client_auth_san_uri),
            ))
            .bind((
                "self_signed_thumbprints",
                input.self_signed_tls_client_auth_thumbprints,
            ))
            .bind((
                "cert_bound_tokens",
                input.tls_client_certificate_bound_access_tokens,
            ))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "oauth2_client", &id_str)?;

        let client = row.try_into_client(id)?;

        Ok((client, raw_secret))
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<OAuth2Client> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('oauth2_client', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "oauth2_client", &id_str)?;

        Ok(row.try_into_client(id)?)
    }

    async fn get_by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> AxiamResult<OAuth2Client> {
        let client_id_owned = client_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OAuth2ClientRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "oauth2_client",
            &format!("client_id={client_id_owned}"),
        )?;

        row.try_into_client().map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateOAuth2Client,
    ) -> AxiamResult<OAuth2Client> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.redirect_uris.is_some() {
            sets.push("redirect_uris = $redirect_uris");
        }
        if input.grant_types.is_some() {
            sets.push("grant_types = $grant_types");
        }
        if input.scopes.is_some() {
            sets.push("scopes = $scopes");
        }
        if input.post_logout_redirect_uris.is_some() {
            sets.push("post_logout_redirect_uris = $post_logout_redirect_uris");
        }
        if input.backchannel_logout_uri.is_some() {
            sets.push("backchannel_logout_uri = $backchannel_logout_uri");
        }
        if input.require_par.is_some() {
            sets.push("require_par = $require_par");
        }
        if input.profile.is_some() {
            sets.push("profile = $profile");
        }
        if input.token_endpoint_auth_method.is_some() {
            sets.push("token_endpoint_auth_method = $token_endpoint_auth_method");
        }
        if input.tls_client_auth_subject_dn.is_some() {
            sets.push("tls_client_auth_subject_dn = $tls_client_auth_subject_dn");
        }
        if input.tls_client_auth_san_dns.is_some() {
            sets.push("tls_client_auth_san_dns = $tls_client_auth_san_dns");
        }
        if input.tls_client_auth_san_uri.is_some() {
            sets.push("tls_client_auth_san_uri = $tls_client_auth_san_uri");
        }
        if input.self_signed_tls_client_auth_thumbprints.is_some() {
            sets.push("self_signed_tls_client_auth_thumbprints = $self_signed_thumbprints");
        }
        if input.tls_client_certificate_bound_access_tokens.is_some() {
            sets.push("tls_client_certificate_bound_access_tokens = $cert_bound_tokens");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('oauth2_client', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            sets.join(", ")
        );

        let db = self.db.current();
        let mut builder = db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(redirect_uris) = input.redirect_uris {
            builder = builder.bind(("redirect_uris", redirect_uris));
        }
        if let Some(grant_types) = input.grant_types {
            builder = builder.bind(("grant_types", grant_types));
        }
        if let Some(scopes) = input.scopes {
            builder = builder.bind(("scopes", scopes));
        }
        if let Some(uris) = input.post_logout_redirect_uris {
            builder = builder.bind(("post_logout_redirect_uris", uris));
        }
        if let Some(uri) = input.backchannel_logout_uri {
            // Empty string is the documented "clear it" sentinel
            // (`UpdateOAuth2Client::backchannel_logout_uri`); it is not a valid
            // URI, so it cannot collide with a real value.
            let stored = if uri.is_empty() { None } else { Some(uri) };
            builder = builder.bind(("backchannel_logout_uri", stored));
        }
        if let Some(require_par) = input.require_par {
            builder = builder.bind(("require_par", require_par));
        }
        if let Some(profile) = input.profile {
            builder = builder.bind(("profile", profile.as_str()));
        }
        if let Some(method) = input.token_endpoint_auth_method {
            builder = builder.bind(("token_endpoint_auth_method", method.as_str()));
        }
        // The three `tls_client_auth_*` parameters take the empty string as
        // their "clear it" sentinel, same as `backchannel_logout_uri` above:
        // neither a DN nor a SAN can legally be empty, so the sentinel cannot
        // collide with a real value, and a client migrated off `tls_client_auth`
        // must be able to shed the expectation rather than carry it forever.
        if let Some(dn) = input.tls_client_auth_subject_dn {
            builder = builder.bind(("tls_client_auth_subject_dn", normalise_optional(Some(dn))));
        }
        if let Some(dns) = input.tls_client_auth_san_dns {
            builder = builder.bind(("tls_client_auth_san_dns", normalise_optional(Some(dns))));
        }
        if let Some(uri) = input.tls_client_auth_san_uri {
            builder = builder.bind(("tls_client_auth_san_uri", normalise_optional(Some(uri))));
        }
        if let Some(thumbprints) = input.self_signed_tls_client_auth_thumbprints {
            builder = builder.bind(("self_signed_thumbprints", thumbprints));
        }
        if let Some(bound) = input.tls_client_certificate_bound_access_tokens {
            builder = builder.bind(("cert_bound_tokens", bound));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "oauth2_client", &id_str)?;

        Ok(row.try_into_client(id)?)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let id_str = id.to_string();

        self.db
            .current()
            .query(
                "DELETE type::record('oauth2_client', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<OAuth2Client>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM oauth2_client \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OAuth2ClientRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_client())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    /// Compare-and-swap upgrade of a legacy `client_secret_hash` (OBS-1).
    ///
    /// `WHERE ... AND client_secret_hash = $expected_hash` is the CAS: if a
    /// secret rotation landed between the read that produced `expected_hash`
    /// and this write, no row matches, nothing is written, and `false` is
    /// returned — the rotated secret is never clobbered back to the old one.
    async fn upgrade_client_secret_hash(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        expected_hash: &str,
        new_hash: &str,
    ) -> AxiamResult<bool> {
        let result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_client SET \
                 client_secret_hash = $new_hash \
                 WHERE tenant_id = $tenant_id \
                 AND client_id = $client_id \
                 AND client_secret_hash = $expected_hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id.to_string()))
            .bind(("expected_hash", expected_hash.to_string()))
            .bind(("new_hash", new_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
        Ok(!rows.is_empty())
    }
}
