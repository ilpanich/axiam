//! SurrealDB implementation of [`OAuth2ClientRepository`].

use axiam_auth::client_secret;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::ciba::{CibaClientMetadata, CibaDeliveryMode, CibaRequestSigningAlg};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client,
    DcrRegistrationReplacement, ManagedBy, OAuth2Client, UpdateOAuth2Client,
};
use axiam_core::repository::{OAuth2ClientRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use rand::RngExt;
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, is_transaction_conflict, paginate, search_bind, search_filter,
    take_first_or_not_found,
};

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
    // X5.1 second half. Rows written before schema v39 have none of these;
    // every default reproduces the pre-v39 behaviour exactly (see `SCHEMA_V39`).
    #[surreal(default)]
    jwks: Option<String>,
    #[surreal(default)]
    jwks_uri: Option<String>,
    #[surreal(default)]
    dpop_bound_access_tokens: bool,
    #[surreal(default)]
    dpop_require_nonce: bool,
    // X7.1. Rows written before schema v54 have neither; both defaults
    // reproduce the pre-v54 behaviour exactly (see `SCHEMA_V54`).
    #[surreal(default)]
    authn_request_params: Option<String>,
    #[surreal(default)]
    browser_sso: bool,
    // T21.3. Rows written before schema v63 have none; the empty list is what
    // such a client may name, which is nothing (see `SCHEMA_V63`).
    #[surreal(default)]
    allowed_resources: Vec<String>,
    // T21.4. Rows written before schema v64 have neither. An absent
    // `managed_by` is an administrator's client, which is what every such row
    // is, and an absent `last_authorized_at` is a client the sweeper has never
    // seen authorized — see `SCHEMA_V64`.
    #[surreal(default)]
    managed_by: Option<String>,
    #[surreal(default)]
    last_authorized_at: Option<DateTime<Utc>>,
    // G-7. Rows written before schema v80 have neither; absent is a client
    // without the CIBA grant, which is what every such row is.
    #[surreal(default)]
    backchannel_token_delivery_mode: Option<String>,
    #[surreal(default)]
    backchannel_client_notification_endpoint: Option<String>,
    // D-61 (schema v81). Absent on older rows: a client sending plain requests.
    #[surreal(default)]
    backchannel_authentication_request_signing_alg: Option<String>,
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
    // X5.1 second half. Rows written before schema v39 have none of these;
    // every default reproduces the pre-v39 behaviour exactly (see `SCHEMA_V39`).
    #[surreal(default)]
    jwks: Option<String>,
    #[surreal(default)]
    jwks_uri: Option<String>,
    #[surreal(default)]
    dpop_bound_access_tokens: bool,
    #[surreal(default)]
    dpop_require_nonce: bool,
    // X7.1. Rows written before schema v54 have neither; both defaults
    // reproduce the pre-v54 behaviour exactly (see `SCHEMA_V54`).
    #[surreal(default)]
    authn_request_params: Option<String>,
    #[surreal(default)]
    browser_sso: bool,
    // T21.3. Rows written before schema v63 have none; the empty list is what
    // such a client may name, which is nothing (see `SCHEMA_V63`).
    #[surreal(default)]
    allowed_resources: Vec<String>,
    // T21.4. Rows written before schema v64 have neither. An absent
    // `managed_by` is an administrator's client, which is what every such row
    // is, and an absent `last_authorized_at` is a client the sweeper has never
    // seen authorized — see `SCHEMA_V64`.
    #[surreal(default)]
    managed_by: Option<String>,
    #[surreal(default)]
    last_authorized_at: Option<DateTime<Utc>>,
    // G-7. Rows written before schema v80 have neither; absent is a client
    // without the CIBA grant, which is what every such row is.
    #[surreal(default)]
    backchannel_token_delivery_mode: Option<String>,
    #[surreal(default)]
    backchannel_client_notification_endpoint: Option<String>,
    // D-61 (schema v81). Absent on older rows: a client sending plain requests.
    #[surreal(default)]
    backchannel_authentication_request_signing_alg: Option<String>,
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

/// Decode the stored `authn_request_params` mode.
///
/// Fails closed on an unrecognised value for the same reason
/// [`decode_profile`] does, with the argument running the other way round: a
/// value this binary does not implement must not resolve to `Honour`, which
/// would act on authentication-request parameters the operator never opted
/// into, nor be quietly downgraded, which would hide a rollback. An **absent**
/// value is a pre-v54 row and correctly reads as `Ignore`.
fn decode_authn_request_params(raw: Option<&str>) -> Result<AuthnRequestParamsMode, DbError> {
    match raw {
        None => Ok(AuthnRequestParamsMode::default()),
        Some(s) => AuthnRequestParamsMode::from_wire(s).ok_or_else(|| {
            DbError::Migration(format!(
                "oauth2_client.authn_request_params holds an unrecognised value {s:?}; this \
                 binary cannot serve a client under a parameter policy it does not implement"
            ))
        }),
    }
}

/// Decode the stored `managed_by` discriminator (T21.4 / D5).
///
/// An **absent** value is a pre-v64 row and correctly reads as `Admin`: every
/// client that existed before this migration was created by an administrator
/// through `POST /oauth2-clients`, so that is the fact rather than a guess.
///
/// An **unrecognised** value fails closed, and this is the decoder where that
/// matters most. `Admin` is the permissive answer in three independent places
/// — it is the only provenance that may carry a FAPI profile (I5), the only
/// one exempt from the forced consent hop (D4), and the only one the sweeper
/// will not touch — so a rollback reading a `cimd` row it does not implement
/// must refuse it rather than promote it to an administrator's client.
fn decode_managed_by(raw: Option<&str>) -> Result<ManagedBy, DbError> {
    match raw {
        None => Ok(ManagedBy::default()),
        Some(s) => ManagedBy::from_wire(s).ok_or_else(|| {
            DbError::Migration(format!(
                "oauth2_client.managed_by holds an unrecognised value {s:?}; this binary \
                 cannot serve a client whose provenance it does not implement, because \
                 every gate that reads this field treats 'admin' as the trusted answer"
            ))
        }),
    }
}

/// Decode the stored CIBA metadata (G-7).
///
/// An absent mode is a client without the grant. An unrecognised one fails
/// closed, for the reason [`decode_profile`] gives: a binary older than the row
/// must not guess how a client it cannot serve wants to be told.
fn decode_ciba(
    mode: Option<&str>,
    endpoint: Option<String>,
    signing_alg: Option<&str>,
) -> Result<CibaClientMetadata, DbError> {
    let backchannel_token_delivery_mode = match mode {
        None => None,
        Some(raw) => Some(CibaDeliveryMode::from_wire(raw).ok_or_else(|| {
            DbError::Migration(format!(
                "oauth2_client.backchannel_token_delivery_mode holds an unrecognised value \
                 {raw:?}; this binary cannot serve a CIBA client in a mode it does not implement"
            ))
        })?),
    };
    // Fails closed for the same reason: a row naming an algorithm this binary
    // does not verify must not be served as if it named none, which would
    // quietly accept the unsigned requests the client registered against.
    let backchannel_authentication_request_signing_alg = match signing_alg {
        None => None,
        Some(raw) => Some(CibaRequestSigningAlg::from_wire(raw).ok_or_else(|| {
            DbError::Migration(format!(
                "oauth2_client.backchannel_authentication_request_signing_alg holds an \
                 unrecognised value {raw:?}; this binary cannot verify a CIBA request signed \
                 with an algorithm it does not implement"
            ))
        })?),
    };
    Ok(CibaClientMetadata {
        backchannel_token_delivery_mode,
        backchannel_client_notification_endpoint: normalise_optional(endpoint),
        backchannel_authentication_request_signing_alg,
    })
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
            jwks: self.jwks,
            jwks_uri: self.jwks_uri,
            dpop_bound_access_tokens: self.dpop_bound_access_tokens,
            dpop_require_nonce: self.dpop_require_nonce,
            authn_request_params: decode_authn_request_params(
                self.authn_request_params.as_deref(),
            )?,
            browser_sso: self.browser_sso,
            allowed_resources: self.allowed_resources,
            managed_by: decode_managed_by(self.managed_by.as_deref())?,
            last_authorized_at: self.last_authorized_at,
            ciba: decode_ciba(
                self.backchannel_token_delivery_mode.as_deref(),
                self.backchannel_client_notification_endpoint,
                self.backchannel_authentication_request_signing_alg
                    .as_deref(),
            )?,
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
            jwks: self.jwks,
            jwks_uri: self.jwks_uri,
            dpop_bound_access_tokens: self.dpop_bound_access_tokens,
            dpop_require_nonce: self.dpop_require_nonce,
            authn_request_params: decode_authn_request_params(
                self.authn_request_params.as_deref(),
            )?,
            browser_sso: self.browser_sso,
            allowed_resources: self.allowed_resources,
            managed_by: decode_managed_by(self.managed_by.as_deref())?,
            last_authorized_at: self.last_authorized_at,
            ciba: decode_ciba(
                self.backchannel_token_delivery_mode.as_deref(),
                self.backchannel_client_notification_endpoint,
                self.backchannel_authentication_request_signing_alg
                    .as_deref(),
            )?,
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

impl<C: Connection> SurrealOAuth2ClientRepository<C> {
    /// [`OAuth2ClientRepository::create`], optionally with the digest of an
    /// RFC 7592 management token written in the same statement (T23.4.1).
    ///
    /// One `CREATE` for both, so a `dcr` client never exists without the token
    /// its registrant was given. `None` writes `NONE`, which is what every
    /// client that is not self-registered carries.
    async fn create_row(
        &self,
        input: CreateOAuth2Client,
        registration_access_token_hash: Option<String>,
    ) -> AxiamResult<(OAuth2Client, String)> {
        let id = new_id();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let client_id = generate_client_id();
        // T21.2 — a public client is created with no secret at all.
        //
        // Not "a secret nobody tells the operator about": none. Minting one
        // unconditionally is what SEC-093 found had given every `tls_client_auth`
        // client a live password-equivalent credential its registration said it
        // did not use, and a public client is the sharper case — its whole
        // registration is the statement that it cannot keep one. An empty
        // `client_secret_hash` is therefore the truth about the row rather than
        // a placeholder, and the token endpoint never consults it: the public
        // arm of `authenticate_client_credential` returns before any hash is
        // read, so no comparison against the empty string can ever be reached.
        let (raw_secret, secret_hash) = if input.token_endpoint_auth_method.is_public() {
            (String::new(), String::new())
        } else {
            let raw = generate_client_secret();
            let hash = client_secret::global()?.hash(&raw);
            (raw, hash)
        };

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
                 tls_client_certificate_bound_access_tokens = $cert_bound_tokens, \
                 jwks = $jwks, \
                 jwks_uri = $jwks_uri, \
                 dpop_bound_access_tokens = $dpop_bound_tokens, \
                 dpop_require_nonce = $dpop_require_nonce, \
                 authn_request_params = $authn_request_params, \
                 browser_sso = $browser_sso, \
                 allowed_resources = $allowed_resources, \
                 managed_by = $managed_by, \
                 registration_access_token_hash = $registration_access_token_hash, \
                 backchannel_token_delivery_mode = $ciba_mode, \
                 backchannel_client_notification_endpoint = $ciba_endpoint, \
                 backchannel_authentication_request_signing_alg = $ciba_signing_alg, \
                 last_authorized_at = NONE",
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
            .bind(("jwks", normalise_optional(input.jwks)))
            .bind(("jwks_uri", normalise_optional(input.jwks_uri)))
            .bind(("dpop_bound_tokens", input.dpop_bound_access_tokens))
            .bind(("dpop_require_nonce", input.dpop_require_nonce))
            .bind(("authn_request_params", input.authn_request_params.as_str()))
            .bind(("browser_sso", input.browser_sso))
            .bind(("allowed_resources", input.allowed_resources))
            // T21.4 / D5 — written from the create input, which the creating
            // code path sets and no request body can reach. A registration
            // arriving at `POST /oauth2/register` cannot claim `admin`,
            // because the handler builds this value rather than echoing one.
            .bind(("managed_by", input.managed_by.as_str().to_owned()))
            .bind((
                "registration_access_token_hash",
                registration_access_token_hash,
            ))
            .bind((
                "ciba_mode",
                input
                    .ciba
                    .backchannel_token_delivery_mode
                    .map(|m| m.as_str().to_owned()),
            ))
            .bind((
                "ciba_signing_alg",
                input
                    .ciba
                    .backchannel_authentication_request_signing_alg
                    .map(|a| a.as_str().to_owned()),
            ))
            .bind((
                "ciba_endpoint",
                normalise_optional(input.ciba.backchannel_client_notification_endpoint),
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
}

impl<C: Connection> OAuth2ClientRepository for SurrealOAuth2ClientRepository<C> {
    async fn create(&self, input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
        self.create_row(input, None).await
    }

    /// T21.5 — create or refresh a CIMD shadow row. See the trait's
    /// documentation for the three guarantees; this is how each is kept.
    ///
    /// **A row with another provenance is never modified** because the
    /// `UPDATE` carries `AND managed_by = 'cimd'` in its `WHERE`, and because
    /// the `CREATE` that follows an update matching nothing is guarded by a
    /// re-read: a row that exists but did not match the update is an
    /// administrator's (or a DCR client's) and is returned as a conflict
    /// rather than written over. The unique index on
    /// `(tenant_id, client_id)` is the backstop for the race — two concurrent
    /// first authorizations for the same document — and the loser of that race
    /// re-reads rather than failing the request, because the row it wanted now
    /// exists and is the one it would have written.
    ///
    /// **No secret is minted**: `client_secret_hash` is written as the empty
    /// string on create and is not in the update's `SET` list at all, so a row
    /// that somehow held one keeps it invisible to the only arm that could
    /// read it (`authenticate_client_credential`'s public arm returns before
    /// any hash is consulted, and `private_key_jwt` never looks at one).
    ///
    /// **`created_at` survives** because the update does not set it; the
    /// table's `updated_at` moves on every write.
    async fn upsert_cimd_client(
        &self,
        client_id: &str,
        input: CreateOAuth2Client,
    ) -> AxiamResult<OAuth2Client> {
        let tenant_id = input.tenant_id;
        let tenant_id_str = tenant_id.to_string();
        let client_id_owned = client_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_client SET \
                 name = $name, \
                 redirect_uris = $redirect_uris, \
                 grant_types = $grant_types, \
                 scopes = $scopes, \
                 token_endpoint_auth_method = $token_endpoint_auth_method, \
                 jwks = $jwks, \
                 jwks_uri = $jwks_uri, \
                 allowed_resources = $allowed_resources, \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id \
                 AND managed_by = 'cimd' \
                 RETURN meta::id(id) AS record_id, *",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .bind(("client_id", client_id_owned.clone()))
            .bind(("name", input.name.clone()))
            .bind(("redirect_uris", input.redirect_uris.clone()))
            .bind(("grant_types", input.grant_types.clone()))
            .bind(("scopes", input.scopes.clone()))
            .bind((
                "token_endpoint_auth_method",
                input.token_endpoint_auth_method.as_str(),
            ))
            .bind(("jwks", normalise_optional(input.jwks.clone())))
            .bind(("jwks_uri", normalise_optional(input.jwks_uri.clone())))
            .bind(("allowed_resources", input.allowed_resources.clone()))
            .await
            .map_err(DbError::from)?;

        let refreshed: Vec<OAuth2ClientRowWithId> = result.take(0).map_err(DbError::from)?;
        if let Some(row) = refreshed.into_iter().next() {
            return row.try_into_client().map_err(Into::into);
        }

        // Nothing was refreshed: either there is no row at all, or there is
        // one this mechanism does not own.
        match self.get_by_client_id(tenant_id, &client_id_owned).await {
            Ok(existing) => {
                return Err(AxiamError::Conflict {
                    reason: format!(
                        "client_id {client_id_owned} already names a {} client in this tenant; \
                         a client ID metadata document cannot replace a registration AXIAM's \
                         operator created",
                        existing.managed_by,
                    ),
                });
            }
            Err(AxiamError::NotFound { .. }) => {}
            Err(e) => return Err(e),
        }

        let id = new_id();
        let id_str = id.to_string();
        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('oauth2_client', $id) SET \
                 tenant_id = $tenant_id, \
                 client_id = $client_id, \
                 client_secret_hash = '', \
                 name = $name, \
                 redirect_uris = $redirect_uris, \
                 grant_types = $grant_types, \
                 scopes = $scopes, \
                 post_logout_redirect_uris = [], \
                 backchannel_logout_uri = NONE, \
                 require_par = false, \
                 profile = $profile, \
                 token_endpoint_auth_method = $token_endpoint_auth_method, \
                 tls_client_auth_subject_dn = NONE, \
                 tls_client_auth_san_dns = NONE, \
                 tls_client_auth_san_uri = NONE, \
                 self_signed_tls_client_auth_thumbprints = [], \
                 tls_client_certificate_bound_access_tokens = false, \
                 jwks = $jwks, \
                 jwks_uri = $jwks_uri, \
                 dpop_bound_access_tokens = false, \
                 dpop_require_nonce = false, \
                 authn_request_params = $authn_request_params, \
                 browser_sso = false, \
                 allowed_resources = $allowed_resources, \
                 managed_by = $managed_by, \
                 last_authorized_at = NONE",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("client_id", client_id_owned.clone()))
            .bind(("name", input.name))
            .bind(("redirect_uris", input.redirect_uris))
            .bind(("grant_types", input.grant_types))
            .bind(("scopes", input.scopes))
            .bind(("profile", input.profile.as_str()))
            .bind((
                "token_endpoint_auth_method",
                input.token_endpoint_auth_method.as_str(),
            ))
            .bind(("jwks", normalise_optional(input.jwks)))
            .bind(("jwks_uri", normalise_optional(input.jwks_uri)))
            .bind(("authn_request_params", input.authn_request_params.as_str()))
            .bind(("allowed_resources", input.allowed_resources))
            .bind(("managed_by", input.managed_by.as_str().to_owned()))
            .await
            .map_err(DbError::from);

        match result {
            Ok(mut result) => {
                let rows: Vec<OAuth2ClientRow> = result.take(0).map_err(DbError::from)?;
                let row = take_first_or_not_found(rows, "oauth2_client", &id_str)?;
                Ok(row.try_into_client(id)?)
            }
            // The unique index refused the write: a concurrent first
            // authorization for the same document won. The row it created is
            // the row this call was about to create, so it is read back rather
            // than reported — the outcome the caller asked for has happened.
            Err(e) => match self.get_by_client_id(tenant_id, &client_id_owned).await {
                Ok(existing) if existing.managed_by == ManagedBy::Cimd => Ok(existing),
                _ => Err(e.into()),
            },
        }
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
        if input.jwks.is_some() {
            sets.push("jwks = $jwks");
        }
        if input.jwks_uri.is_some() {
            sets.push("jwks_uri = $jwks_uri");
        }
        if input.dpop_bound_access_tokens.is_some() {
            sets.push("dpop_bound_access_tokens = $dpop_bound_tokens");
        }
        if input.dpop_require_nonce.is_some() {
            sets.push("dpop_require_nonce = $dpop_require_nonce");
        }
        if input.authn_request_params.is_some() {
            sets.push("authn_request_params = $authn_request_params");
        }
        if input.allowed_resources.is_some() {
            sets.push("allowed_resources = $allowed_resources");
        }
        if input.browser_sso.is_some() {
            sets.push("browser_sso = $browser_sso");
        }
        if input.ciba.is_some() {
            sets.push("backchannel_token_delivery_mode = $ciba_mode");
            sets.push("backchannel_client_notification_endpoint = $ciba_endpoint");
            sets.push("backchannel_authentication_request_signing_alg = $ciba_signing_alg");
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
        // `jwks` and `jwks_uri` take the same empty-string "clear it" sentinel
        // for the same reason: RFC 7591 §2 permits at most one of them, so
        // migrating a client from an inline key set to a published one has to be
        // able to remove the first.
        if let Some(jwks) = input.jwks {
            builder = builder.bind(("jwks", normalise_optional(Some(jwks))));
        }
        if let Some(uri) = input.jwks_uri {
            builder = builder.bind(("jwks_uri", normalise_optional(Some(uri))));
        }
        if let Some(bound) = input.dpop_bound_access_tokens {
            builder = builder.bind(("dpop_bound_tokens", bound));
        }
        if let Some(required) = input.dpop_require_nonce {
            builder = builder.bind(("dpop_require_nonce", required));
        }
        if let Some(mode) = input.authn_request_params {
            builder = builder.bind(("authn_request_params", mode.as_str()));
        }
        if let Some(resources) = input.allowed_resources {
            builder = builder.bind(("allowed_resources", resources));
        }
        if let Some(enabled) = input.browser_sso {
            builder = builder.bind(("browser_sso", enabled));
        }
        if let Some(bound) = input.tls_client_certificate_bound_access_tokens {
            builder = builder.bind(("cert_bound_tokens", bound));
        }
        if let Some(ciba) = input.ciba {
            builder = builder
                .bind((
                    "ciba_mode",
                    ciba.backchannel_token_delivery_mode
                        .map(|m| m.as_str().to_owned()),
                ))
                .bind((
                    "ciba_signing_alg",
                    ciba.backchannel_authentication_request_signing_alg
                        .map(|a| a.as_str().to_owned()),
                ))
                .bind((
                    "ciba_endpoint",
                    normalise_optional(ciba.backchannel_client_notification_endpoint),
                ));
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

        // Free-text filter, applied to BOTH queries below so the
        // total counts matches rather than rows — a pager whose page
        // count belongs to a different result set than the page it
        // shows is worse than no pager. Empty when unsearched, so an
        // unfiltered list runs exactly the query it always ran.
        let search = search_filter(&pagination, &["name", "client_id"]);
        let search_term = search_bind(&pagination);

        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM oauth2_client \
                 WHERE tenant_id = $tenant_id{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id_str.clone()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
                 WHERE tenant_id = $tenant_id{search} \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id_str))
            .bind(("search", search_term))
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

    /// T21.4 — the `dcr_max_clients` ceiling, counted in the datastore.
    ///
    /// `managed_by = $managed_by` rather than `!= 'admin'`: the quota is per
    /// mechanism, so a tenant that later runs both DCR and CIMD gets two
    /// ceilings rather than one shared between them, and a CIMD shadow row
    /// materialised by a legitimate client cannot exhaust the allowance for
    /// self-registration.
    async fn count_by_managed_by(
        &self,
        tenant_id: Uuid,
        managed_by: ManagedBy,
    ) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM oauth2_client \
                 WHERE tenant_id = $tenant_id AND managed_by = $managed_by GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("managed_by", managed_by.as_str().to_owned()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        // No rows at all is `GROUP ALL` over an empty set, which is zero
        // clients rather than a missing answer.
        Ok(rows.first().map_or(0, |r| r.total))
    }

    /// T21.4 — every row with this provenance, deployment-wide, for the
    /// sweeper. See the trait for why it is not tenant-scoped.
    async fn list_all_by_managed_by(
        &self,
        managed_by: ManagedBy,
    ) -> AxiamResult<Vec<OAuth2Client>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
                 WHERE managed_by = $managed_by ORDER BY created_at ASC",
            )
            .bind(("managed_by", managed_by.as_str().to_owned()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<OAuth2ClientRowWithId> = result.take(0).map_err(DbError::from)?;
        Ok(rows
            .into_iter()
            .map(|row| row.try_into_client())
            .collect::<Result<Vec<_>, DbError>>()?)
    }

    /// T21.4 — stamp `last_authorized_at`.
    ///
    /// `AND managed_by != 'admin'` in the `WHERE` clause, not only in the
    /// caller: the restriction is what keeps I1 exact, and a guard that lives
    /// only at one call site is a guard the second call site will not have.
    /// The statement is a no-op against an administrator's client whatever the
    /// caller believed.
    async fn touch_last_authorized(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPDATE oauth2_client SET last_authorized_at = $at \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id \
                 AND managed_by != 'admin'",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id.to_string()))
            .bind(("at", at))
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// T23.4.1 — see the trait. `managed_by` is checked here rather than
    /// trusted, because a management token on any other provenance would be a
    /// self-service write path onto a row nobody registered for themselves.
    async fn create_with_registration_access_token(
        &self,
        input: CreateOAuth2Client,
        registration_access_token_hash: &str,
    ) -> AxiamResult<(OAuth2Client, String)> {
        if input.managed_by != ManagedBy::Dcr {
            return Err(AxiamError::Validation {
                message: "only a dynamically registered client is issued an RFC 7592 \
                          registration access token"
                    .into(),
            });
        }
        if registration_access_token_hash.is_empty() {
            return Err(AxiamError::Validation {
                message: "a registration access token digest must not be empty".into(),
            });
        }
        self.create_row(input, Some(registration_access_token_hash.to_owned()))
            .await
    }

    /// T23.4.1 — the management token's lookup. The `(tenant_id, client_id)`
    /// unique index locates the row and the digest is compared in the same
    /// `WHERE`, beside `managed_by = 'dcr'`; see the trait for why the four
    /// failures share one `None`.
    async fn get_by_registration_access_token(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        registration_access_token_hash: &str,
    ) -> AxiamResult<Option<OAuth2Client>> {
        // An empty digest is not a digest. `NONE != ''` already keeps it from
        // matching a row with no token, and this says so before the query.
        if registration_access_token_hash.is_empty() {
            return Ok(None);
        }
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id \
                 AND managed_by = 'dcr' \
                 AND registration_access_token_hash = $hash \
                 LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id.to_owned()))
            .bind(("hash", registration_access_token_hash.to_owned()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<OAuth2ClientRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(OAuth2ClientRowWithId::try_into_client)
            .transpose()
            .map_err(Into::into)
    }

    /// T23.4.1 — replacement and rotation as one compare-and-swap, in the two
    /// layers X6 uses for every single-use credential (see
    /// `repository::device_grant`'s module header for the measurements).
    ///
    /// 1. The guarded `UPDATE` runs inside `BEGIN`/`COMMIT`, so two concurrent
    ///    replacements on one row conflict and the deployed engine aborts the
    ///    loser, which is answered `None`.
    /// 2. The new digest is the per-attempt nonce: it is read back **after**
    ///    the commit, in a query of its own, and only the caller whose digest
    ///    survived reports success. A loser whose write the engine failed to
    ///    abort finds the winner's digest and is answered `None` — its token
    ///    is dead, which is exactly what it would have been had it lost
    ///    cleanly. Outside the transaction for the reason `SCHEMA_V31` gives.
    async fn replace_dcr_registration(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        expected_hash: &str,
        new_hash: &str,
        replacement: DcrRegistrationReplacement,
    ) -> AxiamResult<Option<OAuth2Client>> {
        if expected_hash.is_empty() || new_hash.is_empty() || expected_hash == new_hash {
            return Ok(None);
        }
        let result = self
            .db
            .current()
            .query(
                "BEGIN TRANSACTION; \
                 LET $after = (UPDATE oauth2_client SET \
                     name = $name, \
                     redirect_uris = $redirect_uris, \
                     grant_types = $grant_types, \
                     scopes = $scopes, \
                     token_endpoint_auth_method = $token_endpoint_auth_method, \
                     jwks = $jwks, \
                     jwks_uri = $jwks_uri, \
                     allowed_resources = $allowed_resources, \
                     backchannel_token_delivery_mode = $ciba_mode, \
                     backchannel_client_notification_endpoint = $ciba_endpoint, \
                     backchannel_authentication_request_signing_alg = $ciba_signing_alg, \
                     registration_access_token_hash = $new_hash, \
                     updated_at = time::now() \
                     WHERE tenant_id = $tenant_id AND client_id = $client_id \
                     AND managed_by = 'dcr' \
                     AND registration_access_token_hash = $expected_hash \
                     RETURN AFTER); \
                 SELECT meta::id(id) AS record_id, * FROM $after; \
                 COMMIT TRANSACTION",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id.to_owned()))
            .bind(("expected_hash", expected_hash.to_owned()))
            .bind(("new_hash", new_hash.to_owned()))
            .bind(("name", replacement.name))
            .bind(("redirect_uris", replacement.redirect_uris))
            .bind(("grant_types", replacement.grant_types))
            .bind(("scopes", replacement.scopes))
            .bind((
                "token_endpoint_auth_method",
                replacement.token_endpoint_auth_method.as_str(),
            ))
            .bind(("jwks", normalise_optional(replacement.jwks)))
            .bind(("jwks_uri", normalise_optional(replacement.jwks_uri)))
            .bind(("allowed_resources", replacement.allowed_resources))
            .bind((
                "ciba_mode",
                replacement
                    .ciba
                    .backchannel_token_delivery_mode
                    .map(|m| m.as_str().to_owned()),
            ))
            .bind((
                "ciba_signing_alg",
                replacement
                    .ciba
                    .backchannel_authentication_request_signing_alg
                    .map(|a| a.as_str().to_owned()),
            ))
            .bind((
                "ciba_endpoint",
                normalise_optional(replacement.ciba.backchannel_client_notification_endpoint),
            ))
            .await;
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        // BEGIN=0, LET=1, SELECT=2, COMMIT=3.
        let rows: Vec<OAuth2ClientRowWithId> = match result.take(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let Some(row) = rows.into_iter().next() else {
            // Unknown client, wrong token, a token already rotated away, or a
            // client with none. Nothing was written.
            return Ok(None);
        };

        // Layer 2: outside, and after, the transaction above.
        let stored = self
            .db
            .current()
            .query(
                "SELECT VALUE registration_access_token_hash FROM oauth2_client \
                 WHERE tenant_id = $tenant_id AND client_id = $client_id LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id.to_owned()))
            .await;
        let mut stored = match stored {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let stored: Vec<Option<String>> = match stored.take(0) {
            Ok(v) => v,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if stored.into_iter().flatten().next().as_deref() != Some(new_hash) {
            // Our write landed and another replacement's landed after it. That
            // one holds the registration; this caller's new token is not the
            // stored one and must not be handed out as though it were.
            return Ok(None);
        }

        Ok(Some(row.try_into_client()?))
    }

    /// T23.4.1 — deletion, conditional on the digest. Inside a transaction so
    /// that a concurrent `PUT` presenting the same token conflicts with it
    /// rather than interleaving; `RETURN BEFORE` is what tells the caller
    /// which client it deleted, so the handler can revoke that client's
    /// refresh tokens by its `client_id` and audit it.
    async fn delete_by_registration_access_token(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        registration_access_token_hash: &str,
    ) -> AxiamResult<Option<OAuth2Client>> {
        if registration_access_token_hash.is_empty() {
            return Ok(None);
        }
        let result = self
            .db
            .current()
            .query(
                "BEGIN TRANSACTION; \
                 LET $before = (DELETE oauth2_client \
                     WHERE tenant_id = $tenant_id AND client_id = $client_id \
                     AND managed_by = 'dcr' \
                     AND registration_access_token_hash = $hash \
                     RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id, * FROM $before; \
                 COMMIT TRANSACTION",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("client_id", client_id.to_owned()))
            .bind(("hash", registration_access_token_hash.to_owned()))
            .await;
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let rows: Vec<OAuth2ClientRowWithId> = match result.take(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        rows.into_iter()
            .next()
            .map(OAuth2ClientRowWithId::try_into_client)
            .transpose()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// X7.1 (T23.1.1 audit) — the decode is the last gate a row edited in the
    /// database passes through before `fapi::enforce_authorization_request`
    /// sees it. An absent value is a pre-v54 row and is the stricter lane; a
    /// value this binary does not implement must resolve to **neither** lane,
    /// because guessing `honour` would act on parameters nobody opted into and
    /// guessing `ignore` would hide that the row is newer than the binary.
    #[test]
    fn the_authn_request_params_decode_fails_closed() {
        assert_eq!(
            decode_authn_request_params(None).unwrap(),
            AuthnRequestParamsMode::Ignore
        );
        assert_eq!(
            decode_authn_request_params(Some("ignore")).unwrap(),
            AuthnRequestParamsMode::Ignore
        );
        assert_eq!(
            decode_authn_request_params(Some("honour")).unwrap(),
            AuthnRequestParamsMode::Honour
        );
        for unknown in ["", "honor", "per_parameter", "true"] {
            assert!(
                decode_authn_request_params(Some(unknown)).is_err(),
                "{unknown:?} must not decode to a lane"
            );
        }
    }

    // --- T23.4.1 / RFC 7592 -------------------------------------------------

    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    fn public_client(tenant_id: Uuid, managed_by: ManagedBy) -> CreateOAuth2Client {
        CreateOAuth2Client {
            tenant_id,
            name: "rfc7592".into(),
            redirect_uris: vec!["http://127.0.0.1/callback".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::None,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: Vec::new(),
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            allowed_resources: vec!["https://mcp.example.com/mcp".into()],
            managed_by,
            ciba: Default::default(),
        }
    }

    fn replacement(redirect: &str) -> DcrRegistrationReplacement {
        DcrRegistrationReplacement {
            name: "renamed".into(),
            redirect_uris: vec![redirect.into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            scopes: vec!["openid".into()],
            token_endpoint_auth_method: ClientAuthMethod::None,
            jwks: None,
            jwks_uri: None,
            allowed_resources: vec!["https://mcp.example.com/mcp".into()],
            ciba: Default::default(),
        }
    }

    /// The digest names one row, in one tenant, under one `client_id`; and
    /// only a `dcr` row can carry one.
    #[tokio::test]
    async fn a_management_token_names_exactly_its_own_row() {
        let repo = SurrealOAuth2ClientRepository::new(setup_db().await);
        let tenant = Uuid::new_v4();
        let (client, _) = repo
            .create_with_registration_access_token(public_client(tenant, ManagedBy::Dcr), "h1")
            .await
            .unwrap();
        let (other, _) = repo
            .create_with_registration_access_token(public_client(tenant, ManagedBy::Dcr), "h2")
            .await
            .unwrap();

        let found = repo
            .get_by_registration_access_token(tenant, &client.client_id, "h1")
            .await
            .unwrap()
            .expect("its own token finds it");
        assert_eq!(found.id, client.id);
        assert_eq!(found.managed_by, ManagedBy::Dcr);

        for (t, id, h) in [
            (tenant, client.client_id.as_str(), "h2"), // another client's token
            (tenant, other.client_id.as_str(), "h1"),  // ... the other way round
            (Uuid::new_v4(), client.client_id.as_str(), "h1"), // another tenant
            (tenant, "oa_unknown", "h1"),              // an unknown client
            (tenant, client.client_id.as_str(), ""),   // no digest at all
        ] {
            assert!(
                repo.get_by_registration_access_token(t, id, h)
                    .await
                    .unwrap()
                    .is_none(),
                "{t} {id} {h:?} must not resolve"
            );
        }

        for provenance in [ManagedBy::Admin, ManagedBy::Cimd] {
            assert!(
                repo.create_with_registration_access_token(public_client(tenant, provenance), "h3")
                    .await
                    .is_err(),
                "{provenance:?} is never issued a management token"
            );
        }
    }

    /// A row created by the ordinary path has no token, so nothing matches it
    /// — not even a digest of the empty string.
    #[tokio::test]
    async fn a_client_created_without_a_token_matches_no_digest() {
        let repo = SurrealOAuth2ClientRepository::new(setup_db().await);
        let tenant = Uuid::new_v4();
        let (client, _) = repo
            .create(public_client(tenant, ManagedBy::Dcr))
            .await
            .unwrap();
        let empty = axiam_auth::token::hash_refresh_token("");
        for digest in ["", empty.as_str(), "NONE"] {
            assert!(
                repo.get_by_registration_access_token(tenant, &client.client_id, digest)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    /// Replacement rotates: the old digest is dead the moment the new one is
    /// live, the second presentation of the old one finds nothing, and the
    /// columns a registration cannot set are untouched.
    #[tokio::test]
    async fn replacement_rotates_the_token_and_touches_nothing_else() {
        let repo = SurrealOAuth2ClientRepository::new(setup_db().await);
        let tenant = Uuid::new_v4();
        let (client, _) = repo
            .create_with_registration_access_token(public_client(tenant, ManagedBy::Dcr), "old")
            .await
            .unwrap();

        let replaced = repo
            .replace_dcr_registration(
                tenant,
                &client.client_id,
                "old",
                "new",
                replacement("http://127.0.0.1/other"),
            )
            .await
            .unwrap()
            .expect("the current token replaces");
        assert_eq!(replaced.redirect_uris, vec!["http://127.0.0.1/other"]);
        assert_eq!(replaced.name, "renamed");
        assert_eq!(replaced.managed_by, ManagedBy::Dcr);
        assert_eq!(replaced.profile, ClientProfile::Standard);
        assert_eq!(
            replaced.authn_request_params,
            AuthnRequestParamsMode::Ignore
        );
        assert!(!replaced.browser_sso);
        assert_eq!(replaced.tenant_id, tenant);
        assert_eq!(replaced.id, client.id);

        assert!(
            repo.replace_dcr_registration(
                tenant,
                &client.client_id,
                "old",
                "newer",
                replacement("http://127.0.0.1/third"),
            )
            .await
            .unwrap()
            .is_none(),
            "the rotated-away token replaces nothing"
        );
        assert!(
            repo.get_by_registration_access_token(tenant, &client.client_id, "old")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.get_by_registration_access_token(tenant, &client.client_id, "new")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Deletion is conditional on the digest, and a second one finds nothing.
    #[tokio::test]
    async fn deletion_needs_the_current_token_and_happens_once() {
        let repo = SurrealOAuth2ClientRepository::new(setup_db().await);
        let tenant = Uuid::new_v4();
        let (client, _) = repo
            .create_with_registration_access_token(public_client(tenant, ManagedBy::Dcr), "tok")
            .await
            .unwrap();
        assert!(
            repo.delete_by_registration_access_token(tenant, &client.client_id, "wrong")
                .await
                .unwrap()
                .is_none()
        );
        let deleted = repo
            .delete_by_registration_access_token(tenant, &client.client_id, "tok")
            .await
            .unwrap()
            .expect("the current token deletes");
        assert_eq!(deleted.client_id, client.client_id);
        assert!(
            repo.delete_by_registration_access_token(tenant, &client.client_id, "tok")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            repo.count_by_managed_by(tenant, ManagedBy::Dcr)
                .await
                .unwrap(),
            0,
            "the deleted row no longer counts against dcr_max_clients"
        );
    }
}
