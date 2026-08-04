//! OAuth2 token exchange — supports authorization_code, client_credentials,
//! and refresh_token grant types. Also provides revocation (RFC 7009) and
//! introspection (RFC 7662).

use axiam_auth::client_secret::{self, ClientSecretVerdict};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    generate_refresh_token, hash_refresh_token, issue_access_token, issue_client_credentials_token,
    issue_id_token, issue_service_account_client_credentials_token, validate_access_token,
};
use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::{CreateRefreshToken, OAuth2Client};
use axiam_core::models::service_account::{SERVICE_ACCOUNT_CLIENT_ID_PREFIX, ServiceAccount};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{
    AuthorizationCodeRepository, OAuth2ClientRepository, RefreshTokenRepository,
    ServiceAccountRepository, TenantRepository, UserRepository,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::OAuth2Error;
use crate::pkce;

/// The single `error_description` every token-endpoint client-authentication
/// failure returns, whatever actually went wrong (SEC-086).
///
/// The `invalid_client` error *code* was already uniform across "no such
/// client" and "wrong secret". The *description* was not: an unknown client
/// said `"client not found"`, which let an unauthenticated caller probe
/// whether a given `client_id` — including an `sa_…` service-account id —
/// exists. The masquerade the QUAL-03/D-11 comments describe was applied to
/// the code and not to the message; this constant applies it to both.
///
/// The `NotFound`-versus-other-error distinction those comments protect is
/// unaffected: it stays internal, mapping to `invalid_client` versus
/// `server_error`, so a DB outage still never reads as bad credentials. Only
/// the caller-visible wording is collapsed.
///
/// Deliberately **not** used at the authorization endpoint
/// (`authorize.rs`): there `client_id` is public by construction, RFC 6749
/// §4.1.2.1 requires informing the resource owner directly rather than
/// redirecting, and no credential is presented — so "invalid client
/// credentials" would be actively misleading there.
const CLIENT_AUTH_FAILED: &str = "invalid client credentials";

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Token request parameters (from form body).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// Token response per RFC 6749.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// RFC 7009 token revocation request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: String,
    pub client_secret: String,
}

/// RFC 7662 token introspection request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: String,
    pub client_secret: String,
}

/// RFC 7662 token introspection response.
#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// OAuth2 token service — handles token exchange, revocation, and
/// introspection.
#[derive(Clone)]
pub struct TokenService<OC, AC, TR, RT, UR, SA> {
    client_repo: OC,
    /// Service-account repository (client-credentials for `sa_…` clients).
    service_account_repo: SA,
    code_repo: AC,
    tenant_repo: TR,
    refresh_token_repo: RT,
    user_repo: UR,
    auth_config: AuthConfig,
    refresh_token_lifetime_secs: i64,
}

impl<OC, AC, TR, RT, UR, SA> TokenService<OC, AC, TR, RT, UR, SA>
where
    OC: OAuth2ClientRepository,
    SA: ServiceAccountRepository,
    AC: AuthorizationCodeRepository,
    TR: TenantRepository,
    RT: RefreshTokenRepository,
    UR: UserRepository,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_repo: OC,
        service_account_repo: SA,
        code_repo: AC,
        tenant_repo: TR,
        refresh_token_repo: RT,
        user_repo: UR,
        auth_config: AuthConfig,
        refresh_token_lifetime_secs: i64,
    ) -> Self {
        Self {
            client_repo,
            service_account_repo,
            code_repo,
            tenant_repo,
            refresh_token_repo,
            user_repo,
            auth_config,
            refresh_token_lifetime_secs,
        }
    }

    /// Verify a presented client secret against the stored hash — the single
    /// point at which every grant authenticates a confidential client.
    ///
    /// The comparison is constant-time and keyed (HMAC-SHA256 under the server
    /// pepper, `axiam_auth::client_secret`). A pre-OBS-1 row still stored as a
    /// bare SHA-256 digest verifies against the legacy scheme and is then
    /// **transparently upgraded**: the replacement hash is written back with a
    /// compare-and-swap so a concurrent rotation is never clobbered.
    ///
    /// Two properties this function exists to guarantee:
    ///
    /// - the upgrade is driven by [`ClientSecretVerdict::MatchNeedsUpgrade`],
    ///   which the hasher only ever returns on a **successful** verification —
    ///   a wrong secret can never cause a write; and
    /// - a failed *write* never becomes a failed *authentication*. The client
    ///   proved possession of the secret; losing the migration is a warning,
    ///   and the next request simply retries it.
    ///
    /// Cost on the hot path: one HMAC-SHA256 over the secret into a stack
    /// buffer, plus an `OnceLock` acquire load. No heap allocation and no lock
    /// — strictly less than the `String` the previous `hash_client_secret`
    /// allocated per request. The DB write happens at most once per legacy
    /// client, on its first authentication after the upgrade.
    async fn verify_client_secret(
        &self,
        tenant_id: Uuid,
        client: &OAuth2Client,
        presented: &str,
    ) -> Result<(), OAuth2Error> {
        let hasher =
            client_secret::global().map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        match hasher.verify(presented, &client.client_secret_hash) {
            ClientSecretVerdict::Match => Ok(()),
            ClientSecretVerdict::MatchNeedsUpgrade { upgraded_hash } => {
                match self
                    .client_repo
                    .upgrade_client_secret_hash(
                        tenant_id,
                        &client.client_id,
                        &client.client_secret_hash,
                        &upgraded_hash,
                    )
                    .await
                {
                    Ok(true) => tracing::info!(
                        client_id = %client.client_id,
                        "upgraded legacy client-secret hash to the peppered scheme (OBS-1)"
                    ),
                    Ok(false) => tracing::debug!(
                        client_id = %client.client_id,
                        "legacy client-secret hash upgrade skipped — a concurrent write won \
                         the compare-and-swap"
                    ),
                    Err(e) => tracing::warn!(
                        client_id = %client.client_id,
                        error = %e,
                        "failed to persist the legacy client-secret hash upgrade (OBS-1); \
                         authentication succeeded, the upgrade will be retried"
                    ),
                }
                Ok(())
            }
            ClientSecretVerdict::Mismatch => {
                Err(OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into()))
            }
        }
    }

    /// Client-credentials for a **service account** (`sa_…` client id).
    ///
    /// Service accounts are AXIAM's machine principal, and until now the only
    /// way one could authenticate in a running server was mTLS
    /// (`POST /api/v1/auth/device`). `create`/`rotate_secret` handed the
    /// operator a `client_secret` that **no flow accepted** — this is the path
    /// that makes it usable.
    ///
    /// Three deliberate differences from the `oauth2_client` branch:
    ///
    /// 1. **The secret is verified BEFORE the status check.** Rejecting a
    ///    disabled account without verifying would let an unauthenticated
    ///    caller distinguish "exists but disabled" from "does not exist" by
    ///    timing. Verifying first means status is only ever consulted for a
    ///    caller who already proved possession of the secret — and even then
    ///    the error returned is the same generic `invalid_client`.
    /// 2. **No scope may be requested.** A service account registers no scopes,
    ///    and the `oauth2_client` branch's rule is that a requested scope must
    ///    be a subset of the registered ones. With an empty registered set the
    ///    only subset is the empty one, so any requested scope is
    ///    `invalid_scope`. Authorization for a service account comes from the
    ///    roles assigned to its subject, exactly as on the mTLS path.
    /// 3. **The token's `sub` is the service-account id**, not the client id,
    ///    so the RBAC engine resolves the same principal whether the account
    ///    authenticated by certificate or by secret.
    async fn handle_client_credentials_service_account(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        client_secret: &str,
        requested_scope: Option<&str>,
        started: std::time::Instant,
    ) -> Result<TokenResponse, OAuth2Error> {
        let t_client_lookup = std::time::Instant::now();
        let sa = self
            .service_account_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|e| match e {
                // Same taxonomy as the oauth2_client branch: only a genuinely
                // unknown client is `invalid_client`; a DB outage must never
                // masquerade as bad credentials (error-oracle, QUAL-03/D-11).
                // The description is CLIENT_AUTH_FAILED here too, so an
                // unauthenticated caller cannot learn whether an `sa_…`
                // client id exists (SEC-086).
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;
        let client_lookup_us = t_client_lookup.elapsed().as_micros() as u64;

        // Defence in depth (§17.2 residual 6). The lookup above is already
        // tenant-scoped in SQL, so this can only fire if that predicate is
        // ever dropped or a repository implementation ignores `tenant_id` —
        // exactly the regression the assertion exists to catch. Without it the
        // cross-tenant property of this grant lives entirely in a `WHERE`
        // clause two crates away, and no test in this crate can prove it
        // because the mocks do not filter by tenant.
        //
        // Deliberately checked *before* the secret is verified: a row from the
        // wrong tenant must not have its secret compared at all, and the
        // presented client id is the caller's own input, so refusing early
        // leaks nothing it did not already know.
        if sa.tenant_id != tenant_id {
            tracing::error!(
                requested_tenant = %tenant_id,
                account_tenant = %sa.tenant_id,
                "service-account lookup returned a row from another tenant — refusing; \
                 this indicates a dropped tenant predicate in the repository layer"
            );
            return Err(OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into()));
        }

        let t_secret_verify = std::time::Instant::now();
        let secret_result = self
            .verify_service_account_secret(tenant_id, &sa, client_secret)
            .await;
        let secret_verify_us = t_secret_verify.elapsed().as_micros() as u64;
        secret_result?;

        // Only now — see point 1 in the doc comment.
        if sa.status != UserStatus::Active {
            tracing::info!(
                client_id = %sa.client_id,
                status = ?sa.status,
                "service-account client-credentials refused: account is not active"
            );
            return Err(OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into()));
        }

        if let Some(scope) = requested_scope.filter(|s| !s.trim().is_empty()) {
            return Err(OAuth2Error::InvalidScope(format!(
                "unregistered scopes: {} — a service account registers no scopes; \
                 its authorization comes from the roles assigned to it",
                scope.split_whitespace().collect::<Vec<_>>().join(", ")
            )));
        }

        let t_tenant_lookup = std::time::Instant::now();
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => OAuth2Error::InvalidRequest("unknown tenant".into()),
                other => OAuth2Error::ServerError(other.to_string()),
            })?;
        let tenant_lookup_us = t_tenant_lookup.elapsed().as_micros() as u64;

        let t_token_mint = std::time::Instant::now();
        let access_token = issue_service_account_client_credentials_token(
            sa.id,
            tenant_id,
            tenant.organization_id,
            &[],
            &self.auth_config,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        let token_mint_us = t_token_mint.elapsed().as_micros() as u64;

        let span = tracing::Span::current();
        span.record("client_lookup_us", client_lookup_us);
        span.record("secret_verify_us", secret_verify_us);
        span.record("tenant_lookup_us", tenant_lookup_us);
        span.record("token_mint_us", token_mint_us);
        span.record("handler_total_us", started.elapsed().as_micros() as u64);

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.auth_config.access_token_lifetime_secs,
            refresh_token: None,
            scope: None,
            id_token: None,
        })
    }

    /// [`Self::verify_client_secret`] for a service account.
    ///
    /// Same contract, against the service-account table: the upgrade is driven
    /// only by `MatchNeedsUpgrade` (so a wrong secret can never cause a write),
    /// and a failed write is a warning rather than a failed authentication.
    ///
    /// This is also what makes the §15.2 Obs 4 lazy migration *reachable*: with
    /// no verification path, `upgrade_client_secret_hash` could never fire for a
    /// service account, so legacy rows could not drain. They can now.
    async fn verify_service_account_secret(
        &self,
        tenant_id: Uuid,
        sa: &ServiceAccount,
        presented: &str,
    ) -> Result<(), OAuth2Error> {
        let hasher =
            client_secret::global().map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        match hasher.verify(presented, &sa.client_secret_hash) {
            ClientSecretVerdict::Match => Ok(()),
            ClientSecretVerdict::MatchNeedsUpgrade { upgraded_hash } => {
                match self
                    .service_account_repo
                    .upgrade_client_secret_hash(
                        tenant_id,
                        &sa.client_id,
                        &sa.client_secret_hash,
                        &upgraded_hash,
                    )
                    .await
                {
                    Ok(true) => tracing::info!(
                        client_id = %sa.client_id,
                        "upgraded legacy service-account secret hash to the peppered scheme"
                    ),
                    Ok(false) => tracing::debug!(
                        client_id = %sa.client_id,
                        "legacy service-account secret-hash upgrade skipped — a concurrent \
                         write won the compare-and-swap"
                    ),
                    Err(e) => tracing::warn!(
                        client_id = %sa.client_id,
                        error = %e,
                        "failed to persist the legacy service-account secret-hash upgrade; \
                         authentication succeeded, the upgrade will be retried"
                    ),
                }
                Ok(())
            }
            ClientSecretVerdict::Mismatch => {
                Err(OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into()))
            }
        }
    }

    /// Dispatch a token request to the appropriate grant handler.
    pub async fn exchange(
        &self,
        tenant_id: Uuid,
        req: TokenRequest,
    ) -> Result<TokenResponse, OAuth2Error> {
        match req.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code(tenant_id, req).await,
            "client_credentials" => self.handle_client_credentials(tenant_id, req).await,
            "refresh_token" => self.handle_refresh_token(tenant_id, req).await,
            _ => Err(OAuth2Error::UnsupportedGrantType),
        }
    }

    /// Exchange an authorization code for tokens (RFC 6749 section 4.1.3).
    async fn handle_authorization_code(
        &self,
        tenant_id: Uuid,
        req: TokenRequest,
    ) -> Result<TokenResponse, OAuth2Error> {
        let code = req
            .code
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("code is required".into()))?;
        let redirect_uri = req
            .redirect_uri
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("redirect_uri is required".into()))?;
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("client_id is required".into()))?;

        // Require client_secret — all clients are confidential (no
        // public-client distinction exists yet).
        //
        // SEC-086 (second pass): this check MUST precede the client lookup.
        // When it ran after, a caller posting no `client_secret` at all got
        // three distinguishable answers — `invalid_client`/generic for an
        // unknown client, `unauthorized_client` for a client lacking the
        // grant, and `invalid_client`/"client_secret is required" for a
        // client that had it — so client existence stayed decidable on this
        // grant even after the description was unified everywhere else.
        // `client_credentials` and `refresh_token` already ordered it this
        // way; only this grant did not.
        let client_secret = req
            .client_secret
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidClient("client_secret is required".into()))?;

        // Authenticate client
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|e| match e {
                // QUAL-03/D-11: only a genuinely-unknown client maps to
                // invalid_client. Any other error (e.g. a DB outage) must
                // surface as a distinct server error, never masquerade as
                // bad client credentials (error-oracle). The distinction is
                // internal only — the caller-visible description is
                // CLIENT_AUTH_FAILED either way, so it cannot be used to
                // probe which client ids exist (SEC-086).
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        // Secret verification must also precede the grant-type check, and for
        // the same reason: `unauthorized_client` is only reachable by a caller
        // who has *already proven possession of the secret*. Ordered the other
        // way, supplying any dummy secret still separated "client exists but
        // lacks this grant" from "no such client" — a second oracle on the
        // same grant, which moving the presence check alone does not close.
        // Both safe grants verify first; this now matches them exactly.
        self.verify_client_secret(tenant_id, &client, client_secret)
            .await?;

        // Verify client is authorized for authorization_code grant
        if !client.grant_types.iter().any(|s| s == "authorization_code") {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for authorization_code grant".into(),
            ));
        }

        // Look up the authorization code without consuming it so we
        // can verify PKCE *before* marking it as used.  This prevents
        // an attacker from burning a valid code by intentionally
        // failing PKCE verification.
        let code_hash = crate::authorize::hash_code(code);
        let auth_code = self
            .code_repo
            .get_by_hash(tenant_id, &code_hash, client_id, redirect_uri)
            .await
            .map_err(|_| {
                OAuth2Error::InvalidGrant(
                    "authorization code is invalid, expired, or already used".into(),
                )
            })?;

        // Verify PKCE before consuming the code
        if let Some(ref challenge) = auth_code.code_challenge {
            let verifier = req.code_verifier.as_deref().ok_or_else(|| {
                OAuth2Error::InvalidGrant("code_verifier required for PKCE".into())
            })?;
            if !pkce::verify_pkce(verifier, challenge) {
                return Err(OAuth2Error::InvalidGrant("PKCE verification failed".into()));
            }
        }

        // Now atomically consume (mark as used) the code.
        self.code_repo
            .consume(tenant_id, &code_hash, client_id, redirect_uri)
            .await
            .map_err(|_| {
                OAuth2Error::InvalidGrant(
                    "authorization code is invalid, expired, or already used".into(),
                )
            })?;

        // Resolve org_id from tenant
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => OAuth2Error::InvalidRequest("unknown tenant".into()),
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        // Issue access token (include scopes from the authorization code).
        // OAuth2 auth-code flow has no persistent session row — use random jti.
        let access_token = issue_access_token(
            auth_code.user_id,
            tenant_id,
            tenant.organization_id,
            &auth_code.scopes,
            &self.auth_config,
            uuid::Uuid::new_v4().to_string(),
            axiam_auth::token::AUD_USER,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Only issue a refresh token when the client is authorized
        // for the refresh_token grant type.
        let refresh_token = if client.grant_types.iter().any(|s| s == "refresh_token") {
            let raw_refresh = generate_refresh_token();
            let refresh_hash = hash_refresh_token(&raw_refresh);
            let refresh_expires =
                Utc::now() + chrono::Duration::seconds(self.refresh_token_lifetime_secs);

            self.refresh_token_repo
                .create(CreateRefreshToken {
                    tenant_id,
                    token_hash: refresh_hash,
                    client_id: client_id.to_string(),
                    user_id: Some(auth_code.user_id),
                    scopes: auth_code.scopes.clone(),
                    expires_at: refresh_expires,
                })
                .await
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
            Some(raw_refresh)
        } else {
            None
        };

        // Issue an ID token when the `openid` scope was requested.
        let id_token = if auth_code.scopes.iter().any(|s| s == "openid") {
            let user = self
                .user_repo
                .get_by_id(tenant_id, auth_code.user_id)
                .await
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
            Some(
                issue_id_token(
                    auth_code.user_id,
                    tenant_id,
                    tenant.organization_id,
                    client_id,
                    auth_code.nonce.as_deref(),
                    Some(&user.email),
                    Some(&user.username),
                    &auth_code.scopes,
                    &self.auth_config,
                )
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?,
            )
        } else {
            None
        };

        let scope = if auth_code.scopes.is_empty() {
            None
        } else {
            Some(auth_code.scopes.join(" "))
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: self.auth_config.access_token_lifetime_secs,
            refresh_token,
            scope,
            id_token,
        })
    }

    /// Client credentials grant (RFC 6749 section 4.4).
    ///
    /// Machine-to-machine flow — no user context, no refresh token.
    ///
    /// # Per-stage timing (I5)
    ///
    /// This handler is the subject of the run-4 TLS plateau investigation, so it
    /// carries a stage breakdown on its span: `client_lookup_us`,
    /// `secret_verify_us`, `tenant_lookup_us`, `token_mint_us` and
    /// `handler_total_us`, recorded on the `oauth2.client_credentials` span and
    /// re-emitted as one DEBUG event on `target: "axiam::perf"`.
    ///
    /// **Cost, and why it is left permanently on:** five `Instant::now()` calls
    /// (~20 ns each on a `clock_gettime` vDSO read) and five
    /// `Span::record` calls that are no-ops when no subscriber is interested —
    /// together well under 0.1 % of the ~370 µs this handler takes even in the
    /// *fast* (plaintext, 2 727 req/s) configuration. No flag gates the
    /// measurement; only the *reporting* is gated, by the ordinary tracing
    /// level (`RUST_LOG=axiam_oauth2=debug`, or any subscriber that samples the
    /// span's fields).
    ///
    /// There is deliberately **no "token persist" stage**: the
    /// `client_credentials` grant issues no refresh token and writes nothing —
    /// the only DB work is the two reads below. That, plus the fact that the
    /// client secret is verified with a single keyed HMAC-SHA256 rather than
    /// Argon2id (see `axiam_auth::client_secret`), is why this endpoint
    /// measures 2 727 req/s where password login measures 69. The OBS-1
    /// remediation deliberately kept this MAC-bound rather than KDF-bound:
    /// client secrets are 256-bit CSPRNG values *and* the digest is now keyed,
    /// so the offline-guessing threat a KDF defends against does not apply.
    #[tracing::instrument(
        name = "oauth2.client_credentials",
        skip(self, req),
        fields(
            client_lookup_us = tracing::field::Empty,
            secret_verify_us = tracing::field::Empty,
            tenant_lookup_us = tracing::field::Empty,
            token_mint_us = tracing::field::Empty,
            handler_total_us = tracing::field::Empty,
        )
    )]
    async fn handle_client_credentials(
        &self,
        tenant_id: Uuid,
        req: TokenRequest,
    ) -> Result<TokenResponse, OAuth2Error> {
        let started = std::time::Instant::now();
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("client_id is required".into()))?;
        let client_secret = req
            .client_secret
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidClient("client_secret is required".into()))?;

        // Service accounts are the other machine principal in AXIAM and live in
        // their own table. Both client-id families are **server-generated** with
        // disjoint prefixes (`oa_` for `oauth2_client`, `sa_` for
        // `service_account`), so the prefix selects the table unambiguously and
        // keeps this path at one lookup.
        //
        // The prefix is NOT a security decision: it only picks which table to
        // look in. The presented secret must still verify against the row that
        // is actually found, so guessing a prefix only routes a caller to a
        // table where their `client_id` does not exist — an `invalid_client`,
        // exactly as before.
        if client_id.starts_with(SERVICE_ACCOUNT_CLIENT_ID_PREFIX) {
            return self
                .handle_client_credentials_service_account(
                    tenant_id,
                    client_id,
                    client_secret,
                    req.scope.as_deref(),
                    started,
                )
                .await;
        }

        // Stage 1 — client lookup (DB round-trip #1).
        let t_client_lookup = std::time::Instant::now();
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|e| match e {
                // QUAL-03/D-11: only a genuinely-unknown client maps to
                // invalid_client. Any other error (e.g. a DB outage) must
                // surface as a distinct server error, never masquerade as
                // bad client credentials (error-oracle). The distinction is
                // internal only — the caller-visible description is
                // CLIENT_AUTH_FAILED either way, so it cannot be used to
                // probe which client ids exist (SEC-086).
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;
        let client_lookup_us = t_client_lookup.elapsed().as_micros() as u64;

        // Stage 2 — client-secret verification. Keyed HMAC-SHA256 into a stack
        // buffer + constant-time compare (`axiam_auth::client_secret`); no heap
        // allocation, no lock, and this does NOT touch the Argon2id
        // `crypto_semaphore` that bounds password verification. A pre-OBS-1
        // row additionally costs one SHA-256 and, once, one DB write to
        // migrate; the timing recorded here therefore includes that one-off
        // upgrade for a legacy client's first authentication.
        let t_secret_verify = std::time::Instant::now();
        let secret_result = self
            .verify_client_secret(tenant_id, &client, client_secret)
            .await;
        let secret_verify_us = t_secret_verify.elapsed().as_micros() as u64;
        secret_result?;

        // Verify grant type is allowed
        if !client.grant_types.iter().any(|s| s == "client_credentials") {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for client_credentials grant".into(),
            ));
        }

        // Resolve scopes: use requested scope if provided, else client's.
        // Validate requested scopes are a subset of the client's allowed
        // scopes to prevent minting tokens with arbitrary privileges.
        let scopes = match req.scope.as_deref() {
            Some(s) => {
                let requested: Vec<String> = s.split_whitespace().map(String::from).collect();
                let invalid: Vec<&str> = requested
                    .iter()
                    .filter(|sc| !client.scopes.contains(sc))
                    .map(String::as_str)
                    .collect();
                if !invalid.is_empty() {
                    return Err(OAuth2Error::InvalidScope(format!(
                        "unregistered scopes: {}",
                        invalid.join(", ")
                    )));
                }
                requested
            }
            None => client.scopes.clone(),
        };

        // Stage 3 — tenant lookup (DB round-trip #2), for the `org_id` claim.
        let t_tenant_lookup = std::time::Instant::now();
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => OAuth2Error::InvalidRequest("unknown tenant".into()),
                other => OAuth2Error::ServerError(other.to_string()),
            })?;
        let tenant_lookup_us = t_tenant_lookup.elapsed().as_micros() as u64;

        // Stage 4 — token mint + EdDSA (Ed25519) signature. No refresh token is
        // issued for client_credentials, so there is no persist stage.
        let t_token_mint = std::time::Instant::now();
        let access_token = issue_client_credentials_token(
            client_id,
            tenant_id,
            tenant.organization_id,
            &scopes,
            &self.auth_config,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        let token_mint_us = t_token_mint.elapsed().as_micros() as u64;

        let scope = if scopes.is_empty() {
            None
        } else {
            Some(scopes.join(" "))
        };

        let handler_total_us = started.elapsed().as_micros() as u64;
        let span = tracing::Span::current();
        span.record("client_lookup_us", client_lookup_us);
        span.record("secret_verify_us", secret_verify_us);
        span.record("tenant_lookup_us", tenant_lookup_us);
        span.record("token_mint_us", token_mint_us);
        span.record("handler_total_us", handler_total_us);
        tracing::debug!(
            target: "axiam::perf",
            stage = "oauth2.client_credentials",
            client_lookup_us,
            secret_verify_us,
            tenant_lookup_us,
            token_mint_us,
            handler_total_us,
            access_token_len = access_token.len(),
            "client_credentials stage timings (I5)"
        );

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: self.auth_config.access_token_lifetime_secs,
            refresh_token: None,
            scope,
            id_token: None,
        })
    }

    /// Refresh token grant (RFC 6749 section 6).
    ///
    /// Single-use rotation: the old refresh token is revoked and a new one
    /// is issued alongside a fresh access token.
    async fn handle_refresh_token(
        &self,
        tenant_id: Uuid,
        req: TokenRequest,
    ) -> Result<TokenResponse, OAuth2Error> {
        let raw_token = req
            .refresh_token
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("refresh_token is required".into()))?;
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("client_id is required".into()))?;

        // Authenticate client BEFORE looking up the refresh token to
        // avoid a token-validity oracle (different error for valid vs
        // invalid tokens when client auth fails).
        let client_secret_val = req
            .client_secret
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidClient("client_secret is required".into()))?;

        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|e| match e {
                // QUAL-03/D-11: only a genuinely-unknown client maps to
                // invalid_client. Any other error (e.g. a DB outage) must
                // surface as a distinct server error, never masquerade as
                // bad client credentials (error-oracle). The distinction is
                // internal only — the caller-visible description is
                // CLIENT_AUTH_FAILED either way, so it cannot be used to
                // probe which client ids exist (SEC-086).
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        self.verify_client_secret(tenant_id, &client, client_secret_val)
            .await?;

        // Verify client is authorized for refresh_token grant
        if !client.grant_types.iter().any(|s| s == "refresh_token") {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for refresh_token grant".into(),
            ));
        }

        // Look up the refresh token by hash (after client auth)
        let token_hash = hash_refresh_token(raw_token);
        let stored = self
            .refresh_token_repo
            .get_by_token_hash(tenant_id, &token_hash)
            .await
            .map_err(|_| {
                OAuth2Error::InvalidGrant("refresh token is invalid, expired, or revoked".into())
            })?;

        // Verify client ownership
        if stored.client_id != client_id {
            return Err(OAuth2Error::InvalidGrant(
                "refresh token was not issued to this client".into(),
            ));
        }

        // Resolve org_id from tenant
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => OAuth2Error::InvalidRequest("unknown tenant".into()),
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        // Issue new access token.
        // OAuth2 refresh flow has no persistent session row — use random jti.
        let access_token = if let Some(user_id) = stored.user_id {
            issue_access_token(
                user_id,
                tenant_id,
                tenant.organization_id,
                &stored.scopes,
                &self.auth_config,
                uuid::Uuid::new_v4().to_string(),
                axiam_auth::token::AUD_USER,
            )
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
        } else {
            // Client-credentials-originated refresh (shouldn't normally
            // happen, but handle gracefully)
            issue_client_credentials_token(
                client_id,
                tenant_id,
                tenant.organization_id,
                &stored.scopes,
                &self.auth_config,
            )
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
        };

        // Refresh token rotation: create new token BEFORE revoking
        // the old one. If `create` fails the old token remains valid
        // and the client can retry; if `revoke` fails after `create`
        // we have a brief window with two valid tokens (less harmful
        // than zero tokens forcing a full re-auth).
        let new_raw_refresh = generate_refresh_token();
        let new_refresh_hash = hash_refresh_token(&new_raw_refresh);
        let refresh_expires =
            Utc::now() + chrono::Duration::seconds(self.refresh_token_lifetime_secs);

        self.refresh_token_repo
            .create(CreateRefreshToken {
                tenant_id,
                token_hash: new_refresh_hash.clone(),
                client_id: client_id.to_string(),
                user_id: stored.user_id,
                scopes: stored.scopes.clone(),
                expires_at: refresh_expires,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Now revoke the old refresh token (single-use rotation).
        // If revoke fails, best-effort cleanup of the new token to
        // avoid orphaned entries; then surface the appropriate error.
        if let Err(revoke_err) = self.refresh_token_repo.revoke(tenant_id, &token_hash).await {
            // Best-effort: delete the newly-created token so it
            // doesn't linger as an orphan.
            if let Err(cleanup_err) = self
                .refresh_token_repo
                .revoke(tenant_id, &new_refresh_hash)
                .await
            {
                tracing::warn!(
                    error = %cleanup_err,
                    "token: failed to revoke orphaned refresh token; token may linger"
                );
            }

            return if matches!(revoke_err, AxiamError::NotFound { .. }) {
                Err(OAuth2Error::InvalidGrant(
                    "refresh token already consumed".into(),
                ))
            } else {
                Err(OAuth2Error::ServerError(
                    "failed to revoke old refresh token".into(),
                ))
            };
        }

        // Re-issue an ID token when the original grant included `openid`.
        let id_token = if stored.scopes.iter().any(|s| s == "openid") {
            if let Some(uid) = stored.user_id {
                let user = self
                    .user_repo
                    .get_by_id(tenant_id, uid)
                    .await
                    .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
                Some(
                    issue_id_token(
                        uid,
                        tenant_id,
                        tenant.organization_id,
                        client_id,
                        None, // no nonce for refresh
                        Some(&user.email),
                        Some(&user.username),
                        &stored.scopes,
                        &self.auth_config,
                    )
                    .map_err(|e| OAuth2Error::ServerError(e.to_string()))?,
                )
            } else {
                None
            }
        } else {
            None
        };

        let scope = if stored.scopes.is_empty() {
            None
        } else {
            Some(stored.scopes.join(" "))
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: self.auth_config.access_token_lifetime_secs,
            refresh_token: Some(new_raw_refresh),
            scope,
            id_token,
        })
    }

    /// Revoke a token per RFC 7009.
    ///
    /// Always returns `Ok(())` — invalid tokens are silently ignored.
    pub async fn revoke_token(
        &self,
        tenant_id: Uuid,
        req: RevokeRequest,
    ) -> Result<(), OAuth2Error> {
        // Authenticate the client making the revocation request
        self.authenticate_client(tenant_id, &req.client_id, &req.client_secret)
            .await?;

        // Try revoking as a refresh token (hash-based lookup).
        // For access tokens (short-lived JWTs), revocation is a no-op —
        // they expire naturally within minutes.
        let token_hash = hash_refresh_token(&req.token);

        // Look up the token first to verify client ownership.
        // Only revoke if found and belongs to the requesting client;
        // otherwise treat as unknown per RFC 7009.
        if let Ok(stored) = self
            .refresh_token_repo
            .get_by_token_hash(tenant_id, &token_hash)
            .await
            && stored.client_id == req.client_id
        {
            self.refresh_token_repo
                .revoke(tenant_id, &token_hash)
                .await
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        }

        Ok(())
    }

    /// Introspect a token per RFC 7662.
    pub async fn introspect_token(
        &self,
        tenant_id: Uuid,
        req: IntrospectRequest,
    ) -> Result<IntrospectionResponse, OAuth2Error> {
        // Authenticate the client making the introspection request
        self.authenticate_client(tenant_id, &req.client_id, &req.client_secret)
            .await?;

        // First try: decode as JWT access token
        if let Ok(validated) = validate_access_token(&req.token, &self.auth_config) {
            let claims = &validated.0;

            // Verify the token belongs to this tenant to prevent
            // cross-tenant introspection / metadata leaks.
            let token_tenant = claims.tenant_id.parse::<Uuid>().unwrap_or(Uuid::nil());
            if token_tenant != tenant_id {
                return Ok(IntrospectionResponse {
                    active: false,
                    ..Default::default()
                });
            }

            return Ok(IntrospectionResponse {
                active: true,
                scope: claims.scope.clone(),
                // Access tokens don't carry an explicit client_id
                // claim; omit it to avoid confusing sub (user ID)
                // with client_id.
                client_id: None,
                sub: Some(claims.sub.clone()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                token_type: Some("Bearer".into()),
            });
        }

        // Second try: look up as refresh token
        let token_hash = hash_refresh_token(&req.token);
        if let Ok(stored) = self
            .refresh_token_repo
            .get_by_token_hash(tenant_id, &token_hash)
            .await
        {
            // Only introspect tokens belonging to the requesting
            // client — prevent cross-client information leaks.
            if stored.client_id != req.client_id {
                return Ok(IntrospectionResponse {
                    active: false,
                    ..Default::default()
                });
            }

            let scope = if stored.scopes.is_empty() {
                None
            } else {
                Some(stored.scopes.join(" "))
            };
            return Ok(IntrospectionResponse {
                active: true,
                scope,
                client_id: Some(stored.client_id),
                sub: stored.user_id.map(|u| u.to_string()),
                exp: Some(stored.expires_at.timestamp()),
                iat: Some(stored.created_at.timestamp()),
                token_type: Some("refresh_token".into()),
            });
        }

        // Token is not recognised — return inactive per RFC 7662
        Ok(IntrospectionResponse {
            active: false,
            ..Default::default()
        })
    }

    /// Verify client credentials. Shared by revoke and introspect.
    async fn authenticate_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), OAuth2Error> {
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|e| match e {
                // QUAL-03/D-11: only a genuinely-unknown client maps to
                // invalid_client. Any other error (e.g. a DB outage) must
                // surface as a distinct server error, never masquerade as
                // bad client credentials (error-oracle). The distinction is
                // internal only — the caller-visible description is
                // CLIENT_AUTH_FAILED either way, so it cannot be used to
                // probe which client ids exist (SEC-086).
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        self.verify_client_secret(tenant_id, &client, client_secret)
            .await?;

        Ok(())
    }
}
