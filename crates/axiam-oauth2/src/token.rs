//! OAuth2 token exchange — supports authorization_code, client_credentials,
//! and refresh_token grant types. Also provides revocation (RFC 7009) and
//! introspection (RFC 7662).

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    generate_refresh_token, hash_refresh_token, issue_access_token, issue_client_credentials_token,
    issue_id_token, validate_access_token,
};
use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::repository::{
    AuthorizationCodeRepository, OAuth2ClientRepository, RefreshTokenRepository, TenantRepository,
    UserRepository,
};
use axiam_db::hash_client_secret;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::OAuth2Error;
use crate::pkce;

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
pub struct TokenService<OC, AC, TR, RT, UR> {
    client_repo: OC,
    code_repo: AC,
    tenant_repo: TR,
    refresh_token_repo: RT,
    user_repo: UR,
    auth_config: AuthConfig,
    refresh_token_lifetime_secs: i64,
}

impl<OC, AC, TR, RT, UR> TokenService<OC, AC, TR, RT, UR>
where
    OC: OAuth2ClientRepository,
    AC: AuthorizationCodeRepository,
    TR: TenantRepository,
    RT: RefreshTokenRepository,
    UR: UserRepository,
{
    pub fn new(
        client_repo: OC,
        code_repo: AC,
        tenant_repo: TR,
        refresh_token_repo: RT,
        user_repo: UR,
        auth_config: AuthConfig,
        refresh_token_lifetime_secs: i64,
    ) -> Self {
        Self {
            client_repo,
            code_repo,
            tenant_repo,
            refresh_token_repo,
            user_repo,
            auth_config,
            refresh_token_lifetime_secs,
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

        // Authenticate client
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|_| OAuth2Error::InvalidClient("client not found".into()))?;

        if let Some(ref secret) = req.client_secret {
            let provided_hash = hash_client_secret(secret);
            if provided_hash != client.client_secret_hash {
                return Err(OAuth2Error::InvalidClient(
                    "invalid client credentials".into(),
                ));
            }
        }

        // Consume the authorization code (atomic single-use)
        let code_hash = crate::authorize::hash_code(code);
        let auth_code = self
            .code_repo
            .consume(tenant_id, &code_hash)
            .await
            .map_err(|_| {
                OAuth2Error::InvalidGrant(
                    "authorization code is invalid, expired, or already used".into(),
                )
            })?;

        // Verify redirect_uri matches
        if auth_code.redirect_uri != redirect_uri {
            return Err(OAuth2Error::InvalidGrant("redirect_uri mismatch".into()));
        }

        // Verify client_id matches
        if auth_code.client_id != client_id {
            return Err(OAuth2Error::InvalidGrant("client_id mismatch".into()));
        }

        // Verify PKCE if code_challenge was used
        if let Some(ref challenge) = auth_code.code_challenge {
            let verifier = req.code_verifier.as_deref().ok_or_else(|| {
                OAuth2Error::InvalidGrant("code_verifier required for PKCE".into())
            })?;
            if !pkce::verify_pkce(verifier, challenge) {
                return Err(OAuth2Error::InvalidGrant("PKCE verification failed".into()));
            }
        }

        // Resolve org_id from tenant
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Issue access token (include scopes from the authorization code)
        let access_token = issue_access_token(
            auth_code.user_id,
            tenant_id,
            tenant.organization_id,
            &auth_code.scopes,
            &self.auth_config,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Generate and persist refresh token
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

        // Issue an ID token when the `openid` scope was requested.
        let id_token = if auth_code.scopes.contains(&"openid".to_string()) {
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
            refresh_token: Some(raw_refresh),
            scope,
            id_token,
        })
    }

    /// Client credentials grant (RFC 6749 section 4.4).
    ///
    /// Machine-to-machine flow — no user context, no refresh token.
    async fn handle_client_credentials(
        &self,
        tenant_id: Uuid,
        req: TokenRequest,
    ) -> Result<TokenResponse, OAuth2Error> {
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("client_id is required".into()))?;
        let client_secret = req
            .client_secret
            .as_deref()
            .ok_or_else(|| OAuth2Error::InvalidRequest("client_secret is required".into()))?;

        // Authenticate client
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|_| OAuth2Error::InvalidClient("client not found".into()))?;

        let provided_hash = hash_client_secret(client_secret);
        if provided_hash != client.client_secret_hash {
            return Err(OAuth2Error::InvalidClient(
                "invalid client credentials".into(),
            ));
        }

        // Verify grant type is allowed
        if !client
            .grant_types
            .contains(&"client_credentials".to_string())
        {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for client_credentials grant".into(),
            ));
        }

        // Resolve scopes: use requested scope if provided, else client's
        let scopes = match req.scope.as_deref() {
            Some(s) => s.split_whitespace().map(String::from).collect::<Vec<_>>(),
            None => client.scopes.clone(),
        };

        // Resolve org_id from tenant
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Issue M2M access token (no refresh token for client_credentials)
        let access_token = issue_client_credentials_token(
            client_id,
            tenant_id,
            tenant.organization_id,
            &scopes,
            &self.auth_config,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let scope = if scopes.is_empty() {
            None
        } else {
            Some(scopes.join(" "))
        };

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

        // Look up the refresh token by hash
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

        // Authenticate client
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|_| OAuth2Error::InvalidClient("client not found".into()))?;

        if let Some(ref secret) = req.client_secret {
            let provided_hash = hash_client_secret(secret);
            if provided_hash != client.client_secret_hash {
                return Err(OAuth2Error::InvalidClient(
                    "invalid client credentials".into(),
                ));
            }
        }

        // Revoke old refresh token (single-use rotation)
        self.refresh_token_repo
            .revoke(tenant_id, &token_hash)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Resolve org_id from tenant
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Issue new access token
        let access_token = if let Some(user_id) = stored.user_id {
            issue_access_token(
                user_id,
                tenant_id,
                tenant.organization_id,
                &stored.scopes,
                &self.auth_config,
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

        // Create and store new refresh token
        let new_raw_refresh = generate_refresh_token();
        let new_refresh_hash = hash_refresh_token(&new_raw_refresh);
        let refresh_expires =
            Utc::now() + chrono::Duration::seconds(self.refresh_token_lifetime_secs);

        self.refresh_token_repo
            .create(CreateRefreshToken {
                tenant_id,
                token_hash: new_refresh_hash,
                client_id: client_id.to_string(),
                user_id: stored.user_id,
                scopes: stored.scopes.clone(),
                expires_at: refresh_expires,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // Re-issue an ID token when the original grant included `openid`.
        let id_token = if stored.scopes.contains(&"openid".to_string()) {
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
        let _ = self.refresh_token_repo.revoke(tenant_id, &token_hash).await;

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
            return Ok(IntrospectionResponse {
                active: true,
                scope: claims.scope.clone(),
                client_id: Some(claims.sub.clone()),
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
            .map_err(|_| OAuth2Error::InvalidClient("client not found".into()))?;

        let provided_hash = hash_client_secret(client_secret);
        if provided_hash != client.client_secret_hash {
            return Err(OAuth2Error::InvalidClient(
                "invalid client credentials".into(),
            ));
        }

        Ok(())
    }
}
