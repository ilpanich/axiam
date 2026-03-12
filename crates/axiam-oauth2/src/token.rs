//! OAuth2 token exchange -- authorization code for tokens.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{generate_refresh_token, issue_access_token};
use axiam_core::repository::{
    AuthorizationCodeRepository, OAuth2ClientRepository, TenantRepository,
};
use axiam_db::hash_client_secret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::OAuth2Error;
use crate::pkce;

/// Token request parameters (from form body).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

/// Token response per RFC 6749.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// OAuth2 token service -- handles token exchange.
#[derive(Clone)]
pub struct TokenService<OC, AC, TR> {
    client_repo: OC,
    code_repo: AC,
    tenant_repo: TR,
    auth_config: AuthConfig,
}

impl<OC, AC, TR> TokenService<OC, AC, TR>
where
    OC: OAuth2ClientRepository,
    AC: AuthorizationCodeRepository,
    TR: TenantRepository,
{
    pub fn new(
        client_repo: OC,
        code_repo: AC,
        tenant_repo: TR,
        auth_config: AuthConfig,
    ) -> Self {
        Self {
            client_repo,
            code_repo,
            tenant_repo,
            auth_config,
        }
    }

    /// Exchange an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        tenant_id: Uuid,
        req: TokenRequest,
    ) -> Result<TokenResponse, OAuth2Error> {
        // 1. Validate grant_type
        if req.grant_type != "authorization_code" {
            return Err(OAuth2Error::UnsupportedGrantType);
        }

        let code = req.code.as_deref().ok_or_else(|| {
            OAuth2Error::InvalidRequest("code is required".into())
        })?;
        let redirect_uri = req.redirect_uri.as_deref().ok_or_else(|| {
            OAuth2Error::InvalidRequest("redirect_uri is required".into())
        })?;
        let client_id = req.client_id.as_deref().ok_or_else(|| {
            OAuth2Error::InvalidRequest("client_id is required".into())
        })?;

        // 2. Authenticate client
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|_| {
                OAuth2Error::InvalidClient("client not found".into())
            })?;

        if let Some(ref secret) = req.client_secret {
            let provided_hash = hash_client_secret(secret);
            if provided_hash != client.client_secret_hash {
                return Err(OAuth2Error::InvalidClient(
                    "invalid client credentials".into(),
                ));
            }
        }

        // 3. Consume the authorization code (atomic single-use)
        let code_hash = crate::authorize::hash_code(code);
        let auth_code = self
            .code_repo
            .consume(tenant_id, &code_hash)
            .await
            .map_err(|_| {
                OAuth2Error::InvalidGrant(
                    "authorization code is invalid, expired, or already used"
                        .into(),
                )
            })?;

        // 4. Verify redirect_uri matches
        if auth_code.redirect_uri != redirect_uri {
            return Err(OAuth2Error::InvalidGrant(
                "redirect_uri mismatch".into(),
            ));
        }

        // 5. Verify client_id matches
        if auth_code.client_id != client_id {
            return Err(OAuth2Error::InvalidGrant(
                "client_id mismatch".into(),
            ));
        }

        // 6. Verify PKCE if code_challenge was used
        if let Some(ref challenge) = auth_code.code_challenge {
            let verifier =
                req.code_verifier.as_deref().ok_or_else(|| {
                    OAuth2Error::InvalidGrant(
                        "code_verifier required for PKCE".into(),
                    )
                })?;
            if !pkce::verify_pkce(verifier, challenge) {
                return Err(OAuth2Error::InvalidGrant(
                    "PKCE verification failed".into(),
                ));
            }
        }

        // 7. Resolve org_id from tenant
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // 8. Issue tokens
        let access_token = issue_access_token(
            auth_code.user_id,
            tenant_id,
            tenant.organization_id,
            &self.auth_config,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let refresh_token = generate_refresh_token();

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
        })
    }
}
