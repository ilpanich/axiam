//! OIDC Federation Service.
//!
//! Handles external OIDC identity provider integration: building
//! authorization URLs, exchanging authorization codes for tokens,
//! validating ID tokens, and provisioning or linking local users
//! to external IdP identities.

use axiam_core::error::AxiamError;
use axiam_core::models::federation::{CreateFederationLink, FederationLink, FederationProtocol};
use axiam_core::models::user::{CreateUser, User};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, UserRepository,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::FederationError;
use crate::validate_metadata_url;

/// Minimal OIDC Discovery document fields we care about.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
}

/// The result of building an authorization URL for the external IdP.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationUrl {
    pub url: String,
}

/// Token response from the external IdP's token endpoint.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[allow(dead_code)]
    access_token: String,
    id_token: Option<String>,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// Claims extracted from the external IdP's ID token.
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub nonce: Option<String>,
}

/// Result of a successful OIDC callback: the local user and their
/// federation link.
#[derive(Debug)]
pub struct FederationCallbackResult {
    pub user: User,
    pub federation_link: FederationLink,
    /// True if the user was newly provisioned during this callback.
    pub newly_provisioned: bool,
}

/// OIDC Federation Service that handles external IdP integration.
///
/// Generic over repository implementations for testability.
pub struct OidcFederationService<FC, FL, UR> {
    federation_config_repo: FC,
    federation_link_repo: FL,
    user_repo: UR,
    http_client: reqwest::Client,
}

impl<FC, FL, UR> OidcFederationService<FC, FL, UR>
where
    FC: FederationConfigRepository,
    FL: FederationLinkRepository,
    UR: UserRepository,
{
    /// Create a new OIDC federation service.
    pub fn new(
        federation_config_repo: FC,
        federation_link_repo: FL,
        user_repo: UR,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            federation_config_repo,
            federation_link_repo,
            user_repo,
            http_client,
        }
    }

    /// Fetch and parse the OIDC discovery document from the provider.
    ///
    /// Only HTTPS URLs are accepted to mitigate SSRF risks, since the
    /// `metadata_url` originates from admin-provided configuration.
    pub async fn discover(
        &self,
        metadata_url: &str,
    ) -> Result<OidcDiscoveryDocument, FederationError> {
        validate_metadata_url(metadata_url)?;

        let response = self
            .http_client
            .get(metadata_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| FederationError::DiscoveryFailed(format!("HTTP request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(FederationError::DiscoveryFailed(format!(
                "HTTP {} from discovery endpoint",
                response.status()
            )));
        }

        let doc = response
            .json::<OidcDiscoveryDocument>()
            .await
            .map_err(|e| {
                FederationError::DiscoveryFailed(format!("Failed to parse discovery document: {e}"))
            })?;

        // Validate that critical endpoints in the discovery document use
        // HTTPS. A compromised/malicious discovery endpoint could return
        // http:// URLs, leaking client_secret during token exchange.
        for (name, url) in [
            ("authorization_endpoint", &doc.authorization_endpoint),
            ("token_endpoint", &doc.token_endpoint),
            ("jwks_uri", &doc.jwks_uri),
        ] {
            if let Ok(parsed) = url::Url::parse(url)
                && parsed.scheme() != "https"
            {
                return Err(FederationError::DiscoveryFailed(format!(
                    "{name} must use HTTPS, got: {url}"
                )));
            }
        }

        Ok(doc)
    }

    /// Build the authorization URL to redirect the user to the external IdP.
    ///
    /// The caller is responsible for generating and storing the `state` and
    /// `nonce` values for CSRF and replay protection.
    pub async fn build_authorization_url(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
    ) -> Result<AuthorizationUrl, FederationError> {
        let config = self
            .federation_config_repo
            .get_by_id(tenant_id, config_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { id, .. } => FederationError::ConfigNotFound(id),
                other => FederationError::Internal(other.to_string()),
            })?;

        if !config.enabled {
            return Err(FederationError::ConfigDisabled);
        }

        if config.protocol != FederationProtocol::OidcConnect {
            return Err(FederationError::ProtocolMismatch(
                "expected OidcConnect protocol".into(),
            ));
        }

        let metadata_url = config
            .metadata_url
            .as_deref()
            .ok_or_else(|| FederationError::DiscoveryFailed("No metadata URL configured".into()))?;

        let discovery = self.discover(metadata_url).await?;

        // Build the authorization URL with required OIDC parameters.
        let mut auth_url = url::Url::parse(&discovery.authorization_endpoint).map_err(|e| {
            FederationError::DiscoveryFailed(format!("Invalid authorization endpoint URL: {e}"))
        })?;

        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", "openid email profile")
            .append_pair("state", state)
            .append_pair("nonce", nonce);

        let url = auth_url.to_string();

        info!(
            tenant_id = %tenant_id,
            config_id = %config_id,
            provider = %config.provider,
            "Built OIDC authorization URL"
        );

        Ok(AuthorizationUrl { url })
    }

    /// Handle the callback from the external IdP after user authentication.
    ///
    /// Exchanges the authorization code for tokens, validates the ID token,
    /// and provisions or links the user.
    pub async fn handle_callback(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        code: &str,
        redirect_uri: &str,
        expected_nonce: &str,
    ) -> Result<FederationCallbackResult, FederationError> {
        let config = self
            .federation_config_repo
            .get_by_id(tenant_id, config_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { id, .. } => FederationError::ConfigNotFound(id),
                other => FederationError::Internal(other.to_string()),
            })?;

        if !config.enabled {
            return Err(FederationError::ConfigDisabled);
        }

        if config.protocol != FederationProtocol::OidcConnect {
            return Err(FederationError::ProtocolMismatch(
                "expected OidcConnect protocol".into(),
            ));
        }

        let metadata_url = config
            .metadata_url
            .as_deref()
            .ok_or_else(|| FederationError::DiscoveryFailed("No metadata URL configured".into()))?;

        let discovery = self.discover(metadata_url).await?;

        // Exchange authorization code for tokens.
        let token_response = self
            .exchange_code(
                &discovery.token_endpoint,
                code,
                redirect_uri,
                &config.client_id,
                &config.client_secret,
            )
            .await?;

        let id_token_str = token_response.id_token.ok_or_else(|| {
            FederationError::TokenExchangeFailed("No id_token in token response".into())
        })?;

        // Decode and validate the ID token claims.
        // TODO(T19.6): Implement JWKS-based JWT signature verification
        // and fail closed (reject unverified tokens) unless an explicit
        // insecure-federation dev/test flag is enabled. Until then,
        // tokens are decoded without cryptographic verification.
        warn!(
            tenant_id = %tenant_id,
            config_id = %config_id,
            "ID token decoded without JWT signature verification — \
             JWKS validation not yet implemented"
        );
        let claims = Self::decode_id_token_claims(&id_token_str)?;

        // Validate nonce to prevent replay attacks.
        if let Some(ref token_nonce) = claims.nonce {
            if token_nonce != expected_nonce {
                return Err(FederationError::IdTokenValidationFailed(
                    "Nonce mismatch".into(),
                ));
            }
        } else {
            return Err(FederationError::IdTokenValidationFailed(
                "Missing nonce in ID token".into(),
            ));
        }

        // Validate standard registered claims (exp, aud).
        // Per OIDC Core §2, exp and aud are REQUIRED claims.
        let exp = claims.exp.ok_or_else(|| {
            FederationError::IdTokenValidationFailed("Missing required 'exp' claim".into())
        })?;
        let now = chrono::Utc::now().timestamp() as u64;
        if now > exp {
            return Err(FederationError::IdTokenValidationFailed(
                "ID token has expired".into(),
            ));
        }

        let aud = claims.aud.as_ref().ok_or_else(|| {
            FederationError::IdTokenValidationFailed("Missing required 'aud' claim".into())
        })?;
        let client_id = &config.client_id;
        let aud_matches = match aud {
            serde_json::Value::String(s) => s == client_id,
            serde_json::Value::Array(arr) => {
                arr.iter().any(|v| v.as_str() == Some(client_id.as_str()))
            }
            _ => false,
        };
        if !aud_matches {
            return Err(FederationError::IdTokenValidationFailed(
                "Audience does not match client_id".into(),
            ));
        }

        info!(
            tenant_id = %tenant_id,
            config_id = %config_id,
            external_subject = %claims.sub,
            "OIDC callback: token exchange successful"
        );

        // Provision or link the user.
        self.provision_or_link_user(tenant_id, config_id, &claims)
            .await
    }

    /// Exchange an authorization code for tokens at the external IdP's
    /// token endpoint.
    async fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, FederationError> {
        let response = self
            .http_client
            .post(token_endpoint)
            .timeout(std::time::Duration::from_secs(10))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .map_err(|e| {
                FederationError::TokenExchangeFailed(format!("HTTP request failed: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // Log truncated body server-side for debugging; never
            // expose the raw IdP response to the API client.
            warn!(
                status = %status,
                body_preview = %body.chars().take(200).collect::<String>(),
                "Token exchange failed with non-success status"
            );
            return Err(FederationError::TokenExchangeFailed(format!(
                "IdP returned HTTP {status}"
            )));
        }

        response.json::<TokenResponse>().await.map_err(|e| {
            FederationError::TokenExchangeFailed(format!("Failed to parse token response: {e}"))
        })
    }

    /// Decode the payload of a JWT ID token without cryptographic
    /// verification.
    ///
    /// This extracts the claims from the middle (payload) segment of the
    /// JWT. Full signature verification against the JWKS endpoint should
    /// be implemented before production use.
    fn decode_id_token_claims(id_token: &str) -> Result<IdTokenClaims, FederationError> {
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(FederationError::IdTokenValidationFailed(
                "Invalid JWT structure".into(),
            ));
        }

        // The payload is the second segment, base64url-encoded.
        use base64::Engine;
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| {
                FederationError::IdTokenValidationFailed(format!("Base64 decode failed: {e}"))
            })?;

        serde_json::from_slice::<IdTokenClaims>(&payload_bytes).map_err(|e| {
            FederationError::IdTokenValidationFailed(format!(
                "Failed to parse ID token claims: {e}"
            ))
        })
    }

    /// Provision a new user or link an existing one to the external IdP
    /// identity.
    ///
    /// If a `FederationLink` already exists for this external subject,
    /// returns the linked user. Otherwise, creates a new user and link.
    async fn provision_or_link_user(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        claims: &IdTokenClaims,
    ) -> Result<FederationCallbackResult, FederationError> {
        // Check if a link already exists for this external subject.
        let existing_link = self
            .federation_link_repo
            .get_by_external_subject(tenant_id, config_id, &claims.sub)
            .await;

        match existing_link {
            Ok(link) => {
                // Link exists — fetch the associated user.
                let user = self
                    .user_repo
                    .get_by_id(tenant_id, link.user_id)
                    .await
                    .map_err(|e| {
                        FederationError::ProvisioningFailed(format!(
                            "Failed to fetch linked user: {e}"
                        ))
                    })?;

                info!(
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    external_subject = %claims.sub,
                    "Returning existing federated user"
                );

                Ok(FederationCallbackResult {
                    user,
                    federation_link: link,
                    newly_provisioned: false,
                })
            }
            Err(AxiamError::NotFound { .. }) => {
                // No link — provision a new user.
                self.provision_new_user(tenant_id, config_id, claims).await
            }
            Err(e) => Err(FederationError::ProvisioningFailed(format!(
                "Failed to check existing federation link: {e}"
            ))),
        }
    }

    /// Create a new local user and federation link for an external IdP
    /// identity.
    async fn provision_new_user(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        claims: &IdTokenClaims,
    ) -> Result<FederationCallbackResult, FederationError> {
        // Use the external subject as the username basis, and the email
        // if available. Federated users get a random non-usable password
        // since they authenticate through the external IdP.
        let username = claims
            .name
            .clone()
            .or_else(|| claims.email.clone())
            .unwrap_or_else(|| format!("federated-{}", &claims.sub));

        let email = claims
            .email
            .clone()
            .unwrap_or_else(|| format!("{}@federated.local", claims.sub));

        // Generate a random password that cannot be used for direct
        // login. Federated users must always authenticate via their IdP.
        let random_password = Uuid::new_v4().to_string();

        let create_user = CreateUser {
            tenant_id,
            username,
            email,
            password: random_password,
            metadata: Some(serde_json::json!({
                "federation_config_id": config_id.to_string(),
                "external_subject": claims.sub,
                "provisioned_by": "oidc_federation",
            })),
        };

        let user = self.user_repo.create(create_user).await.map_err(|e| {
            FederationError::ProvisioningFailed(format!("Failed to create user: {e}"))
        })?;

        let create_link = CreateFederationLink {
            tenant_id,
            user_id: user.id,
            federation_config_id: config_id,
            external_subject: claims.sub.clone(),
            external_email: claims.email.clone(),
        };

        let link = self
            .federation_link_repo
            .create(create_link)
            .await
            .map_err(|e| {
                FederationError::ProvisioningFailed(format!(
                    "Failed to create federation link: {e}"
                ))
            })?;

        info!(
            tenant_id = %tenant_id,
            user_id = %user.id,
            external_subject = %claims.sub,
            "Provisioned new federated user"
        );

        Ok(FederationCallbackResult {
            user,
            federation_link: link,
            newly_provisioned: true,
        })
    }
}
