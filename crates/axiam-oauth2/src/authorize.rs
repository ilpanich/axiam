//! OAuth2 authorization code grant — authorization endpoint logic.

use axiam_core::models::oauth2_client::{CreateAuthorizationCode, OAuth2Client};
use axiam_core::repository::{AuthorizationCodeRepository, OAuth2ClientRepository};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::OAuth2Error;

/// Authorization request parameters (from query string).
#[derive(Debug)]
pub struct AuthorizeRequest {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// OIDC nonce — passed through to the authorization code for
    /// inclusion in the ID token.
    pub nonce: Option<String>,
}

/// Authorization response -- contains the code to return to the client.
#[derive(Debug)]
pub struct AuthorizeResponse {
    pub code: String,
    pub state: Option<String>,
    pub redirect_uri: String,
}

/// OAuth2 authorization service -- handles the authorization code grant.
#[derive(Clone)]
pub struct AuthorizeService<OC, AC> {
    client_repo: OC,
    code_repo: AC,
    code_lifetime_secs: i64,
}

impl<OC, AC> AuthorizeService<OC, AC>
where
    OC: OAuth2ClientRepository,
    AC: AuthorizationCodeRepository,
{
    pub fn new(client_repo: OC, code_repo: AC, code_lifetime_secs: i64) -> Self {
        Self {
            client_repo,
            code_repo,
            code_lifetime_secs,
        }
    }

    /// Process an authorization request, returning a code on success.
    pub async fn authorize(&self, req: AuthorizeRequest) -> Result<AuthorizeResponse, OAuth2Error> {
        // 1. Validate response_type
        if req.response_type != "code" {
            return Err(OAuth2Error::UnsupportedResponseType);
        }

        // 2. Look up client
        let client = self
            .client_repo
            .get_by_client_id(req.tenant_id, &req.client_id)
            .await
            .map_err(|_| OAuth2Error::InvalidClient("client not found".into()))?;

        // 3. Validate redirect_uri
        if !client.redirect_uris.contains(&req.redirect_uri) {
            return Err(OAuth2Error::InvalidRequest(
                "redirect_uri not registered".into(),
            ));
        }

        // 4. Validate grant type
        if !client
            .grant_types
            .contains(&"authorization_code".to_string())
        {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for authorization_code grant".into(),
            ));
        }

        // 5. Resolve scopes and validate against client's registered scopes
        let scopes = parse_scopes(req.scope.as_deref(), &client);
        if req.scope.is_some() {
            let invalid: Vec<&str> = scopes
                .iter()
                .filter(|s| !client.scopes.contains(s))
                .map(String::as_str)
                .collect();
            if !invalid.is_empty() {
                return Err(OAuth2Error::InvalidScope(format!(
                    "unregistered scopes: {}",
                    invalid.join(", ")
                )));
            }
        }

        // 6. Validate PKCE parameters
        if req.code_challenge.is_some() {
            match req.code_challenge_method.as_deref() {
                None => {
                    return Err(OAuth2Error::InvalidRequest(
                        "code_challenge_method required when \
                         code_challenge is present"
                            .into(),
                    ));
                }
                Some("S256") => {}
                Some(_) => {
                    return Err(OAuth2Error::InvalidRequest(
                        "only S256 code_challenge_method is supported".into(),
                    ));
                }
            }
        } else if req.code_challenge_method.is_some() {
            return Err(OAuth2Error::InvalidRequest(
                "code_challenge required with code_challenge_method".into(),
            ));
        }

        // 7. Generate random authorization code
        let raw_code = generate_auth_code();
        let code_hash = hash_code(&raw_code);

        // 8. Store authorization code
        let expires_at = Utc::now() + chrono::Duration::seconds(self.code_lifetime_secs);
        let _stored = self
            .code_repo
            .create(CreateAuthorizationCode {
                tenant_id: req.tenant_id,
                client_id: req.client_id,
                user_id: req.user_id,
                code_hash,
                redirect_uri: req.redirect_uri.clone(),
                scopes,
                code_challenge: req.code_challenge,
                code_challenge_method: req.code_challenge_method,
                nonce: req.nonce,
                expires_at,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(AuthorizeResponse {
            code: raw_code,
            state: req.state,
            redirect_uri: req.redirect_uri,
        })
    }
}

/// Generate a cryptographically random authorization code (32 bytes, base64url).
fn generate_auth_code() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rand::Rng::random(&mut rng);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hash of an authorization code, hex-encoded.
pub fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

/// Parse the `scope` parameter into a vec, defaulting to client's allowed scopes.
fn parse_scopes(scope: Option<&str>, client: &OAuth2Client) -> Vec<String> {
    match scope {
        Some(s) => s.split_whitespace().map(String::from).collect(),
        None => client.scopes.clone(),
    }
}
