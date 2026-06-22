//! OAuth2 authorization code grant — authorization endpoint logic.

use axiam_core::models::oauth2_client::CreateAuthorizationCode;
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
    code_lifetime_secs: u64,
}

impl<OC, AC> AuthorizeService<OC, AC>
where
    OC: OAuth2ClientRepository,
    AC: AuthorizationCodeRepository,
{
    pub fn new(client_repo: OC, code_repo: AC, code_lifetime_secs: u64) -> Self {
        Self {
            client_repo,
            code_repo,
            code_lifetime_secs,
        }
    }

    /// Process an authorization request, returning a code on success.
    pub async fn authorize(&self, req: AuthorizeRequest) -> Result<AuthorizeResponse, OAuth2Error> {
        // 1. Look up client — must happen BEFORE any redirectable
        //    errors to avoid open-redirect to unvalidated URIs.
        let client = self
            .client_repo
            .get_by_client_id(req.tenant_id, &req.client_id)
            .await
            .map_err(|_| OAuth2Error::InvalidClient("client not found".into()))?;

        // 2. Validate redirect_uri — also before any redirectable
        //    errors per RFC 6749 §4.1.2.1.
        if !client.redirect_uris.contains(&req.redirect_uri) {
            return Err(OAuth2Error::InvalidRedirectUri(
                "redirect_uri not registered".into(),
            ));
        }

        // 2b. SEC-025: Enforce PKCE for public clients.
        // A public client has no client_secret (client_secret_hash is empty).
        // Per OAuth 2.0 Security BCP §7.6 and RFC 7636, public clients MUST use PKCE.
        let is_public_client = client.client_secret_hash.is_empty();
        if is_public_client && req.code_challenge.is_none() {
            return Err(OAuth2Error::InvalidRequest(
                "PKCE (code_challenge) is required for public clients".into(),
            ));
        }

        // 3. Validate response_type (now safe to redirect errors)
        if req.response_type != "code" {
            return Err(OAuth2Error::UnsupportedResponseType);
        }

        // 4. Validate grant type
        if !client.grant_types.iter().any(|s| s == "authorization_code") {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for authorization_code grant".into(),
            ));
        }

        // 5. Resolve scopes and validate against client's registered scopes
        let scopes = parse_scopes(req.scope.as_deref());
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
        let lifetime =
            i64::try_from(self.code_lifetime_secs).expect("code_lifetime_secs exceeds i64::MAX");
        let expires_at = Utc::now() + chrono::Duration::seconds(lifetime);
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

/// Parse the `scope` parameter into a vec.
///
/// When the request omits `scope`, an empty set is returned rather
/// than the client's full registered scopes. This prevents implicit
/// granting of `openid` (and the associated ID token issuance) when
/// the client didn't explicitly request it.
fn parse_scopes(scope: Option<&str>) -> Vec<String> {
    match scope {
        Some(s) => s.split_whitespace().map(String::from).collect(),
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests — SEC-025 PKCE enforcement
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::oauth2_client::{
        AuthorizationCode, CreateAuthorizationCode, CreateOAuth2Client, OAuth2Client,
        UpdateOAuth2Client,
    };
    use axiam_core::repository::{
        AuthorizationCodeRepository, OAuth2ClientRepository, PaginatedResult, Pagination,
    };
    use chrono::Utc;
    use uuid::Uuid;

    // ---- Mock repositories ----

    #[derive(Clone)]
    struct MockClientRepo {
        client: OAuth2Client,
    }

    impl OAuth2ClientRepository for MockClientRepo {
        async fn create(&self, _input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
            unimplemented!()
        }
        async fn get_by_id(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn get_by_client_id(
            &self,
            _tenant_id: Uuid,
            _client_id: &str,
        ) -> AxiamResult<OAuth2Client> {
            Ok(self.client.clone())
        }
        async fn update(
            &self,
            _tid: Uuid,
            _id: Uuid,
            _input: UpdateOAuth2Client,
        ) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn delete(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }
        async fn list(
            &self,
            _tid: Uuid,
            _page: Pagination,
        ) -> AxiamResult<PaginatedResult<OAuth2Client>> {
            unimplemented!()
        }
    }

    #[derive(Clone)]
    struct MockCodeRepo;

    impl AuthorizationCodeRepository for MockCodeRepo {
        async fn create(&self, input: CreateAuthorizationCode) -> AxiamResult<AuthorizationCode> {
            Ok(AuthorizationCode {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                client_id: input.client_id,
                user_id: input.user_id,
                code_hash: input.code_hash,
                redirect_uri: input.redirect_uri,
                scopes: input.scopes,
                code_challenge: input.code_challenge,
                code_challenge_method: input.code_challenge_method,
                nonce: input.nonce,
                expires_at: input.expires_at,
                used: false,
                created_at: Utc::now(),
            })
        }
        async fn get_by_hash(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<AuthorizationCode> {
            unimplemented!()
        }
        async fn consume(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<AuthorizationCode> {
            unimplemented!()
        }
        async fn delete_expired(&self) -> AxiamResult<u64> {
            Ok(0)
        }
    }

    fn make_client(is_public: bool) -> OAuth2Client {
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".into(),
            // Public client has an empty secret hash; confidential has a non-empty one.
            client_secret_hash: if is_public {
                String::new()
            } else {
                "some-hash".into()
            },
            name: "Test Client".into(),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into(), "profile".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_authorize_request(
        tenant_id: Uuid,
        client: &OAuth2Client,
        code_challenge: Option<&str>,
    ) -> AuthorizeRequest {
        AuthorizeRequest {
            tenant_id,
            user_id: Uuid::new_v4(),
            response_type: "code".into(),
            client_id: client.client_id.clone(),
            redirect_uri: client.redirect_uris[0].clone(),
            scope: Some("openid".into()),
            state: Some("state-xyz".into()),
            code_challenge: code_challenge.map(String::from),
            code_challenge_method: code_challenge.map(|_| "S256".into()),
            nonce: None,
        }
    }

    // SEC-025 Case 1: public client WITHOUT code_challenge → InvalidRequest
    #[tokio::test]
    async fn authorize_public_client_without_pkce_returns_invalid_request() {
        let client = make_client(true); // public
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let req = make_authorize_request(tenant_id, &client, None);
        let result = svc.authorize(req).await;

        assert!(
            result.is_err(),
            "public client without PKCE must be rejected"
        );
        assert!(
            matches!(result.unwrap_err(), OAuth2Error::InvalidRequest(_)),
            "error must be InvalidRequest"
        );
    }

    // SEC-025 Case 2: public client WITH valid S256 code_challenge → success
    #[tokio::test]
    async fn authorize_public_client_with_s256_pkce_succeeds() {
        let client = make_client(true); // public
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        // Provide a valid S256 code_challenge (any base64url string is syntactically valid here)
        let req = make_authorize_request(
            tenant_id,
            &client,
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        );
        let result = svc.authorize(req).await;

        assert!(
            result.is_ok(),
            "public client with S256 PKCE must succeed, got: {:?}",
            result
        );
    }

    // SEC-025 Case 3: confidential client WITHOUT PKCE → success (unchanged)
    #[tokio::test]
    async fn authorize_confidential_client_without_pkce_succeeds() {
        let client = make_client(false); // confidential
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let req = make_authorize_request(tenant_id, &client, None);
        let result = svc.authorize(req).await;

        assert!(
            result.is_ok(),
            "confidential client without PKCE must still succeed, got: {:?}",
            result
        );
    }
}
