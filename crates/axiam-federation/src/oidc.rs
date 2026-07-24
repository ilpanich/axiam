//! OIDC Federation Service.
//!
//! Handles external OIDC identity provider integration: building
//! authorization URLs, exchanging authorization codes for tokens,
//! validating ID tokens with JWKS-based signature verification,
//! and provisioning or linking local users to external IdP identities.

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::federation::{CreateFederationLink, FederationLink, FederationProtocol};
use axiam_core::models::user::{CreateUser, User};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, UserRepository,
};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::discovery_cache::DiscoveryCache;
use crate::error::FederationError;
use crate::jwks_cache::JwksCache;
use crate::secrets::decrypt_client_secret_or_legacy;
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
///
/// This struct is used as the generic parameter for `jsonwebtoken::decode`.
/// `aud` is an `Option<serde_json::Value>` because OIDC allows `aud` to be
/// either a single string or an array of strings; jsonwebtoken handles the
/// audience check internally via `Validation::set_audience`.
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
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
///
/// `Clone` (QUAL-07, axiam-api-rest): hoisted `AppState<C>` singleton,
/// constructed once at startup and cloned per Actix worker.
#[derive(Clone)]
pub struct OidcFederationService<FC, FL, UR> {
    federation_config_repo: FC,
    federation_link_repo: FL,
    user_repo: UR,
    http_client: reqwest::Client,
    /// Process-wide JWKS cache (D-01/D-02/D-03).
    cache: Arc<JwksCache>,
    /// Process-wide OIDC discovery-document cache (plan A4 / CQ-B23).
    ///
    /// Not a constructor parameter — derived from `cache`'s
    /// `allow_private_networks` bit in [`OidcFederationService::new`] so
    /// every existing call site (production and the `JwksCache::new()` /
    /// `JwksCache::new_allow_private_networks()` test seam alike) gets a
    /// consistently-configured discovery cache for free, without having to
    /// thread a second constructor argument through every caller.
    discovery_cache: Arc<DiscoveryCache>,
    /// AES-256-GCM key for decrypting the federation client_secret at use-time (SEC-045).
    encryption_key: [u8; 32],
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
        cache: Arc<JwksCache>,
        encryption_key: [u8; 32],
    ) -> Self {
        // Mirror the JWKS cache's SEC-054 allow-private-networks bit onto
        // the discovery cache so both caches honor the same test seam under
        // a single injected flag (see the `discovery_cache` field doc).
        let discovery_cache = Arc::new(if cache.allow_private_networks() {
            DiscoveryCache::new_allow_private_networks()
        } else {
            DiscoveryCache::new()
        });
        Self {
            federation_config_repo,
            federation_link_repo,
            user_repo,
            http_client,
            cache,
            discovery_cache,
            encryption_key,
        }
    }

    /// Fetch and parse the OIDC discovery document from the provider.
    ///
    /// Only HTTPS URLs are accepted to mitigate SSRF risks, since the
    /// `metadata_url` originates from admin-provided configuration.
    ///
    /// CQ-B23: served from `self.discovery_cache` (1-h TTL, 24-h
    /// stale-while-revalidate) rather than fetching fresh on every call —
    /// both `build_authorization_url` and `handle_callback` call `discover`
    /// once per login, so without a cache a single login round-trip cost
    /// two full discovery fetches.
    pub async fn discover(
        &self,
        metadata_url: &str,
    ) -> Result<OidcDiscoveryDocument, FederationError> {
        // Test-only seam (mirrors `JwksCache::new_allow_private_networks`,
        // SEC-054): `self.cache`'s allow-private bit is threaded through here
        // so integration tests can point `metadata_url` at a loopback
        // wiremock IdP. `false` (the JwksCache default, and the ONLY value
        // ever produced by `JwksCache::new()` in production) preserves the
        // exact pre-existing behavior below. MUST NOT be set to `true`
        // outside of test code — production always constructs `JwksCache`
        // via `new()`.
        let allow_private = self.cache.allow_private_networks();

        if !allow_private {
            validate_metadata_url(metadata_url)?;
        }

        self.discovery_cache
            .get_or_fetch(&self.http_client, metadata_url)
            .await
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
    /// Exchanges the authorization code for tokens, cryptographically
    /// validates the ID token (JWKS signature + iss/aud/exp/nonce claims),
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

        // Decrypt the client secret at use-time (SEC-045 / D-10..D-13).
        // Supports both encrypted rows (post-backfill) and legacy plaintext
        // rows (brief deploy window before backfill runs).
        let client_secret = decrypt_client_secret_or_legacy(
            &self.encryption_key,
            config.client_secret_nonce.as_deref(),
            config.client_secret_ciphertext.as_deref(),
            &config.client_secret,
        )
        .map_err(|_| FederationError::ConfigIncomplete)?;

        // Exchange authorization code for tokens.
        let token_response = self
            .exchange_code(
                &discovery.token_endpoint,
                code,
                redirect_uri,
                &config.client_id,
                &client_secret,
            )
            .await?;

        let id_token_str = token_response.id_token.ok_or_else(|| {
            FederationError::TokenExchangeFailed("No id_token in token response".into())
        })?;

        // Cryptographically verify the ID token (D-01..D-05).
        let claims = self
            .verify_id_token(
                &id_token_str,
                &discovery,
                &config.client_id,
                &config.allowed_algorithms,
                (tenant_id, config_id),
            )
            .await?;

        // Validate nonce to prevent replay attacks.
        // TODO(plan 04-05): source nonce from federation_login_state keyed by `state`
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

        info!(
            tenant_id = %tenant_id,
            config_id = %config_id,
            external_subject = %claims.sub,
            "OIDC callback: token exchange and verification successful"
        );

        // Provision or link the user.
        self.provision_or_link_user(tenant_id, config_id, &claims)
            .await
    }

    /// Verify an OIDC ID token with full cryptographic validation.
    ///
    /// Performs in order:
    ///
    /// 1. Belt-and-suspenders raw-header `alg=none` check (D-04).
    /// 2. `decode_header` to obtain `alg` + `kid`.
    /// 3. Algorithm allow-list check against `config.allowed_algorithms` (D-04).
    /// 4. JWKS lookup via cache; forced refetch on unknown kid (D-01/D-02/D-03).
    /// 5. Full `jsonwebtoken::decode` with `iss`, `aud`, `exp`/`iat`, and 60 s leeway (D-05).
    pub async fn verify_id_token(
        &self,
        token: &str,
        discovery: &OidcDiscoveryDocument,
        client_id: &str,
        allowed_algorithms: &[String],
        cache_key: (Uuid, Uuid),
    ) -> Result<IdTokenClaims, FederationError> {
        // Step 1 — Belt-and-suspenders: reject `alg=none` by inspecting the raw
        // JOSE header before handing the token to `decode_header`.
        // `jsonwebtoken` 10 does not have an `Algorithm::None` variant and
        // `decode_header` returns `InvalidAlgorithmName` for "none", so this
        // check is defense-in-depth. Case-insensitive per RFC 7518.
        reject_alg_none_raw(token)?;

        // Step 2 — Parse the JOSE header to get `alg` and `kid`.
        let header = decode_header(token).map_err(|_| FederationError::JwtSignatureInvalid)?;

        // Step 3 — Algorithm allow-list check.
        let allowed: Vec<Algorithm> = map_algorithm_strings(allowed_algorithms);
        if !allowed.contains(&header.alg) {
            return Err(FederationError::AlgorithmNotAllowed(format!(
                "{:?}",
                header.alg
            )));
        }

        // Step 4 — Resolve JWKS from cache and find the matching JWK by kid.
        let jwks = self
            .cache
            .get_or_fetch(&self.http_client, cache_key, &discovery.jwks_uri)
            .await?;

        let jwk = find_jwk(&jwks, header.kid.as_deref());

        let jwk = if let Some(j) = jwk {
            j
        } else {
            // Unknown kid → forced refetch (rate-limited to 1 per 60 s).
            let refreshed_jwks = self
                .cache
                .force_refetch_if_allowed(&self.http_client, cache_key, &discovery.jwks_uri)
                .await?;
            find_jwk(&refreshed_jwks, header.kid.as_deref())
                .ok_or(FederationError::JwksKidUnknown)?
        };

        // Step 5 — Build the decoding key and validation parameters.
        let decoding_key =
            DecodingKey::from_jwk(&jwk).map_err(|_| FederationError::JwksKidUnknown)?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = allowed;
        validation.set_issuer(&[&discovery.issuer]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "iat"]);
        validation.leeway = 60; // REQ-5 clock-skew tolerance

        let token_data =
            decode::<IdTokenClaims>(token, &decoding_key, &validation).map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::InvalidSignature => FederationError::JwtSignatureInvalid,
                    _ => FederationError::JwtClaimRejected(e.to_string()),
                }
            })?;

        Ok(token_data.claims)
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
        // SECHRD-02: route the token-endpoint POST through the shared,
        // IP-pinning SSRF guard (D-01a/b/c) — the token endpoint comes from
        // the (already HTTPS-validated) discovery document, not just the
        // configured issuer, so it must be guarded here too.
        let form_params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];
        // Test-only seam — see `discover()`'s matching comment. `false` in
        // every production code path (`JwksCache::new()`'s default).
        let allow_private = self.cache.allow_private_networks();
        let response = crate::ssrf::guarded_fetch(token_endpoint, allow_private, |c, u| {
            c.post(u).form(&form_params)
        })
        .await
        .map_err(|e| FederationError::TokenExchangeFailed(e.to_string()))?;

        // CQ-B23: same 256 KiB cap as `discover`, enforced via a streaming,
        // running-byte-count read (`ssrf::read_capped_body`) rather than
        // buffering the whole response first — see that function's doc
        // comment for why buffer-then-check is insufficient against a
        // chunked/lying response.
        const MAX_TOKEN_RESPONSE_SIZE: usize = 256 * 1024; // 256 KiB

        if !response.status().is_success() {
            let status = response.status();
            let body_bytes = crate::ssrf::read_capped_body(response, MAX_TOKEN_RESPONSE_SIZE)
                .await
                .unwrap_or_default();
            let body = String::from_utf8_lossy(&body_bytes);
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

        let body_bytes = crate::ssrf::read_capped_body(response, MAX_TOKEN_RESPONSE_SIZE)
            .await
            .map_err(|e| match e {
                crate::ssrf::SsrfError::ResponseTooLarge(cap) => {
                    FederationError::TokenExchangeFailed(format!(
                        "Token response too large (max {cap} bytes)"
                    ))
                }
                other => FederationError::TokenExchangeFailed(format!(
                    "Failed to read token response: {other}"
                )),
            })?;

        serde_json::from_slice::<TokenResponse>(&body_bytes).map_err(|e| {
            FederationError::TokenExchangeFailed(format!("Failed to parse token response: {e}"))
        })
    }

    /// Provision a new user or link an existing one to the external IdP
    /// identity.
    async fn provision_or_link_user(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        claims: &IdTokenClaims,
    ) -> Result<FederationCallbackResult, FederationError> {
        let existing_link = self
            .federation_link_repo
            .get_by_external_subject(tenant_id, config_id, &claims.sub)
            .await;

        match existing_link {
            Ok(link) => {
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
                self.provision_new_user(tenant_id, config_id, claims).await
            }
            Err(e) => Err(FederationError::ProvisioningFailed(format!(
                "Failed to check existing federation link: {e}"
            ))),
        }
    }

    async fn provision_new_user(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        claims: &IdTokenClaims,
    ) -> Result<FederationCallbackResult, FederationError> {
        let username = claims
            .email
            .clone()
            .unwrap_or_else(|| format!("federated-{}-{}", config_id, claims.sub));

        let email = claims
            .email
            .clone()
            .unwrap_or_else(|| format!("{}.{}@federated.local", claims.sub, config_id));

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

// ---------------------------------------------------------------------------
// Private helpers (also used by unit tests via direct calls)
// ---------------------------------------------------------------------------

/// Belt-and-suspenders `alg=none` rejection (D-04).
///
/// Decodes the JOSE header from the raw JWT first segment and asserts the
/// `alg` field is not "none" (case-insensitive). `jsonwebtoken` 10 does not
/// have an `Algorithm::None` variant, but defense-in-depth mandates this
/// explicit check before `decode_header` is ever called.
pub(crate) fn reject_alg_none_raw(token: &str) -> Result<(), FederationError> {
    let first = token.split('.').next().unwrap_or("");
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(first)
        .map_err(|_| FederationError::JwtSignatureInvalid)?;
    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| FederationError::JwtSignatureInvalid)?;
    if let Some(alg) = header_json.get("alg").and_then(|v| v.as_str())
        && alg.to_lowercase() == "none"
    {
        return Err(FederationError::AlgorithmNotAllowed("none".into()));
    }
    Ok(())
}

/// Map a list of algorithm name strings to `jsonwebtoken::Algorithm` values.
///
/// Unknown strings and "none" are silently dropped, so "none" can never be
/// accidentally opted back in via the `allowed_algorithms` column.
pub(crate) fn map_algorithm_strings(names: &[String]) -> Vec<Algorithm> {
    names
        .iter()
        .filter_map(|s| match s.as_str() {
            "RS256" => Some(Algorithm::RS256),
            "RS384" => Some(Algorithm::RS384),
            "RS512" => Some(Algorithm::RS512),
            "ES256" => Some(Algorithm::ES256),
            "ES384" => Some(Algorithm::ES384),
            "EdDSA" => Some(Algorithm::EdDSA),
            "PS256" => Some(Algorithm::PS256),
            "PS384" => Some(Algorithm::PS384),
            "PS512" => Some(Algorithm::PS512),
            _ => None,
        })
        .collect()
}

/// Find a JWK by `kid` in a JWK set.
///
/// If `kid` is `None` and the set has exactly one key, returns that key
/// as a best-effort match (common for single-key IdPs).
pub(crate) fn find_jwk(
    jwks: &jsonwebtoken::jwk::JwkSet,
    kid: Option<&str>,
) -> Option<jsonwebtoken::jwk::Jwk> {
    match kid {
        Some(k) => jwks
            .keys
            .iter()
            .find(|j| j.common.key_id.as_deref() == Some(k))
            .cloned(),
        None if jwks.keys.len() == 1 => jwks.keys.first().cloned(),
        None => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::sync::Arc;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Test helpers — Ed25519 keypair (embedded, test-only)
    // -----------------------------------------------------------------------

    /// Ed25519 test private key (PKCS#8 PEM). NOT secret — test fixtures only.
    ///
    /// This is the same key used in `axiam-auth` token tests.
    const TEST_PRIV_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n\
-----END PRIVATE KEY-----";

    /// Base64url-encoded x coordinate (raw 32-byte Ed25519 public key) that
    /// corresponds to TEST_PRIV_PEM. Used to construct the test JWK.
    const TEST_PUB_X: &str = "cweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs";

    fn test_jwks() -> jsonwebtoken::jwk::JwkSet {
        let jwk_json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key-1",
                "use": "sig",
                "x": TEST_PUB_X
            }]
        });
        serde_json::from_value(jwk_json).expect("test JWK must deserialize")
    }

    fn test_enc_key() -> EncodingKey {
        EncodingKey::from_ed_pem(TEST_PRIV_PEM.as_bytes()).expect("test private key must parse")
    }

    async fn populate_cache(
        cache: Arc<JwksCache>,
        tenant_id: Uuid,
        config_id: Uuid,
        jwks: jsonwebtoken::jwk::JwkSet,
    ) {
        let mut guard = cache.0.write().await;
        guard.insert(
            (tenant_id, config_id),
            crate::jwks_cache::JwksCacheEntry {
                keys: jwks,
                fetched_at: chrono::Utc::now(),
                last_refetch_attempt: None,
            },
        );
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_claims_json(
        iss: &str,
        aud: &str,
        exp_delta: i64,
        nonce: Option<&str>,
    ) -> serde_json::Value {
        let exp = (now_secs() as i64 + exp_delta) as u64;
        let mut c = serde_json::json!({
            "sub": "user-sub-123",
            "iss": iss,
            "aud": aud,
            "exp": exp,
            "iat": now_secs()
        });
        if let Some(n) = nonce {
            c["nonce"] = serde_json::json!(n);
        }
        c
    }

    fn token_with_kid(key: &EncodingKey, claims: &serde_json::Value, kid: &str) -> String {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some(kid.to_string());
        encode(&h, claims, key).unwrap()
    }

    fn disc(iss: &str) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: iss.to_string(),
            authorization_endpoint: format!("{iss}/auth"),
            token_endpoint: format!("{iss}/token"),
            userinfo_endpoint: None,
            jwks_uri: "http://127.0.0.1:0/unreachable-jwks".to_string(),
        }
    }

    /// Invoke the core verification logic directly (without a full service).
    async fn verify(
        token: &str,
        discovery: &OidcDiscoveryDocument,
        client_id: &str,
        allowed: &[String],
        tid: Uuid,
        cid: Uuid,
        cache: Arc<JwksCache>,
    ) -> Result<IdTokenClaims, FederationError> {
        reject_alg_none_raw(token)?;
        let header = decode_header(token).map_err(|_| FederationError::JwtSignatureInvalid)?;
        let allowed_algs = map_algorithm_strings(allowed);
        if !allowed_algs.contains(&header.alg) {
            return Err(FederationError::AlgorithmNotAllowed(format!(
                "{:?}",
                header.alg
            )));
        }
        let http = reqwest::Client::new();
        let jwks = cache
            .get_or_fetch(&http, (tid, cid), &discovery.jwks_uri)
            .await?;
        let jwk = match find_jwk(&jwks, header.kid.as_deref()) {
            Some(j) => j,
            None => {
                // Unknown kid → forced refetch.
                let refreshed = cache
                    .force_refetch_if_allowed(&http, (tid, cid), &discovery.jwks_uri)
                    .await?;
                find_jwk(&refreshed, header.kid.as_deref())
                    .ok_or(FederationError::JwksKidUnknown)?
            }
        };
        let dk = DecodingKey::from_jwk(&jwk).map_err(|_| FederationError::JwksKidUnknown)?;
        let mut v = Validation::new(header.alg);
        v.algorithms = allowed_algs;
        v.set_issuer(&[&discovery.issuer]);
        v.set_audience(&[client_id]);
        v.set_required_spec_claims(&["iss", "aud", "exp", "iat"]);
        v.leeway = 60;
        decode::<IdTokenClaims>(token, &dk, &v)
            .map(|d| d.claims)
            .map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::InvalidSignature => FederationError::JwtSignatureInvalid,
                    _ => FederationError::JwtClaimRejected(e.to_string()),
                }
            })
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn verify_rejects_alg_none_in_raw_header() {
        for alg_val in ["none", "None", "NONE"] {
            let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(format!(r#"{{"alg":"{alg_val}","typ":"JWT"}}"#));
            let payload_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#);
            let token = format!("{header_b64}.{payload_b64}.");
            let result = reject_alg_none_raw(&token);
            assert!(
                matches!(result, Err(FederationError::AlgorithmNotAllowed(_))),
                "alg={alg_val} must be rejected, got: {result:?}"
            );
        }
    }

    #[test]
    fn verify_rejects_disallowed_alg() {
        // allowed_algorithms = ["RS256"], but token is EdDSA.
        // map_algorithm_strings drops EdDSA when the list only has RS256.
        let allowed = vec!["RS256".to_string()];
        let allowed_algs = map_algorithm_strings(&allowed);
        assert!(!allowed_algs.contains(&Algorithm::EdDSA));

        let key = test_enc_key();
        let claims = make_claims_json("https://idp.example.com", "client-abc", 300, None);
        let token = token_with_kid(&key, &claims, "test-key-1");

        // decode_header succeeds, but alg check fails.
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert!(
            !allowed_algs.contains(&header.alg),
            "EdDSA should not be in RS256-only allow list"
        );
    }

    #[tokio::test]
    async fn verify_rejects_wrong_iss() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let key = test_enc_key();
        // iss = evil, but discovery says good.
        let claims = make_claims_json("https://evil.example.com", "client-abc", 300, Some("n1"));
        let token = token_with_kid(&key, &claims, "test-key-1");

        let d = disc("https://good.example.com");
        let result = verify(
            &token,
            &d,
            "client-abc",
            &["EdDSA".to_string()],
            tid,
            cid,
            cache,
        )
        .await;
        assert!(
            matches!(result, Err(FederationError::JwtClaimRejected(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_wrong_aud() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let key = test_enc_key();
        let claims = make_claims_json("https://idp.example.com", "other-client", 300, Some("n1"));
        let token = token_with_kid(&key, &claims, "test-key-1");

        let d = disc("https://idp.example.com");
        let result = verify(
            &token,
            &d,
            "client-abc",
            &["EdDSA".to_string()],
            tid,
            cid,
            cache,
        )
        .await;
        assert!(
            matches!(result, Err(FederationError::JwtClaimRejected(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_expired() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let key = test_enc_key();
        // exp = now - 120s (outside 60s leeway).
        let claims = make_claims_json("https://idp.example.com", "client-abc", -120, Some("n1"));
        let token = token_with_kid(&key, &claims, "test-key-1");

        let d = disc("https://idp.example.com");
        let result = verify(
            &token,
            &d,
            "client-abc",
            &["EdDSA".to_string()],
            tid,
            cid,
            cache,
        )
        .await;
        assert!(
            matches!(result, Err(FederationError::JwtClaimRejected(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn verify_accepts_within_60s_skew() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let key = test_enc_key();
        // exp = now - 30s — within 60s leeway.
        let claims = make_claims_json("https://idp.example.com", "client-abc", -30, Some("n1"));
        let token = token_with_kid(&key, &claims, "test-key-1");

        let d = disc("https://idp.example.com");
        let result = verify(
            &token,
            &d,
            "client-abc",
            &["EdDSA".to_string()],
            tid,
            cid,
            cache,
        )
        .await;
        assert!(
            result.is_ok(),
            "token within 60s leeway must be accepted: {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_unknown_kid_after_forced_refetch() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();

        // Cache has kid="known-key" but token uses kid="unknown-kid".
        let jwk_json = serde_json::json!({
            "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "known-key",
                        "use": "sig", "x": TEST_PUB_X }]
        });
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwk_json).unwrap();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, jwks).await;

        let key = test_enc_key();
        let claims = make_claims_json("https://idp.example.com", "client-abc", 300, Some("n1"));

        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("unknown-kid".to_string());
        let token = encode(&h, &claims, &key).unwrap();

        let d = OidcDiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/auth".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: None,
            // Unreachable — forced refetch will fail, returning JwksKidUnknown.
            jwks_uri: "http://127.0.0.1:0/unreachable-jwks".to_string(),
        };

        let result = verify(
            &token,
            &d,
            "client-abc",
            &["EdDSA".to_string()],
            tid,
            cid,
            cache,
        )
        .await;
        assert!(
            matches!(result, Err(FederationError::JwksKidUnknown)),
            "unknown kid after forced refetch must return JwksKidUnknown: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // CQ-B23: DiscoveryCache wired into `discover()` (plan A4)
    // -----------------------------------------------------------------------

    /// Build a real `OidcFederationService` backed by an in-memory,
    /// unconfigured SurrealDB instance. `discover()` never touches the
    /// repos, only `self.http_client` + `self.discovery_cache`, so a real
    /// (but empty) DB is sufficient purely for construction — mirrors
    /// `axiam-server`'s `req5_oidc_e2e.rs::make_oidc_svc` helper.
    async fn make_test_service(
        cache: Arc<JwksCache>,
    ) -> OidcFederationService<
        axiam_db::SurrealFederationConfigRepository<surrealdb::engine::local::Db>,
        axiam_db::SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
        axiam_db::SurrealUserRepository<surrealdb::engine::local::Db>,
    > {
        use surrealdb::Surreal;
        use surrealdb::engine::local::Mem;

        let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("http client");

        OidcFederationService::new(
            axiam_db::SurrealFederationConfigRepository::new(db.clone()),
            axiam_db::SurrealFederationLinkRepository::new(db.clone()),
            axiam_db::SurrealUserRepository::new(db.clone()),
            http_client,
            cache,
            [0u8; 32], // gitleaks:allow
        )
    }

    /// CQ-B23: a second `discover()` call for the same `metadata_url` within
    /// the 1-h TTL must be served from the `DiscoveryCache` — the mock
    /// discovery endpoint must receive exactly ONE request across both
    /// calls. This exercises the full `discover()` wiring (not just the
    /// isolated `DiscoveryCache` unit tests in `discovery_cache.rs`),
    /// proving `build_authorization_url`/`handle_callback` no longer each
    /// pay for their own fetch.
    ///
    /// Uses the same `allow_private_networks` wiremock seam as the
    /// `JwksCache` tests elsewhere in this crate (`JwksCache::
    /// new_allow_private_networks`), which `OidcFederationService::new`
    /// mirrors onto the internal `DiscoveryCache` automatically.
    #[tokio::test]
    async fn discover_second_call_within_ttl_does_not_refetch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        let doc_json = serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc_json))
            // MUST be hit exactly once across BOTH `discover()` calls below —
            // wiremock panics on drop if this expectation is not met exactly.
            .expect(1)
            .mount(&server)
            .await;

        let cache = Arc::new(JwksCache::new_allow_private_networks());
        let svc = make_test_service(cache).await;
        let metadata_url = format!("{base}/.well-known/openid-configuration");

        let first = svc
            .discover(&metadata_url)
            .await
            .expect("first discover() must succeed");
        let second = svc
            .discover(&metadata_url)
            .await
            .expect("second discover() must be served from cache, not error");

        assert_eq!(first.issuer, second.issuer);
        assert_eq!(second.jwks_uri, format!("{base}/jwks"));

        // Explicit verification (in addition to the Drop-time check) so a
        // failure here fails loudly at this line rather than shows up as a
        // late panic-during-drop.
        server.verify().await;
    }

    // -----------------------------------------------------------------------
    // R5 additions — provisioning / account-linking + token-exchange error arms
    //
    // These use lightweight stateful stub repos (no SurrealDB needed) to drive
    // the private `provision_or_link_user` / `provision_new_user` branches, and
    // `wiremock` (via the `allow_private_networks` seam) to drive the
    // `exchange_code` error arms.
    // -----------------------------------------------------------------------

    use axiam_core::error::{AxiamError, AxiamResult};
    use axiam_core::models::federation::{
        CreateFederationConfig, FederationConfig, UpdateFederationConfig,
    };
    use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
    use axiam_core::repository::{PaginatedResult, Pagination};
    use std::sync::Mutex;

    struct StubConfigRepo;
    impl FederationConfigRepository for StubConfigRepo {
        async fn create(&self, _: CreateFederationConfig) -> AxiamResult<FederationConfig> {
            unimplemented!()
        }
        async fn get_by_id(&self, _: Uuid, _: Uuid) -> AxiamResult<FederationConfig> {
            unimplemented!()
        }
        async fn update(
            &self,
            _: Uuid,
            _: Uuid,
            _: UpdateFederationConfig,
        ) -> AxiamResult<FederationConfig> {
            unimplemented!()
        }
        async fn delete(&self, _: Uuid, _: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }
        async fn list(
            &self,
            _: Uuid,
            _: Pagination,
        ) -> AxiamResult<PaginatedResult<FederationConfig>> {
            unimplemented!()
        }
        async fn list_with_legacy_plaintext_secret(&self) -> AxiamResult<Vec<FederationConfig>> {
            unimplemented!()
        }
        async fn set_encrypted_secret(
            &self,
            _: Uuid,
            _: Uuid,
            _: String,
            _: String,
            _: i64,
        ) -> AxiamResult<()> {
            unimplemented!()
        }
    }

    struct StubLinkRepo {
        existing: Option<FederationLink>,
        get_returns_db_error: bool,
        fail_create: bool,
        created: Mutex<Vec<CreateFederationLink>>,
    }
    impl StubLinkRepo {
        fn provisioning() -> Self {
            Self {
                existing: None,
                get_returns_db_error: false,
                fail_create: false,
                created: Mutex::new(Vec::new()),
            }
        }
    }
    impl FederationLinkRepository for StubLinkRepo {
        async fn create(&self, input: CreateFederationLink) -> AxiamResult<FederationLink> {
            if self.fail_create {
                return Err(AxiamError::Database("link create boom".into()));
            }
            let link = FederationLink {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                user_id: input.user_id,
                federation_config_id: input.federation_config_id,
                external_subject: input.external_subject.clone(),
                external_email: input.external_email.clone(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            self.created.lock().unwrap().push(input);
            Ok(link)
        }
        async fn get_by_external_subject(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
        ) -> AxiamResult<FederationLink> {
            if self.get_returns_db_error {
                return Err(AxiamError::Database("link lookup boom".into()));
            }
            self.existing.clone().ok_or(AxiamError::NotFound {
                entity: "federation_link".into(),
                id: "no-link".into(),
            })
        }
        async fn get_by_user_id(&self, _: Uuid, _: Uuid) -> AxiamResult<Vec<FederationLink>> {
            unimplemented!()
        }
        async fn delete(&self, _: Uuid, _: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }
    }

    struct StubUserRepo {
        preset: Option<User>,
        fail_create: bool,
        created: Mutex<Vec<CreateUser>>,
    }
    impl StubUserRepo {
        fn provisioning() -> Self {
            Self {
                preset: None,
                fail_create: false,
                created: Mutex::new(Vec::new()),
            }
        }
    }
    impl UserRepository for StubUserRepo {
        async fn create(&self, input: CreateUser) -> AxiamResult<User> {
            if self.fail_create {
                return Err(AxiamError::Database("user create boom".into()));
            }
            let user = User {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                username: input.username.clone(),
                email: input.email.clone(),
                password_hash: "x".into(),
                status: UserStatus::Active,
                mfa_enabled: false,
                mfa_secret: None,
                totp_last_used_step: None,
                failed_login_attempts: 0,
                last_failed_login_at: None,
                locked_until: None,
                email_verified_at: None,
                deletion_pending: false,
                scheduled_purge_at: None,
                metadata: input.metadata.clone().unwrap_or(serde_json::Value::Null),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            self.created.lock().unwrap().push(input);
            Ok(user)
        }
        async fn get_by_id(&self, _: Uuid, _: Uuid) -> AxiamResult<User> {
            self.preset.clone().ok_or(AxiamError::NotFound {
                entity: "user".into(),
                id: "no-user".into(),
            })
        }
        async fn get_by_username(&self, _: Uuid, _: &str) -> AxiamResult<User> {
            unimplemented!()
        }
        async fn get_by_email(&self, _: Uuid, _: &str) -> AxiamResult<User> {
            unimplemented!()
        }
        async fn update(&self, _: Uuid, _: Uuid, _: UpdateUser) -> AxiamResult<User> {
            unimplemented!()
        }
        async fn delete(&self, _: Uuid, _: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }
        async fn update_totp_step(&self, _: Uuid, _: Uuid, _: u64) -> AxiamResult<bool> {
            unimplemented!()
        }
        async fn list(&self, _: Uuid, _: Pagination) -> AxiamResult<PaginatedResult<User>> {
            unimplemented!()
        }
        async fn increment_failed_logins(
            &self,
            _: Uuid,
            _: Uuid,
            _: u32,
            _: i64,
            _: f64,
            _: i64,
        ) -> AxiamResult<()> {
            unimplemented!()
        }
        async fn anonymize_user(&self, _: Uuid, _: Uuid, _: &str, _: &str) -> AxiamResult<()> {
            unimplemented!()
        }
    }

    type StubService = OidcFederationService<StubConfigRepo, StubLinkRepo, StubUserRepo>;

    fn make_stub_service(
        link: StubLinkRepo,
        user: StubUserRepo,
        cache: Arc<JwksCache>,
    ) -> StubService {
        OidcFederationService::new(
            StubConfigRepo,
            link,
            user,
            reqwest::Client::new(),
            cache,
            [0u8; 32], // gitleaks:allow
        )
    }

    fn claims_with(email: Option<&str>) -> IdTokenClaims {
        IdTokenClaims {
            sub: "external-sub-1".into(),
            iss: Some("https://idp.example.com".into()),
            aud: None,
            exp: None,
            iat: None,
            email: email.map(String::from),
            email_verified: Some(true),
            name: Some("Test User".into()),
            nonce: None,
        }
    }

    // ----- provisioning -----

    #[tokio::test]
    async fn provision_new_user_uses_email_for_username_and_email() {
        let tenant = Uuid::new_v4();
        let cfg = Uuid::new_v4();
        let svc = make_stub_service(
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new()),
        );
        let claims = claims_with(Some("alice@example.com"));
        let result = svc
            .provision_or_link_user(tenant, cfg, &claims)
            .await
            .expect("provisioning should succeed");
        assert!(result.newly_provisioned);
        assert_eq!(result.user.username, "alice@example.com");
        assert_eq!(result.user.email, "alice@example.com");
        assert_eq!(result.federation_link.external_subject, "external-sub-1");
        assert_eq!(
            result.federation_link.external_email.as_deref(),
            Some("alice@example.com")
        );
    }

    #[tokio::test]
    async fn provision_new_user_without_email_synthesizes_identifiers() {
        let tenant = Uuid::new_v4();
        let cfg = Uuid::new_v4();
        let svc = make_stub_service(
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new()),
        );
        let claims = claims_with(None);
        let result = svc
            .provision_or_link_user(tenant, cfg, &claims)
            .await
            .expect("provisioning without email should succeed");
        assert!(result.newly_provisioned);
        assert_eq!(
            result.user.username,
            format!("federated-{cfg}-external-sub-1")
        );
        assert_eq!(
            result.user.email,
            format!("external-sub-1.{cfg}@federated.local")
        );
        assert!(result.federation_link.external_email.is_none());
    }

    #[tokio::test]
    async fn provision_returns_existing_link_without_reprovisioning() {
        let tenant = Uuid::new_v4();
        let cfg = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let preset_user = User {
            id: user_id,
            tenant_id: tenant,
            username: "existing".into(),
            email: "existing@example.com".into(),
            password_hash: "x".into(),
            status: UserStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            totp_last_used_step: None,
            failed_login_attempts: 0,
            last_failed_login_at: None,
            locked_until: None,
            email_verified_at: None,
            deletion_pending: false,
            scheduled_purge_at: None,
            metadata: serde_json::Value::Null,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let link = StubLinkRepo {
            existing: Some(FederationLink {
                id: Uuid::new_v4(),
                tenant_id: tenant,
                user_id,
                federation_config_id: cfg,
                external_subject: "external-sub-1".into(),
                external_email: Some("existing@example.com".into()),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }),
            get_returns_db_error: false,
            fail_create: false,
            created: Mutex::new(Vec::new()),
        };
        let user = StubUserRepo {
            preset: Some(preset_user),
            fail_create: false,
            created: Mutex::new(Vec::new()),
        };
        let svc = make_stub_service(link, user, Arc::new(JwksCache::new()));
        let result = svc
            .provision_or_link_user(tenant, cfg, &claims_with(Some("x@example.com")))
            .await
            .expect("existing link should resolve");
        assert!(!result.newly_provisioned);
        assert_eq!(result.user.id, user_id);
    }

    #[tokio::test]
    async fn provision_maps_link_lookup_db_error_to_provisioning_failed() {
        let link = StubLinkRepo {
            existing: None,
            get_returns_db_error: true,
            fail_create: false,
            created: Mutex::new(Vec::new()),
        };
        let svc = make_stub_service(
            link,
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .provision_or_link_user(
                Uuid::new_v4(),
                Uuid::new_v4(),
                &claims_with(Some("a@b.com")),
            )
            .await
            .expect_err("a non-NotFound lookup error must surface");
        assert!(
            matches!(err, FederationError::ProvisioningFailed(ref m) if m.contains("existing federation link")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn provision_user_create_failure_maps_to_provisioning_failed() {
        let user = StubUserRepo {
            preset: None,
            fail_create: true,
            created: Mutex::new(Vec::new()),
        };
        let svc = make_stub_service(
            StubLinkRepo::provisioning(),
            user,
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .provision_or_link_user(
                Uuid::new_v4(),
                Uuid::new_v4(),
                &claims_with(Some("a@b.com")),
            )
            .await
            .expect_err("user create failure must surface");
        assert!(
            matches!(err, FederationError::ProvisioningFailed(ref m) if m.contains("create user")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn provision_link_create_failure_maps_to_provisioning_failed() {
        let link = StubLinkRepo {
            existing: None,
            get_returns_db_error: false,
            fail_create: true,
            created: Mutex::new(Vec::new()),
        };
        let svc = make_stub_service(
            link,
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .provision_or_link_user(
                Uuid::new_v4(),
                Uuid::new_v4(),
                &claims_with(Some("a@b.com")),
            )
            .await
            .expect_err("link create failure must surface");
        assert!(
            matches!(err, FederationError::ProvisioningFailed(ref m) if m.contains("federation link")),
            "got: {err:?}"
        );
    }

    // ----- exchange_code error arms (wiremock) -----

    #[tokio::test]
    async fn exchange_code_non_success_status_maps_to_token_exchange_failed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid_grant"))
            .mount(&server)
            .await;

        let svc = make_stub_service(
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let endpoint = format!("{}/token", server.uri());
        let err = svc
            .exchange_code(&endpoint, "code", "https://rp/cb", "cid", "secret")
            .await
            .expect_err("HTTP 400 from token endpoint must fail");
        // WHY: the raw IdP body is never leaked; the client sees the status only.
        assert!(
            matches!(err, FederationError::TokenExchangeFailed(ref m) if m.contains("400")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn exchange_code_invalid_json_maps_to_token_exchange_failed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json-at-all"))
            .mount(&server)
            .await;

        let svc = make_stub_service(
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let endpoint = format!("{}/token", server.uri());
        let err = svc
            .exchange_code(&endpoint, "code", "https://rp/cb", "cid", "secret")
            .await
            .expect_err("unparseable token body must fail");
        assert!(
            matches!(err, FederationError::TokenExchangeFailed(ref m) if m.contains("parse")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn exchange_code_success_returns_id_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = serde_json::json!({
            "access_token": "at",
            "id_token": "the-id-token",
            "token_type": "Bearer",
            "expires_in": 3600
        });
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let svc = make_stub_service(
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let endpoint = format!("{}/token", server.uri());
        let tokens = svc
            .exchange_code(&endpoint, "code", "https://rp/cb", "cid", "secret")
            .await
            .expect("valid token response should parse");
        assert_eq!(tokens.id_token.as_deref(), Some("the-id-token"));
    }
}
