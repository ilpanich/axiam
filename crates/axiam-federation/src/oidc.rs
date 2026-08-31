//! OIDC Federation Service.
//!
//! Handles external OIDC identity provider integration: building
//! authorization URLs, exchanging authorization codes for tokens,
//! validating ID tokens with JWKS-based signature verification,
//! and provisioning or linking local users to external IdP identities.

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::federation::{
    CreateFederationLink, FederationConfig, FederationLink, FederationProtocol, ProviderKind,
};
use axiam_core::models::federation_claims::{MappedIdentity, map_identity};
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
// X4: the unverified-issuer reader is shared with `axiam-oauth2`'s exchange
// grant, so it lives in `axiam-auth` (the crate both depend on) rather than
// being written twice. Re-exported here so this crate's own call sites and
// tests keep referring to it by the module they use.
use crate::validate_metadata_url;
pub use axiam_auth::token::unverified_issuer_of;

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

/// A verified ID token: the typed claims AXIAM needs, plus the full claim
/// object an operator's `attribute_map` may name.
///
/// Both come from one `decode` call, so there is no path by which a mapped
/// value comes from a token whose signature was not checked.
#[derive(Debug, Clone)]
pub struct VerifiedIdToken {
    /// The claims AXIAM itself reads.
    pub claims: IdTokenClaims,
    /// Every verified claim, as sent.
    pub raw: serde_json::Value,
}

/// Merge provider-supplied, **unsigned** values under a verified claim set.
///
/// Apple is why this exists: the user's name arrives once, in a form field of
/// the `response_mode=form_post` callback, and never in the ID token. The merge
/// is deliberately one-directional — an existing verified claim is never
/// overwritten — so an attacker who can shape the form POST cannot restate a
/// claim the signature already fixed.
fn merge_unsigned_claims(verified: &mut serde_json::Value, unsigned: &serde_json::Value) {
    let (Some(target), Some(source)) = (verified.as_object_mut(), unsigned.as_object()) else {
        return;
    };
    for (key, value) in source {
        // `sub`, `iss`, `aud`, `exp` and every other signed claim are already
        // present and therefore untouchable. Only genuinely absent keys can be
        // contributed.
        target.entry(key.clone()).or_insert_with(|| value.clone());
    }
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

    // ------------------------------------------------------------------
    // Collaborator accessors (X4)
    // ------------------------------------------------------------------
    //
    // The external token-exchange path lives in a sibling module and needs the
    // same collaborators this one already owns. Exposing them `pub(crate)`
    // beats a second service with its own copies: two JWKS caches would mean
    // two rollover states, and two federation-link repositories would mean two
    // answers to "which user is this".

    pub(crate) fn jwks_cache(&self) -> &JwksCache {
        &self.cache
    }

    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    pub(crate) fn federation_config_repo_ref(&self) -> &FC {
        &self.federation_config_repo
    }

    pub(crate) fn federation_link_repo_ref(&self) -> &FL {
        &self.federation_link_repo
    }

    pub(crate) fn user_repo_ref(&self) -> &UR {
        &self.user_repo
    }

    /// The test-only allow-private-networks seam, read once here so the OAuth2
    /// path reaches it the same way `discover` does rather than growing a
    /// second copy of the reasoning. `false` in every production code path.
    pub(crate) fn allow_private_networks(&self) -> bool {
        self.cache.allow_private_networks()
    }

    /// The AES-256-GCM key used to decrypt a stored client secret at use time
    /// (SEC-045). Borrowed rather than copied so no call site can accidentally
    /// keep one alive past the request that needed it.
    pub(crate) fn encryption_key_ref(&self) -> &[u8; 32] {
        &self.encryption_key
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
        let config = self.load_config(tenant_id, config_id).await?;
        self.build_authorization_url_for(&config, redirect_uri, state, nonce, None)
            .await
    }

    /// Fetch a config, mapping the repository's `NotFound` onto this crate's.
    ///
    /// One helper rather than the same six-line `map_err` at four call sites:
    /// a config that is missing and a config whose tenant does not match are
    /// the same answer here, and they must stay the same answer.
    pub(crate) async fn load_config(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<FederationConfig, FederationError> {
        self.federation_config_repo
            .get_by_id(tenant_id, config_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { id, .. } => FederationError::ConfigNotFound(id),
                other => FederationError::Internal(other.to_string()),
            })
    }

    /// Build the OIDC authorization URL from an already-resolved config.
    ///
    /// Split from [`OidcFederationService::build_authorization_url`] because a
    /// config may be **inherited**: it can live in the organization-scope
    /// tenant while the login is for one of that organization's tenants, and a
    /// `get_by_id(requesting_tenant, id)` cannot find it. The REST layer
    /// resolves it once and hands it here.
    ///
    /// `pkce_challenge` is `Some` when the config opts into PKCE. On this path
    /// it is an addition to the server-side `nonce`, not a replacement for it —
    /// see [`crate::pkce`] for why it is opt-in here and mandatory on the
    /// OAuth2 path.
    pub async fn build_authorization_url_for(
        &self,
        config: &FederationConfig,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        pkce_challenge: Option<&str>,
    ) -> Result<AuthorizationUrl, FederationError> {
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

        // Per-config scopes, defaulting per kind. This used to be the literal
        // string "openid email profile", which is why Apple could not work: it
        // rejects `profile` and wants `name email`.
        let scopes = config.effective_scopes().join(" ");

        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce);

        if let Some(challenge) = pkce_challenge {
            auth_url
                .query_pairs_mut()
                .append_pair("code_challenge", challenge)
                .append_pair("code_challenge_method", crate::pkce::CHALLENGE_METHOD);
        }

        // Apple returns the authorization code by cross-site form POST whenever
        // `name` or `email` is requested, and returns the user's name *only* in
        // that POST. Setting it explicitly rather than relying on Apple's
        // inference keeps the callback route AXIAM registers and the response
        // mode Apple uses from drifting apart.
        if config.provider_kind == ProviderKind::Apple {
            auth_url
                .query_pairs_mut()
                .append_pair("response_mode", "form_post");
        }

        let url = auth_url.to_string();

        info!(
            tenant_id = %config.tenant_id,
            config_id = %config.id,
            provider = %config.provider,
            provider_kind = %config.provider_kind.as_str(),
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
        let config = self.load_config(tenant_id, config_id).await?;
        self.handle_callback_for(
            &config,
            tenant_id,
            code,
            redirect_uri,
            expected_nonce,
            None,
            None,
        )
        .await
    }

    /// Complete an OIDC login from an already-resolved config.
    ///
    /// `requesting_tenant_id` is where the user and the federation link are
    /// created, and it is **not** necessarily `config.tenant_id`: an inherited
    /// organization-level provider signs people into the tenant they asked for,
    /// not into the organization scope the config lives in. Getting this
    /// backwards would put every tenant's federated users in one shared tenant.
    ///
    /// `extra_claims` carries data a provider sends *outside* the ID token.
    /// Apple is the reason it exists: the user's name arrives once, in a form
    /// field of the `response_mode=form_post` callback, and never again. Values
    /// there are merged **under** the ID token's, so a signed claim always wins
    /// over an unsigned form field.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_callback_for(
        &self,
        config: &FederationConfig,
        requesting_tenant_id: Uuid,
        code: &str,
        redirect_uri: &str,
        expected_nonce: &str,
        code_verifier: Option<&str>,
        extra_claims: Option<&serde_json::Value>,
    ) -> Result<FederationCallbackResult, FederationError> {
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
        let stored_secret = decrypt_client_secret_or_legacy(
            &self.encryption_key,
            config.client_secret_nonce.as_deref(),
            config.client_secret_ciphertext.as_deref(),
            &config.client_secret,
        )
        .map_err(|_| FederationError::ConfigIncomplete)?;

        // Apple's client secret is an ES256 JWT that expires, not a string.
        // What was decrypted above is then the `.p8` private key, and the
        // secret is minted fresh here with a five-minute life — see
        // `crate::apple` for why this is minted rather than stored.
        let client_secret = if config.mints_client_secret() {
            crate::apple::mint_client_secret(
                config.apple_team_id.as_deref().unwrap_or_default(),
                config.apple_key_id.as_deref().unwrap_or_default(),
                &config.client_id,
                &stored_secret,
            )?
        } else {
            stored_secret
        };

        // Exchange authorization code for tokens.
        let token_response = self
            .exchange_code_with_pkce(
                &discovery.token_endpoint,
                code,
                redirect_uri,
                &config.client_id,
                &client_secret,
                code_verifier,
            )
            .await?;

        let id_token_str = token_response.id_token.ok_or_else(|| {
            FederationError::TokenExchangeFailed("No id_token in token response".into())
        })?;

        // Cryptographically verify the ID token (D-01..D-05), resolving a
        // templated issuer against the config's accepted tenants (§6).
        let verified = self
            .verify_id_token_full(
                &id_token_str,
                &discovery,
                &config.client_id,
                &config.allowed_algorithms,
                &config.allowed_issuer_tenants,
                (config.tenant_id, config.id),
            )
            .await?;
        let claims = verified.claims;

        // Validate nonce to prevent replay attacks. The expected value comes
        // from the server-side `federation_login_state` row, never from the
        // caller (SECHRD-07/D-04).
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
            tenant_id = %requesting_tenant_id,
            config_id = %config.id,
            external_subject = %claims.sub,
            "OIDC callback: token exchange and verification successful"
        );

        // Apply the configured attribute map to the *verified* claim set. The
        // raw object is used rather than the typed `IdTokenClaims` so an
        // operator can map a claim AXIAM has no field for.
        let mut merged = verified.raw;
        if let Some(extra) = extra_claims {
            merge_unsigned_claims(&mut merged, extra);
        }
        let identity = map_identity(config.provider_kind, &config.attribute_map, &merged)
            .ok_or_else(|| {
                FederationError::IdTokenValidationFailed(
                    "no external subject could be mapped from the ID token".into(),
                )
            })?;

        self.provision_or_link_identity(requesting_tenant_id, config.id, &identity)
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
        self.verify_id_token_full(
            token,
            discovery,
            client_id,
            allowed_algorithms,
            // No templated-issuer allow-list: this entry point is for a
            // provider whose discovery document names a concrete issuer, and
            // `resolve_expected_issuer` refuses a templated one with an empty
            // list rather than accepting anyone.
            &[],
            cache_key,
        )
        .await
        .map(|v| v.claims)
    }

    /// [`OidcFederationService::verify_id_token`], plus the raw verified claim
    /// object and templated-issuer resolution.
    ///
    /// The raw object is what makes `attribute_map` able to name a claim AXIAM
    /// has no typed field for; it is produced by the *same* `decode` call that
    /// checks the signature, so there is no path by which a mapped value comes
    /// from an unverified token.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_id_token_full(
        &self,
        token: &str,
        discovery: &OidcDiscoveryDocument,
        client_id: &str,
        allowed_algorithms: &[String],
        allowed_issuer_tenants: &[String],
        cache_key: (Uuid, Uuid),
    ) -> Result<VerifiedIdToken, FederationError> {
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

        // Step 5a — Resolve the issuer to require. For every provider that
        // publishes a concrete one this is the discovered string unchanged; for
        // Entra's `common` authority it substitutes the token's `tid`, which
        // must appear in the config's allow-list. See `crate::issuer`.
        let expected_issuer = crate::issuer::resolve_expected_issuer(
            &discovery.issuer,
            token,
            allowed_issuer_tenants,
        )?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = allowed;
        validation.set_issuer(&[&expected_issuer]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "iat"]);
        validation.leeway = 60; // REQ-5 clock-skew tolerance

        // Decoded as an open object, then narrowed. One `decode` call, so the
        // typed claims and the raw map are the same verified bytes — decoding
        // twice would leave room for them to disagree.
        let token_data =
            decode::<serde_json::Value>(token, &decoding_key, &validation).map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::InvalidSignature => FederationError::JwtSignatureInvalid,
                    _ => FederationError::JwtClaimRejected(e.to_string()),
                }
            })?;

        let raw = token_data.claims;
        let claims: IdTokenClaims = serde_json::from_value(raw.clone()).map_err(|e| {
            FederationError::JwtClaimRejected(format!("ID token claims are not usable: {e}"))
        })?;

        Ok(VerifiedIdToken { claims, raw })
    }

    /// Exchange an authorization code for tokens at the external IdP's
    /// token endpoint.
    #[allow(dead_code)]
    async fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, FederationError> {
        self.exchange_code_with_pkce(
            token_endpoint,
            code,
            redirect_uri,
            client_id,
            client_secret,
            None,
        )
        .await
    }

    /// [`OidcFederationService::exchange_code`], echoing a PKCE verifier when
    /// the config opted into one.
    #[allow(clippy::too_many_arguments)]
    async fn exchange_code_with_pkce(
        &self,
        token_endpoint: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, FederationError> {
        // SECHRD-02: route the token-endpoint POST through the shared,
        // IP-pinning SSRF guard (D-01a/b/c) — the token endpoint comes from
        // the (already HTTPS-validated) discovery document, not just the
        // configured issuer, so it must be guarded here too.
        let mut form_params: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];
        if let Some(verifier) = code_verifier.filter(|v| !v.trim().is_empty()) {
            form_params.push(("code_verifier", verifier));
        }
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
    ///
    /// `pub(crate)` since X4: the external token-exchange path
    /// ([`crate::token_exchange`]) resolves its subject through **this exact
    /// function** rather than a parallel one, so a partner token and a browser
    /// login can never disagree about which AXIAM user an `(issuer, sub)` pair
    /// means, and the JIT provisioning rules are written down once.
    pub(crate) async fn provision_or_link_user(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        claims: &IdTokenClaims,
    ) -> Result<FederationCallbackResult, FederationError> {
        // The X4 exchange path has typed claims and no config in hand, so it
        // gets the standard OIDC mapping — which is exactly what this function
        // did before `attribute_map` was applied anywhere.
        let identity = MappedIdentity {
            external_subject: claims.sub.clone(),
            username: claims.email.clone(),
            email: claims.email.clone(),
            email_verified: claims.email_verified.unwrap_or(false),
            display_name: claims.name.clone(),
        };
        self.provision_or_link_identity(tenant_id, config_id, &identity)
            .await
    }

    /// Resolve a mapped external identity to an AXIAM user, provisioning one on
    /// first sight.
    ///
    /// `tenant_id` is the tenant the user belongs to — the **requesting**
    /// tenant, which for an inherited organization-level provider is not the
    /// tenant the config lives in. `config_id` is the provider's id either way,
    /// so the `(tenant_id, federation_config_id, external_subject)` uniqueness
    /// index means "one link per external identity per tenant", and the same
    /// Google account signing into two tenants through one inherited config
    /// gets two AXIAM users. That is correct rather than a defect: tenants are
    /// data-isolation boundaries, and one user row spanning two of them would
    /// be the actual bug.
    pub(crate) async fn provision_or_link_identity(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        identity: &MappedIdentity,
    ) -> Result<FederationCallbackResult, FederationError> {
        let existing_link = self
            .federation_link_repo
            .get_by_external_subject(tenant_id, config_id, &identity.external_subject)
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
                    external_subject = %identity.external_subject,
                    "Returning existing federated user"
                );

                Ok(FederationCallbackResult {
                    user,
                    federation_link: link,
                    newly_provisioned: false,
                })
            }
            Err(AxiamError::NotFound { .. }) => {
                self.provision_new_user(tenant_id, config_id, identity)
                    .await
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
        identity: &MappedIdentity,
    ) -> Result<FederationCallbackResult, FederationError> {
        // The fallbacks are unchanged from before `attribute_map` was applied,
        // and with an empty map the mapped values are the same ones this used
        // to read directly — so an existing config provisions identically.
        let username = identity
            .username
            .clone()
            .unwrap_or_else(|| format!("federated-{}-{}", config_id, identity.external_subject));

        let email = identity.email.clone().unwrap_or_else(|| {
            format!(
                "{}.{}@federated.local",
                identity.external_subject, config_id
            )
        });

        // Deliberately v4, not `new_id()`: a non-usable password must still be
        // unguessable, and v7 trades randomness for a sortable timestamp.
        // See `axiam_core::id` — v7 is for identifiers, never for secrets.
        let random_password = Uuid::new_v4().to_string();

        let mut metadata = serde_json::json!({
            "federation_config_id": config_id.to_string(),
            "external_subject": identity.external_subject,
            "provisioned_by": "oidc_federation",
        });
        // `User` has no display-name column, so a mapped one goes here rather
        // than being dropped — which is what happened to every attribute map
        // written before this change.
        if let Some(ref display_name) = identity.display_name {
            metadata["display_name"] = serde_json::Value::String(display_name.clone());
        }

        let create_user = CreateUser {
            tenant_id,
            username,
            email,
            password: random_password,
            metadata: Some(metadata),
        };

        let user = self.user_repo.create(create_user).await.map_err(|e| {
            FederationError::ProvisioningFailed(format!("Failed to create user: {e}"))
        })?;

        let create_link = CreateFederationLink {
            tenant_id,
            user_id: user.id,
            federation_config_id: config_id,
            external_subject: identity.external_subject.clone(),
            external_email: identity.email.clone(),
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
            external_subject = %identity.external_subject,
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
        async fn list_token_exchange_enabled(
            &self,
            _tenant_id: Uuid,
        ) -> AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
        }
        async fn list_enabled(&self, _tenant_id: Uuid) -> AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
        }
        async fn list_inheritable_enabled(
            &self,
            _tenant_id: Uuid,
        ) -> AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
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

    /// An existing federation link resolves, but the linked `user_id` no
    /// longer has a matching user row (e.g. the user was deleted out from
    /// under the link) — `user_repo.get_by_id` fails and must be mapped to
    /// `ProvisioningFailed`, not silently re-provisioned.
    #[tokio::test]
    async fn provision_existing_link_but_user_lookup_fails_maps_to_provisioning_failed() {
        let tenant = Uuid::new_v4();
        let cfg = Uuid::new_v4();
        let link = StubLinkRepo {
            existing: Some(FederationLink {
                id: Uuid::new_v4(),
                tenant_id: tenant,
                user_id: Uuid::new_v4(),
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
        // preset: None -> StubUserRepo::get_by_id returns NotFound.
        let svc = make_stub_service(
            link,
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .provision_or_link_user(tenant, cfg, &claims_with(Some("x@example.com")))
            .await
            .expect_err("dangling link with no matching user must fail");
        assert!(
            matches!(err, FederationError::ProvisioningFailed(ref m) if m.contains("fetch linked user")),
            "got: {err:?}"
        );
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

    /// A 200 token response whose body exceeds the 256 KiB read cap must be
    /// rejected rather than fully buffered (CQ-B23).
    #[tokio::test]
    async fn exchange_code_oversized_success_body_maps_to_token_exchange_failed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Comfortably over the 256 KiB cap.
        let oversized_body = "x".repeat(300 * 1024);
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(oversized_body))
            .mount(&server)
            .await;

        let svc = make_stub_service(
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let endpoint = format!("{}/token", server.uri());
        let err = svc
            .exchange_code(
                &endpoint,
                "code",
                "https://rp/cb",
                "cid",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("oversized token response body must be rejected");
        assert!(
            matches!(err, FederationError::TokenExchangeFailed(ref m) if m.contains("too large")),
            "{err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // build_authorization_url / handle_callback error arms + verify_id_token
    // via the real service method (not the free-standing `verify()` test
    // helper above, which duplicates but never exercises the production
    // `OidcFederationService::verify_id_token`).
    // -----------------------------------------------------------------------

    /// Configurable `FederationConfigRepository` stub: returns a preset
    /// `get_by_id` outcome. All other methods are never exercised by
    /// `build_authorization_url`/`handle_callback`, so they stay
    /// `unimplemented!()`.
    enum ConfigOutcome {
        Found(Box<FederationConfig>),
        NotFound,
        DbError,
    }

    struct ConfigRepoStub {
        outcome: ConfigOutcome,
    }

    impl FederationConfigRepository for ConfigRepoStub {
        async fn create(&self, _: CreateFederationConfig) -> AxiamResult<FederationConfig> {
            unimplemented!()
        }
        async fn get_by_id(&self, _: Uuid, _: Uuid) -> AxiamResult<FederationConfig> {
            match &self.outcome {
                ConfigOutcome::Found(c) => Ok((**c).clone()),
                ConfigOutcome::NotFound => Err(AxiamError::NotFound {
                    entity: "federation_config".into(),
                    id: "no-config".into(),
                }),
                ConfigOutcome::DbError => Err(AxiamError::Database("config lookup boom".into())),
            }
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
        async fn list_token_exchange_enabled(
            &self,
            _tenant_id: Uuid,
        ) -> AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
        }
        async fn list_enabled(&self, _tenant_id: Uuid) -> AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
        }
        async fn list_inheritable_enabled(
            &self,
            _tenant_id: Uuid,
        ) -> AxiamResult<Vec<FederationConfig>> {
            Ok(Vec::new())
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

    type ConfigService = OidcFederationService<ConfigRepoStub, StubLinkRepo, StubUserRepo>;

    fn make_config_service(outcome: ConfigOutcome, cache: Arc<JwksCache>) -> ConfigService {
        OidcFederationService::new(
            ConfigRepoStub { outcome },
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            reqwest::Client::new(),
            cache,
            [0u8; 32], // gitleaks:allow
        )
    }

    /// A baseline valid, enabled OIDC config pointing at `metadata_url`.
    fn base_config(metadata_url: Option<&str>) -> FederationConfig {
        FederationConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: "test-idp".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: metadata_url.map(String::from),
            client_id: "client-abc".into(),
            client_secret: Uuid::new_v4().to_string(),
            attribute_map: serde_json::json!({}),
            enabled: true,
            allowed_algorithms: vec!["EdDSA".to_string()],
            idp_signing_cert_pem: None,
            client_secret_ciphertext: None,
            client_secret_nonce: None,
            client_secret_key_version: None,
            token_exchange: Default::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            provider_kind: axiam_core::models::federation::ProviderKind::GenericOidc,
            provider_slug: None,
            allow_tenant_inheritance: false,
            scopes: Vec::new(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            allowed_issuer_tenants: Vec::new(),
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: false,
        }
    }

    #[tokio::test]
    async fn build_authorization_url_rejects_config_not_found() {
        let svc = make_config_service(ConfigOutcome::NotFound, Arc::new(JwksCache::new()));
        let err = svc
            .build_authorization_url(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "https://rp/cb",
                "st",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("missing config must fail");
        assert!(matches!(err, FederationError::ConfigNotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn build_authorization_url_maps_other_db_error_to_internal() {
        let svc = make_config_service(ConfigOutcome::DbError, Arc::new(JwksCache::new()));
        let err = svc
            .build_authorization_url(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "https://rp/cb",
                "st",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("non-NotFound lookup error must surface");
        assert!(matches!(err, FederationError::Internal(_)), "{err:?}");
    }

    #[tokio::test]
    async fn build_authorization_url_rejects_disabled_config() {
        let mut cfg = base_config(Some(
            "https://idp.example.com/.well-known/openid-configuration",
        ));
        cfg.enabled = false;
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .build_authorization_url(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "https://rp/cb",
                "st",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("disabled config must fail");
        assert!(matches!(err, FederationError::ConfigDisabled), "{err:?}");
    }

    #[tokio::test]
    async fn build_authorization_url_rejects_protocol_mismatch() {
        let mut cfg = base_config(Some(
            "https://idp.example.com/.well-known/openid-configuration",
        ));
        cfg.protocol = FederationProtocol::Saml;
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .build_authorization_url(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "https://rp/cb",
                "st",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("SAML config must fail OIDC-only build");
        assert!(
            matches!(err, FederationError::ProtocolMismatch(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn build_authorization_url_rejects_missing_metadata_url() {
        let cfg = base_config(None);
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .build_authorization_url(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "https://rp/cb",
                "st",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("missing metadata_url must fail");
        assert!(
            matches!(err, FederationError::DiscoveryFailed(ref m) if m.contains("metadata URL")),
            "{err:?}"
        );
    }

    /// `DiscoveryCache::get_or_fetch` validates that `authorization_endpoint`
    /// parses as a URL *before* `build_authorization_url` ever gets the
    /// document (see `discovery_cache.rs`'s per-endpoint validation loop),
    /// so a malformed `authorization_endpoint` is rejected one layer down
    /// with a `"{name} is not a valid URL: ..."` message — the
    /// `url::Url::parse(&discovery.authorization_endpoint)` re-check inside
    /// `build_authorization_url` itself (oidc.rs) is unreachable
    /// belt-and-suspenders defense-in-depth given that upstream guarantee.
    /// This test still exercises the real end-to-end error propagation path.
    #[tokio::test]
    async fn build_authorization_url_rejects_invalid_authorization_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        // authorization_endpoint is not a valid absolute URL.
        let doc_json = serde_json::json!({
            "issuer": base,
            "authorization_endpoint": "::not a url::",
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc_json))
            .mount(&server)
            .await;

        let metadata_url = format!("{base}/.well-known/openid-configuration");
        let cfg = base_config(Some(&metadata_url));
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let err = svc
            .build_authorization_url(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "https://rp/cb",
                "st",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("invalid authorization_endpoint must fail discovery");
        assert!(
            matches!(err, FederationError::DiscoveryFailed(ref m) if m.contains("authorization_endpoint is not a valid URL")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn build_authorization_url_succeeds_and_includes_params() {
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
            .mount(&server)
            .await;

        let metadata_url = format!("{base}/.well-known/openid-configuration");
        let cfg = base_config(Some(&metadata_url));
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let result = svc
            .build_authorization_url(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "https://rp/cb",
                "state-1",
                "nonce-1",
            )
            .await
            .expect("valid discovery must succeed");
        assert!(result.url.starts_with(&format!("{base}/authorize?")));
        assert!(result.url.contains("state=state-1"));
        assert!(result.url.contains("nonce=nonce-1"));
        assert!(result.url.contains("client_id=client-abc"));
    }

    #[tokio::test]
    async fn handle_callback_rejects_config_not_found() {
        let svc = make_config_service(ConfigOutcome::NotFound, Arc::new(JwksCache::new()));
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "code",
                "https://rp/cb",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("missing config must fail");
        assert!(matches!(err, FederationError::ConfigNotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn handle_callback_rejects_disabled_config() {
        let mut cfg = base_config(Some(
            "https://idp.example.com/.well-known/openid-configuration",
        ));
        cfg.enabled = false;
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "code",
                "https://rp/cb",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("disabled config must fail");
        assert!(matches!(err, FederationError::ConfigDisabled), "{err:?}");
    }

    #[tokio::test]
    async fn handle_callback_rejects_protocol_mismatch() {
        let mut cfg = base_config(Some(
            "https://idp.example.com/.well-known/openid-configuration",
        ));
        cfg.protocol = FederationProtocol::Saml;
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "code",
                "https://rp/cb",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("SAML config must fail OIDC-only callback");
        assert!(
            matches!(err, FederationError::ProtocolMismatch(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn handle_callback_rejects_missing_metadata_url() {
        let cfg = base_config(None);
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new()),
        );
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "code",
                "https://rp/cb",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("missing metadata_url must fail");
        assert!(
            matches!(err, FederationError::DiscoveryFailed(ref m) if m.contains("metadata URL")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn handle_callback_maps_other_db_error_to_internal() {
        let svc = make_config_service(ConfigOutcome::DbError, Arc::new(JwksCache::new()));
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "code",
                "https://rp/cb",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("non-NotFound lookup error must surface");
        assert!(matches!(err, FederationError::Internal(_)), "{err:?}");
    }

    /// `discover()`'s `allow_private` seam is `false` by default (as it is
    /// for every production `JwksCache::new()`), so a non-HTTPS
    /// `metadata_url` must be rejected by `validate_metadata_url` before any
    /// network call is attempted — no wiremock server needed.
    #[tokio::test]
    async fn discover_rejects_non_https_metadata_url_in_production_mode() {
        let svc = make_config_service(ConfigOutcome::NotFound, Arc::new(JwksCache::new()));
        let err = svc
            .discover("http://insecure.example.com/.well-known/openid-configuration")
            .await
            .expect_err("non-HTTPS metadata_url must be rejected");
        assert!(
            matches!(err, FederationError::InvalidMetadataUrl(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn handle_callback_rejects_config_incomplete_when_secret_missing() {
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
            .mount(&server)
            .await;

        let metadata_url = format!("{base}/.well-known/openid-configuration");
        let mut cfg = base_config(Some(&metadata_url));
        cfg.client_secret = String::new(); // no legacy plaintext, no ciphertext
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "code",
                "https://rp/cb",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("missing client secret must fail before token exchange");
        assert!(matches!(err, FederationError::ConfigIncomplete), "{err:?}");
    }

    #[tokio::test]
    async fn handle_callback_rejects_missing_id_token_in_token_response() {
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
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at",
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let metadata_url = format!("{base}/.well-known/openid-configuration");
        let cfg = base_config(Some(&metadata_url));
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "code",
                "https://rp/cb",
                &Uuid::new_v4().to_string(),
            )
            .await
            .expect_err("token response without id_token must fail");
        assert!(
            matches!(err, FederationError::TokenExchangeFailed(ref m) if m.contains("No id_token")),
            "{err:?}"
        );
    }

    /// Full happy-path IdP round trip through `handle_callback`: discovery,
    /// token exchange, JWKS-verified ID token, nonce check, and new-user
    /// provisioning — end to end through the real service methods.
    #[tokio::test]
    async fn handle_callback_full_success_provisions_new_user() {
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
            .mount(&server)
            .await;

        let key = test_enc_key();
        let claims = make_claims_json(&base, "client-abc", 300, Some("expected-nonce"));
        let id_token = token_with_kid(&key, &claims, "test-key-1");

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at",
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;

        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key-1",
                "use": "sig",
                "x": TEST_PUB_X
            }]
        });
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
            .mount(&server)
            .await;

        let metadata_url = format!("{base}/.well-known/openid-configuration");
        let cfg = base_config(Some(&metadata_url));
        let cache = Arc::new(JwksCache::new_allow_private_networks());
        let svc = OidcFederationService::new(
            ConfigRepoStub {
                outcome: ConfigOutcome::Found(Box::new(cfg)),
            },
            StubLinkRepo::provisioning(),
            StubUserRepo::provisioning(),
            reqwest::Client::new(),
            cache,
            [0u8; 32], // gitleaks:allow
        );

        let tenant_id = Uuid::new_v4();
        let config_id = Uuid::new_v4();
        let result = svc
            .handle_callback(
                tenant_id,
                config_id,
                "auth-code",
                "https://rp/cb",
                "expected-nonce",
            )
            .await
            .expect("full happy-path callback must succeed");
        assert!(result.newly_provisioned);
        assert_eq!(result.federation_link.external_subject, "user-sub-123");
    }

    #[tokio::test]
    async fn handle_callback_rejects_nonce_mismatch() {
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
            .mount(&server)
            .await;

        let key = test_enc_key();
        let claims = make_claims_json(&base, "client-abc", 300, Some("actual-nonce"));
        let id_token = token_with_kid(&key, &claims, "test-key-1");
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at",
                "id_token": id_token,
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key-1",
                "use": "sig",
                "x": TEST_PUB_X
            }]
        });
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
            .mount(&server)
            .await;

        let metadata_url = format!("{base}/.well-known/openid-configuration");
        let cfg = base_config(Some(&metadata_url));
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "auth-code",
                "https://rp/cb",
                "expected-nonce", // does not match "actual-nonce" in the token
            )
            .await
            .expect_err("nonce mismatch must be rejected");
        assert!(
            matches!(err, FederationError::IdTokenValidationFailed(ref m) if m.contains("Nonce mismatch")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn handle_callback_rejects_missing_nonce_claim() {
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
            .mount(&server)
            .await;

        let key = test_enc_key();
        // No nonce claim at all.
        let claims = make_claims_json(&base, "client-abc", 300, None);
        let id_token = token_with_kid(&key, &claims, "test-key-1");
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at",
                "id_token": id_token,
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key-1",
                "use": "sig",
                "x": TEST_PUB_X
            }]
        });
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
            .mount(&server)
            .await;

        let metadata_url = format!("{base}/.well-known/openid-configuration");
        let cfg = base_config(Some(&metadata_url));
        let svc = make_config_service(
            ConfigOutcome::Found(Box::new(cfg)),
            Arc::new(JwksCache::new_allow_private_networks()),
        );
        let err = svc
            .handle_callback(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "auth-code",
                "https://rp/cb",
                "expected-nonce",
            )
            .await
            .expect_err("missing nonce claim must be rejected");
        assert!(
            matches!(err, FederationError::IdTokenValidationFailed(ref m) if m.contains("Missing nonce")),
            "{err:?}"
        );
    }

    // ----- verify_id_token via the real service method -----

    #[tokio::test]
    async fn verify_id_token_service_method_accepts_valid_token() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let svc = make_config_service(ConfigOutcome::NotFound, Arc::clone(&cache));

        let key = test_enc_key();
        let claims = make_claims_json(
            "https://idp.example.com",
            "client-abc",
            300,
            Some(&Uuid::new_v4().to_string()),
        );
        let token = token_with_kid(&key, &claims, "test-key-1");
        let d = disc("https://idp.example.com");

        let result = svc
            .verify_id_token(&token, &d, "client-abc", &["EdDSA".to_string()], (tid, cid))
            .await
            .expect("valid token via real service method must be accepted");
        assert_eq!(result.sub, "user-sub-123");
    }

    #[tokio::test]
    async fn verify_id_token_service_method_rejects_invalid_signature() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let svc = make_config_service(ConfigOutcome::NotFound, Arc::clone(&cache));

        // Sign with a DIFFERENT key than the one in the JWKS (same kid), so
        // the signature check itself fails. Generated at runtime (rather
        // than a hard-coded PEM literal) so static secret scanners don't
        // flag it — any fresh Ed25519 key works here since all that matters
        // is that it differs from the key in the JWKS.
        let wrong_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("wrong test key must generate");
        let wrong_key = EncodingKey::from_ed_pem(wrong_keypair.serialize_pem().as_bytes())
            .expect("wrong test key must parse");
        let claims = make_claims_json(
            "https://idp.example.com",
            "client-abc",
            300,
            Some(&Uuid::new_v4().to_string()),
        );
        let token = token_with_kid(&wrong_key, &claims, "test-key-1");
        let d = disc("https://idp.example.com");

        let result = svc
            .verify_id_token(&token, &d, "client-abc", &["EdDSA".to_string()], (tid, cid))
            .await;
        assert!(
            matches!(result, Err(FederationError::JwtSignatureInvalid)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn verify_id_token_service_method_rejects_disallowed_alg() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let svc = make_config_service(ConfigOutcome::NotFound, Arc::clone(&cache));

        let key = test_enc_key();
        let claims = make_claims_json(
            "https://idp.example.com",
            "client-abc",
            300,
            Some(&Uuid::new_v4().to_string()),
        );
        let token = token_with_kid(&key, &claims, "test-key-1");
        let d = disc("https://idp.example.com");

        // allowed_algorithms only lists RS256; token is signed EdDSA.
        let result = svc
            .verify_id_token(&token, &d, "client-abc", &["RS256".to_string()], (tid, cid))
            .await;
        assert!(
            matches!(result, Err(FederationError::AlgorithmNotAllowed(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn verify_id_token_service_method_forced_refetch_on_unknown_kid() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();

        let jwk_json = serde_json::json!({
            "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "known-key",
                        "use": "sig", "x": TEST_PUB_X }]
        });
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwk_json).unwrap();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, jwks).await;

        let svc = make_config_service(ConfigOutcome::NotFound, Arc::clone(&cache));

        let key = test_enc_key();
        let claims = make_claims_json(
            "https://idp.example.com",
            "client-abc",
            300,
            Some(&Uuid::new_v4().to_string()),
        );
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("unknown-kid".to_string());
        let token = encode(&h, &claims, &key).unwrap();

        let d = OidcDiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/auth".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri: "http://127.0.0.1:0/unreachable-jwks".to_string(),
        };

        let result = svc
            .verify_id_token(&token, &d, "client-abc", &["EdDSA".to_string()], (tid, cid))
            .await;
        assert!(
            matches!(result, Err(FederationError::JwksKidUnknown)),
            "{result:?}"
        );
    }

    /// Unknown `kid` triggers a forced refetch (D-01/D-02/D-03) that *does*
    /// find the key at the live JWKS endpoint — exercises the success arm of
    /// the forced-refetch branch (as opposed to the sibling test above,
    /// where the forced refetch itself fails because the endpoint is
    /// unreachable).
    #[tokio::test]
    async fn verify_id_token_service_method_forced_refetch_finds_key_and_succeeds() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();

        // Cache is stale: only knows about an unrelated kid.
        let stale_jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "known-key",
                        "use": "sig", "x": TEST_PUB_X }]
        }))
        .unwrap();

        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new_allow_private_networks());
        populate_cache(Arc::clone(&cache), tid, cid, stale_jwks).await;

        // Live endpoint has the real key under "test-key-1".
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .mount(&server)
            .await;

        let svc = make_config_service(ConfigOutcome::NotFound, Arc::clone(&cache));

        let key = test_enc_key();
        let claims = make_claims_json(&base, "client-abc", 300, Some(&Uuid::new_v4().to_string()));
        let token = token_with_kid(&key, &claims, "test-key-1");
        let d = OidcDiscoveryDocument {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}/auth"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: None,
            jwks_uri: format!("{base}/jwks"),
        };

        let result = svc
            .verify_id_token(&token, &d, "client-abc", &["EdDSA".to_string()], (tid, cid))
            .await
            .expect("forced refetch must find the key and verification must succeed");
        assert_eq!(result.sub, "user-sub-123");
    }

    /// A structurally valid, correctly-signed token whose claims fail the
    /// `iss`/`aud`/`exp` checks must be rejected via the real service
    /// method's `JwtClaimRejected` arm (not just the free-standing `verify()`
    /// test helper used by the sibling `verify_rejects_*` tests above).
    #[tokio::test]
    async fn verify_id_token_service_method_rejects_claim_validation_failure() {
        let tid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let cache = Arc::new(JwksCache::new());
        populate_cache(Arc::clone(&cache), tid, cid, test_jwks()).await;

        let svc = make_config_service(ConfigOutcome::NotFound, Arc::clone(&cache));

        let key = test_enc_key();
        // aud does not match the client_id passed to verify_id_token.
        let claims = make_claims_json(
            "https://idp.example.com",
            "someone-else",
            300,
            Some(&Uuid::new_v4().to_string()),
        );
        let token = token_with_kid(&key, &claims, "test-key-1");
        let d = disc("https://idp.example.com");

        let result = svc
            .verify_id_token(&token, &d, "client-abc", &["EdDSA".to_string()], (tid, cid))
            .await;
        assert!(
            matches!(result, Err(FederationError::JwtClaimRejected(_))),
            "{result:?}"
        );
    }

    // ----- map_algorithm_strings / find_jwk direct coverage -----

    #[test]
    fn map_algorithm_strings_maps_every_supported_name_and_drops_unknown() {
        let names: Vec<String> = [
            "RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA", "PS256", "PS384", "PS512",
            "none", "bogus",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mapped = map_algorithm_strings(&names);
        assert_eq!(
            mapped,
            vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::RS512,
                Algorithm::ES256,
                Algorithm::ES384,
                Algorithm::EdDSA,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::PS512,
            ]
        );
    }

    #[test]
    fn find_jwk_returns_none_for_no_kid_and_multiple_keys() {
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [
                { "kty": "OKP", "crv": "Ed25519", "kid": "k1", "use": "sig", "x": TEST_PUB_X },
                { "kty": "OKP", "crv": "Ed25519", "kid": "k2", "use": "sig", "x": TEST_PUB_X },
            ]
        }))
        .unwrap();
        assert!(find_jwk(&jwks, None).is_none());
    }

    #[test]
    fn find_jwk_returns_sole_key_when_kid_absent_and_single_key() {
        let jwks = test_jwks();
        let found = find_jwk(&jwks, None);
        assert!(found.is_some());
    }

    #[test]
    fn find_jwk_returns_none_when_kid_requested_not_present() {
        let jwks = test_jwks();
        assert!(find_jwk(&jwks, Some("does-not-exist")).is_none());
    }
}
