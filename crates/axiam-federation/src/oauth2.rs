//! The plain-OAuth2 login variant: authentication by userinfo call.
//!
//! This is the path for providers that do not issue an OIDC ID token. GitHub
//! publishes no discovery document and no `id_token` at all; Facebook's web
//! authorization-code flow returns only an access token to a confidential
//! client. Neither can go through [`crate::oidc`], which requires both.
//!
//! # What it trusts, stated plainly
//!
//! On the OIDC path AXIAM verifies a JWS signature against the provider's JWKS
//! by `kid`, with `alg` checked against an allow-list, and validates `iss`,
//! `aud`, `exp`, `iat` and `nonce`. Every one of those is a cryptographic
//! statement bound to this specific login attempt.
//!
//! Here **none of them exist**. The entire trust argument is one sentence:
//!
//! > The access token we just received, at a token endpoint we configured,
//! > using a client secret only we hold, works against a userinfo endpoint we
//! > configured.
//!
//! That is real — it is what the whole OAuth2-as-authentication world runs on —
//! but it is *configuration and transport* trust rather than *cryptographic*
//! trust. A substituted `userinfo_endpoint` is an authentication bypass with no
//! signature to catch it, which is why that field is validated as absolute
//! HTTPS on write, fetched through the same IP-pinning SSRF guard as every
//! other outbound call, and never derived from anything the IdP sends at
//! runtime.
//!
//! Three things follow, all enforced rather than documented:
//!
//! 1. A provider that supports OIDC properly cannot be configured onto this
//!    path (`validate_protocol_for_kind` in `axiam-core`).
//! 2. PKCE is mandatory here (see [`crate::pkce`]).
//! 3. An email the provider does not affirmatively mark verified is never
//!    adopted as an AXIAM identity.
//!
//! See `claude_dev/federation-sso-login-design.md` §3.

use axiam_core::models::federation::{FederationConfig, FederationProtocol, ProviderKind};
use axiam_core::models::federation_claims::map_identity;
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, UserRepository,
};
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::FederationError;
use crate::oidc::{AuthorizationUrl, FederationCallbackResult, OidcFederationService};
use crate::secrets::decrypt_client_secret_or_legacy;

/// Cap on a token or userinfo response body.
///
/// Same 256 KiB the OIDC token exchange uses. A userinfo document that does not
/// fit in a quarter-megabyte is not a userinfo document.
const MAX_RESPONSE_SIZE: usize = 256 * 1024;

/// GitHub's verified-address endpoint, derived from the configured
/// `userinfo_endpoint`.
///
/// `GET /user` frequently returns a null or unverified `email` — the user keeps
/// it private — so the primary *verified* address has to come from `/user/emails`.
///
/// Derived rather than hard-coded to `https://api.github.com/user/emails`,
/// because that constant would be wrong for every GitHub Enterprise Server
/// deployment, whose API lives at `https://<host>/api/v3/user`. The `/emails`
/// resource is a sibling of `/user` on whichever host the operator configured,
/// which is a fact about GitHub's API shape rather than about github.com.
fn github_emails_endpoint(userinfo_endpoint: &str) -> String {
    format!("{}/emails", userinfo_endpoint.trim_end_matches('/'))
}

/// Sent on every GitHub API call.
///
/// GitHub rejects requests with no `User-Agent`, and its REST API wants an
/// explicit version header rather than whatever the default happens to be that
/// month.
const GITHUB_USER_AGENT: &str = "axiam-federation";

/// Token response from a plain-OAuth2 provider.
///
/// `id_token` is deliberately absent from this struct. If a provider sends one
/// on this path it is ignored rather than half-trusted: verifying it properly
/// means discovery and a JWKS, which is the OIDC path, and an unverified ID
/// token is worth less than the userinfo call already made.
#[derive(Debug, Deserialize)]
struct OAuth2TokenResponse {
    access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    scope: Option<String>,
}

/// One entry of GitHub's `GET /user/emails` response.
#[derive(Debug, Deserialize)]
struct GithubEmail {
    email: String,
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    primary: bool,
}

/// The three endpoints a plain-OAuth2 config must carry.
///
/// Returned as a borrowed triple so the caller's error message can name the
/// field that is missing rather than saying "the config is incomplete".
fn required_endpoints(config: &FederationConfig) -> Result<(&str, &str, &str), FederationError> {
    fn need<'a>(v: Option<&'a String>, name: &str) -> Result<&'a str, FederationError> {
        v.map(String::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                FederationError::ConfigInvalid(format!(
                    "{name} is required for an OAuth2 provider — there is no discovery \
                     document to derive it from"
                ))
            })
    }
    Ok((
        need(
            config.authorization_endpoint.as_ref(),
            "authorization_endpoint",
        )?,
        need(config.token_endpoint.as_ref(), "token_endpoint")?,
        need(config.userinfo_endpoint.as_ref(), "userinfo_endpoint")?,
    ))
}

impl<FC, FL, UR> OidcFederationService<FC, FL, UR>
where
    FC: FederationConfigRepository,
    FL: FederationLinkRepository,
    UR: UserRepository,
{
    /// Build the authorize URL for a plain-OAuth2 provider.
    ///
    /// `pkce_challenge` is not optional in the caller's sense: the REST layer
    /// always generates a pair for this protocol, because `state` alone is all
    /// that would otherwise bind the code to the browser that started the flow.
    pub async fn build_oauth2_authorization_url(
        &self,
        config: &FederationConfig,
        redirect_uri: &str,
        state: &str,
        pkce_challenge: &str,
    ) -> Result<AuthorizationUrl, FederationError> {
        if !config.enabled {
            return Err(FederationError::ConfigDisabled);
        }
        if config.protocol != FederationProtocol::OAuth2 {
            return Err(FederationError::ProtocolMismatch(
                "expected OAuth2 protocol".into(),
            ));
        }

        let (authorization_endpoint, _, _) = required_endpoints(config)?;
        // The same HTTPS-only check the OIDC `metadata_url` gets. Skipped
        // behind the private-network test seam, exactly as `discover` does, so
        // integration tests can point at a loopback mock provider.
        if !self.allow_private_networks() {
            crate::validate_metadata_url(authorization_endpoint)?;
        }

        let mut url = url::Url::parse(authorization_endpoint).map_err(|e| {
            FederationError::ConfigInvalid(format!("authorization_endpoint is not a URL: {e}"))
        })?;

        let scopes = config.effective_scopes();
        if scopes.is_empty() {
            return Err(FederationError::ConfigInvalid(
                "scopes are required for an OAuth2 provider — a provider's scope names \
                 are its own and guessing one produces an authorize URL that fails at \
                 the provider"
                    .into(),
            ));
        }

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", crate::pkce::CHALLENGE_METHOD);

        info!(
            tenant_id = %config.tenant_id,
            config_id = %config.id,
            provider_kind = %config.provider_kind.as_str(),
            "Built OAuth2 authorization URL"
        );

        Ok(AuthorizationUrl {
            url: url.to_string(),
        })
    }

    /// Complete a plain-OAuth2 login.
    ///
    /// `requesting_tenant_id` is where the user and the federation link are
    /// created, which is **not** necessarily `config.tenant_id`: an inherited
    /// organization-level provider signs people into the tenant they asked for,
    /// not into the organization scope the config lives in.
    pub async fn handle_oauth2_callback(
        &self,
        config: &FederationConfig,
        requesting_tenant_id: Uuid,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<FederationCallbackResult, FederationError> {
        if !config.enabled {
            return Err(FederationError::ConfigDisabled);
        }
        if config.protocol != FederationProtocol::OAuth2 {
            return Err(FederationError::ProtocolMismatch(
                "expected OAuth2 protocol".into(),
            ));
        }
        if code_verifier.trim().is_empty() {
            // Not a "missing parameter": on this path the verifier is the
            // replay protection, so its absence is a security failure rather
            // than a validation slip.
            return Err(FederationError::ConfigInvalid(
                "PKCE is mandatory for OAuth2 providers and no code verifier was stored \
                 for this login"
                    .into(),
            ));
        }

        let (_, token_endpoint, userinfo_endpoint) = required_endpoints(config)?;
        let allow_private = self.allow_private_networks();
        if !allow_private {
            crate::validate_metadata_url(token_endpoint)?;
            crate::validate_metadata_url(userinfo_endpoint)?;
        }

        let client_secret = decrypt_client_secret_or_legacy(
            self.encryption_key_ref(),
            config.client_secret_nonce.as_deref(),
            config.client_secret_ciphertext.as_deref(),
            &config.client_secret,
        )
        .map_err(|_| FederationError::ConfigIncomplete)?;

        let access_token = self
            .oauth2_exchange_code(
                token_endpoint,
                code,
                redirect_uri,
                &config.client_id,
                &client_secret,
                code_verifier,
                allow_private,
            )
            .await?;

        let mut claims = self
            .oauth2_fetch_userinfo(userinfo_endpoint, &access_token, allow_private)
            .await?;

        if config.provider_kind == ProviderKind::Github {
            self.github_merge_verified_email(
                &mut claims,
                &github_emails_endpoint(userinfo_endpoint),
                &access_token,
                allow_private,
            )
            .await?;
        }

        let identity = map_identity(config.provider_kind, &config.attribute_map, &claims)
            .ok_or_else(|| {
                FederationError::UserinfoUnusable(
                    "no external subject could be mapped from the response".into(),
                )
            })?;

        // The rule, applied uniformly across every OAuth2 provider rather than
        // only GitHub: an address the provider has not affirmatively marked
        // verified is not an identity. Both "absent" and "present but
        // unverified" land here, because both mean the same thing — nobody has
        // proved they control that mailbox.
        if !identity.email_verified {
            warn!(
                tenant_id = %requesting_tenant_id,
                config_id = %config.id,
                provider_kind = %config.provider_kind.as_str(),
                has_email = identity.email.is_some(),
                "refusing an OAuth2 federated login with no verified email"
            );
            return Err(FederationError::UnverifiedExternalEmail);
        }

        info!(
            tenant_id = %requesting_tenant_id,
            config_id = %config.id,
            provider_kind = %config.provider_kind.as_str(),
            "OAuth2 callback: userinfo resolved an identity"
        );

        self.provision_or_link_identity(requesting_tenant_id, config.id, &identity)
            .await
    }

    /// Exchange the authorization code for an access token.
    async fn oauth2_exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
        code_verifier: &str,
        allow_private: bool,
    ) -> Result<String, FederationError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", code_verifier),
        ];

        // `Accept: application/json` is load-bearing, not politeness: GitHub's
        // token endpoint answers `application/x-www-form-urlencoded` by default
        // and only returns JSON when asked. Without it the parse below fails on
        // a response that was perfectly successful.
        let response = crate::ssrf::guarded_fetch(token_endpoint, allow_private, |c, u| {
            c.post(u)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
                .form(&form)
        })
        .await
        .map_err(|e| FederationError::TokenExchangeFailed(e.to_string()))?;

        let status = response.status();
        let body = crate::ssrf::read_capped_body(response, MAX_RESPONSE_SIZE)
            .await
            .map_err(|e| {
                FederationError::TokenExchangeFailed(format!("failed to read token response: {e}"))
            })?;

        if !status.is_success() {
            warn!(
                %status,
                body_preview = %String::from_utf8_lossy(&body).chars().take(200).collect::<String>(),
                "OAuth2 token exchange failed with non-success status"
            );
            return Err(FederationError::TokenExchangeFailed(format!(
                "IdP returned HTTP {status}"
            )));
        }

        // A 200 carrying `{"error": "..."}` is how several providers report a
        // reused or expired code. Treating it as success would hand the next
        // step an empty bearer token and produce a confusing userinfo failure
        // instead of the real one.
        let parsed: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            FederationError::TokenExchangeFailed(format!("failed to parse token response: {e}"))
        })?;
        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
            warn!(idp_error = %err, "OAuth2 token endpoint returned an error in a 200 body");
            return Err(FederationError::TokenExchangeFailed(format!(
                "IdP rejected the authorization code ({err})"
            )));
        }

        let token: OAuth2TokenResponse = serde_json::from_value(parsed).map_err(|e| {
            FederationError::TokenExchangeFailed(format!("token response has no access_token: {e}"))
        })?;
        if token.access_token.trim().is_empty() {
            return Err(FederationError::TokenExchangeFailed(
                "token response carried an empty access_token".into(),
            ));
        }
        Ok(token.access_token)
    }

    /// Fetch the userinfo document. This call *is* the authentication.
    async fn oauth2_fetch_userinfo(
        &self,
        userinfo_endpoint: &str,
        access_token: &str,
        allow_private: bool,
    ) -> Result<serde_json::Value, FederationError> {
        let bearer = format!("Bearer {access_token}");
        let response = crate::ssrf::guarded_fetch(userinfo_endpoint, allow_private, |c, u| {
            c.get(u)
                .header(reqwest::header::AUTHORIZATION, &bearer)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
        })
        .await
        .map_err(|e| FederationError::UserinfoUnusable(e.to_string()))?;

        let status = response.status();
        let body = crate::ssrf::read_capped_body(response, MAX_RESPONSE_SIZE)
            .await
            .map_err(|e| FederationError::UserinfoUnusable(format!("failed to read: {e}")))?;

        if !status.is_success() {
            return Err(FederationError::UserinfoUnusable(format!(
                "userinfo endpoint returned HTTP {status}"
            )));
        }

        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| FederationError::UserinfoUnusable(format!("not JSON: {e}")))?;
        if !value.is_object() {
            return Err(FederationError::UserinfoUnusable(
                "response was not a JSON object".into(),
            ));
        }
        Ok(value)
    }

    /// Replace GitHub's unreliable `email` with the primary **verified** one.
    ///
    /// Written into the ordinary `email` / `email_verified` keys rather than a
    /// synthetic one, so a default attribute map and an operator's custom map
    /// both name the same thing. Whatever `GET /user` said about the address is
    /// overwritten: that field is the one this call exists to distrust.
    async fn github_merge_verified_email(
        &self,
        claims: &mut serde_json::Value,
        emails_endpoint: &str,
        access_token: &str,
        allow_private: bool,
    ) -> Result<(), FederationError> {
        let bearer = format!("Bearer {access_token}");
        let response = crate::ssrf::guarded_fetch(emails_endpoint, allow_private, |c, u| {
            c.get(u)
                .header(reqwest::header::AUTHORIZATION, &bearer)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT)
        })
        .await
        .map_err(|e| FederationError::UserinfoUnusable(format!("GitHub email lookup: {e}")))?;

        let status = response.status();
        let body = crate::ssrf::read_capped_body(response, MAX_RESPONSE_SIZE)
            .await
            .map_err(|e| FederationError::UserinfoUnusable(format!("GitHub email lookup: {e}")))?;

        if !status.is_success() {
            // Most often a token granted without `user:email`. Say which,
            // because the fix is a scope change in the config and nothing about
            // the signing-in user.
            return Err(FederationError::UserinfoUnusable(format!(
                "GitHub returned HTTP {status} for the verified-email lookup; the \
                 configured scopes must include `user:email`"
            )));
        }

        let emails: Vec<GithubEmail> = serde_json::from_slice(&body).map_err(|e| {
            FederationError::UserinfoUnusable(format!("GitHub email list is not parseable: {e}"))
        })?;

        // Primary *and* verified. A verified non-primary address is somebody
        // else's choice of which mailbox represents them, and picking one for
        // them would silently key their AXIAM account on an address they did
        // not nominate.
        let chosen = emails.iter().find(|e| e.primary && e.verified);

        match chosen {
            Some(e) => {
                claims["email"] = serde_json::Value::String(e.email.clone());
                claims["email_verified"] = serde_json::Value::Bool(true);
                Ok(())
            }
            None => {
                // Overwrite rather than leave whatever `GET /user` said: the
                // caller refuses on `email_verified`, and leaving a stale
                // truthy value there would defeat the check.
                claims["email_verified"] = serde_json::Value::Bool(false);
                Err(FederationError::UnverifiedExternalEmail)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::federation::TokenExchangeTrust;
    use axiam_core::models::federation_claims::MappedIdentity;
    use chrono::Utc;

    fn oauth2_config(kind: ProviderKind) -> FederationConfig {
        FederationConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: "GitHub".into(),
            protocol: FederationProtocol::OAuth2,
            metadata_url: None,
            client_id: "cid".into(),
            client_secret: String::new(),
            attribute_map: serde_json::json!({}),
            enabled: true,
            allowed_algorithms: Vec::new(),
            idp_signing_cert_pem: None,
            client_secret_ciphertext: None,
            client_secret_nonce: None,
            client_secret_key_version: None,
            token_exchange: TokenExchangeTrust::default(),
            provider_kind: kind,
            provider_slug: None,
            allow_tenant_inheritance: false,
            scopes: Vec::new(),
            authorization_endpoint: Some("https://github.com/login/oauth/authorize".into()),
            token_endpoint: Some("https://github.com/login/oauth/access_token".into()),
            userinfo_endpoint: Some("https://api.github.com/user".into()),
            allowed_issuer_tenants: Vec::new(),
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: false,
            button_icon: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn every_missing_endpoint_names_itself() {
        let mut c = oauth2_config(ProviderKind::GenericOauth2);
        c.userinfo_endpoint = None;
        let err = required_endpoints(&c).unwrap_err();
        assert!(err.to_string().contains("userinfo_endpoint"));
        // Blank is missing, not present-and-empty: an empty string would sail
        // past a `is_some()` check and fail at the HTTP layer instead.
        c.userinfo_endpoint = Some("   ".into());
        assert!(required_endpoints(&c).is_err());

        let mut c = oauth2_config(ProviderKind::GenericOauth2);
        c.token_endpoint = None;
        assert!(
            required_endpoints(&c)
                .unwrap_err()
                .to_string()
                .contains("token_endpoint")
        );
    }

    #[test]
    fn a_complete_config_yields_all_three_endpoints() {
        let c = oauth2_config(ProviderKind::Github);
        let (a, t, u) = required_endpoints(&c).unwrap();
        assert_eq!(a, "https://github.com/login/oauth/authorize");
        assert_eq!(t, "https://github.com/login/oauth/access_token");
        assert_eq!(u, "https://api.github.com/user");
    }

    /// GitHub's own defaults must be a working configuration out of the box,
    /// because "read:user user:email" is the difference between a login and an
    /// HTTP 403 on the email lookup.
    #[test]
    fn githubs_default_scopes_include_the_one_the_email_lookup_needs() {
        let scopes = ProviderKind::Github.default_scopes();
        assert!(scopes.contains(&"user:email".to_string()));
    }

    /// The chosen address must be primary AND verified — the selection rule is
    /// what decides which mailbox an AXIAM account is keyed on.
    #[test]
    fn the_github_email_selection_takes_primary_and_verified_only() {
        let list: Vec<GithubEmail> = serde_json::from_value(serde_json::json!([
            {"email": "old@example.com", "verified": true, "primary": false},
            {"email": "unverified@example.com", "verified": false, "primary": true},
            {"email": "me@users.noreply.github.com", "verified": true, "primary": true}
        ]))
        .unwrap();
        let chosen = list.iter().find(|e| e.primary && e.verified).unwrap();
        assert_eq!(chosen.email, "me@users.noreply.github.com");

        // With no primary-and-verified entry there is no answer, and the caller
        // refuses rather than falling back to a verified-but-not-primary one.
        let list: Vec<GithubEmail> = serde_json::from_value(serde_json::json!([
            {"email": "old@example.com", "verified": true, "primary": false},
            {"email": "unverified@example.com", "verified": false, "primary": true}
        ]))
        .unwrap();
        assert!(list.iter().find(|e| e.primary && e.verified).is_none());
    }

    /// A GitHub email list with absent flags must not read as verified.
    #[test]
    fn missing_github_email_flags_default_to_false() {
        let list: Vec<GithubEmail> =
            serde_json::from_value(serde_json::json!([{"email": "a@b.test"}])).unwrap();
        assert!(!list[0].verified);
        assert!(!list[0].primary);
    }

    /// An `id_token` on this path is ignored rather than half-trusted.
    #[test]
    fn a_token_response_with_an_id_token_still_only_yields_the_access_token() {
        let parsed: OAuth2TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "at",
            "token_type": "bearer",
            "id_token": "eyJ...",
        }))
        .unwrap();
        assert_eq!(parsed.access_token, "at");
    }

    /// Derived from the configured endpoint, so GitHub Enterprise Server works
    /// — a hard-coded `api.github.com` would have silently excluded it.
    #[test]
    fn the_email_endpoint_is_a_sibling_of_the_configured_userinfo_endpoint() {
        assert_eq!(
            github_emails_endpoint("https://api.github.com/user"),
            "https://api.github.com/user/emails"
        );
        assert_eq!(
            github_emails_endpoint("https://ghe.example.com/api/v3/user"),
            "https://ghe.example.com/api/v3/user/emails"
        );
        // A trailing slash is the same endpoint, not a different one.
        assert_eq!(
            github_emails_endpoint("https://api.github.com/user/"),
            "https://api.github.com/user/emails"
        );
    }

    #[test]
    fn a_mapped_identity_needs_a_subject_before_anything_else() {
        let c = oauth2_config(ProviderKind::Github);
        let claims = serde_json::json!({"login": "octocat", "email": "a@b.test"});
        assert!(
            map_identity(c.provider_kind, &c.attribute_map, &claims).is_none(),
            "no `id` means no subject, and no subject means no identity"
        );
    }

    #[test]
    fn a_github_identity_maps_out_of_the_documented_shape() {
        let c = oauth2_config(ProviderKind::Github);
        let claims = serde_json::json!({
            "id": 583231,
            "login": "octocat",
            "name": "The Octocat",
            "email": "octocat@users.noreply.github.com",
            "email_verified": true,
        });
        let m: MappedIdentity = map_identity(c.provider_kind, &c.attribute_map, &claims).unwrap();
        assert_eq!(m.external_subject, "583231");
        assert_eq!(m.username.as_deref(), Some("octocat"));
        assert!(m.email_verified);
    }
}
