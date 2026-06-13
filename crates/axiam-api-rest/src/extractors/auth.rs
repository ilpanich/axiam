//! JWT-based authentication extractor.
//!
//! [`AuthenticatedUser`] implements Actix-Web's `FromRequest` trait.
//! It extracts the JWT from the `axiam_access` httpOnly cookie (browser clients)
//! or falls back to `Authorization: Bearer <token>` header (service clients).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::dev::Payload;
use actix_web::web;
use actix_web::{HttpMessage, HttpRequest};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_M2M, AUD_USER, CachedUserIdentity, ValidatedClaims, validate_access_token,
};
use axiam_core::error::AxiamError;
use axiam_core::repository::SessionRepository;
use axiam_db::SurrealSessionRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;

/// Object-safe per-request session-validity check (D-15 / REQ-7).
///
/// Access tokens are stateless JWTs, so revoking a session (deleting its row)
/// has no effect unless every authenticated request re-checks that the session
/// behind the token's `jti` (= `session.id`) is still active. This trait is the
/// object-safe seam that lets the connection-agnostic [`AuthenticatedUser`]
/// extractor perform that check without being generic over the DB `Connection`.
///
/// Mirrors the [`crate::authz::AuthzChecker`] boxed-future pattern because the
/// underlying repository methods are native `async fn` (RPITIT, not dyn-safe).
pub trait SessionValidator: Send + Sync {
    /// Returns `true` if a non-expired session with `session_id` exists for
    /// `tenant_id`. A revoked session (row deleted) or an expired one is
    /// considered inactive.
    fn is_session_active<'a>(
        &'a self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

impl<C: Connection> SessionValidator for SurrealSessionRepository<C> {
    fn is_session_active<'a>(
        &'a self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.get_by_id(tenant_id, session_id).await {
                Ok(session) => session.expires_at > chrono::Utc::now(),
                Err(_) => false,
            }
        })
    }
}

/// Authenticated user context extracted from a valid JWT.
///
/// Use this as a handler parameter to require authentication.
/// If the audit middleware has already validated the token, the cached
/// claims are reused to avoid double verification.
///
/// **Audience narrowing (D-19 / D-21):** only tokens with `aud = axiam:user`
/// are accepted on user-facing routes. M2M tokens are rejected with 401.
/// When `aud` is absent and `AuthConfig.allow_missing_aud_as_user` is `true`,
/// the token is accepted with a `WARN` log on every request. No in-process
/// rate limit is applied — operator-side log filtering (Loki dedup, fluent-bit
/// rewrite_tag, etc.) handles burst noise. This trade-off keeps the extractor
/// allocation-free and avoids shared mutable state.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    /// The session ID — equals the JWT `jti` claim which is set to
    /// `session.id` for user-facing tokens (D-15). Use this for
    /// selective session invalidation on password change.
    pub session_id: Uuid,
    pub claims: ValidatedClaims,
}

impl actix_web::FromRequest for AuthenticatedUser {
    type Error = AxiamApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Synchronous JWT/aud/jti extraction first (ends the `req` borrow before
        // the async block). Clone the optional session validator (an Arc) so the
        // returned future is `'static`.
        let user_result = extract_user(req);
        let validator = req
            .app_data::<web::Data<Arc<dyn SessionValidator>>>()
            .map(|d| d.get_ref().clone());

        Box::pin(async move {
            let user = user_result?;
            // REQ-7 / D-15: reject access tokens whose session has been revoked
            // (row deleted on password change/reset/MFA reset) or expired. The
            // validator is optional so non-session test harnesses are unaffected;
            // the production server (and session-security tests) always register it.
            if let Some(validator) = validator
                && !validator
                    .is_session_active(user.tenant_id, user.session_id)
                    .await
            {
                return Err(AxiamError::AuthenticationFailed {
                    reason: "session revoked or expired".into(),
                }
                .into());
            }
            Ok(user)
        })
    }
}

/// Service-account context extracted from a valid M2M JWT.
///
/// Use this as a handler parameter to require M2M authentication.
/// Accepts only tokens with `aud = axiam:m2m`; user tokens are rejected.
#[derive(Debug, Clone)]
pub struct AuthenticatedServiceAccount {
    /// OAuth2 `client_id` (the token `sub` for M2M tokens).
    pub client_id: String,
    pub tenant_id: Uuid,
    pub claims: ValidatedClaims,
}

impl actix_web::FromRequest for AuthenticatedServiceAccount {
    type Error = AxiamApiError;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        std::future::ready(extract_service_account(req))
    }
}

// ---------------------------------------------------------------------------
// Shared token extraction
// ---------------------------------------------------------------------------

/// Decode and validate the JWT from the request — shared between both
/// extractors. Does not apply audience narrowing.
fn parse_validated_claims(req: &HttpRequest) -> Result<ValidatedClaims, AxiamApiError> {
    let config = req
        .app_data::<web::Data<AuthConfig>>()
        .ok_or(AxiamError::Internal("missing auth config".into()))?;

    // Try cookie first (browser clients), then Authorization header (service clients).
    let token = if let Some(cookie) = req.cookie("axiam_access") {
        cookie.value().to_owned()
    } else {
        // Fall back to Authorization: Bearer header for non-browser clients.
        let header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AxiamError::AuthenticationFailed {
                reason: "missing authentication credentials".into(),
            })?;

        // Parse `Authorization` as case-insensitive Bearer with flexible whitespace.
        let header = header.trim();
        let mut parts = header.splitn(2, char::is_whitespace);
        let scheme = parts.next().unwrap_or("");
        let credentials = parts.next().unwrap_or("").trim();

        if !scheme.eq_ignore_ascii_case("bearer") || credentials.is_empty() {
            return Err(AxiamError::AuthenticationFailed {
                reason: "invalid Authorization scheme, expected Bearer".into(),
            }
            .into());
        }
        credentials.to_owned()
    };

    let validated = validate_access_token(&token, config).map_err(AxiamError::from)?;
    Ok(validated)
}

// ---------------------------------------------------------------------------
// AuthenticatedUser extractor
// ---------------------------------------------------------------------------

fn extract_user(req: &HttpRequest) -> Result<AuthenticatedUser, AxiamApiError> {
    // Try to reuse claims cached by the audit middleware.
    if let Some(cached) = req.extensions().get::<Arc<CachedUserIdentity>>() {
        let config = req
            .app_data::<web::Data<AuthConfig>>()
            .ok_or(AxiamError::Internal("missing auth config".into()))?;

        let session_id = check_user_aud_and_parse_jti(&cached.claims, config)?;
        return Ok(AuthenticatedUser {
            user_id: cached.user_id,
            tenant_id: cached.tenant_id,
            org_id: cached.org_id,
            session_id,
            claims: cached.claims.clone(),
        });
    }

    let config = req
        .app_data::<web::Data<AuthConfig>>()
        .ok_or(AxiamError::Internal("missing auth config".into()))?;

    let validated = parse_validated_claims(req)?;

    let session_id = check_user_aud_and_parse_jti(&validated, config)?;

    let user_id =
        Uuid::parse_str(&validated.0.sub).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid sub claim".into(),
        })?;

    let tenant_id =
        Uuid::parse_str(&validated.0.tenant_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id claim".into(),
        })?;

    let org_id =
        Uuid::parse_str(&validated.0.org_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid org_id claim".into(),
        })?;

    Ok(AuthenticatedUser {
        user_id,
        tenant_id,
        org_id,
        session_id,
        claims: validated,
    })
}

/// Enforce the audience narrowing policy for user-facing routes and
/// parse the `jti` claim as a `Uuid` (= session ID).
///
/// Audience rules (D-19, D-21):
/// - `aud = axiam:user` → accepted.
/// - `aud` absent AND `allow_missing_aud_as_user = true` → accepted; a
///   `WARN` is emitted on every such request. No in-process rate limiting is
///   applied here — operator-side log deduplication (Loki, fluent-bit, etc.)
///   handles burst noise, keeping this hot path allocation-free and
///   lock-free.
/// - `aud` absent AND `allow_missing_aud_as_user = false` → 401.
/// - `aud = axiam:m2m` → 401 (audience mismatch — wrong token type for
///   this route).
/// - Any other `aud` value → 401 (unknown audience).
fn check_user_aud_and_parse_jti(
    validated: &ValidatedClaims,
    config: &AuthConfig,
) -> Result<Uuid, AxiamApiError> {
    match validated.0.aud.as_deref() {
        Some(AUD_USER) => {
            // Expected audience — accept.
        }
        None => {
            if config.allow_missing_aud_as_user {
                // Back-compat window: treat as axiam:user, but warn unconditionally.
                // TRADE-OFF: no in-process rate limit on this warn. Operator-side
                // log filtering (e.g. Loki `rate()` alert, fluent-bit rewrite_tag
                // dedup) is the intended mechanism for suppressing burst noise
                // during the rollout window. Keeping this path lock-free is
                // intentional — auth hot paths must not contend on shared atomics.
                let jti = &validated.0.jti;
                tracing::warn!(
                    token_jti = %jti,
                    "accepted access token without aud — backward-compat window active"
                );
            } else {
                return Err(AxiamError::AuthenticationFailed {
                    reason: "aud required".into(),
                }
                .into());
            }
        }
        Some(AUD_M2M) => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "audience mismatch — this route requires axiam:user audience".into(),
            }
            .into());
        }
        Some(_) => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "unknown audience".into(),
            }
            .into());
        }
    }

    Uuid::parse_str(&validated.0.jti).map_err(|_| {
        AxiamError::AuthenticationFailed {
            reason: "invalid jti".into(),
        }
        .into()
    })
}

// ---------------------------------------------------------------------------
// AuthenticatedServiceAccount extractor
// ---------------------------------------------------------------------------

fn extract_service_account(
    req: &HttpRequest,
) -> Result<AuthenticatedServiceAccount, AxiamApiError> {
    let validated = parse_validated_claims(req)?;

    match validated.0.aud.as_deref() {
        Some(AUD_M2M) => {
            // Expected audience — accept.
        }
        Some(AUD_USER) => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "audience mismatch — this route requires axiam:m2m audience".into(),
            }
            .into());
        }
        Some(_) | None => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "audience mismatch — this route requires axiam:m2m audience".into(),
            }
            .into());
        }
    }

    let tenant_id =
        Uuid::parse_str(&validated.0.tenant_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id claim".into(),
        })?;

    Ok(AuthenticatedServiceAccount {
        client_id: validated.0.sub.clone(),
        tenant_id,
        claims: validated,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use axiam_auth::token::{issue_access_token, issue_client_credentials_token};
    use uuid::Uuid;

    fn test_auth_config() -> AuthConfig {
        let private_key = "\
-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n\
-----END PRIVATE KEY-----";
        let public_key = "\
-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n\
-----END PUBLIC KEY-----";
        AuthConfig {
            jwt_private_key_pem: private_key.into(),
            jwt_public_key_pem: public_key.into(),
            access_token_lifetime_secs: 900,
            refresh_token_lifetime_secs: 2_592_000,
            jwt_issuer: "axiam-test".into(),
            pepper: None,
            min_password_length: 12,
            mfa_encryption_key: None,
            federation_encryption_key: None,
            allow_missing_aud_as_user: true,
            cookie_secure: true,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM-Test".into(),
            max_failed_login_attempts: 5,
            lockout_duration_secs: 300,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
            auth_code_lifetime_secs: 600,
            oauth2_issuer_url: String::new(),
            email_verification_grace_period_hours: 24,
            password_reset_token_expiry_hours: 1,
            webauthn_rp_id: "localhost".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            webauthn_rp_name: "AXIAM-Test".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
        }
    }

    fn make_user_token(config: &AuthConfig, jti: Option<String>) -> String {
        let jti = jti.unwrap_or_else(|| Uuid::new_v4().to_string());
        issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            config,
            jti,
            AUD_USER,
        )
        .unwrap()
    }

    fn make_m2m_token(config: &AuthConfig) -> String {
        issue_client_credentials_token("my-service", Uuid::new_v4(), Uuid::new_v4(), &[], config)
            .unwrap()
    }

    fn make_no_aud_token(config: &AuthConfig) -> String {
        // Manually craft via issue_access_token then patch — actually simpler to
        // issue a user token and strip aud. We don't have that API, so instead
        // we use the fact that decode_access_token does not require aud.
        // The simplest approach: issue with AUD_USER but override aud to None
        // by constructing claims manually.
        use axiam_auth::token::AccessTokenClaims;
        use chrono::Utc;
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let now = Utc::now().timestamp();
        let claims = AccessTokenClaims {
            sub: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            org_id: Uuid::new_v4().to_string(),
            iss: "axiam-test".into(),
            iat: now,
            exp: now + 900,
            jti: Uuid::new_v4().to_string(),
            aud: None, // no audience
            scope: None,
        };
        let key = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes()).unwrap();
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn req_with_config_and_bearer(config: AuthConfig, token: &str) -> actix_web::HttpRequest {
        TestRequest::default()
            .app_data(web::Data::new(config))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request()
    }

    // -----------------------------------------------------------------------
    // AuthenticatedUser tests
    // -----------------------------------------------------------------------

    #[test]
    fn accepts_axiam_user_audience() {
        let config = test_auth_config();
        let token = make_user_token(&config, None);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn accepts_missing_aud_when_flag_true() {
        let mut config = test_auth_config();
        config.allow_missing_aud_as_user = true;
        let token = make_no_aud_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(
            result.is_ok(),
            "expected Ok with flag=true, got: {result:?}"
        );
    }

    #[test]
    fn rejects_missing_aud_when_flag_false() {
        let mut config = test_auth_config();
        config.allow_missing_aud_as_user = false;
        let token = make_no_aud_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(result.is_err(), "expected 401, got Ok when flag=false");
    }

    #[test]
    fn rejects_axiam_m2m_audience_on_user_route() {
        let config = test_auth_config();
        let token = make_m2m_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(
            result.is_err(),
            "expected rejection of m2m token on user route"
        );
    }

    #[test]
    fn session_id_matches_jti() {
        let config = test_auth_config();
        let jti = "11111111-1111-1111-1111-111111111111".to_string();
        let token = make_user_token(&config, Some(jti.clone()));
        let req = req_with_config_and_bearer(config, &token);
        let user = extract_user(&req).expect("should succeed");
        assert_eq!(user.session_id.to_string(), jti);
    }

    // -----------------------------------------------------------------------
    // AuthenticatedServiceAccount tests
    // -----------------------------------------------------------------------

    #[test]
    fn service_account_extractor_accepts_m2m() {
        let config = test_auth_config();
        let token = make_m2m_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_service_account(&req);
        assert!(result.is_ok(), "expected Ok for m2m token, got: {result:?}");
    }

    #[test]
    fn service_account_extractor_rejects_user_token() {
        let config = test_auth_config();
        let token = make_user_token(&config, None);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_service_account(&req);
        assert!(
            result.is_err(),
            "expected rejection of user token on m2m route"
        );
    }
}
