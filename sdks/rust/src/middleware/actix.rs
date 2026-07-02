//! Actix-Web `FromRequest` extractor `AxiamUser` (CONTRACT.md §10).
//!
//! Mirrors the server's JWT auth extractor (`extractors/auth.rs` under the
//! REST API crate) — **mirror only, do not import** (that file depends on
//! server-only auth/core/db crates that this SDK may not depend on; see
//! 16-PATTERNS.md for the full domain-boundary rule).
//!
//! ## §10 contract steps implemented here
//! 1. Extract the session from the `axiam_access` cookie, falling back to
//!    `Authorization: Bearer <token>` (§10.1, cookie-then-header).
//! 2. Verify the token locally against the cached JWKS from 16-02's
//!    [`crate::token::JwksVerifier`] via `app_data` — no AXIAM-server
//!    round-trip (§10.2).
//! 3. Build and inject `AxiamUser { user_id, tenant_id, roles }` from the
//!    verified claims (§10.3).
//! 4. Map `AuthError` -> HTTP 401 and `AuthzError` -> HTTP 403 with a
//!    standardized JSON error body (§10 closing requirement), via
//!    [`AxiamExtractorError`]'s `actix_web::ResponseError` impl.
//!
//! The verified result is never cached beyond the token's own `exp` — the
//! [`crate::token::JwksVerifier`] re-checks `exp` on every call, so no
//! additional TTL bookkeeping is needed here (§10 "MUST NOT cache session
//! verification results longer than the token's remaining TTL").

use std::future::Future;
use std::pin::Pin;

use actix_web::{dev::Payload, web, HttpRequest, HttpResponse};
use serde::Serialize;
use uuid::Uuid;

use crate::token::JwksVerifier;
use crate::AxiamError;

/// Authenticated identity injected by the [`AxiamUser`] extractor.
///
/// At minimum carries `user_id`, `tenant_id`, and `roles` per CONTRACT.md
/// §10's closing "Interface contract" clause.
#[derive(Debug, Clone)]
pub struct AxiamUser {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    /// Derived from the verified access token's `scope` claim (space-separated
    /// OAuth2 scopes) — AXIAM's `AccessTokenClaims` has no dedicated `roles`
    /// claim (confirmed against `crates/axiam-auth/src/token.rs`), so `scope`
    /// is the closest available authorization-relevant claim to surface here.
    /// Empty when the token carries no `scope` claim.
    pub roles: Vec<String>,
}

/// The SDK's extractor-local error type, mapping to the standardized JSON
/// error body + HTTP status per CONTRACT.md §10's closing requirement
/// (`AuthError` -> 401, `AuthzError` -> 403).
#[derive(Debug)]
pub struct AxiamExtractorError(pub AxiamError);

impl From<AxiamError> for AxiamExtractorError {
    fn from(err: AxiamError) -> Self {
        Self(err)
    }
}

impl std::fmt::Display for AxiamExtractorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Delegate to the inner AxiamError's redacting Display — never emits
        // a raw token value (§7, §10 "standardized JSON error body").
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

impl actix_web::ResponseError for AxiamExtractorError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match &self.0 {
            AxiamError::Auth { .. } => actix_web::http::StatusCode::UNAUTHORIZED,
            AxiamError::Authz { .. } => actix_web::http::StatusCode::FORBIDDEN,
            AxiamError::Network { .. } => actix_web::http::StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let (error, message) = match &self.0 {
            AxiamError::Auth { message } => ("authentication_failed", message.clone()),
            AxiamError::Authz { message, .. } => ("authorization_denied", message.clone()),
            AxiamError::Network { message, .. } => ("authentication_failed", message.clone()),
        };
        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: error.into(),
            message,
        })
    }
}

impl AxiamExtractorError {
    fn missing_credentials() -> Self {
        Self(AxiamError::Auth {
            message: "missing authentication credentials".into(),
        })
    }

    fn invalid_scheme() -> Self {
        Self(AxiamError::Auth {
            message: "invalid Authorization scheme, expected Bearer".into(),
        })
    }

    fn misconfigured() -> Self {
        Self(AxiamError::Auth {
            message: "missing JwksVerifier app_data — extractor misconfigured".into(),
        })
    }

    fn invalid_claim(name: &str) -> Self {
        Self(AxiamError::Auth {
            message: format!("invalid {name} claim"),
        })
    }
}

/// §10.1: extract the bearer token from the `axiam_access` cookie, falling
/// back to the `Authorization: Bearer` header (cookie-then-header, matching
/// the server-side extractor's parse logic — see the module doc comment for
/// the analog file reference).
fn extract_token(req: &HttpRequest) -> Result<String, AxiamExtractorError> {
    if let Some(cookie) = req.cookie("axiam_access") {
        return Ok(cookie.value().to_owned());
    }

    let header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(AxiamExtractorError::missing_credentials)?;

    let header = header.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or("");
    let credentials = parts.next().unwrap_or("").trim();

    if !scheme.eq_ignore_ascii_case("bearer") || credentials.is_empty() {
        return Err(AxiamExtractorError::invalid_scheme());
    }

    Ok(credentials.to_owned())
}

impl actix_web::FromRequest for AxiamUser {
    type Error = AxiamExtractorError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Clone what we need synchronously so the returned future is
        // `'static` and does not borrow `req` (matches the server-side
        // extractor's FromRequest shape — see the module doc comment).
        let token_result = extract_token(req);
        let verifier = req.app_data::<web::Data<JwksVerifier>>().cloned();

        Box::pin(async move {
            let token = token_result?;

            // §10.2: verify locally against the cached JWKS — no
            // AXIAM-server round-trip.
            let verifier = verifier.ok_or_else(AxiamExtractorError::misconfigured)?;
            let claims = verifier.verify(&token).await?;

            // §10.3: build and inject the authenticated identity.
            let user_id = Uuid::parse_str(&claims.sub)
                .map_err(|_| AxiamExtractorError::invalid_claim("sub"))?;
            let tenant_id = Uuid::parse_str(&claims.tenant_id)
                .map_err(|_| AxiamExtractorError::invalid_claim("tenant_id"))?;
            let roles = claims
                .scope
                .as_deref()
                .map(|s| s.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default();

            Ok(AxiamUser {
                user_id,
                tenant_id,
                roles,
            })
        })
    }
}
