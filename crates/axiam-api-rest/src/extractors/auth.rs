//! JWT-based authentication extractor.
//!
//! [`AuthenticatedUser`] implements Actix-Web's `FromRequest` trait.
//! It extracts and validates the `Authorization: Bearer <token>` header,
//! returning the authenticated user's identity.

use std::sync::Arc;

use actix_web::dev::Payload;
use actix_web::web;
use actix_web::{HttpMessage, HttpRequest};
use axiam_audit::middleware::CachedUserIdentity;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{ValidatedClaims, validate_access_token};
use axiam_core::error::AxiamError;
use uuid::Uuid;

use crate::error::AxiamApiError;

/// Authenticated user context extracted from a valid JWT.
///
/// Use this as a handler parameter to require authentication.
/// If the audit middleware has already validated the token, the cached
/// claims are reused to avoid double verification.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub claims: ValidatedClaims,
}

impl actix_web::FromRequest for AuthenticatedUser {
    type Error = AxiamApiError;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        std::future::ready(extract_user(req))
    }
}

fn extract_user(req: &HttpRequest) -> Result<AuthenticatedUser, AxiamApiError> {
    // Try to reuse claims cached by the audit middleware.
    if let Some(cached) = req.extensions().get::<Arc<CachedUserIdentity>>() {
        return Ok(AuthenticatedUser {
            user_id: cached.user_id,
            tenant_id: cached.tenant_id,
            org_id: cached.org_id,
            claims: cached.claims.clone(),
        });
    }

    let config = req
        .app_data::<web::Data<AuthConfig>>()
        .ok_or(AxiamError::Internal("missing auth config".into()))?;

    let header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AxiamError::AuthenticationFailed {
            reason: "missing Authorization header".into(),
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

    let token = credentials;
    let validated = validate_access_token(token, config).map_err(AxiamError::from)?;

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
        claims: validated,
    })
}
