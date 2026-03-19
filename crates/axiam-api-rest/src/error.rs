//! HTTP error response mapping for AXIAM API.
//!
//! Provides [`AxiamApiError`], a newtype around [`AxiamError`] that
//! implements Actix-Web's [`ResponseError`] trait.

use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use axiam_core::error::AxiamError;
use serde::Serialize;

/// Newtype wrapper so we can implement Actix-Web's `ResponseError`
/// for the core `AxiamError` (orphan rule).
#[derive(Debug)]
pub struct AxiamApiError(pub AxiamError);

impl std::fmt::Display for AxiamApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<AxiamError> for AxiamApiError {
    fn from(err: AxiamError) -> Self {
        Self(err)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

impl actix_web::ResponseError for AxiamApiError {
    fn status_code(&self) -> StatusCode {
        match &self.0 {
            AxiamError::NotFound { .. } => StatusCode::NOT_FOUND,
            AxiamError::AlreadyExists { .. } => StatusCode::CONFLICT,
            AxiamError::AuthenticationFailed { .. } => StatusCode::UNAUTHORIZED,
            AxiamError::AuthorizationDenied { .. } => StatusCode::FORBIDDEN,
            AxiamError::Validation { .. } | AxiamError::TenantContext => StatusCode::BAD_REQUEST,
            AxiamError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AxiamError::EmailConfig(_) => StatusCode::BAD_REQUEST,
            AxiamError::Database(_)
            | AxiamError::Certificate(_)
            | AxiamError::Crypto(_)
            | AxiamError::EmailDelivery(_)
            | AxiamError::WebhookDelivery(_)
            | AxiamError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let error = match &self.0 {
            AxiamError::NotFound { .. } => "not_found",
            AxiamError::AlreadyExists { .. } => "already_exists",
            AxiamError::AuthenticationFailed { .. } => "authentication_failed",
            AxiamError::AuthorizationDenied { .. } => "authorization_denied",
            AxiamError::Validation { .. } => "validation_error",
            AxiamError::TenantContext => "tenant_context",
            AxiamError::RateLimited => "rate_limited",
            _ => "internal_error",
        };

        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: error.into(),
            message: self.0.to_string(),
        })
    }
}
