//! HTTP error response mapping for AXIAM API.
//!
//! Provides [`AxiamApiError`], a newtype around [`AxiamError`] that
//! implements Actix-Web's [`ResponseError`] trait.

use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use axiam_core::error::AxiamError;
use serde::Serialize;
use tracing::error;

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
    /// The action being checked (e.g. `"users:create"`), when known.
    /// Populated only for `authorization_denied` (403) responses;
    /// omitted from the JSON body otherwise (SDK-Q02).
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    /// The resource id being checked, when known and not the "global"
    /// nil-UUID sentinel. Populated only for `authorization_denied` (403)
    /// responses; omitted from the JSON body otherwise (SDK-Q02).
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<String>,
}

impl actix_web::ResponseError for AxiamApiError {
    fn status_code(&self) -> StatusCode {
        match &self.0 {
            AxiamError::NotFound { .. } => StatusCode::NOT_FOUND,
            AxiamError::AlreadyExists { .. } => StatusCode::CONFLICT,
            AxiamError::AuthenticationFailed { .. } | AxiamError::ReplayDetected => {
                StatusCode::UNAUTHORIZED
            }
            AxiamError::AuthorizationDenied { .. } => StatusCode::FORBIDDEN,
            AxiamError::Validation { .. } | AxiamError::TenantContext => StatusCode::BAD_REQUEST,
            AxiamError::PasswordPolicy { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            AxiamError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AxiamError::EmailConfig(_) => StatusCode::BAD_REQUEST,
            AxiamError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AxiamError::Database(_)
            | AxiamError::Certificate(_)
            | AxiamError::Crypto(_)
            | AxiamError::EmailDelivery(_)
            | AxiamError::WebhookDelivery(_)
            | AxiamError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // Note: ReplayDetected is handled above in the UNAUTHORIZED arm.
        }
    }

    fn error_response(&self) -> HttpResponse {
        // Client-facing error code slug.
        let error_code = match &self.0 {
            AxiamError::NotFound { .. } => "not_found",
            AxiamError::AlreadyExists { .. } => "already_exists",
            AxiamError::AuthenticationFailed { .. } | AxiamError::ReplayDetected => {
                "authentication_failed"
            }
            AxiamError::AuthorizationDenied { .. } => "authorization_denied",
            AxiamError::Validation { .. } => "validation_error",
            AxiamError::PasswordPolicy { .. } => "password_policy_violation",
            AxiamError::TenantContext => "tenant_context",
            AxiamError::RateLimited => "rate_limited",
            AxiamError::EmailConfig(_) => "email_config_error",
            AxiamError::ServiceUnavailable(_) => "service_unavailable",
            // Server-error variants: log detail, return generic message.
            _ => "internal_error",
        };

        // Client-facing message: echo for known client errors; generic for 5xx.
        // SEC-011/SEC-039/CQ-B33: internal detail (DB strings, crypto messages,
        // stack traces) MUST NOT appear in the response body.
        let message = match &self.0 {
            AxiamError::NotFound { .. }
            | AxiamError::AlreadyExists { .. }
            | AxiamError::AuthenticationFailed { .. }
            | AxiamError::ReplayDetected
            | AxiamError::AuthorizationDenied { .. }
            | AxiamError::Validation { .. }
            | AxiamError::PasswordPolicy { .. }
            | AxiamError::TenantContext
            | AxiamError::RateLimited
            | AxiamError::EmailConfig(_)
            | AxiamError::ServiceUnavailable(_) => self.0.to_string(),
            // 5xx variants: log the detail server-side, return only a generic message.
            _ => {
                error!(
                    error = %self.0,
                    "internal server error"
                );
                "An internal error occurred".to_string()
            }
        };

        // SDK-Q02: surface the checked action/resource on authorization
        // denials so SDKs can parse them from the response body (CONTRACT
        // §2 "if available from the response body"). Every other error
        // kind omits both fields (skip_serializing_if above).
        let (action, resource_id) = match &self.0 {
            AxiamError::AuthorizationDenied {
                action,
                resource_id,
                ..
            } => (action.clone(), resource_id.clone()),
            _ => (None, None),
        };

        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: error_code.into(),
            message,
            action,
            resource_id,
        })
    }
}
