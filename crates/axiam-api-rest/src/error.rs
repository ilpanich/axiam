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
            AxiamError::AlreadyExists { .. } | AxiamError::Conflict { .. } => StatusCode::CONFLICT,
            AxiamError::AuthenticationFailed { .. } | AxiamError::ReplayDetected => {
                StatusCode::UNAUTHORIZED
            }
            AxiamError::AuthorizationDenied { .. }
            | AxiamError::OpaqueRequired
            | AxiamError::MfaEnforced => StatusCode::FORBIDDEN,
            AxiamError::Validation { .. } | AxiamError::TenantContext => StatusCode::BAD_REQUEST,
            AxiamError::PasswordPolicy { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            AxiamError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AxiamError::EmailConfig(_) => StatusCode::BAD_REQUEST,
            AxiamError::ServiceUnavailable(_) | AxiamError::WriteContention => {
                StatusCode::SERVICE_UNAVAILABLE
            }
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
            AxiamError::Conflict { .. } => "conflict",
            AxiamError::AuthenticationFailed { .. } | AxiamError::ReplayDetected => {
                "authentication_failed"
            }
            AxiamError::AuthorizationDenied { .. } => "authorization_denied",
            // Distinct from `authentication_failed` on purpose: an SDK reads
            // this to switch to `/auth/opaque/*` rather than to tell the user
            // their password was wrong.
            AxiamError::OpaqueRequired => "opaque_required",
            // Distinct from `authorization_denied` on purpose, and for the
            // same reason `opaque_required` is: the caller holds every
            // permission the action needs — it is their own account — and the
            // refusal is a tenant policy only an administrator can act
            // against. A client switches on this to name the administrator
            // rather than to say "forbidden" (T-267).
            AxiamError::MfaEnforced => "mfa_enforced",
            AxiamError::Validation { .. } => "validation_error",
            AxiamError::PasswordPolicy { .. } => "password_policy_violation",
            AxiamError::TenantContext => "tenant_context",
            AxiamError::RateLimited => "rate_limited",
            AxiamError::EmailConfig(_) => "email_config_error",
            AxiamError::ServiceUnavailable(_) => "service_unavailable",
            // T-262 / R-4. Its own slug rather than `service_unavailable`,
            // because the two are different operational events and an operator
            // reading logs needs to tell "the datastore is contended" from
            // "the Argon2 gate is saturated".
            AxiamError::WriteContention => "write_contention",
            // Server-error variants: log detail, return generic message.
            _ => "internal_error",
        };

        // Client-facing message: echo for known client errors; generic for 5xx.
        // SEC-011/SEC-039/CQ-B33: internal detail (DB strings, crypto messages,
        // stack traces) MUST NOT appear in the response body.
        let message = match &self.0 {
            AxiamError::NotFound { .. }
            | AxiamError::AlreadyExists { .. }
            | AxiamError::Conflict { .. }
            | AxiamError::AuthenticationFailed { .. }
            | AxiamError::ReplayDetected
            | AxiamError::AuthorizationDenied { .. }
            | AxiamError::OpaqueRequired
            | AxiamError::MfaEnforced
            | AxiamError::Validation { .. }
            | AxiamError::PasswordPolicy { .. }
            | AxiamError::TenantContext
            | AxiamError::RateLimited
            | AxiamError::EmailConfig(_)
            | AxiamError::ServiceUnavailable(_)
            // Safe to echo: the variant carries no payload, so its `Display`
            // is the fixed sentence written on it and never the engine's own
            // words, which stay on `DbError::Conflict` for the log.
            | AxiamError::WriteContention => self.0.to_string(),
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

        let mut builder = HttpResponse::build(self.status_code());
        // T-262 / R-4: the one response that carries a header. A contended
        // write is transient, and `Retry-After` is how an HTTP client is told
        // so — CONTRACT §16.1 makes every SDK honour it as a **floor**, so a
        // caller's own backoff still governs the wait and a `1` cannot shorten
        // it. One second is a convention, not a measurement: the server does
        // not know how long contention will last, and a fabricated number
        // would be worse than a conventional one.
        //
        // Set here rather than inside the slug match above so the status and
        // the header cannot drift apart.
        if matches!(self.0, AxiamError::WriteContention) {
            builder.insert_header((actix_web::http::header::RETRY_AFTER, "1"));
        }
        builder.json(ErrorBody {
            error: error_code.into(),
            message,
            action,
            resource_id,
        })
    }
}

#[cfg(test)]
mod write_contention_tests {
    use actix_web::ResponseError;
    use actix_web::body::MessageBody;
    use actix_web::http::header::RETRY_AFTER;

    use super::*;

    fn render(err: AxiamError) -> (u16, Option<String>, serde_json::Value) {
        let response = AxiamApiError(err).error_response();
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = response.into_body().try_into_bytes().unwrap();
        (status, retry_after, serde_json::from_slice(&bytes).unwrap())
    }

    /// T-262 / R-4. A write that lost a datastore race and stayed lost is a
    /// statement about the server, so it answers `503` and says when to come
    /// back — the answer an IdP driving SCIM provisioning retries, rather than
    /// the `500` it reads as a failed sync and recovers from by re-sending the
    /// whole record.
    #[test]
    fn a_contended_write_answers_503_with_retry_after() {
        let (status, retry_after, body) = render(AxiamError::WriteContention);
        assert_eq!(status, 503);
        assert_eq!(retry_after.as_deref(), Some("1"));
        assert_eq!(body["error"], "write_contention");
    }

    /// The response body must never carry the engine's own words. The variant
    /// has no payload, so this cannot regress by accident — but it could
    /// regress by somebody giving it one "for debugging", which is what this
    /// pins.
    #[test]
    fn the_body_never_carries_the_engines_message() {
        let (_, _, body) = render(AxiamError::WriteContention);
        let rendered = body.to_string();
        for leak in ["Transaction", "write conflict", "surreal", "SurrealDB"] {
            assert!(
                !rendered.contains(leak),
                "{leak:?} must not appear in the response body: {rendered}"
            );
        }
    }

    /// **I4 twin.** The two neighbouring answers are unchanged, and they are
    /// the ones it would be easy to fold this into. A uniqueness violation and
    /// a state precondition are both statements about the *request*: they stay
    /// `409`, carry no `Retry-After`, and mean "do something else", not "come
    /// back".
    #[test]
    fn the_409_answers_are_untouched_and_carry_no_retry_after() {
        for (err, slug) in [
            (
                AxiamError::AlreadyExists {
                    entity: "user".into(),
                },
                "already_exists",
            ),
            (
                AxiamError::Conflict {
                    reason: "the export is stale".into(),
                },
                "conflict",
            ),
        ] {
            let (status, retry_after, body) = render(err);
            assert_eq!(status, 409);
            assert_eq!(retry_after, None, "a 409 must not advertise a retry");
            assert_eq!(body["error"], slug);
        }
    }

    /// And `503 service_unavailable` — the Argon2-gate answer — keeps its own
    /// slug and gains no header. The two are different operational events and
    /// an operator reading logs has to be able to tell them apart.
    #[test]
    fn the_other_503_is_a_different_answer() {
        let (status, retry_after, body) =
            render(AxiamError::ServiceUnavailable("hash gate saturated".into()));
        assert_eq!(status, 503);
        assert_eq!(retry_after, None);
        assert_eq!(body["error"], "service_unavailable");
    }
}
