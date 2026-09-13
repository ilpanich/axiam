//! SCIM error responses (RFC 7644 §3.12).
//!
//! A SCIM error body is NOT the same shape as AXIAM's ordinary REST error
//! envelope (`axiam_api_rest::error::AxiamApiError`) — it has its own
//! `schemas`/`status`/`scimType`/`detail` fields, mandated by the spec so
//! generic SCIM clients (Okta, Entra, ...) can parse failures uniformly
//! across every vendor's implementation. [`ScimError`] is that shape;
//! `From<AxiamError>`/`From<AxiamApiError>` translate AXIAM's own error
//! taxonomy into it so handlers can freely `?`-propagate repository and
//! authorization errors without hand-mapping each call site.

use actix_web::http::{StatusCode, header};
use actix_web::{HttpResponse, ResponseError};
use axiam_api_rest::AxiamApiError;
use axiam_core::error::AxiamError;
use serde::Serialize;

/// `urn:ietf:params:scim:api:messages:2.0:Error` (RFC 7644 §3.12).
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

#[derive(Debug)]
pub struct ScimError {
    pub status: StatusCode,
    /// RFC 7644 §3.12 `scimType` — a detail code for 400/409 responses.
    /// `None` for status codes the RFC doesn't define a `scimType` table for
    /// (401/403/404/5xx).
    pub scim_type: Option<&'static str>,
    pub detail: String,
    /// Seconds to put in `Retry-After`, set only on a *retry advisory* — a
    /// transient failure the caller is being told to repeat (T-262 / R-4).
    ///
    /// Its presence does two things in [`ResponseError::error_response`]: it
    /// emits the header, and it exempts the body from the blanket 5xx
    /// redaction. Set it only from a fixed, payload-free `detail`; see
    /// [`ScimError::retry_later`].
    pub retry_after: Option<u32>,
}

impl ScimError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type: None,
            detail: detail.into(),
            retry_after: None,
        }
    }

    pub fn with_type(
        status: StatusCode,
        scim_type: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            scim_type: Some(scim_type),
            detail: detail.into(),
            retry_after: None,
        }
    }

    /// A transient failure the caller is being told to repeat: `503` plus the
    /// `Retry-After: secs` that makes the status actionable (T-262 / R-4).
    ///
    /// Unlike every other 5xx this type produces, the `detail` reaches the
    /// client verbatim — so it MUST be a fixed sentence carrying no payload.
    /// Nothing derived from a datastore message, a query, or a caller's input
    /// may be interpolated into it.
    pub fn retry_later(detail: impl Into<String>, secs: u32) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            // RFC 7644 §3.12 defines no `scimType` for 503.
            scim_type: None,
            detail: detail.into(),
            retry_after: Some(secs),
        }
    }

    pub fn not_found(resource_type: &str, id: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            format!("{resource_type} {id} not found"),
        )
    }

    /// RFC 7644 §3.12: 400 with `scimType: invalidFilter` — the caller sent a
    /// filter expression outside the supported subset (`userName eq`,
    /// `externalId eq`). Complex filters are explicitly out of scope (B4).
    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self::with_type(StatusCode::BAD_REQUEST, "invalidFilter", detail)
    }

    /// RFC 7644 §3.12: 400 with `scimType: invalidPath` — an unsupported (or
    /// malformed) PATCH `path`. B4 restricts PATCH to the standard attribute
    /// paths Okta/Entra actually send; anything else lands here.
    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self::with_type(StatusCode::BAD_REQUEST, "invalidPath", detail)
    }

    /// RFC 7644 §3.12: 400 with `scimType: invalidValue`.
    pub fn invalid_value(detail: impl Into<String>) -> Self {
        Self::with_type(StatusCode::BAD_REQUEST, "invalidValue", detail)
    }

    /// RFC 7644 §3.12: 400 with `scimType: mutability` — an attempt to write
    /// a read-only/immutable attribute.
    pub fn mutability(detail: impl Into<String>) -> Self {
        Self::with_type(StatusCode::BAD_REQUEST, "mutability", detail)
    }

    /// RFC 7644 §3.12: 501 Not Implemented — bulk operations and complex
    /// filters are explicitly out of scope for this crate (B4). The RFC does
    /// not define a `scimType` for 501, so `scim_type` stays `None`.
    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, detail)
    }
}

impl std::fmt::Display for ScimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SCIM error {}: {}", self.status, self.detail)
    }
}

impl std::error::Error for ScimError {}

#[derive(Serialize)]
struct ScimErrorBody {
    schemas: [&'static str; 1],
    status: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "scimType")]
    scim_type: Option<&'static str>,
    detail: String,
}

impl ResponseError for ScimError {
    fn status_code(&self) -> StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        let mut builder = HttpResponse::build(self.status);
        // T-262 / R-4: the half of the contract that makes a 503 useful.
        // CONTRACT §16.1 makes every SDK honour `Retry-After` as a **floor**,
        // so the caller's own backoff still governs the wait. Set from the
        // same field the redaction carve-out below reads, so the header and
        // the body it explains cannot drift apart.
        if let Some(secs) = self.retry_after {
            builder.insert_header((header::RETRY_AFTER, secs.to_string()));
        }

        if self.status.is_server_error() {
            if self.retry_after.is_none() {
                // SEC-011/CQ-B33 parity with AxiamApiError: never leak internal
                // detail (DB strings, etc.) in a 5xx body — log it instead.
                tracing::error!(status = %self.status, detail = %self.detail, "SCIM internal error");
                return builder.json(ScimErrorBody {
                    schemas: [SCIM_ERROR_SCHEMA],
                    status: self.status.as_u16().to_string(),
                    scim_type: None,
                    detail: "An internal error occurred".to_string(),
                });
            }
            // A retry advisory is the one 5xx whose detail is echoed: it is a
            // fixed constant (see `retry_later`), and redacting it would turn
            // "retry this request" into "the server broke" — a dead end for
            // the provisioning IdP the `Retry-After` above is aimed at. Still
            // logged, at WARN rather than ERROR: sustained contention is worth
            // an operator's attention, but it is not a fault.
            tracing::warn!(status = %self.status, detail = %self.detail, "SCIM transient failure");
        }

        builder.json(ScimErrorBody {
            schemas: [SCIM_ERROR_SCHEMA],
            status: self.status.as_u16().to_string(),
            scim_type: self.scim_type,
            detail: self.detail.clone(),
        })
    }
}

/// Translate AXIAM's own error taxonomy into the SCIM error shape so
/// handlers can `?`-propagate repository calls directly.
impl From<AxiamError> for ScimError {
    fn from(err: AxiamError) -> Self {
        match &err {
            AxiamError::NotFound { entity, id } => {
                Self::new(StatusCode::NOT_FOUND, format!("{entity} {id} not found"))
            }
            AxiamError::AlreadyExists { entity } => Self::with_type(
                StatusCode::CONFLICT,
                "uniqueness",
                format!("{entity} already exists"),
            ),
            AxiamError::AuthenticationFailed { reason } => {
                Self::new(StatusCode::UNAUTHORIZED, reason.clone())
            }
            AxiamError::AuthorizationDenied { reason, .. } => {
                Self::new(StatusCode::FORBIDDEN, reason.clone())
            }
            AxiamError::Validation { message } => Self::invalid_value(message.clone()),
            AxiamError::PasswordPolicy { message } => Self::invalid_value(message.clone()),
            AxiamError::TenantContext => {
                Self::new(StatusCode::BAD_REQUEST, "tenant context missing or invalid")
            }
            AxiamError::RateLimited => {
                Self::new(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
            }
            AxiamError::ServiceUnavailable(msg) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, msg.clone())
            }
            // T-262 / R-4, completing `3ccef6a30`, which wired this variant
            // into REST and gRPC but not here. A SCIM caller that lost an
            // optimistic-concurrency race must be told to repeat the request,
            // not that the server broke: an IdP reading a 500 marks the sync
            // failed and re-sends the whole record. `err.to_string()` is safe
            // to echo because the variant carries no payload — the engine's
            // own words stay on `DbError::Conflict`, in the log.
            //
            // Not a 409/`uniqueness`: RFC 7644 §3.12 reads that as "your
            // request conflicts with the resource's state", which would have
            // the client change the request rather than resend it.
            AxiamError::WriteContention => Self::retry_later(err.to_string(), 1),
            // 5xx-shaped variants: message content is dropped by
            // `error_response`'s server-error branch above regardless of what
            // we put in `detail`, so a plain `to_string()` here is fine.
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        }
    }
}

/// `RequirePermission::check` returns `AxiamApiError` (axiam-api-rest's own
/// newtype). Unwrap it back to `AxiamError` and reuse the mapping above so
/// SCIM authorization denials get a proper SCIM error body instead of
/// AXIAM's ordinary REST envelope.
impl From<AxiamApiError> for ScimError {
    fn from(err: AxiamApiError) -> Self {
        err.0.into()
    }
}

#[cfg(test)]
mod tests {
    use actix_web::body::MessageBody;

    use super::*;

    /// The whole point of this module: a SCIM client must never receive AXIAM's
    /// ordinary REST envelope. Each arm below pins the STATUS and the RFC 7644
    /// `scimType` a generic SCIM client (Okta, Entra) dispatches on — getting
    /// the status right but the `scimType` wrong is a silent interop failure,
    /// because those clients branch on `scimType` to decide whether to retry,
    /// re-map an attribute, or surface a conflict to an administrator.
    #[test]
    fn axiam_errors_map_to_the_rfc_7644_status_and_scim_type() {
        let cases: Vec<(AxiamError, StatusCode, Option<&'static str>)> = vec![
            (
                AxiamError::NotFound {
                    entity: "User".into(),
                    id: "abc".into(),
                },
                StatusCode::NOT_FOUND,
                None,
            ),
            // `uniqueness` is the one a provisioning client acts on: it means
            // "this user already exists", not "retry later".
            (
                AxiamError::AlreadyExists {
                    entity: "User".into(),
                },
                StatusCode::CONFLICT,
                Some("uniqueness"),
            ),
            (
                AxiamError::AuthenticationFailed {
                    reason: "bad token".into(),
                },
                StatusCode::UNAUTHORIZED,
                None,
            ),
            (
                AxiamError::AuthorizationDenied {
                    reason: "no grant".into(),
                    action: Some("users:create".into()),
                    resource_id: None,
                },
                StatusCode::FORBIDDEN,
                None,
            ),
            (
                AxiamError::Validation {
                    message: "userName is required".into(),
                },
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
            ),
            (
                AxiamError::PasswordPolicy {
                    message: "too short".into(),
                },
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
            ),
            (AxiamError::TenantContext, StatusCode::BAD_REQUEST, None),
            (AxiamError::RateLimited, StatusCode::TOO_MANY_REQUESTS, None),
            (
                AxiamError::ServiceUnavailable("db down".into()),
                StatusCode::SERVICE_UNAVAILABLE,
                None,
            ),
            // T-262 / R-4: 503, NOT the 500 the catch-all used to give it, and
            // not the 409 `uniqueness` that would have the client rewrite the
            // request instead of repeating it.
            (
                AxiamError::WriteContention,
                StatusCode::SERVICE_UNAVAILABLE,
                None,
            ),
            // The catch-all: every remaining variant is 5xx-shaped.
            (
                AxiamError::Database("connection reset".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
            ),
            (
                AxiamError::Internal("boom".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
            ),
        ];

        for (err, want_status, want_type) in cases {
            let rendered = format!("{err}");
            let scim: ScimError = err.into();
            assert_eq!(scim.status, want_status, "status for {rendered}");
            assert_eq!(scim.scim_type, want_type, "scimType for {rendered}");
        }
    }

    #[test]
    fn not_found_detail_names_the_entity_and_id() {
        let scim: ScimError = AxiamError::NotFound {
            entity: "Group".into(),
            id: "g-1".into(),
        }
        .into();
        assert!(scim.detail.contains("Group"), "detail: {}", scim.detail);
        assert!(scim.detail.contains("g-1"), "detail: {}", scim.detail);
    }

    #[test]
    fn status_code_is_the_status_the_error_carries() {
        // ResponseError::status_code is what Actix uses to build the response
        // line; a constructor that set `status` without it being reflected here
        // would send a 200 with an error body.
        let e = ScimError::not_implemented("bulk is out of scope");
        assert_eq!(ResponseError::status_code(&e), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(e.scim_type, None);

        let m = ScimError::mutability("readOnly attribute");
        assert_eq!(ResponseError::status_code(&m), StatusCode::BAD_REQUEST);
        assert_eq!(m.scim_type, Some("mutability"));
    }

    #[test]
    fn display_carries_the_status_and_detail_for_logs() {
        let e = ScimError::new(StatusCode::NOT_FOUND, "User 42 not found");
        let s = e.to_string();
        assert!(s.contains("404"), "{s}");
        assert!(s.contains("User 42 not found"), "{s}");
    }

    /// Render an error the way Actix will, so a test can read the status, the
    /// `Retry-After` header and the JSON body a SCIM client actually receives
    /// — the three things the T-262 contract is written in terms of.
    fn render(err: ScimError) -> (StatusCode, Option<String>, serde_json::Value) {
        let response = ResponseError::error_response(&err);
        let status = response.status();
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = response.into_body().try_into_bytes().unwrap();
        (status, retry_after, serde_json::from_slice(&bytes).unwrap())
    }

    /// SEC-011: a 5xx body must not echo the internal detail — the DB string
    /// that produced it goes to the log, not to a SCIM client. This is the
    /// asymmetry worth pinning, since the 4xx branch DOES echo detail.
    ///
    /// It is also the **control** for the `WriteContention` carve-out below:
    /// that carve-out must stay one variant wide, so this asserts the actual
    /// body, not merely the status.
    #[test]
    fn server_errors_do_not_leak_detail_into_the_body() {
        let (status, retry_after, body) =
            render(AxiamError::Database("host=db-1 user=axiam".into()).into());
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(retry_after, None, "a 500 must not advertise a retry");
        assert_eq!(body["detail"], "An internal error occurred");
        let rendered = body.to_string();
        for leak in ["host=db-1", "user=axiam"] {
            assert!(
                !rendered.contains(leak),
                "{leak:?} must not appear in the response body: {rendered}"
            );
        }

        let client_error = ScimError::invalid_value("userName is required");
        let resp = ResponseError::error_response(&client_error);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// T-262 / R-4, completing `3ccef6a30`. A SCIM caller that loses an
    /// optimistic-concurrency race is told to come back, not that the server
    /// broke — the whole point being that an IdP (Okta, Entra) can tell a
    /// repeatable request from a failed sync it must re-send in full.
    #[test]
    fn a_contended_write_answers_503_with_retry_after() {
        let (status, retry_after, body) = render(AxiamError::WriteContention.into());
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the catch-all must no longer swallow this variant"
        );
        assert_eq!(retry_after.as_deref(), Some("1"));
        assert_eq!(body["status"], "503");
        // RFC 7644 §3.12 defines no `scimType` for 5xx.
        assert_eq!(body.get("scimType"), None);
    }

    /// The half a naïve match arm alone would still get wrong: the blanket 5xx
    /// redaction would replace the one detail that is worth sending, leaving a
    /// client with a `Retry-After` and a body saying the server is broken.
    #[test]
    fn the_retry_advisory_detail_survives_the_5xx_redaction() {
        let (_, _, body) = render(AxiamError::WriteContention.into());
        assert_ne!(
            body["detail"], "An internal error occurred",
            "the carve-out is what makes the 503 actionable"
        );
        assert_eq!(body["detail"], AxiamError::WriteContention.to_string());
    }

    /// The variant carries no payload, so the engine's own words cannot reach
    /// the body by accident — only by somebody giving it a payload "for
    /// debugging". That is what this pins, now that the detail is echoed.
    #[test]
    fn the_retry_advisory_never_carries_the_engines_message() {
        let (_, _, body) = render(AxiamError::WriteContention.into());
        let rendered = body.to_string();
        for leak in ["Transaction", "write conflict", "surreal", "SurrealDB"] {
            assert!(
                !rendered.contains(leak),
                "{leak:?} must not appear in the response body: {rendered}"
            );
        }
    }

    /// The other 503 is a different operational event — the Argon2 gate, not
    /// the datastore — and it is not a retry advisory: it gains no header and
    /// keeps the blanket redaction. Same split `axiam-api-rest` draws.
    #[test]
    fn the_other_503_is_a_different_answer() {
        let (status, retry_after, body) =
            render(AxiamError::ServiceUnavailable("hash gate saturated".into()).into());
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after, None);
        assert_eq!(body["detail"], "An internal error occurred");
    }
}
