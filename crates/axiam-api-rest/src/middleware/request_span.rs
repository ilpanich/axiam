//! The request tracer's root span, with credentials kept out of the target
//! (F4 P23W3-03, closing T-325).
//!
//! `tracing-actix-web`'s [`DefaultRootSpanBuilder`] records `http.target` as
//! the request's path **and query string**, verbatim, on every route — and the
//! JSON log formatter repeats a span's fields on every event logged inside it.
//! Several query parameters are bearer values or personal data: the SAML SSO
//! endpoint's pending-sign-on `handle`, `RelayState` and `SAMLRequest` (T23.2.3),
//! `/oauth2/authorize`'s `state` and `login_hint`, `end_session`'s
//! `id_token_hint`, a password-reset or GDPR-cancellation `token`, an
//! administrator's `search` term. A log reader — or a log pipeline — held all
//! of them.
//!
//! [`RedactingRootSpanBuilder`] records the same field set as the default
//! builder, under the same span name and target (so `RUST_LOG` filters select
//! it exactly as before), with one difference: `http.target` is
//! [`redacted_target`] — every query **value** is replaced by `[redacted]`
//! unless its parameter is on the short list of structural ones in
//! [`KEPT_QUERY_PARAMETERS`], and a path segment matched by a `{token}` route
//! parameter is replaced too. Parameter **names** stay, so a log still says
//! which parameters a request carried. It records no header but `User-Agent`,
//! as the default builder does (W8 / T9.4).
//!
//! An allow-list, not a deny-list: a parameter added tomorrow is redacted until
//! somebody decides its value is harmless, rather than logged until somebody
//! notices it is not.

use actix_web::Error;
use actix_web::HttpMessage;
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use tracing::Span;
use tracing_actix_web::{DefaultRootSpanBuilder, RequestId, RootSpanBuilder};

/// What a redacted value is replaced with.
pub const REDACTED: &str = "[redacted]";

/// The query parameters whose values are recorded as sent: identifiers of a
/// tenant, organization or client, protocol switches and pagination. Never a
/// credential, a handle, a hint, a redirect target or a search term.
pub const KEPT_QUERY_PARAMETERS: &[&str] = &[
    "tenant_id",
    "org_id",
    "organization_id",
    "client_id",
    "response_type",
    "response_mode",
    "scope",
    "prompt",
    "max_age",
    "display",
    "ui_locales",
    "axiam_login_hop",
    "reauth",
    "SigAlg",
    "limit",
    "offset",
    "page",
    "per_page",
    "sort",
    "order",
];

/// Route parameters whose path segment is a bearer value (`/account/export/{token}`).
const REDACTED_PATH_PARAMETERS: &[&str] = &["token"];

/// The span target the default builder's spans carry. Kept, so a deployment's
/// `RUST_LOG` directives select the root span exactly as before (with the
/// shipped `axiam=info` filter it is not recorded at all unless an operator
/// enables `tracing_actix_web`).
const SPAN_TARGET: &str = "tracing_actix_web::root_span_builder";

/// `path` and `query` as they may be recorded: query values redacted except
/// for [`KEPT_QUERY_PARAMETERS`], and every path segment that `pattern` (the
/// matched route, `{name}` placeholders included) marks as a token replaced by
/// [`REDACTED`].
#[must_use]
pub fn redacted_target(path: &str, query: &str, pattern: Option<&str>) -> String {
    let mut out = redacted_path(path, pattern);
    if query.is_empty() {
        return out;
    }
    out.push('?');
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((name, value)) => {
                out.push_str(name);
                out.push('=');
                let decoded = percent_decoded_name(name);
                if KEPT_QUERY_PARAMETERS.contains(&decoded.as_str()) {
                    out.push_str(value);
                } else {
                    out.push_str(REDACTED);
                }
            }
            None => out.push_str(pair),
        }
    }
    out
}

fn percent_decoded_name(name: &str) -> String {
    url::form_urlencoded::parse(name.as_bytes())
        .next()
        .map(|(decoded, _)| decoded.into_owned())
        .unwrap_or_default()
}

fn redacted_path(path: &str, pattern: Option<&str>) -> String {
    let Some(pattern) = pattern else {
        return path.to_owned();
    };
    let segments: Vec<&str> = path.split('/').collect();
    let placeholders: Vec<&str> = pattern.split('/').collect();
    if segments.len() != placeholders.len() {
        return path.to_owned();
    }
    segments
        .iter()
        .zip(placeholders)
        .map(|(segment, placeholder)| {
            let name = placeholder
                .strip_prefix('{')
                .and_then(|p| p.strip_suffix('}'))
                .map(|p| p.split(':').next().unwrap_or_default());
            match name {
                Some(name) if REDACTED_PATH_PARAMETERS.contains(&name) => REDACTED,
                _ => segment,
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn http_flavor(version: actix_web::http::Version) -> &'static str {
    use actix_web::http::Version;
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "other",
    }
}

/// The root span builder `axiam-server` wraps the application in. See the
/// module documentation.
pub struct RedactingRootSpanBuilder;

impl RootSpanBuilder for RedactingRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        let user_agent = request
            .headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let pattern = request.match_pattern();
        let route = pattern.as_deref().unwrap_or("default");
        let method = request.method().as_str();
        let target = redacted_target(request.path(), request.query_string(), pattern.as_deref());
        let connection_info = request.connection_info();
        let request_id = request
            .extensions()
            .get::<RequestId>()
            .map(ToString::to_string)
            .unwrap_or_default();
        tracing::info_span!(
            target: SPAN_TARGET,
            "HTTP request",
            http.method = %method,
            http.route = %route,
            http.flavor = %http_flavor(request.version()),
            http.scheme = %connection_info.scheme(),
            http.host = %connection_info.host(),
            http.client_ip = %connection_info.realip_remote_addr().unwrap_or(""),
            http.user_agent = %user_agent,
            http.target = %target,
            http.status_code = tracing::field::Empty,
            otel.name = %format!("{method} {route}"),
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            trace_id = tracing::field::Empty,
            request_id = %request_id,
            exception.message = tracing::field::Empty,
            exception.details = tracing::field::Empty,
        )
    }

    fn on_request_end<B: MessageBody>(span: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use actix_web::{App, HttpResponse, web};
    use tracing_actix_web::TracingLogger;

    use super::*;

    /// T-325's values and the pre-existing bearer and personal values, each
    /// redacted; structural values kept; names kept.
    #[test]
    fn query_values_are_redacted_unless_structural() {
        let target = redacted_target(
            "/saml/v2/0b5f1d6e-6f0a-4c39-9d1e-2b8f2a1c7e10/sso/continue",
            "handle=AbC-_09&axiam_login_hop=1",
            None,
        );
        assert_eq!(
            target,
            "/saml/v2/0b5f1d6e-6f0a-4c39-9d1e-2b8f2a1c7e10/sso/continue?handle=[redacted]&axiam_login_hop=1"
        );
        for sensitive in [
            "RelayState",
            "SAMLRequest",
            // T23.2.4: the single-logout endpoint's second message parameter.
            "SAMLResponse",
            "Signature",
            "state",
            "login_hint",
            "id_token_hint",
            "code",
            "code_challenge",
            "nonce",
            "redirect_uri",
            "token",
            "user_code",
            "search",
            "request_uri",
            "handle",
        ] {
            let query = format!("{sensitive}=probe-value-123&tenant_id=t-1");
            let recorded = redacted_target("/x", &query, None);
            assert!(!recorded.contains("probe-value-123"), "{sensitive} leaked");
            assert!(recorded.contains(&format!("{sensitive}={REDACTED}")));
            assert!(recorded.ends_with("&tenant_id=t-1"));
        }
        // A percent-encoded name is judged by its decoded spelling, and still
        // recorded as sent.
        assert_eq!(
            redacted_target("/x", "tenant%5Fid=t-1&st%61te=v", None),
            "/x?tenant%5Fid=t-1&st%61te=[redacted]"
        );
        assert_eq!(redacted_target("/x", "", None), "/x");
        assert_eq!(redacted_target("/x", "flag", None), "/x?flag");
    }

    /// T23.2.4, T-377: no single-logout message parameter is a kept one. The
    /// message, its relay state and its signature are redacted by default;
    /// `SigAlg` — an algorithm URI, no value of anyone's — is the one structural
    /// parameter of the Redirect binding the list already kept before `/slo`
    /// existed, and nothing was added for it.
    #[test]
    fn the_single_logout_parameters_are_redacted_and_none_was_added_to_the_kept_list() {
        for name in ["SAMLRequest", "SAMLResponse", "RelayState", "Signature"] {
            assert!(
                !KEPT_QUERY_PARAMETERS.contains(&name),
                "{name} must not be a kept parameter"
            );
        }
        let target = redacted_target(
            "/saml/v2/0b5f1d6e-6f0a-4c39-9d1e-2b8f2a1c7e10/slo",
            "SAMLResponse=probe-value&RelayState=probe-relay&SigAlg=probe-alg&Signature=probe-sig",
            None,
        );
        assert_eq!(
            target,
            "/saml/v2/0b5f1d6e-6f0a-4c39-9d1e-2b8f2a1c7e10/slo?SAMLResponse=[redacted]&RelayState=[redacted]&SigAlg=probe-alg&Signature=[redacted]"
        );
    }

    #[test]
    fn a_token_route_parameter_is_redacted_from_the_path() {
        assert_eq!(
            redacted_target(
                "/api/v1/account/export/export-handle-value",
                "",
                Some("/api/v1/account/export/{token}")
            ),
            "/api/v1/account/export/[redacted]"
        );
        assert_eq!(
            redacted_target("/api/v1/users/42", "", Some("/api/v1/users/{user_id}")),
            "/api/v1/users/42"
        );
    }

    /// The span the application actually records: run a request through
    /// `TracingLogger` with this builder and read the `http.target` it wrote.
    #[actix_rt::test]
    async fn the_recorded_span_carries_the_redacted_target() {
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let app = actix_web::test::init_service(
            App::new()
                .wrap(TracingLogger::<RedactingRootSpanBuilder>::new())
                .route(
                    "/saml/v2/{tenant_id}/sso/continue",
                    web::get().to(|| async {
                        tracing::info!("inside the request");
                        HttpResponse::Ok().finish()
                    }),
                ),
        )
        .await;
        let request = actix_web::test::TestRequest::get()
            .uri("/saml/v2/t-1/sso/continue?handle=AbC-handle-value&axiam_login_hop=1")
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert!(response.status().is_success());

        let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(log.contains("inside the request"), "the event was recorded");
        assert!(
            log.contains("handle=[redacted]&axiam_login_hop=1"),
            "the span records the redacted target"
        );
        assert!(
            !log.contains("AbC-handle-value"),
            "the handle never reaches the log"
        );
    }
}
