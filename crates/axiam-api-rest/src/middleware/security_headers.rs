//! Actix-Web middleware that injects OWASP-recommended security headers into
//! every HTTP response.
//!
//! Headers added:
//! - `X-Content-Type-Options: nosniff` — prevent MIME-type sniffing
//! - `X-Frame-Options: DENY` — prevent clickjacking
//! - `Referrer-Policy: strict-origin-when-cross-origin` — limit referrer leakage
//! - `Content-Security-Policy` — restrict resource origins (ASVS V14.4.4). The
//!   policy mirrors the frontend Nginx policy (`docker/nginx.conf`) so the one
//!   middleware covers both the JSON API responses and the same-origin Swagger UI
//!   served at `/api/docs/` (swagger-ui 5.x is CSP-friendly: scripts load from
//!   `'self'`; `style-src` allows `'unsafe-inline'` for its runtime-injected
//!   styles and `img-src` allows `data:` for its inline icons).
//!
//! # A response may carry a stricter policy of its own
//!
//! The global policy is written only when the handler did not set
//! `Content-Security-Policy` itself. Exactly one handler does: the SAML IdP's
//! auto-post page (T23.2.3), whose policy is narrower than the global one in
//! every directive but two — a per-response `script-src 'nonce-…'` for the one
//! inline `submit()`, and `form-action` naming exactly the origin of the
//! assertion consumer service that response is posted to. The global policy is
//! not loosened for anything else: a response that sets no policy gets it
//! byte for byte, as before.

use std::future::{Future, Ready, ready};
use std::pin::Pin;

use actix_web::Error;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};

/// Middleware that appends OWASP security headers to every response.
pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersService { inner: service }))
    }
}

/// The inner service produced by [`SecurityHeadersMiddleware`].
pub struct SecurityHeadersService<S> {
    inner: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            let headers = res.headers_mut();
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );
            let csp = HeaderName::from_static("content-security-policy");
            if !headers.contains_key(&csp) {
                headers.insert(
                    csp,
                    HeaderValue::from_static(
                        "default-src 'self'; \
                     script-src 'self'; \
                     style-src 'self' 'unsafe-inline'; \
                     img-src 'self' data:; \
                     frame-ancestors 'none'; \
                     form-action 'self'; \
                     base-uri 'self'",
                    ),
                );
            }
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{App, HttpResponse, test, web};

    use super::*;

    const GLOBAL_SCRIPT_SRC: &str = "script-src 'self';";

    /// F4 (W3 review, D-27): since the middleware keeps a handler's own
    /// policy, a handler that set a *weaker* one would weaken the page. Exactly
    /// one handler may set a policy — the SAML auto-post page, whose policy
    /// `handlers::saml_idp`'s own test pins as narrower — and this test fails
    /// the day a second source file in this crate names the header.
    #[actix_rt::test]
    async fn exactly_one_handler_sets_its_own_policy() {
        fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("readable source tree") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        let mut setters: Vec<String> = files
            .iter()
            .filter(|path| {
                std::fs::read_to_string(path)
                    .expect("readable source file")
                    .to_ascii_lowercase()
                    .contains("content-security-policy")
            })
            .map(|path| {
                path.strip_prefix(&src)
                    .expect("under src")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        setters.sort();
        assert_eq!(
            setters,
            vec![
                "handlers/saml_idp.rs".to_owned(),
                "middleware/security_headers.rs".to_owned()
            ],
            "a new source file names Content-Security-Policy: the middleware keeps a \
             handler's own policy (D-27), so prove the new one is narrower than the global \
             policy and add it here"
        );
    }

    /// A response that sets no policy gets the global one; a response that sets
    /// its own keeps it (the SAML auto-post page, T23.2.3). Nothing else
    /// changes: the other three headers are written either way.
    #[actix_rt::test]
    async fn the_global_policy_is_written_unless_the_handler_set_its_own() {
        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware)
                .route(
                    "/plain",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                )
                .route(
                    "/own",
                    web::get().to(|| async {
                        HttpResponse::Ok()
                            .insert_header((
                                "Content-Security-Policy",
                                "default-src 'none'; form-action https://sp.example.test",
                            ))
                            .finish()
                    }),
                ),
        )
        .await;

        let plain =
            test::call_service(&app, test::TestRequest::get().uri("/plain").to_request()).await;
        let csp = plain.headers().get("content-security-policy").unwrap();
        assert!(csp.to_str().unwrap().contains(GLOBAL_SCRIPT_SRC));
        assert!(csp.to_str().unwrap().contains("form-action 'self'"));

        let own = test::call_service(&app, test::TestRequest::get().uri("/own").to_request()).await;
        let values: Vec<_> = own
            .headers()
            .get_all("content-security-policy")
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            values,
            vec!["default-src 'none'; form-action https://sp.example.test".to_owned()]
        );
        for res in [&plain, &own] {
            assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
            assert_eq!(
                res.headers().get("x-content-type-options").unwrap(),
                "nosniff"
            );
        }
    }
}
