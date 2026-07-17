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
            headers.insert(
                HeaderName::from_static("content-security-policy"),
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
            Ok(res)
        })
    }
}
