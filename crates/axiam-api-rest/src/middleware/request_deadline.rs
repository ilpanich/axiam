//! A bound on how long a REST request may take, used with the WebSocket
//! database engine (`AXIAM__DB__ENGINE=ws`).
//!
//! The WebSocket engine does not fail a query while it reconnects to the
//! database: the query waits for the connection to come back. The SDK offers no
//! per-query timeout on its remote engines, so the bound is applied here, to the
//! whole request: one that has not answered within the deadline is answered
//! `503 Service Unavailable` with `Retry-After`, and the work behind it is
//! dropped. With the HTTP engine (the default) the server is built with no
//! deadline and this middleware passes every request straight through.
//!
//! The deadline (`AXIAM__DB__WS_REQUEST_DEADLINE_SECS`, 60 s by default) sits
//! above the longest legitimate request — an SSF long poll waits up to 30 s —
//! so a healthy request never meets it.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::time::Duration;

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::http::header::{HeaderValue, RETRY_AFTER};
use actix_web::{HttpResponse, ResponseError};

/// Middleware factory: [`RequestDeadline::new`] with `None` is a pass-through.
#[derive(Debug, Clone, Copy)]
pub struct RequestDeadline {
    deadline: Option<Duration>,
}

impl RequestDeadline {
    /// Answer a request still running after `deadline` with `503`; `None` or a
    /// zero duration imposes no bound.
    #[must_use]
    pub fn new(deadline: Option<Duration>) -> Self {
        Self {
            deadline: deadline.filter(|d| !d.is_zero()),
        }
    }
}

/// The answer to a request that outlived the deadline.
#[derive(Debug)]
struct DeadlineExceeded;

impl std::fmt::Display for DeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the request did not complete in time; the datastore may be unavailable")
    }
}

impl ResponseError for DeadlineExceeded {
    fn status_code(&self) -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }

    fn error_response(&self) -> HttpResponse {
        let mut response = HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "service_unavailable",
            "error_description": self.to_string(),
        }));
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("1"));
        response
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestDeadline
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = RequestDeadlineService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestDeadlineService {
            service,
            deadline: self.deadline,
        }))
    }
}

/// The service [`RequestDeadline`] wraps around the application.
pub struct RequestDeadlineService<S> {
    service: S,
    deadline: Option<Duration>,
}

impl<S, B> Service<ServiceRequest> for RequestDeadlineService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        let Some(deadline) = self.deadline else {
            return Box::pin(fut);
        };
        Box::pin(async move {
            match tokio::time::timeout(deadline, fut).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!(
                        deadline_secs = deadline.as_secs(),
                        "a REST request outlived the request deadline (WebSocket database \
                         engine) and was answered 503"
                    );
                    Err(DeadlineExceeded.into())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test, web};

    async fn slow() -> HttpResponse {
        tokio::time::sleep(Duration::from_millis(300)).await;
        HttpResponse::Ok().finish()
    }

    #[actix_web::test]
    async fn a_request_past_the_deadline_is_answered_503_with_retry_after() {
        let app = test::init_service(
            App::new()
                .wrap(RequestDeadline::new(Some(Duration::from_millis(50))))
                .route("/slow", web::get().to(slow)),
        )
        .await;
        // The middleware answers with an error, which the HTTP dispatcher
        // renders as the error's response — rendered here the same way.
        let err = test::try_call_service(&app, test::TestRequest::get().uri("/slow").to_request())
            .await
            .expect_err("the deadline refuses the request");
        let res = err.error_response();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(res.headers().get(RETRY_AFTER).unwrap(), "1");
    }

    #[actix_web::test]
    async fn a_request_within_the_deadline_or_without_one_is_untouched() {
        for deadline in [Some(Duration::from_secs(5)), None, Some(Duration::ZERO)] {
            let app = test::init_service(
                App::new()
                    .wrap(RequestDeadline::new(deadline))
                    .route("/slow", web::get().to(slow)),
            )
            .await;
            let res =
                test::call_service(&app, test::TestRequest::get().uri("/slow").to_request()).await;
            assert_eq!(res.status(), StatusCode::OK, "{deadline:?}");
        }
    }
}
