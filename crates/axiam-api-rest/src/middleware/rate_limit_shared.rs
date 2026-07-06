//! Async SurrealDB-backed shared rate-limit pre-check middleware
//! (SECHRD-03 / D-01a, D-01b, D-01d).
//!
//! [`RateLimitShared`] runs an async windowed-CAS increment against the
//! `rate_limit_bucket` table (`SurrealRateLimitBucketRepository`) BEFORE
//! the existing per-replica in-memory `Governor`/`GovernorLayer`
//! (`server.rs::build_governor`, kept byte-for-byte unchanged as the
//! fail-open fallback). This closes the multi-replica HPA gap where
//! per-replica in-memory buckets otherwise multiply the effective rate
//! limit by the replica count.
//!
//! **Fail-open (D-01b, T-24-42 accepted risk):** when the shared store is
//! unreachable (or no DB handle / no client-IP key is available), this
//! middleware logs a `warn`-level alarm and forwards the request unchanged
//! so the existing in-memory governor makes the decision instead. A
//! counter-store outage must never hard-block auth traffic — this is the
//! ONE deliberate fail-open exception in this phase; every other control
//! fails closed.
//!
//! **CRITICAL (RESEARCH Pitfall 1):** `governor::StateStore::measure_and_replace`
//! is a *synchronous* trait method. This middleware is deliberately NOT a
//! `StateStore` implementation and never calls `block_on`/`futures::executor::
//! block_on` — it is a separate async Actix `Transform`/`Service` (mirroring
//! [`crate::middleware::authz::AuthzMiddleware`]'s scaffold) that performs
//! its own async SurrealDB round-trip, then delegates to the inner service.

use std::future::{Future, Ready, ready};
use std::marker::PhantomData;
use std::rc::Rc;

use actix_governor::KeyExtractor;
use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{ContentType, RETRY_AFTER};
use actix_web::{Error, HttpResponse, web};
use axiam_db::repository::SurrealRateLimitBucketRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;

use crate::extractors::rate_limit::XForwardedForKeyExtractor;
use crate::state::AppState;

/// Fixed-window duration (seconds) for the shared bucket. A simple
/// fixed-window counter is acceptable here (unlike the in-memory GCRA
/// governor) because this layer only needs to be *approximately* right —
/// it fails open by design (RESEARCH.md "Don't Hand-Roll").
const WINDOW_SECS: i64 = 60;

/// Reads the SAME `AXIAM__RATE_LIMIT__TRUSTED_HOPS` env var
/// `server.rs::build_governor` uses, so the shared-store bucket key and the
/// in-memory governor's key are derived from the identical client IP
/// (D-01d parity — a rotating XFF must not yield a fresh bucket in either
/// layer).
fn trusted_hops() -> usize {
    std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Truncates `now` down to the start of the current fixed
/// [`WINDOW_SECS`]-second window.
fn window_start(now: DateTime<Utc>) -> DateTime<Utc> {
    let epoch = now.timestamp();
    let start_epoch = epoch - epoch.rem_euclid(WINDOW_SECS);
    DateTime::<Utc>::from_timestamp(start_epoch, 0).unwrap_or(now)
}

/// Builds the same-shaped 429 response the in-memory governor returns
/// (`extractors::rate_limit::XForwardedForKeyExtractor::exceed_rate_limit_response`),
/// so clients see one consistent rate-limit contract regardless of which
/// layer rejected the request.
fn too_many_requests_response() -> HttpResponse {
    HttpResponse::TooManyRequests()
        .content_type(ContentType::json())
        .insert_header((RETRY_AFTER, WINDOW_SECS.to_string()))
        .body(r#"{"error":"rate_limit_exceeded"}"#)
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/// Shared SurrealDB-backed rate-limit pre-check middleware.
///
/// Generic over the SurrealDB connection type `C` so it can be wired
/// against both the production `DbClient` and the in-memory `Mem` engine
/// used in tests. `endpoint` MUST be unique per rate-limited resource so
/// the shared bucket key (`"{endpoint}:{ip}"`) preserves per-endpoint
/// granularity — never collapse distinct endpoints into one global bucket.
///
/// Wire this BEFORE (i.e. `.wrap()` AFTER, since the last `.wrap()` call is
/// the outermost layer and therefore executes first) `build_governor(...)`
/// on the same resource, e.g.:
///
/// ```ignore
/// web::resource("/login")
///     .wrap(build_governor(rate_limit_cfg.login_per_min))
///     .wrap(RateLimitShared::<C>::new("login", rate_limit_cfg.login_per_min))
///     .route(web::post().to(handlers::auth::login::<C>))
/// ```
pub struct RateLimitShared<C: Connection + Clone> {
    endpoint: &'static str,
    limit: u32,
    _marker: PhantomData<C>,
}

impl<C: Connection + Clone> RateLimitShared<C> {
    pub fn new(endpoint: &'static str, limit: u32) -> Self {
        Self {
            endpoint,
            limit,
            _marker: PhantomData,
        }
    }
}

impl<C: Connection + Clone> Clone for RateLimitShared<C> {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint,
            limit: self.limit,
            _marker: PhantomData,
        }
    }
}

impl<S, B, C> Transform<S, ServiceRequest> for RateLimitShared<C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
    C: Connection + Clone + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = RateLimitSharedService<S, C>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitSharedService {
            inner: Rc::new(service),
            endpoint: self.endpoint,
            limit: self.limit,
            _marker: PhantomData,
        }))
    }
}

// ---------------------------------------------------------------------------
// Inner service
// ---------------------------------------------------------------------------

pub struct RateLimitSharedService<S, C: Connection + Clone> {
    inner: Rc<S>,
    endpoint: &'static str,
    limit: u32,
    _marker: PhantomData<C>,
}

impl<S, B, C> Service<ServiceRequest> for RateLimitSharedService<S, C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
    C: Connection + Clone + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let endpoint = self.endpoint;
        let limit = self.limit;
        let inner = Rc::clone(&self.inner);

        // Reuse the EXACT fixed IP-key extraction logic (D-01d) so the
        // shared bucket key and the in-memory governor's key agree.
        let extractor = XForwardedForKeyExtractor::with_trusted_hops(trusted_hops());
        let ip = extractor.extract(&req).ok();

        // The SurrealDB handle is read from `web::Data<AppState<C>>` (QUAL-01
        // — was a standalone `web::Data<Surreal<C>>` registration). Its
        // absence is treated exactly like a DB error below — fail open to
        // the in-memory governor.
        let db = req
            .app_data::<web::Data<AppState<C>>>()
            .map(|d| d.db.clone());

        Box::pin(async move {
            let allow = match (ip, db) {
                (Some(ip), Some(db)) => {
                    let repo = SurrealRateLimitBucketRepository::new(db);
                    let key = format!("{endpoint}:{ip}");
                    let window = window_start(Utc::now());
                    match repo.increment(&key, window).await {
                        Ok(count) => count <= limit as u64,
                        Err(err) => {
                            // Fail OPEN (D-01b): a counter-store outage must
                            // never hard-block auth traffic. T-24-43: do NOT
                            // log the raw key (endpoint:ip) at info+ — this
                            // warn-level alarm omits it.
                            tracing::warn!(
                                endpoint,
                                error = %err,
                                "shared rate-limit store unreachable; falling back \
                                 to per-replica in-memory governor"
                            );
                            true
                        }
                    }
                }
                // No client-IP key or no DB handle available — fail open;
                // the in-memory governor still makes the real decision.
                _ => true,
            };

            if allow {
                let res = inner.call(req).await?;
                Ok(res.map_into_left_body())
            } else {
                let res = req.into_response(too_many_requests_response());
                Ok(res.map_into_right_body())
            }
        })
    }
}
