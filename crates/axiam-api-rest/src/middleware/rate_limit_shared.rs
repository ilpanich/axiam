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
use actix_web::dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{ContentType, RETRY_AFTER};
use actix_web::{Error, HttpMessage, HttpResponse, web};
use axiam_db::repository::SurrealRateLimitBucketRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;

use crate::config::rate_limit::RateLimitKeyMode;
use crate::extractors::rate_limit::{
    RateLimitClientId, XForwardedForKeyExtractor, extract_form_client_id,
};
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
    /// D8: bucket-key derivation mode. Always [`RateLimitKeyMode::Ip`] for
    /// instances built via [`RateLimitShared::new`] — only
    /// [`RateLimitShared::new_client_identity_aware`] ever sets this to
    /// something else.
    key_mode: RateLimitKeyMode,
    /// D8: whether this resource has a form-encoded OAuth2 `client_id` to
    /// peek at (`/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect`
    /// ONLY — see [`RateLimitShared::new_client_identity_aware`]). `false`
    /// for every other resource (including `/auth/login`), which never
    /// touches the request body and always keys per-IP.
    client_identity_aware: bool,
    _marker: PhantomData<C>,
}

impl<C: Connection + Clone> RateLimitShared<C> {
    /// Plain IP-keyed constructor — unchanged since before D8. Use this for
    /// every endpoint EXCEPT `/oauth2/token`, `/oauth2/revoke`, and
    /// `/oauth2/introspect`. In particular, `/auth/login` MUST keep using
    /// this constructor: it authenticates a user via username/password, so
    /// there is no OAuth2 `client_id` in the request to key on, and this
    /// type never reads `AXIAM__RATE_LIMIT__KEY` for it.
    pub fn new(endpoint: &'static str, limit: u32) -> Self {
        Self {
            endpoint,
            limit,
            key_mode: RateLimitKeyMode::Ip,
            client_identity_aware: false,
            _marker: PhantomData,
        }
    }

    /// D8 constructor for the three endpoints where an OAuth2 client
    /// authenticates itself via a form-encoded `client_id`
    /// (`client_secret_post`, RFC 6749 §2.3.1): `/oauth2/token`,
    /// `/oauth2/revoke`, `/oauth2/introspect`.
    ///
    /// When `key_mode` is [`RateLimitKeyMode::ClientId`] or
    /// [`RateLimitKeyMode::IpClientId`], this middleware peeks (and
    /// restores) the request body to read `client_id`, and stashes it into
    /// the request extensions (as [`RateLimitClientId`]) so the downstream
    /// in-memory `Governor`'s `ClientAwareKeyExtractor` on the SAME
    /// resource can reuse it without a second body read. When `key_mode` is
    /// [`RateLimitKeyMode::Ip`] this is exactly as if `new()` had been
    /// called — the body is never touched.
    ///
    /// **Do not use this constructor for `/auth/login` or any other
    /// endpoint without a client identity** — see
    /// [`crate::config::rate_limit::RateLimitKeyMode`] docs.
    pub fn new_client_identity_aware(
        endpoint: &'static str,
        limit: u32,
        key_mode: RateLimitKeyMode,
    ) -> Self {
        Self {
            endpoint,
            limit,
            key_mode,
            client_identity_aware: true,
            _marker: PhantomData,
        }
    }
}

impl<C: Connection + Clone> Clone for RateLimitShared<C> {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint,
            limit: self.limit,
            key_mode: self.key_mode,
            client_identity_aware: self.client_identity_aware,
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
            key_mode: self.key_mode,
            client_identity_aware: self.client_identity_aware,
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
    key_mode: RateLimitKeyMode,
    client_identity_aware: bool,
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

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let endpoint = self.endpoint;
        let limit = self.limit;
        let key_mode = self.key_mode;
        let client_identity_aware = self.client_identity_aware;
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
            // D8: for the client-identity-aware endpoints only
            // (`/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect` —
            // never `/auth/login`), peek the form-encoded body for
            // `client_id` and restore the payload so the handler's
            // `web::Form<..>` extractor still sees the full body
            // untouched. This ALSO stashes the result into request
            // extensions for the downstream in-memory `Governor`'s
            // `ClientAwareKeyExtractor` to reuse (see
            // `extractors::rate_limit::RateLimitClientId`).
            //
            // Skipped entirely in `ip` mode (the default) — no body read,
            // byte-for-byte the pre-D8 code path.
            let client_id = if client_identity_aware {
                let client_id = if key_mode != RateLimitKeyMode::Ip {
                    let bytes = req.extract::<web::Bytes>().await.unwrap_or_default();
                    let client_id = extract_form_client_id(&bytes);
                    // Restore the body EXACTLY as read so the handler's
                    // `web::Form<..>` extraction downstream is unaffected —
                    // this middleware must be transparent to the request.
                    req.set_payload(Payload::from(bytes));
                    client_id
                } else {
                    None
                };
                req.extensions_mut()
                    .insert(RateLimitClientId(client_id.clone()));
                client_id
            } else {
                None
            };

            // The bucket-key "identity" part: IP alone (`ip` mode, or
            // fail-safe fallback when no client_id was found), the
            // client_id alone, or the `(ip, client_id)` pair. Mirrors
            // `extractors::rate_limit::ClientAwareKeyExtractor` exactly so
            // this shared-store pre-check and the in-memory governor never
            // disagree about which bucket a request belongs to.
            let key_part = match (key_mode, &client_id) {
                (RateLimitKeyMode::Ip, _) | (_, None) => ip.map(|ip| ip.to_string()),
                (RateLimitKeyMode::ClientId, Some(cid)) => Some(format!("client:{cid}")),
                (RateLimitKeyMode::IpClientId, Some(cid)) => {
                    ip.map(|ip| format!("{ip}:client:{cid}"))
                }
            };

            let allow = match (key_part, db) {
                (Some(key_part), Some(db)) => {
                    let repo = SurrealRateLimitBucketRepository::new(db);
                    let key = format!("{endpoint}:{key_part}");
                    let window = window_start(Utc::now());
                    match repo.increment(&key, window).await {
                        Ok(count) => count <= limit as u64,
                        Err(err) => {
                            // Fail OPEN (D-01b): a counter-store outage must
                            // never hard-block auth traffic. T-24-43: do NOT
                            // log the raw key (endpoint:ip/client_id) at
                            // info+ — this warn-level alarm omits it.
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
                // No key part (IP unavailable) or no DB handle available —
                // fail open; the in-memory governor still makes the real
                // decision.
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
