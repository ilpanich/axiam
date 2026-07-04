//! gRPC rate limiting via tower-governor (per D-10, D-11), brought to parity
//! with the fixed REST limiter (SECHRD-03, D-01c).
//!
//! Two layers cooperate here (mirroring
//! `axiam-api-rest::middleware::rate_limit_shared` / `extractors::rate_limit`):
//!
//! - [`GrpcTrustedHopsKeyExtractor`] — a custom `tower_governor::KeyExtractor`
//!   that replaces `SmartIpKeyExtractor`. `SmartIpKeyExtractor` unconditionally
//!   trusts the LEFTMOST `X-Forwarded-For` hop and, more fundamentally, can
//!   never find tonic's real peer address at all (it only looks for an
//!   `axum::extract::ConnectInfo<SocketAddr>` extension or a bare `SocketAddr`
//!   extension — tonic inserts `TcpConnectInfo`/`TlsConnectInfo<TcpConnectInfo>`
//!   instead). This extractor mirrors the fixed REST
//!   `XForwardedForKeyExtractor` (plan 24-03): a configured `trusted_hops`
//!   selects the rightmost trusted XFF hop, and when there are NOT enough
//!   hops to trust, XFF is ignored entirely and the verified tonic connection
//!   peer address is used instead (never `hops[0]` — SECHRD-03/D-01d).
//! - [`GrpcSharedRateLimitLayer`] — an async pre-check `tower::Layer` that
//!   reuses the plan-24-04 `SurrealRateLimitBucketRepository` shared-store
//!   counter, run BEFORE the existing per-replica in-memory `GovernorLayer`
//!   (kept byte-for-byte unchanged as the fail-open fallback, D-01b). This is
//!   deliberately NOT a `governor::StateStore` impl and never calls
//!   `block_on` — `StateStore::measure_and_replace` is a *synchronous* trait
//!   method (RESEARCH Pitfall 1), so the shared-store check is a separate
//!   async tower service that performs its own SurrealDB round-trip and then
//!   delegates to the inner service.
//!
//! HARD CONSTRAINT (D-01c coordination note): the `Quota::per_second(...)
//! .burst_size(...)` throughput/quota math in [`build_grpc_governor_layer`]
//! is untouched by this module — CORR-01/Phase 26 owns it.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axiam_db::repository::SurrealRateLimitBucketRepository;
use chrono::{DateTime, Utc};
use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use http::{Request, Response};
use surrealdb::{Connection, Surreal};
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tower::{Layer, Service};
use tower_governor::{
    GovernorLayer, errors::GovernorError, governor::GovernorConfigBuilder,
    key_extractor::KeyExtractor,
};

// ---------------------------------------------------------------------------
// Custom trusted_hops-aware KeyExtractor (Task 1 — replaces SmartIpKeyExtractor)
// ---------------------------------------------------------------------------

/// Reads the SAME `AXIAM__RATE_LIMIT__TRUSTED_HOPS` env var the REST shared
/// pre-check (`axiam-api-rest::middleware::rate_limit_shared::trusted_hops`)
/// and `server.rs::build_governor` use, so the gRPC key and the REST key are
/// derived identically from the same deployment-topology configuration.
///
/// `pub(crate)` so `server.rs::start_grpc_server` can pass the SAME value to
/// both [`build_grpc_governor_layer`] (via this function internally) and
/// [`GrpcSharedRateLimitLayer::new`] — the key-extraction logic in the
/// shared-store pre-check and the in-memory governor MUST stay in lockstep.
pub(crate) fn trusted_hops_from_env() -> usize {
    std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Extracts the gRPC caller's IP from `X-Forwarded-For`, falling back to the
/// verified tonic connection peer address (`TcpConnectInfo`/
/// `TlsConnectInfo<TcpConnectInfo>`).
///
/// `trusted_hops` controls how many rightmost XFF entries are trusted
/// reverse-proxy hops to skip (mirrors
/// `axiam-api-rest::extractors::rate_limit::XForwardedForKeyExtractor`).
/// When `trusted_hops >= hops.len()`, the header is NOT trusted at all and
/// XFF is ignored entirely — the key is derived from the verified peer
/// address instead (a client cannot manufacture extra hops to force a
/// fallback to an attacker-controlled `hops[0]` — SECHRD-03/D-01d).
#[derive(Debug, Clone, Default)]
pub struct GrpcTrustedHopsKeyExtractor {
    pub trusted_hops: usize,
}

impl GrpcTrustedHopsKeyExtractor {
    /// Create an extractor keyed by `trusted_hops` trusted reverse-proxy
    /// hops (0 = no trusted hops; XFF is only ever used when it has more
    /// than 0 entries beyond what's trusted).
    pub fn new(trusted_hops: usize) -> Self {
        Self { trusted_hops }
    }
}

impl KeyExtractor for GrpcTrustedHopsKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if let Some(forwarded_for) = req.headers().get("x-forwarded-for")
            && let Ok(val) = forwarded_for.to_str()
        {
            let hops: Vec<&str> = val.split(',').map(str::trim).collect();
            // Select the rightmost-untrusted hop (parity with REST).
            if self.trusted_hops < hops.len() {
                let idx = hops.len() - 1 - self.trusted_hops;
                if let Ok(ip) = hops[idx].parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
            // Fewer hops than trusted_hops requires: the header cannot be
            // trusted. Fall through to the verified peer address below
            // instead of indexing into XFF (SECHRD-03 — no `hops[0]`
            // fallback that would let a rotating XFF mint a fresh bucket).
        }

        grpc_peer_addr(req)
            .map(|addr| addr.ip())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Reads the verified tonic connection peer address from request
/// extensions, mirroring `tonic::Request::remote_addr()`'s own lookup
/// (`TcpConnectInfo` for plaintext, `TlsConnectInfo<TcpConnectInfo>` for TLS)
/// — the extension types tonic's `ConnectInfoLayer` actually inserts (NOT
/// the `axum::extract::ConnectInfo<SocketAddr>` / bare `SocketAddr`
/// extensions `SmartIpKeyExtractor` looks for, which tonic never sets).
fn grpc_peer_addr<T>(req: &Request<T>) -> Option<SocketAddr> {
    req.extensions()
        .get::<TcpConnectInfo>()
        .and_then(TcpConnectInfo::remote_addr)
        .or_else(|| {
            req.extensions()
                .get::<TlsConnectInfo<TcpConnectInfo>>()
                .and_then(|info| info.get_ref().remote_addr())
        })
}

/// Concrete type alias for the gRPC GovernorLayer.
///
/// - `K` = [`GrpcTrustedHopsKeyExtractor`] — trusted_hops-aware, keys off the
///   verified peer address when XFF hops are insufficient (SECHRD-03).
/// - `M` = NoOpMiddleware — no rate-limit headers injected into responses (gRPC transport)
/// - `RespBody` = tonic::body::Body — tonic's native streaming body type
pub type GrpcGovernorLayer =
    GovernorLayer<GrpcTrustedHopsKeyExtractor, NoOpMiddleware<QuantaInstant>, tonic::body::Body>;

/// Build a [`GovernorLayer`] for gRPC server-wide rate limiting.
///
/// The layer uses token-bucket semantics (via the `governor` crate) with one
/// token replenished per second and a burst allowance of `authz_per_sec` tokens.
/// For service-mesh patterns where the authz endpoint is called on every request,
/// the default of 100 tokens/sec is intentionally generous.
///
/// # Panics
///
/// Panics at startup if `authz_per_sec` is 0 — the governor crate requires a
/// non-zero burst size.
pub fn build_grpc_governor_layer(authz_per_sec: u32) -> GrpcGovernorLayer {
    assert!(authz_per_sec >= 1, "grpc_authz_per_sec must be >= 1");

    // CQ-B44: was `.per_second(1).burst_size(authz_per_sec)` — the hardcoded
    // `per_second(1)` meant the rate was 1 req/s regardless of `authz_per_sec`.
    // Fixed: replenish `authz_per_sec` tokens per second with 2× burst.
    // SECHRD-03/D-01c: key extractor swapped to GrpcTrustedHopsKeyExtractor
    // for IP-spoofing resistance parity with REST — this throughput/quota
    // math is otherwise untouched (CORR-01/Phase 26 owns it).
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(authz_per_sec as u64)
            .burst_size(authz_per_sec * 2)
            .key_extractor(GrpcTrustedHopsKeyExtractor::new(trusted_hops_from_env()))
            .finish()
            .expect("valid GovernorConfig for gRPC rate limiter"),
    );

    GovernorLayer::new(config)
}

// ---------------------------------------------------------------------------
// Shared SurrealDB-backed pre-check layer (Task 2 — D-01a/b/c parity)
// ---------------------------------------------------------------------------

/// Fixed-window duration (seconds) for the shared bucket — same value and
/// rationale as the REST shared pre-check
/// (`axiam-api-rest::middleware::rate_limit_shared::WINDOW_SECS`): a simple
/// fixed-window counter is acceptable here since this layer only needs to be
/// *approximately* right (it fails open by design).
const WINDOW_SECS: i64 = 60;

/// Truncates `now` down to the start of the current fixed
/// [`WINDOW_SECS`]-second window.
fn window_start(now: DateTime<Utc>) -> DateTime<Utc> {
    let epoch = now.timestamp();
    let start_epoch = epoch - epoch.rem_euclid(WINDOW_SECS);
    DateTime::<Utc>::from_timestamp(start_epoch, 0).unwrap_or(now)
}

/// Builds a gRPC `RESOURCE_EXHAUSTED` response — the same status the
/// in-memory `GovernorLayer` returns for `GovernorError::TooManyRequests`
/// (see `tower_governor::errors::GovernorError`'s `Response<tonic::body::Body>`
/// conversion) — so clients see one consistent rate-limit contract
/// regardless of which layer rejected the request.
fn too_many_requests_response() -> Response<tonic::body::Body> {
    tonic::Status::resource_exhausted("rate limit exceeded").into_http()
}

/// Async SurrealDB-backed shared rate-limit pre-check `tower::Layer` for the
/// gRPC path (SECHRD-03 / D-01a, D-01b, D-01c, D-01d).
///
/// Reuses [`SurrealRateLimitBucketRepository::increment`] (plan 24-04) —
/// there is no reimplemented counter here. Wire this layer BEFORE (i.e.
/// `.layer()` it FIRST — tower's `ServiceBuilder`/`Server::builder()`
/// executes the FIRST-added layer with the request FIRST, the opposite of
/// actix's last-`.wrap()`-is-outermost rule) the existing
/// [`build_grpc_governor_layer`] `GovernorLayer` on the same
/// `Server::builder()`, e.g.:
///
/// ```ignore
/// Server::builder()
///     .layer(GrpcSharedRateLimitLayer::new(db, "grpc_authz", grpc_config.grpc_authz_per_sec, trusted_hops))
///     .layer(build_grpc_governor_layer(grpc_config.grpc_authz_per_sec))
///     .add_service(authz_svc)
/// ```
///
/// **Fail-open (D-01b, T-24-73 accepted risk):** when the shared store is
/// unreachable, or no client IP can be extracted, this layer logs a
/// `warn`-level alarm and forwards the request unchanged so the existing
/// in-memory governor makes the decision instead — a counter-store outage
/// must never hard-block gRPC authz traffic.
///
/// **CRITICAL (RESEARCH Pitfall 1):** `governor::StateStore::measure_and_replace`
/// is a *synchronous* trait method. This layer is deliberately NOT a
/// `StateStore` implementation and never calls `block_on` — it performs its
/// own async SurrealDB round-trip as a plain `tower::Layer`/`Service`, then
/// delegates to the inner service.
pub struct GrpcSharedRateLimitLayer<C: Connection> {
    db: Surreal<C>,
    endpoint: &'static str,
    limit: u32,
    trusted_hops: usize,
}

impl<C: Connection> GrpcSharedRateLimitLayer<C> {
    /// `endpoint` MUST be unique per rate-limited gRPC surface so the shared
    /// bucket key (`"{endpoint}:{ip}"`) preserves per-surface granularity —
    /// never collapse distinct surfaces into one global bucket.
    pub fn new(db: Surreal<C>, endpoint: &'static str, limit: u32, trusted_hops: usize) -> Self {
        Self {
            db,
            endpoint,
            limit,
            trusted_hops,
        }
    }
}

// Manual `Clone` impl (NOT `#[derive(Clone)]`): `Surreal<C>` is `Clone` for
// EVERY `C` unconditionally (it's an `Arc`-backed handle internally — see
// `surrealdb::Surreal<C>`'s own `impl<C> Clone for Surreal<C>`, no `C: Clone`
// bound). A derived `Clone` incorrectly adds a spurious `C: Clone` bound
// (derive macros bound every generic type parameter that appears in a
// field), which broke `start_grpc_server<..., C>`'s generic wiring — the
// concrete `C` there (`surrealdb::engine::remote::http::Client`) has no
// `Clone` impl, and forcing this layer to require one would leak into the
// caller's generic bounds for no reason. Mirrors the REST
// `RateLimitShared`/`RateLimitSharedService` precedent
// (`axiam-api-rest::middleware::rate_limit_shared`).
impl<C: Connection> Clone for GrpcSharedRateLimitLayer<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            endpoint: self.endpoint,
            limit: self.limit,
            trusted_hops: self.trusted_hops,
        }
    }
}

impl<S, C> Layer<S> for GrpcSharedRateLimitLayer<C>
where
    C: Connection + 'static,
{
    type Service = GrpcSharedRateLimitService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcSharedRateLimitService {
            inner,
            db: self.db.clone(),
            endpoint: self.endpoint,
            limit: self.limit,
            trusted_hops: self.trusted_hops,
        }
    }
}

/// Inner `tower::Service` produced by [`GrpcSharedRateLimitLayer`].
pub struct GrpcSharedRateLimitService<S, C: Connection> {
    inner: S,
    db: Surreal<C>,
    endpoint: &'static str,
    limit: u32,
    trusted_hops: usize,
}

// Manual `Clone` impl for the same reason as `GrpcSharedRateLimitLayer`
// above: only `S: Clone` should be required, never `C: Clone` (`Surreal<C>`
// clones unconditionally regardless of `C`).
impl<S: Clone, C: Connection> Clone for GrpcSharedRateLimitService<S, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            db: self.db.clone(),
            endpoint: self.endpoint,
            limit: self.limit,
            trusted_hops: self.trusted_hops,
        }
    }
}

impl<S, C> Service<Request<tonic::body::Body>> for GrpcSharedRateLimitService<S, C>
where
    S: Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    C: Connection + 'static,
{
    type Response = Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<tonic::body::Body>) -> Self::Future {
        // Standard clone-and-swap so the returned future owns an
        // independent, ready-to-call copy of the inner service (mirrors
        // tower-http's convention for async-wrapping middlewares).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let db = self.db.clone();
        let endpoint = self.endpoint;
        let limit = self.limit;
        let key_extractor = GrpcTrustedHopsKeyExtractor::new(self.trusted_hops);

        Box::pin(async move {
            let ip = key_extractor.extract(&req).ok();

            let allow = match ip {
                Some(ip) => {
                    let repo = SurrealRateLimitBucketRepository::new(db);
                    let key = format!("{endpoint}:{ip}");
                    let window = window_start(Utc::now());
                    match repo.increment(&key, window).await {
                        Ok(count) => count <= limit as u64,
                        Err(err) => {
                            // Fail OPEN (D-01b): a counter-store outage must
                            // never hard-block gRPC authz traffic. Do NOT
                            // log the raw key (endpoint:ip) at info+ (mirrors
                            // the REST T-24-43 note) — this warn-level alarm
                            // omits it.
                            tracing::warn!(
                                endpoint,
                                error = %err,
                                "shared gRPC rate-limit store unreachable; falling back \
                                 to per-replica in-memory governor"
                            );
                            true
                        }
                    }
                }
                // No client-IP key available — fail open; the in-memory
                // governor still makes the real decision.
                None => true,
            };

            if allow {
                inner.call(req).await
            } else {
                Ok(too_many_requests_response())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with_xff(xff: Option<&str>) -> Request<()> {
        let mut builder = Request::builder();
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        builder.body(()).unwrap()
    }

    fn req_with_xff_and_peer(xff: Option<&str>, peer: SocketAddr) -> Request<()> {
        let mut req = req_with_xff(xff);
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer),
        });
        req
    }

    #[test]
    fn uses_rightmost_trusted_xff_hop_when_enough_hops_present() {
        // trusted_hops=1, 3 hops present -> index = 3 - 1 - 1 = 1
        let extractor = GrpcTrustedHopsKeyExtractor::new(1);
        let req = req_with_xff(Some("203.0.113.9, 198.51.100.7, 192.0.2.1"));

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn falls_back_to_peer_addr_when_trusted_hops_exceeds_hop_count() {
        // SECHRD-03/D-01d: trusted_hops(1) >= hops.len()(1) => XFF is
        // completely untrusted; a rotating single-hop XFF must NOT be used
        // (never `hops[0]`) — fall through to the verified peer address.
        let extractor = GrpcTrustedHopsKeyExtractor::new(1);
        let peer: SocketAddr = "203.0.113.42:1234".parse().unwrap();

        let req1 = req_with_xff_and_peer(Some("198.51.100.1"), peer);
        let req2 = req_with_xff_and_peer(Some("6.6.6.6"), peer);

        let key1 = extractor.extract(&req1).unwrap();
        let key2 = extractor.extract(&req2).unwrap();

        assert_eq!(key1, peer.ip());
        assert_eq!(key2, peer.ip());
        assert_eq!(key1, key2, "rotating XFF must not yield a fresh key");
    }

    #[test]
    fn errors_when_no_xff_and_no_peer_info() {
        let extractor = GrpcTrustedHopsKeyExtractor::new(0);
        let req = req_with_xff(None);

        assert!(matches!(
            extractor.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }
}
