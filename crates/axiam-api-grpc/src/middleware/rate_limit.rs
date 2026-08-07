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
//! - [`GrpcSharedRateLimitLayer`] — a pre-check `tower::Layer` over the
//!   process-wide write-behind `axiam_db::SharedRateLimitCounter` (the SAME
//!   counter type and env knobs — `AXIAM__RATE_LIMIT__SHARED`,
//!   `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` — the REST `RateLimitShared`
//!   middleware uses), run BEFORE the existing per-replica in-memory
//!   `GovernorLayer` (kept byte-for-byte unchanged as the fail-open fallback,
//!   D-01b). This is deliberately NOT a `governor::StateStore` impl and never
//!   calls `block_on` — `StateStore::measure_and_replace` is a *synchronous*
//!   trait method (RESEARCH Pitfall 1).
//!
//!   Since the H2 performance fix this layer performs NO datastore round trip
//!   on the request path (it used to `await` one `UPSERT` per call, and being
//!   server-wide, *every* gRPC call paid it — see the layer's own docs for the
//!   measurements). A single background flusher coalesces the in-memory
//!   increments into one write per bucket per sync interval.
//!
//! HARD CONSTRAINT (D-01c coordination note): the `Quota::per_second(...)
//! .burst_size(...)` throughput/quota math in [`build_grpc_governor_layer`]
//! is untouched by this module — CORR-01/Phase 26 owns it.
//!
//! # Units and scope (run-4 fixes I1 and I2)
//!
//! - **I1 — units.** The gRPC ceilings are configured **per second**; the
//!   shared cross-replica bucket runs a fixed **60-second** window shared with
//!   the REST limiter. The conversion lives in exactly one place,
//!   [`per_sec_to_window_limit`], and the production constructor
//!   ([`GrpcSharedRateLimitLayer::new_method_scoped`]) takes per-second
//!   ceilings so no caller can hand a per-second number to a per-minute
//!   window again.
//! - **I2 — scope.** Both layers used to be server-wide, so the *authz*
//!   ceiling throttled identity reads and admin traffic too. Buckets are now
//!   split per [`GrpcMethodFamily`] (authz-check / identity-read / admin /
//!   infrastructure).
//!
//! # SEC-079 — the admin ceiling is absolute, not derived
//!
//! The admin family contains `axiam.v1.UserService/ValidateCredentials`, an
//! **Argon2id verification**. Its ceiling is a CPU guard, so it is an absolute
//! constant ([`ADMIN_PER_SEC_DEFAULT`]) rather than a multiple of — or the
//! same number as — the read-sized `authz_per_sec` base. See that constant's
//! docs for the full reasoning; the short version is that when the I1 units
//! bug was fixed the effective per-IP ceiling on that RPC rose 60x, and
//! deriving it from a read-sized base would let a `gateway`/`mesh` posture
//! raise it further still.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axiam_db::SharedRateLimitCounter;
use axiam_db::repository::SurrealRateLimitBucketRepository;
use chrono::{DateTime, Utc};
use governor::Quota;
use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use http::{Request, Response};
use surrealdb::Connection;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tower::{Layer, Service};
use tower_governor::{
    GovernorLayer,
    errors::GovernorError,
    governor::{Governor, GovernorConfigBuilder},
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

// ---------------------------------------------------------------------------
// Per-method scoping (I2)
// ---------------------------------------------------------------------------

/// The rate-limit bucket family a gRPC method belongs to (I2).
///
/// **Why this exists.** Both gRPC rate-limit layers used to be *server-wide*:
/// one bucket, sized from `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, shared by every
/// method on every service. Run 4 measured `UserInfoService/GetUserInfo` — an
/// identity read that sustains ~12 700/s — collapsing to the *authz* ceiling
/// under production posture, because a `check_access` sizing decision was
/// silently also a userinfo sizing decision
/// (`claude_dev/improvement-after-run4-benchmark.md` I2). Splitting the
/// buckets lets an operator size the authz path (called once per protected
/// request) independently of identity reads and of administrative traffic.
///
/// **Classification is by gRPC path**, i.e. `/<package>.<Service>/<Method>`,
/// which is the only identity available to a `tower::Layer` running before
/// tonic resolves per-RPC claims (the same structural reason the buckets key
/// on IP — see `crate::config::GrpcRateLimitKeyMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrpcMethodFamily {
    /// `axiam.v1.AuthorizationService` — `CheckAccess` / `BatchCheckAccess`.
    /// Also the family for any **unrecognized** path: an unknown method must
    /// land in the strictest bucket rather than in the unlimited one.
    AuthzCheck,
    /// Identity reads: `axiam.v1.UserInfoService` (OIDC-style self lookup)
    /// and `axiam.v1.TokenService` (validate/introspect). High-frequency,
    /// cheap, and measured an order of magnitude faster than an authz check.
    IdentityRead,
    /// Administrative / user-management traffic: `axiam.v1.UserService`
    /// (`GetUser`, `ValidateCredentials`). `ValidateCredentials` hashes a
    /// password, so this family is deliberately NOT sized from read capacity —
    /// its ceiling is the absolute [`ADMIN_PER_SEC_DEFAULT`] (SEC-079).
    Admin,
    /// Infrastructure probes: gRPC **reflection** and **health**. Their whole
    /// job is to answer during an incident, when the limited families are most
    /// likely to be saturated, so this family gets a deliberately generous
    /// ceiling ([`INFRA_PER_SEC`]) — but a **finite** one.
    ///
    /// This family used to be a literal pass-through (`Unlimited`) that
    /// bypassed BOTH limiter layers, selected by a prefix test on the
    /// attacker-controlled `:path`. Neither service is registered today, so
    /// the practical effect was unmetered HTTP/2 stream churn rather than DB
    /// work — but registering a health service would have turned it into a
    /// genuinely unmetered endpoint. A generous bucket keeps probes working
    /// during an overload without leaving an unbounded surface behind
    /// (security re-verification 2026-08-03, residual 4).
    Infra,
}

/// gRPC reflection service package prefix (v1 and v1alpha).
const REFLECTION_PREFIX: &str = "/grpc.reflection.";
/// gRPC health-checking service package prefix.
const HEALTH_PREFIX: &str = "/grpc.health.";

impl GrpcMethodFamily {
    /// Classifies a gRPC request path (`/<package>.<Service>/<Method>`).
    ///
    /// Unknown paths deliberately fall into [`Self::AuthzCheck`] — the
    /// strictest limited family — so that adding a service without updating
    /// this function fails safe (throttled) rather than open (unlimited).
    pub fn classify(path: &str) -> Self {
        if path.starts_with(REFLECTION_PREFIX) || path.starts_with(HEALTH_PREFIX) {
            return Self::Infra;
        }
        match path.split('/').nth(1).unwrap_or_default() {
            "axiam.v1.UserInfoService" | "axiam.v1.TokenService" => Self::IdentityRead,
            "axiam.v1.UserService" => Self::Admin,
            // "axiam.v1.AuthorizationService" and everything else.
            _ => Self::AuthzCheck,
        }
    }

    /// Shared-counter bucket-name prefix for this family.
    ///
    /// These names are part of the persisted `rate_limit_bucket` key space
    /// (`"{endpoint}:{ip}"`), so `grpc_authz` is kept byte-for-byte for the
    /// authz family — an in-flight upgrade keeps counting against the same
    /// rows.
    ///
    /// Every family now has one: the infrastructure family is bucketed like
    /// the rest rather than skipping the counter entirely (residual 4).
    pub const fn shared_endpoint(self) -> &'static str {
        match self {
            Self::AuthzCheck => "grpc_authz",
            Self::IdentityRead => "grpc_identity",
            Self::Admin => "grpc_admin",
            Self::Infra => "grpc_infra",
        }
    }
}

/// Per-family gRPC ceilings, in requests **per second per IP** (I2).
///
/// The unit is per-second at every boundary of this type. The shared
/// cross-replica layer runs a 60-second window and therefore converts with
/// [`per_sec_to_window_limit`] internally — callers never do that arithmetic
/// themselves, which is precisely the bug I1 fixed (the per-second number was
/// handed to a per-minute window verbatim, making the effective ceiling
/// 1/60th of the configured one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcRateLimits {
    /// `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` — authorization decisions.
    pub authz_per_sec: u32,
    /// `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` — userinfo / token reads.
    pub identity_per_sec: u32,
    /// `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` — user management. Defaults to the
    /// absolute [`ADMIN_PER_SEC_DEFAULT`], never to a multiple of
    /// [`Self::authz_per_sec`] (SEC-079).
    pub admin_per_sec: u32,
}

/// Identity reads default to this multiple of the authz ceiling — they were
/// measured ~14x faster than an authz check (12 665/s vs 887/s, run 4) and a
/// resource server does one per protected request just like a check. The
/// multiplier (rather than a fixed number) is what keeps the family coherent
/// when `AXIAM__RATE_LIMIT__PROFILE` raises the authz ceiling.
pub const IDENTITY_PER_SEC_MULTIPLE: u32 = 5;

/// Default ceiling for the [`GrpcMethodFamily::Admin`] family, in requests per
/// second per IP — **an absolute number, deliberately not derived from
/// [`GrpcRateLimits::authz_per_sec`]** (SEC-079).
///
/// **Why absolute.** The admin family contains
/// `axiam.v1.UserService/ValidateCredentials`, which performs a real Argon2id
/// `verify_password` (~19 MiB of memory arena per verification). Its ceiling is
/// therefore a **CPU/memory guard on an online-password-guessing surface**, not
/// a throughput ceiling on a read. `authz_per_sec` is a read-sized base (100/s
/// shipped, and `AXIAM__RATE_LIMIT__PROFILE=gateway`/`mesh` raise it to
/// 1 000/s / 5 000/s); deriving the admin ceiling from it — even 1:1 — makes a
/// service-mesh capacity decision silently also a credential-guessing-breadth
/// decision. Decoupling the two is the entire point of this constant.
///
/// **Why 10/s (600/min per IP).** The family holds exactly two RPCs, `GetUser`
/// and `ValidateCredentials`; the high-volume identity read is `GetUserInfo` on
/// `UserInfoService`, which lives in [`GrpcMethodFamily::IdentityRead`] and is
/// unaffected. 600 administrative calls per minute from one client IP is well
/// above any real admin console or M2M provisioning loop, and roughly an order
/// of magnitude below the point at which concurrent Argon2id verifications
/// become the server's dominant cost. It also restores the protection the I1
/// units fix accidentally removed: before that fix the shared window enforced
/// the per-second number against a 60-second window, so the deployed ceiling
/// was ~100/**minute**; correcting the units silently raised it to
/// ~6 000/minute. 600/minute is the CPU-appropriate value the doc comment
/// always claimed this family had.
///
/// Operators who genuinely need more can still pin
/// `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` — explicit configuration always wins.
pub const ADMIN_PER_SEC_DEFAULT: u32 = 10;

/// Ceiling for the [`GrpcMethodFamily::Infra`] family (gRPC reflection and
/// health), in requests per second per IP — generous, but finite.
///
/// Infrastructure probes are intrinsically low-rate: a Kubernetes liveness or
/// readiness probe runs on the order of once every few seconds per prober, and
/// even a large fleet of sidecars sharing one NAT egress IP stays orders of
/// magnitude below 100/s. So this ceiling can never be the thing that breaks a
/// health check during an incident — which is the property that made the family
/// a pass-through in the first place — while still bounding the surface, so a
/// health service registered later is not an unmetered endpoint reachable by
/// prefix-matching an attacker-controlled `:path` (residual 4).
///
/// It is an absolute constant for the same reason as
/// [`ADMIN_PER_SEC_DEFAULT`]: probe volume has nothing to do with authz
/// capacity, so a posture preset must not move it.
pub const INFRA_PER_SEC: u32 = 100;

impl GrpcRateLimits {
    /// Derives the whole family from the authz ceiling alone — the shape an
    /// operator gets when only `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` (or a
    /// posture preset) is set.
    ///
    /// Only [`Self::identity_per_sec`] actually scales: `ValidateCredentials`
    /// is an Argon2id verification, so the admin ceiling is a CPU guard and
    /// takes the absolute [`ADMIN_PER_SEC_DEFAULT`] rather than inheriting a
    /// read-sized base (SEC-079).
    pub const fn from_authz_per_sec(authz_per_sec: u32) -> Self {
        Self {
            authz_per_sec,
            identity_per_sec: authz_per_sec.saturating_mul(IDENTITY_PER_SEC_MULTIPLE),
            admin_per_sec: ADMIN_PER_SEC_DEFAULT,
        }
    }

    /// The per-second ceiling for `family`.
    ///
    /// Every family is limited: [`GrpcMethodFamily::Infra`] takes the fixed
    /// [`INFRA_PER_SEC`], which is why this is not configurable per instance
    /// (residual 4).
    pub const fn per_sec(self, family: GrpcMethodFamily) -> u32 {
        match family {
            GrpcMethodFamily::AuthzCheck => self.authz_per_sec,
            GrpcMethodFamily::IdentityRead => self.identity_per_sec,
            GrpcMethodFamily::Admin => self.admin_per_sec,
            GrpcMethodFamily::Infra => INFRA_PER_SEC,
        }
    }

    /// The ceiling for `family` expressed in the shared layer's 60-second
    /// window (I1).
    pub const fn window_limit(self, family: GrpcMethodFamily) -> u32 {
        per_sec_to_window_limit(self.per_sec(family))
    }
}

/// Concrete type alias for the gRPC GovernorLayer.
///
/// - `K` = [`GrpcTrustedHopsKeyExtractor`] — trusted_hops-aware, keys off the
///   verified peer address when XFF hops are insufficient (SECHRD-03).
/// - `M` = NoOpMiddleware — no rate-limit headers injected into responses (gRPC transport)
/// - `RespBody` = tonic::body::Body — tonic's native streaming body type
pub type GrpcGovernorLayer =
    GovernorLayer<GrpcTrustedHopsKeyExtractor, NoOpMiddleware<QuantaInstant>, tonic::body::Body>;

/// Concrete type alias for one per-family in-memory governor service.
type GrpcGovernor<S> =
    Governor<GrpcTrustedHopsKeyExtractor, NoOpMiddleware<QuantaInstant>, S, tonic::body::Body>;

/// Build a [`GovernorLayer`] for gRPC server-wide rate limiting.
///
/// The layer uses token-bucket semantics (via the `governor` crate) with
/// `authz_per_sec` tokens replenished per second and a burst allowance equal
/// to `authz_per_sec` (one second's worth of tokens). For service-mesh
/// patterns where the authz endpoint is called on every request, the default
/// of 100 tokens/sec is intentionally generous.
///
/// # Panics
///
/// Panics at startup if `authz_per_sec` is 0 — the governor crate requires a
/// non-zero burst size.
pub fn build_grpc_governor_layer(authz_per_sec: u32) -> GrpcGovernorLayer {
    assert!(authz_per_sec >= 1, "grpc_authz_per_sec must be >= 1");

    // CORR-01 (D-01): the PREVIOUS "fix" here (CQ-B44) called
    // `tower_governor`'s OWN `GovernorConfigBuilder::per_second(n)` /
    // `.burst_size(authz_per_sec * 2)` as if `.per_second(n)` meant "n tokens
    // per second." It does NOT — `tower_governor`'s builder methods set the
    // replenish PERIOD (i.e. "one token every n seconds"), so with the
    // default `grpc_authz_per_sec=100` the governor replenished 1 token every
    // 100 seconds, and raising the configured rate made throughput WORSE, not
    // better. Fixed by bypassing `tower_governor`'s confusing
    // `.per_second()`/`.per_millisecond()` convenience methods entirely and
    // constructing the underlying `governor::Quota` directly via
    // `Quota::per_second`, whose `replenish_interval()` is `1s /
    // authz_per_sec` and whose `burst_size()` is `authz_per_sec` — then
    // feeding that quota into the builder via `.const_period()`/
    // `.const_burst_size()`. Burst is `authz_per_sec` (not `* 2`), per D-01.
    //
    // SECHRD-03/D-01c: key extractor is GrpcTrustedHopsKeyExtractor for
    // IP-spoofing resistance parity with REST — unrelated to this quota math.
    let burst = NonZeroU32::new(authz_per_sec).expect("authz_per_sec >= 1 asserted above");
    let quota = Quota::per_second(burst);

    let config = Arc::new(
        GovernorConfigBuilder::default()
            .const_period(quota.replenish_interval())
            .const_burst_size(quota.burst_size().get())
            .key_extractor(GrpcTrustedHopsKeyExtractor::new(trusted_hops_from_env()))
            .finish()
            .expect("valid GovernorConfig for gRPC rate limiter"),
    );

    GovernorLayer::new(config)
}

/// Build the per-method-family in-memory governor stack (I2).
///
/// One independent [`GovernorLayer`] per [`GrpcMethodFamily`], each with its
/// own token bucket keyed by client IP. Replaces the single server-wide
/// governor, which made the authz ceiling the ceiling for every gRPC surface.
///
/// Since residual 4 the infrastructure family (reflection / health) gets a
/// governor too — a generous [`INFRA_PER_SEC`] one — instead of a pass-through
/// that bypassed both limiter layers.
///
/// # Panics
///
/// Panics at startup if any family's ceiling is 0 — the governor crate
/// requires a non-zero burst size (same contract as
/// [`build_grpc_governor_layer`]).
pub fn build_grpc_method_scoped_governor_layer(
    limits: GrpcRateLimits,
) -> GrpcMethodScopedGovernorLayer {
    GrpcMethodScopedGovernorLayer {
        authz: build_grpc_governor_layer(limits.per_sec(GrpcMethodFamily::AuthzCheck)),
        identity: build_grpc_governor_layer(limits.per_sec(GrpcMethodFamily::IdentityRead)),
        admin: build_grpc_governor_layer(limits.per_sec(GrpcMethodFamily::Admin)),
        infra: build_grpc_governor_layer(limits.per_sec(GrpcMethodFamily::Infra)),
    }
}

/// `tower::Layer` producing [`GrpcMethodScopedGovernor`] — see
/// [`build_grpc_method_scoped_governor_layer`].
#[derive(Clone)]
pub struct GrpcMethodScopedGovernorLayer {
    authz: GrpcGovernorLayer,
    identity: GrpcGovernorLayer,
    admin: GrpcGovernorLayer,
    infra: GrpcGovernorLayer,
}

impl<S: Clone> Layer<S> for GrpcMethodScopedGovernorLayer {
    type Service = GrpcMethodScopedGovernor<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcMethodScopedGovernor {
            authz: self.authz.layer(inner.clone()),
            identity: self.identity.layer(inner.clone()),
            admin: self.admin.layer(inner.clone()),
            infra: self.infra.layer(inner),
        }
    }
}

/// Dispatches each request to the governor for its [`GrpcMethodFamily`].
///
/// All four branches wrap clones of the SAME inner service, so this is a
/// routing decision over rate-limit state only — the request itself reaches
/// the identical tonic router whichever branch it takes. There is no
/// pass-through branch: the infrastructure family has its own (generous)
/// governor rather than bypassing the layer (residual 4).
#[derive(Clone)]
pub struct GrpcMethodScopedGovernor<S> {
    authz: GrpcGovernor<S>,
    identity: GrpcGovernor<S>,
    admin: GrpcGovernor<S>,
    infra: GrpcGovernor<S>,
}

impl<S> Service<Request<tonic::body::Body>> for GrpcMethodScopedGovernor<S>
where
    S: Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Every branch must be ready before we can promise `call` will
        // succeed, since the family is only known once the request arrives.
        // In practice all four wrap clones of the same always-ready tonic
        // router, so this is a formality that keeps the tower contract exact.
        std::task::ready!(Service::poll_ready(&mut self.authz, cx))?;
        std::task::ready!(Service::poll_ready(&mut self.identity, cx))?;
        std::task::ready!(Service::poll_ready(&mut self.admin, cx))?;
        Service::poll_ready(&mut self.infra, cx)
    }

    fn call(&mut self, req: Request<tonic::body::Body>) -> Self::Future {
        // Standard clone-and-swap per branch so the returned future owns an
        // independent, ready-to-call copy (same convention as
        // `GrpcSharedRateLimitService::call`).
        match GrpcMethodFamily::classify(req.uri().path()) {
            GrpcMethodFamily::AuthzCheck => {
                let clone = self.authz.clone();
                let mut svc = std::mem::replace(&mut self.authz, clone);
                Box::pin(async move { svc.call(req).await })
            }
            GrpcMethodFamily::IdentityRead => {
                let clone = self.identity.clone();
                let mut svc = std::mem::replace(&mut self.identity, clone);
                Box::pin(async move { svc.call(req).await })
            }
            GrpcMethodFamily::Admin => {
                let clone = self.admin.clone();
                let mut svc = std::mem::replace(&mut self.admin, clone);
                Box::pin(async move { svc.call(req).await })
            }
            GrpcMethodFamily::Infra => {
                let clone = self.infra.clone();
                let mut svc = std::mem::replace(&mut self.infra, clone);
                Box::pin(async move { svc.call(req).await })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared SurrealDB-backed pre-check layer (Task 2 — D-01a/b/c parity)
// ---------------------------------------------------------------------------

/// Fixed-window duration (seconds) for the shared bucket — same value and
/// rationale as the REST shared pre-check
/// (`axiam-api-rest::middleware::rate_limit_shared::WINDOW_SECS`): a simple
/// fixed-window counter is acceptable here since this layer only needs to be
/// *approximately* right (it fails open by design).
pub const WINDOW_SECS: i64 = 60;

/// Converts a per-**second** ceiling into the budget for one
/// [`WINDOW_SECS`]-second shared window (I1).
///
/// **This is the units bug this constant exists to prevent.** The gRPC
/// ceiling (`AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`) is per second; the shared
/// cross-replica bucket is a fixed 60-second window shared with the REST
/// limiter, whose knobs are per minute. Before I1 the per-second number was
/// handed to [`GrpcSharedRateLimitLayer::new`] verbatim, so the shared layer
/// enforced "N per 60 s" while the operator had configured "N per second" —
/// and since the stricter of the two cooperating layers wins, the effective
/// ceiling was **1/60th** of the configured one. Run 4 measured exactly that:
/// with `GRPC_AUTHZ_PER_SEC=100`, all three gRPC scenarios admitted ~100 ops
/// per minute (`claude_dev/improvement-after-run4-benchmark.md` I1).
///
/// The multiply saturates: an operator who configures a per-second ceiling
/// above `u32::MAX / 60` gets `u32::MAX` for the window (effectively
/// unlimited, which is what they asked for) instead of a wrapped — and
/// therefore *tiny* — budget.
///
/// The alternative fix, a per-second shared window, was rejected: it would
/// fork the `rate_limit_bucket` schema away from the REST limiter's and
/// change the write-behind flusher cadence, for no enforcement benefit.
pub const fn per_sec_to_window_limit(per_sec: u32) -> u32 {
    per_sec.saturating_mul(WINDOW_SECS as u32)
}

/// Truncates `now` down to the start of the current fixed
/// [`WINDOW_SECS`]-second window.
///
/// No longer on the request path — [`GrpcSharedRateLimitService::call`] hands
/// the raw `now` to [`axiam_db::SharedRateLimitCounter::check_at`] instead
/// (run-5 J1). Kept, and asserted by a test, because [`WINDOW_SECS`] must
/// keep agreeing with the counter's configured window.
#[cfg_attr(not(test), allow(dead_code))]
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

/// Shared (cross-replica) rate-limit pre-check `tower::Layer` for the gRPC
/// path (SECHRD-03 / D-01a, D-01b, D-01c, D-01d).
///
/// Consults the process-wide write-behind [`SharedRateLimitCounter`]
/// (`axiam-db::rate_limit_counter`) — the SAME counter type and the SAME env
/// knobs the REST `RateLimitShared` middleware uses, so both listeners behave
/// identically. There is no reimplemented counter here. Wire this layer BEFORE
/// (i.e. `.layer()` it FIRST — tower's `ServiceBuilder`/`Server::builder()`
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
/// # No synchronous datastore write on the request path (H2 fix)
///
/// This layer used to `await` one SurrealDB `UPSERT` per call. Because it is a
/// **server-wide** layer on the tonic listener, EVERY gRPC call paid that
/// write — measured at ~39–46 ms of datastore-attributed latency, pinning the
/// listener at ~20 ops/s regardless of concurrency
/// (`claude_dev/postseed-transient-investigation.md` §1, §2, §7). It now pays
/// only an in-memory sharded-map increment
/// ([`SharedRateLimitCounter::check`], fully synchronous), while a single
/// background flusher coalesces the increments into one datastore write per
/// bucket per `AXIAM__RATE_LIMIT__SHARED_SYNC_MS`. Cross-replica enforcement
/// is therefore eventual, with the overshoot bound stated precisely in the
/// [`axiam_db::rate_limit_counter`] module docs; the in-memory governor still
/// makes a full per-replica decision on the same traffic.
///
/// Everything else is unchanged: the same `{endpoint}:{ip}` bucket key, the
/// same `GrpcTrustedHopsKeyExtractor` key derivation (D-01d), and the same
/// `RESOURCE_EXHAUSTED` rejection.
///
/// **Fail-open (D-01b, T-24-73 accepted risk):** when no client IP can be
/// extracted, or the shared layer is disabled via
/// `AXIAM__RATE_LIMIT__SHARED=off`, this layer forwards the request unchanged
/// so the existing in-memory governor makes the decision instead. Store
/// outages are surfaced by the counter's flusher (a `warn` alarm that never
/// includes the raw key) while decisions keep being served from local counts —
/// a counter-store outage must never hard-block gRPC authz traffic.
///
/// **CRITICAL (RESEARCH Pitfall 1):** `governor::StateStore::measure_and_replace`
/// is a *synchronous* trait method. This layer is deliberately NOT a
/// `StateStore` implementation and never calls `block_on`.
///
/// No longer generic over the SurrealDB connection type: it holds a
/// non-generic [`SharedRateLimitCounter`] (which owns the boxed store), which
/// is why the SurrealDB handle only appears in [`Self::new`]'s signature.
#[derive(Clone)]
pub struct GrpcSharedRateLimitLayer {
    counter: SharedRateLimitCounter,
    scope: SharedScope,
    trusted_hops: usize,
}

/// How a [`GrpcSharedRateLimitLayer`] derives `(bucket endpoint, window
/// limit)` for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedScope {
    /// One bucket for every request, whatever the method — the pre-I2 shape.
    /// `limit` is already expressed in the 60-second window.
    Uniform { endpoint: &'static str, limit: u32 },
    /// One bucket per [`GrpcMethodFamily`] (I2), sized from per-second
    /// ceilings and converted with [`per_sec_to_window_limit`].
    PerFamily(GrpcRateLimits),
}

impl SharedScope {
    /// `(endpoint, window limit)` for `path`.
    ///
    /// Every path resolves to a bucket — since residual 4 there is no family
    /// that skips the shared counter.
    fn resolve(self, path: &str) -> (&'static str, u32) {
        match self {
            Self::Uniform { endpoint, limit } => (endpoint, limit),
            Self::PerFamily(limits) => {
                let family = GrpcMethodFamily::classify(path);
                (family.shared_endpoint(), limits.window_limit(family))
            }
        }
    }
}

impl GrpcSharedRateLimitLayer {
    /// Builds the layer and its process-wide write-behind counter from a
    /// SurrealDB handle, reading `AXIAM__RATE_LIMIT__SHARED` /
    /// `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` via
    /// [`axiam_db::SharedRateLimitConfig::from_env`].
    ///
    /// Call this ONCE per process (as `start_grpc_server` does): the counter's
    /// local counts live in the instance it creates, so building several would
    /// fragment them. Use [`Self::with_counter`] to share one counter
    /// explicitly.
    ///
    /// `endpoint` MUST be unique per rate-limited gRPC surface so the shared
    /// bucket key (`"{endpoint}:{ip}"`) preserves per-surface granularity —
    /// never collapse distinct surfaces into one global bucket.
    ///
    /// **Units:** `limit` is the budget for one [`WINDOW_SECS`]-second window,
    /// NOT a per-second rate. Prefer [`Self::new_method_scoped`], whose
    /// parameter type ([`GrpcRateLimits`]) is per-second at the boundary and
    /// does the conversion itself — that is the shape that makes the I1 units
    /// bug unrepresentable.
    pub fn new<C: Connection>(
        db: impl Into<axiam_db::DbHandle<C>>,
        endpoint: &'static str,
        limit: u32,
        trusted_hops: usize,
    ) -> Self {
        Self::with_counter(
            SharedRateLimitCounter::from_env(Arc::new(SurrealRateLimitBucketRepository::new(db))),
            endpoint,
            limit,
            trusted_hops,
        )
    }

    /// Builds the layer over an EXISTING counter — for tests, and for any
    /// deployment that wants the gRPC listener and something else to share one
    /// counter instance.
    ///
    /// `limit` is per [`WINDOW_SECS`]-second window — see [`Self::new`].
    pub fn with_counter(
        counter: SharedRateLimitCounter,
        endpoint: &'static str,
        limit: u32,
        trusted_hops: usize,
    ) -> Self {
        Self {
            counter,
            scope: SharedScope::Uniform { endpoint, limit },
            trusted_hops,
        }
    }

    /// **The production constructor (I1 + I2).** Builds the layer and its
    /// process-wide write-behind counter with one shared bucket per
    /// [`GrpcMethodFamily`], sized from **per-second** ceilings.
    ///
    /// The per-second → per-window conversion happens here, once, via
    /// [`per_sec_to_window_limit`] — a caller cannot get the units wrong
    /// because it never sees the window.
    pub fn new_method_scoped<C: Connection>(
        db: impl Into<axiam_db::DbHandle<C>>,
        limits: GrpcRateLimits,
        trusted_hops: usize,
    ) -> Self {
        Self::with_counter_method_scoped(
            SharedRateLimitCounter::from_env(Arc::new(SurrealRateLimitBucketRepository::new(db))),
            limits,
            trusted_hops,
        )
    }

    /// [`Self::new_method_scoped`] over an EXISTING counter — for tests and
    /// for sharing one counter instance across listeners.
    pub fn with_counter_method_scoped(
        counter: SharedRateLimitCounter,
        limits: GrpcRateLimits,
        trusted_hops: usize,
    ) -> Self {
        Self {
            counter,
            scope: SharedScope::PerFamily(limits),
            trusted_hops,
        }
    }

    /// The `(bucket endpoint, window limit)` this layer applies to `path`.
    ///
    /// Exposed so the units at the composition root can be asserted directly
    /// by a test instead of by reading the call site (I1 acceptance).
    pub fn resolve_for_path(&self, path: &str) -> (&'static str, u32) {
        self.scope.resolve(path)
    }
}

impl<S> Layer<S> for GrpcSharedRateLimitLayer {
    type Service = GrpcSharedRateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcSharedRateLimitService {
            inner,
            counter: self.counter.clone(),
            scope: self.scope,
            trusted_hops: self.trusted_hops,
        }
    }
}

/// Inner `tower::Service` produced by [`GrpcSharedRateLimitLayer`].
///
/// `Clone` requires only `S: Clone` — [`SharedRateLimitCounter`] is an
/// `Arc`-backed handle, so every clone (one per request, via tonic's
/// clone-and-swap) shares the SAME counter state.
#[derive(Clone)]
pub struct GrpcSharedRateLimitService<S> {
    inner: S,
    counter: SharedRateLimitCounter,
    scope: SharedScope,
    trusted_hops: usize,
}

impl<S> Service<Request<tonic::body::Body>> for GrpcSharedRateLimitService<S>
where
    S: Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
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

        // Cheap `Arc` clone — every request shares the ONE process-wide
        // counter, never a fresh one (a per-request counter would count
        // nothing).
        let counter = self.counter.clone();
        // I2: the bucket (and its ceiling) depend on which method family the
        // request belongs to. Every family resolves to a bucket — reflection
        // and health are counted too, against a generous one (residual 4).
        let (endpoint, limit) = self.scope.resolve(req.uri().path());
        let key_extractor = GrpcTrustedHopsKeyExtractor::new(self.trusted_hops);

        // The rate-limit decision itself is now synchronous and taken BEFORE
        // the future is even created — no datastore round trip on the path of
        // this (server-wide!) layer. The returned future only awaits the inner
        // service.
        let ip = key_extractor.extract(&req).ok();
        let allow = match ip {
            Some(ip) => {
                // Same bucket key shape as before — `{endpoint}:{ip}` — and
                // the authz family keeps the `grpc_authz` endpoint name, so an
                // in-flight upgrade keeps counting against the same
                // `rate_limit_bucket` records.
                let key = format!("{endpoint}:{ip}");
                // `check_at` (not `check`): the counter derives the window
                // itself AND sees the offset into it, which is what its
                // sliding-window mode needs to bound every rolling minute
                // rather than only the aligned ones (run-5 J1,
                // `axiam_db::rate_limit_counter::WindowMode`).
                counter.check_at(&key, Utc::now(), limit)
            }
            // No client-IP key available — fail open; the in-memory governor
            // still makes the real decision. (A counter built with
            // `AXIAM__RATE_LIMIT__SHARED=off` also always allows, from inside
            // `check`.)
            None => true,
        };

        Box::pin(async move {
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

    // -----------------------------------------------------------------
    // CORR-01/D-02: sustained-throughput + monotonicity regression test
    // -----------------------------------------------------------------
    //
    // Drives sustained load against the SAME `governor::Quota::per_second`
    // construction `build_grpc_governor_layer` uses (see the production
    // function above) via a `FakeRelativeClock`, and asserts the permitted
    // count over a simulated window approximates the configured rate — the
    // only reliable way to distinguish a correctly-throttling governor from
    // one that is inverted (RESEARCH Pitfall 1: a naive "does the first
    // burst get through" smoke test looks identical either way).
    //
    // This test would FAIL against the old, inverted construction: with
    // `tower_governor`'s `.per_second(n)` treated as "n tokens/sec" (the
    // CQ-B44 bug), the replenish period becomes `n` SECONDS, so over a
    // 1-second simulated window virtually no additional tokens regenerate
    // past the initial burst — the sustained (post-burst) count would be
    // ~0, not approximately `n`.
    fn permitted_over_window(rate: u32, window: std::time::Duration) -> u64 {
        use governor::RateLimiter;
        use governor::clock::FakeRelativeClock;

        let burst = NonZeroU32::new(rate).expect("rate >= 1");
        let quota = Quota::per_second(burst);
        let clock = FakeRelativeClock::default();
        let limiter = RateLimiter::direct_with_clock(quota, clock.clone());

        // Drain the initial burst (the bucket starts full) — burst capacity
        // is a separate, already-asserted property (D-01: burst ==
        // authz_per_sec); it must NOT be counted as "sustained" throughput,
        // or a fully-inverted governor with a large burst could still look
        // like it's passing this test on the first drain alone.
        while limiter.check().is_ok() {}

        // Now simulate sustained load: advance the fake clock in small
        // steps across the window, greedily draining whatever new tokens
        // have accumulated at each step — this proves tokens keep
        // replenishing throughout the window (sustained throughput), not
        // just once at t=0.
        let step = std::time::Duration::from_millis(5);
        let mut elapsed = std::time::Duration::ZERO;
        let mut permitted: u64 = 0;
        while elapsed < window {
            clock.advance(step);
            elapsed += step;
            while limiter.check().is_ok() {
                permitted += 1;
            }
        }
        permitted
    }

    #[test]
    fn governor_sustained_throughput_matches_configured_rate() {
        let window = std::time::Duration::from_secs(1);
        let rate = 50u32;

        let permitted = permitted_over_window(rate, window);

        // Tolerance band accounts for the fake clock's discrete 5ms step
        // granularity relative to the token replenish interval; well
        // outside this band would mean the governor is not throttling at
        // approximately the configured rate (CORR-01's ~1/100s inversion
        // would put this number at ~0, nowhere close to 50).
        let lower = (rate as f64 * 0.7) as u64;
        let upper = (rate as f64 * 1.3) as u64;
        assert!(
            permitted >= lower && permitted <= upper,
            "expected sustained throughput approximately {rate} req/s over a \
             1s window (allowed range {lower}..={upper}), got {permitted} — \
             the governor quota construction may be inverted again (CORR-01)"
        );
        assert!(
            permitted > 1,
            "sustained throughput of {permitted} over 1s is consistent with \
             the ~1-token/100s inversion bug this test guards against"
        );
    }

    #[test]
    fn governor_higher_configured_rate_permits_strictly_more_requests() {
        // Monotonicity guard: a higher `authz_per_sec` must yield strictly
        // more permitted requests than a lower one over the SAME simulated
        // window. An inverted construction (period, not rate) would make
        // this relationship backwards (raising the configured rate makes
        // the governor SLOWER) or flat (both effectively ~0).
        let window = std::time::Duration::from_secs(1);

        let low = permitted_over_window(10, window);
        let high = permitted_over_window(100, window);

        assert!(
            high > low,
            "expected a higher configured rate (100/s) to permit strictly \
             more sustained requests than a lower rate (10/s) over the same \
             1s window, got low={low} high={high} — the quota construction \
             may be inverted (CORR-01)"
        );
    }

    // -----------------------------------------------------------------
    // I1 — the shared-window units, pinned at the boundary
    // -----------------------------------------------------------------

    /// The shared bucket's window is 60 s and the gRPC ceilings are per
    /// second. If this ever stops being true, `per_sec_to_window_limit` is
    /// wrong and the ×60 units bug is back.
    #[test]
    fn shared_window_is_sixty_seconds() {
        assert_eq!(WINDOW_SECS, 60);
    }

    #[test]
    fn per_sec_converts_to_a_sixty_second_window_budget() {
        assert_eq!(per_sec_to_window_limit(1), 60);
        assert_eq!(per_sec_to_window_limit(100), 6_000);
        assert_eq!(per_sec_to_window_limit(1_000), 60_000);
        // Saturating, never wrapping: a wrapped multiply would produce a
        // TINY budget from a huge configured rate — the opposite of what the
        // operator asked for, and silently.
        assert_eq!(per_sec_to_window_limit(u32::MAX), u32::MAX);
        assert_eq!(per_sec_to_window_limit(u32::MAX / 2), u32::MAX);
    }

    /// **The I1 call-site pin.** The layer the composition root builds
    /// (`server.rs::start_grpc_server` → `new_method_scoped`) must enforce
    /// `configured_per_sec × 60` against its 60-second window — NOT the
    /// per-second number verbatim, which is what made the effective ceiling
    /// 1/60th of the configured one.
    #[test]
    fn method_scoped_shared_layer_enforces_per_sec_times_sixty() {
        let limits = GrpcRateLimits::from_authz_per_sec(100);
        let layer = GrpcSharedRateLimitLayer::with_counter_method_scoped(
            SharedRateLimitCounter::disabled(axiam_db::SharedRateLimitConfig::default()),
            limits,
            0,
        );

        let (endpoint, limit) =
            layer.resolve_for_path("/axiam.v1.AuthorizationService/CheckAccess");
        assert_eq!(endpoint, "grpc_authz", "bucket key must not change (I1)");
        assert_eq!(
            limit, 6_000,
            "the 60-second shared window must budget 100/s × 60 = 6 000; a bare 100 \
             here is the ×60 units bug (I1)"
        );

        // The same conversion applies to every family.
        assert_eq!(
            layer.resolve_for_path("/axiam.v1.UserInfoService/GetUserInfo"),
            ("grpc_identity", 100 * IDENTITY_PER_SEC_MULTIPLE * 60)
        );
        assert_eq!(
            layer.resolve_for_path("/axiam.v1.UserService/GetUser"),
            ("grpc_admin", ADMIN_PER_SEC_DEFAULT * 60)
        );
        assert_eq!(
            layer.resolve_for_path("/grpc.health.v1.Health/Check"),
            ("grpc_infra", INFRA_PER_SEC * 60),
            "the infrastructure family is bucketed, not skipped (residual 4)"
        );
    }

    /// The legacy uniform constructor is unchanged: its `limit` is already a
    /// window budget and is applied to every path, whatever the method.
    #[test]
    fn uniform_scope_applies_one_bucket_to_every_path() {
        let layer = GrpcSharedRateLimitLayer::with_counter(
            SharedRateLimitCounter::disabled(axiam_db::SharedRateLimitConfig::default()),
            "grpc_authz",
            42,
            0,
        );
        for path in [
            "/axiam.v1.AuthorizationService/CheckAccess",
            "/axiam.v1.UserInfoService/GetUserInfo",
            "/grpc.health.v1.Health/Check",
            "/",
        ] {
            assert_eq!(layer.resolve_for_path(path), ("grpc_authz", 42));
        }
    }

    // -----------------------------------------------------------------
    // I2 — per-method-family scoping
    // -----------------------------------------------------------------

    #[test]
    fn classifies_each_service_into_its_family() {
        use GrpcMethodFamily::*;
        for (path, expected) in [
            ("/axiam.v1.AuthorizationService/CheckAccess", AuthzCheck),
            (
                "/axiam.v1.AuthorizationService/BatchCheckAccess",
                AuthzCheck,
            ),
            ("/axiam.v1.UserInfoService/GetUserInfo", IdentityRead),
            ("/axiam.v1.TokenService/ValidateToken", IdentityRead),
            ("/axiam.v1.TokenService/IntrospectToken", IdentityRead),
            ("/axiam.v1.UserService/GetUser", Admin),
            ("/axiam.v1.UserService/ValidateCredentials", Admin),
            ("/grpc.health.v1.Health/Check", Infra),
            ("/grpc.health.v1.Health/Watch", Infra),
            (
                "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
                Infra,
            ),
            (
                "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                Infra,
            ),
        ] {
            assert_eq!(GrpcMethodFamily::classify(path), expected, "{path}");
        }
    }

    /// Fail-safe default: an unrecognized path lands in the STRICTEST limited
    /// family, never in the most generous one. Adding a service without
    /// updating `classify` must not silently create a loosely-limited gRPC
    /// surface.
    #[test]
    fn unknown_paths_fall_back_to_the_strictest_family() {
        for path in [
            "/",
            "/nonsense",
            "/some.other.Service/Method",
            "/axiam.v1.FutureService/Whatever",
        ] {
            assert_eq!(
                GrpcMethodFamily::classify(path),
                GrpcMethodFamily::AuthzCheck,
                "{path} must fail safe into the authz bucket"
            );
        }
    }

    /// I2's core claim: an identity read is no longer throttled by the authz
    /// ceiling, and the three limited families use three distinct buckets.
    #[test]
    fn families_get_distinct_buckets_and_distinct_ceilings() {
        let limits = GrpcRateLimits::from_authz_per_sec(100);
        assert_eq!(limits.authz_per_sec, 100);
        assert_eq!(limits.identity_per_sec, 500);
        assert_eq!(limits.admin_per_sec, ADMIN_PER_SEC_DEFAULT);
        assert!(
            limits.identity_per_sec > limits.authz_per_sec,
            "identity reads measured ~14x an authz check; their ceiling must not \
             be the authz ceiling (I2)"
        );

        let endpoints: Vec<_> = [
            GrpcMethodFamily::AuthzCheck,
            GrpcMethodFamily::IdentityRead,
            GrpcMethodFamily::Admin,
            GrpcMethodFamily::Infra,
        ]
        .iter()
        .map(|f| f.shared_endpoint())
        .collect();
        assert_eq!(
            endpoints,
            vec!["grpc_authz", "grpc_identity", "grpc_admin", "grpc_infra"]
        );
    }

    /// **SEC-079.** The admin ceiling is a CPU guard on an Argon2id RPC and
    /// must NOT scale with the read-sized authz base — otherwise a
    /// `gateway`/`mesh` posture (or any operator raising the authz ceiling for
    /// service-mesh throughput) silently widens online password guessing.
    #[test]
    fn admin_ceiling_never_derives_from_the_authz_ceiling() {
        for authz in [1, 100, 1_000, 5_000, 60_000, u32::MAX] {
            let limits = GrpcRateLimits::from_authz_per_sec(authz);
            assert_eq!(
                limits.admin_per_sec, ADMIN_PER_SEC_DEFAULT,
                "authz={authz}: the admin ceiling must stay at the absolute default \
                 ({ADMIN_PER_SEC_DEFAULT}/s); deriving it from a read-sized base is SEC-079"
            );
            assert_eq!(
                limits.per_sec(GrpcMethodFamily::Admin),
                ADMIN_PER_SEC_DEFAULT
            );
        }

        // And the absolute value is the CPU-appropriate one: 10/s = 600/min
        // per IP through the 60-second shared window.
        assert_eq!(ADMIN_PER_SEC_DEFAULT, 10);
        assert_eq!(
            GrpcRateLimits::from_authz_per_sec(100).window_limit(GrpcMethodFamily::Admin),
            600,
            "600 credential checks per minute per IP — not the 6 000 the units fix \
             would have produced from the read-sized base"
        );
    }

    /// A profile preset that raises the authz ceiling raises the **identity**
    /// family with it, so `gateway`/`mesh` cannot end up with identity reads
    /// stricter than authz checks — and moves nothing else.
    #[test]
    fn derived_family_scales_with_the_authz_ceiling() {
        for authz in [100, 1_000, 5_000] {
            let limits = GrpcRateLimits::from_authz_per_sec(authz);
            assert_eq!(limits.identity_per_sec, authz * IDENTITY_PER_SEC_MULTIPLE);
            assert_eq!(limits.admin_per_sec, ADMIN_PER_SEC_DEFAULT);
            assert_eq!(limits.per_sec(GrpcMethodFamily::Infra), INFRA_PER_SEC);
            assert!(limits.identity_per_sec >= limits.authz_per_sec);
        }
        // Saturating, not wrapping.
        let huge = GrpcRateLimits::from_authz_per_sec(u32::MAX);
        assert_eq!(huge.identity_per_sec, u32::MAX);
    }

    /// **Residual 4.** The infrastructure family is generous but finite, and
    /// its ceiling is fixed rather than posture-derived.
    #[test]
    fn infra_family_is_generous_but_finite() {
        assert_eq!(INFRA_PER_SEC, 100);
        for authz in [1, 100, 5_000] {
            let limits = GrpcRateLimits::from_authz_per_sec(authz);
            assert_eq!(limits.per_sec(GrpcMethodFamily::Infra), INFRA_PER_SEC);
            assert_eq!(
                limits.window_limit(GrpcMethodFamily::Infra),
                INFRA_PER_SEC * 60
            );
        }
        // Read through the accessor (not the constant) so these stay real
        // assertions rather than const-folded no-ops.
        let infra = GrpcRateLimits::from_authz_per_sec(1).per_sec(GrpcMethodFamily::Infra);
        assert!(
            infra >= 100,
            "a liveness probe must never be the thing that breaks during an incident, \
             got {infra}/s"
        );
        assert!(
            infra < u32::MAX,
            "…but the family must be bounded — an unbounded prefix match on the \
             attacker-controlled :path is what residual 4 closed"
        );
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
