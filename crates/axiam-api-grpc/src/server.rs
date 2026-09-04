//! Tonic gRPC server setup.
//!
//! CQ-B20: Server builder sets message-size limits, per-connection timeout,
//! and concurrency limit to prevent resource exhaustion.
//!
//! # TLS (REQ-15 AC-1, R-1 / T-234)
//!
//! This listener does **not** ask tonic to terminate TLS. It takes the
//! already-built rustls configuration as a value — [`GrpcTls`] — and does the
//! handshake itself in [`crate::tls_incoming`], handing tonic an
//! already-encrypted stream through `serve_with_incoming`.
//!
//! That indirection is the whole point of the change, and it buys two things
//! `tonic::transport::ServerTlsConfig` cannot express, because it accepts
//! neither a `rustls::ServerConfig` nor a certificate resolver:
//!
//! - **the leaf can be replaced while the listener runs.** The configuration
//!   this crate is handed carries `axiam-server`'s `ReloadableCertResolver`,
//!   the same instance the REST listener serves from when both listen on the
//!   same leaf, so one `SIGHUP` (or one hourly poll) renews both. Before this,
//!   the gRPC leaf was fixed at boot and a 90-day ACME certificate expired in
//!   place unless an operator restarted the container — the failure T-214
//!   fixed for REST and T-234 recorded as still open for gRPC.
//! - **TLS 1.3 only.** The configuration is built with
//!   `with_protocol_versions(&[&rustls::version::TLS13])`, matching the REST
//!   posture (ASVS V9.1.2). Under `ServerTlsConfig` the crate default left
//!   TLS 1.2 negotiable, which is the caveat T-233 recorded.
//!
//! Who builds that configuration is not a free choice: `ReloadableCertResolver`
//! lives in `axiam-server` (layer 8) and this crate is layer 6, so the value
//! has to arrive from above (`scripts/check-crate-layering.py` enforces it).
//! The composition root reads `AXIAM__GRPC_TLS_CERT_PATH` /
//! `AXIAM__GRPC_TLS_KEY_PATH` — unchanged flat names, unchanged
//! panic-on-unreadable, so a typo is still a failed boot — and passes
//! [`GrpcTls::Rustls`] or [`GrpcTls::Plaintext`]. The `INFO`/`WARN` lines the
//! Pi runbook §14.4 greps for (`gRPC server TLS enabled`,
//! `gRPC TLS is DISABLED`) are still emitted from here, so which mode a
//! listener came up in is still readable from this listener's own log.
//!
//! D2 (benchmark plan — native gRPC TLS termination): this is the same
//! mechanism the p2-tls13 native-TLS bench overlay
//! (`benchmarks/targets/axiam/docker-compose.native-tls.yml`) turns on,
//! pointed at the SAME server cert/key files the REST listener uses
//! (`crates/axiam-server/src/tls.rs` / `AXIAM__SERVER__TLS__CERT_PATH`+
//! `KEY_PATH`) so the two protocols present identical PKI material.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::repository::{
    AuditLogRepository, GroupRepository, PermissionRepository, ReactorRepository,
    ResourceRepository, RoleRepository, ScopeRepository, UserRepository,
};
use axiam_db::DbHandle;
use surrealdb::Connection;
use tokio::sync::Semaphore;
use tonic::transport::Server;
use uuid::Uuid;

use crate::config::GrpcConfig;
use crate::middleware::auth::AuthInterceptor;
use crate::middleware::drain_rejected::DrainRejectedBodyLayer;
use crate::middleware::rate_limit::{
    GrpcSharedRateLimitLayer, build_grpc_method_scoped_governor_layer, trusted_hops_from_env,
};
use crate::middleware::strict_revocation::{GrpcStrictRevocationLayer, SessionRevocationCheck};
use crate::proto::authorization_service_server::AuthorizationServiceServer;
use crate::proto::reactor_admin_service_server::ReactorAdminServiceServer;
use crate::proto::token_service_server::TokenServiceServer;
use crate::proto::user_info_service_server::UserInfoServiceServer;
use crate::proto::user_service_server::UserServiceServer;
use crate::services::{
    AuthorizationServiceImpl, ReactorAdminServiceImpl, TokenServiceImpl, UserInfoServiceImpl,
    UserServiceImpl,
};
use crate::tls_incoming::tls_incoming;

/// How the gRPC listener terminates TLS, as decided by the composition root.
///
/// # Why a value rather than an env read
///
/// The certificate the listener serves must be replaceable while it runs, and
/// the machinery that does that — `axiam_server::tls::ReloadableCertResolver`,
/// the reload trigger it is registered with, and the `SIGHUP`/poll task that
/// fires them — lives in `axiam-server`. That crate is layer 8; this one is
/// layer 6, and `scripts/check-crate-layering.py` fails any build where an
/// edge points the other way. So the configuration arrives already built, and
/// the two listeners end up sharing one resolver instance instead of this
/// crate growing its own second copy of the reload mechanism.
///
/// Reading the env vars stays with the composition root for the same reason:
/// deciding TLS is on is a deployment fact, and the only place that can act on
/// it — by building a config over the *same* leaf the REST listener resolved —
/// is the place that already resolved it.
///
/// # Example
///
/// What `axiam-server`'s `main()` does. `grpc_tls_from_env` returns `None` when
/// neither `AXIAM__GRPC_TLS_CERT_PATH` nor `AXIAM__GRPC_TLS_KEY_PATH` is set —
/// the in-mesh posture, where a sidecar owns transport security — and panics
/// when one is set but unreadable, because a listener that fell back to
/// plaintext on a typo would serve cleartext on a port an operator believes is
/// encrypted:
///
/// ```ignore
/// // In axiam-server, which owns the reloadable certificate resolver:
/// let tls = match axiam_server::tls::grpc_tls_from_env() {
///     Some(config) => {
///         // Idempotent — the REST bind calls this too, and either listener
///         // can be the only one with TLS on.
///         axiam_server::tls::spawn_leaf_reloader(reload_interval_secs);
///         axiam_api_grpc::GrpcTls::Rustls(config)
///     }
///     None => axiam_api_grpc::GrpcTls::Plaintext,
/// };
///
/// axiam_api_grpc::start_grpc_server(addr, /* ..., */ tls).await?;
/// ```
///
/// A caller outside that crate — a test, or an embedding that manages its own
/// PKI — can build the configuration itself; nothing here requires the
/// resolver, only that whoever wants renewals without a restart uses one:
///
/// ```
/// use std::sync::Arc;
/// use axiam_api_grpc::GrpcTls;
///
/// # fn build(config: Arc<rustls::ServerConfig>) -> GrpcTls {
/// let tls = GrpcTls::Rustls(config);
/// # tls
/// # }
/// // ...or, for an in-mesh deployment behind a sidecar:
/// let plaintext = GrpcTls::Plaintext;
/// assert!(matches!(plaintext, GrpcTls::Plaintext));
/// ```
#[derive(Clone)]
pub enum GrpcTls {
    /// No transport security on this listener.
    ///
    /// The shipped default, and correct for an in-mesh deployment where a
    /// sidecar terminates mutual TLS, or a loopback bind behind a terminating
    /// reverse proxy. Emits the `gRPC TLS is DISABLED` warning the Pi runbook
    /// §14.4 tells operators to grep for.
    Plaintext,
    /// Terminate TLS in-process with this rustls configuration.
    ///
    /// Expected to be TLS 1.3-only and to resolve its leaf through a reloadable
    /// resolver; `axiam_server::tls::build_grpc_rustls_server_config` builds
    /// exactly that. Nothing here enforces those properties — this crate cannot
    /// see the resolver behind the config — which is why the builder that can
    /// is the one the composition root calls.
    Rustls(Arc<rustls::ServerConfig>),
}

/// Start the gRPC server with all registered services.
///
/// Applies two cooperating rate-limit layers (SECHRD-03, D-01a/b/c — gap
/// closure for 24-07): the [`GrpcSharedRateLimitLayer`] cross-replica
/// pre-check runs FIRST (outermost), failing OPEN to the per-replica in-memory
/// governor stack (per D-10). Both layers derive their client-IP key from the
/// SAME `trusted_hops` value so gRPC keying stays in lockstep across the
/// shared counter and the in-memory fallback, and both are sized from the
/// same per-second [`crate::middleware::rate_limit::GrpcRateLimits`] value.
///
/// Since I1/I2 the ceilings are **per method family**, not server-wide:
/// `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` sizes `AuthorizationService`,
/// `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` sizes `UserInfoService`/`TokenService`,
/// `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` sizes `UserService`, and gRPC
/// reflection/health are never limited.
///
/// Since the H2 performance fix the shared pre-check performs NO synchronous
/// datastore write: it is backed by the process-wide write-behind
/// `axiam_db::SharedRateLimitCounter`, built ONCE here (this layer is
/// server-wide, so every gRPC call used to pay one `UPSERT`). Knobs:
/// `AXIAM__RATE_LIMIT__SHARED` (on|off, default on) and
/// `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` (default 1000, clamped 50..=60000) —
/// the same two the REST listener reads.
///
/// Transport limits (CQ-B20):
/// - Max message size: 4 MiB decode / 4 MiB encode
/// - Per-connection timeout: 30 s
/// - Concurrency limit: 256 streams per connection
///
/// TLS (REQ-15 AC-1): env-gated via `AXIAM__GRPC_TLS_CERT_PATH` /
/// `AXIAM__GRPC_TLS_KEY_PATH`. When absent, TLS is disabled and a warning
/// is logged (acceptable for in-mesh/loopback deployments).
///
/// # `strict_revocation_checker` (A4/J10)
///
/// `Some(..)` only when `AXIAM__GRPC__STRICT_REVOCATION=true`, and it MUST be
/// the SAME session-repository instance the REST path holds. A second instance
/// would carry a second validation cache, and a cache the REST invalidation
/// hooks never reach is exactly the stale allow strict mode exists to prevent.
/// `None` keeps the shipped posture: gRPC trusts JWT lifetime, so revocation
/// takes effect at token expiry (up to 15 min) rather than immediately. See
/// [`crate::middleware::strict_revocation`] for the full posture table.
///
/// # `reactor_engine`, `reactor_repo`, `reactor_audit_repo`, `reactor_routing_invalidator` (X1 / R2.3)
///
/// `reactor_engine` is a SECOND [`AuthorizationEngine`] instance, built from
/// the same repositories as `engine`. `AuthorizationEngine` does not
/// implement `Clone`, so `ReactorAdminServiceImpl` cannot share `engine`'s
/// instance — it is given its own, mirroring `AuthorizationServiceImpl`'s.
/// Two engines over the same repositories is correct, not wasteful: the
/// decision cache and invalidation broadcaster (when configured) are handed
/// to both by the caller, so the two stay coherent with each other exactly as
/// `axiam-server`'s REST `AuthzChecker` and this gRPC listener already do.
/// `reactor_routing_invalidator` MUST be the same closure over the same
/// `ReactorRoutingTable` the REST admin handlers invalidate through, or a
/// registration written over gRPC would not take effect on this replica
/// until the routing table's TTL expired.
#[allow(clippy::too_many_arguments)]
pub async fn start_grpc_server<R, P, Res, S, G, U, C, Rr, A>(
    addr: SocketAddr,
    engine: AuthorizationEngine<R, P, Res, S, G>,
    user_repo: U,
    auth_config: AuthConfig,
    grpc_config: &GrpcConfig,
    db: impl Into<DbHandle<C>>,
    batch_max_concurrency: usize,
    strict_revocation_checker: Option<Arc<dyn SessionRevocationCheck>>,
    reactor_engine: AuthorizationEngine<R, P, Res, S, G>,
    reactor_repo: Rr,
    reactor_audit_repo: A,
    reactor_routing_invalidator: Arc<dyn Fn(Uuid) + Send + Sync>,
    // SEC-101 — whether the composed reactor transport can deliver at all.
    // MUST be read from the same gate `axiam-api-rest` holds, so the two
    // admin surfaces refuse (or accept) the same registrations.
    reactor_dispatch_available: bool,
    // B1 — the process-wide Argon2id gate. MUST be a clone of the same
    // `Arc<Semaphore>` `AppState::crypto_semaphore` holds: the permit count
    // bounds peak concurrent ~19 MiB hash arenas for the WHOLE process, so a
    // listener with its own instance would silently double the bound.
    // `UserService/ValidateCredentials` is this listener's only consumer.
    crypto_semaphore: Arc<Semaphore>,
    // Where `UserService/ValidateCredentials` reads the tenant's
    // `max_failed_login_attempts` and backoff. MUST resolve from the same
    // settings store REST's login handler reads, or the same account locks
    // after a different number of failures depending on which transport the
    // attacker used. `axiam_auth::lockout::SettingsLockoutPolicy` is that
    // resolver; `StaticLockoutPolicy` is the deployment-default fallback.
    lockout_policy: Arc<dyn axiam_auth::lockout::LockoutPolicySource>,
    // R-1 / T-234 — how this listener terminates TLS, decided and built by the
    // composition root. See [`GrpcTls`] for why it is a value and not an env
    // read, and the module docs for what changed.
    tls: GrpcTls,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
    U: UserRepository + Clone + 'static,
    C: Connection + 'static,
    Rr: ReactorRepository + 'static,
    A: AuditLogRepository + 'static,
{
    // I2: per-family ceilings (unset knobs derived from the authz ceiling).
    let rate_limits = grpc_config.rate_limits();
    tracing::info!(
        bind = %addr,
        grpc_authz_per_sec = rate_limits.authz_per_sec,
        grpc_identity_per_sec = rate_limits.identity_per_sec,
        grpc_admin_per_sec = rate_limits.admin_per_sec,
        "Starting gRPC server",
    );

    // SECHRD-03 gap closure (24-07 follow-up): the shared-store pre-check
    // MUST use the same trusted_hops value as the in-memory governor's key
    // extractor (both ultimately key off GrpcTrustedHopsKeyExtractor logic)
    // so a rotating XFF cannot mint a fresh bucket in one layer while being
    // correctly collapsed in the other.
    let trusted_hops = trusted_hops_from_env();
    // Built exactly ONCE per process: this constructs the write-behind
    // `SharedRateLimitCounter` (and spawns its single background flusher on
    // this runtime). Cloning the LAYER is fine — the counter inside is an
    // `Arc` handle, so every clone shares the same local counts. Building a
    // second layer would create a second, independent counter.
    //
    // I1 (units) + I2 (scope): both layers are now built from the SAME
    // per-second `GrpcRateLimits` value. `new_method_scoped` converts each
    // per-second ceiling into the shared layer's 60-second window budget
    // itself (`per_sec_to_window_limit`) — previously the per-second number
    // was passed to a per-minute window verbatim, which made the effective
    // gRPC ceiling 1/60th of the configured one.
    let shared_rate_limit_layer =
        GrpcSharedRateLimitLayer::new_method_scoped(db, rate_limits, trusted_hops);
    let governor_layer = build_grpc_method_scoped_governor_layer(rate_limits);

    // A4/J10: built before the interceptors take ownership of `auth_config`.
    // The layer needs it to decode (not verify — see the module docs) the
    // bearer token far enough to learn which session a request names.
    let strict_revocation_layer = strict_revocation_checker.map(|checker| {
        tracing::warn!(
            "gRPC STRICT REVOCATION enabled — every gRPC request now re-checks \
             session validity, matching REST. Expect the gRPC check profile to \
             approach REST's revocation-checked one; with the session-validation \
             cache disabled this is one datastore read per request."
        );
        GrpcStrictRevocationLayer::new(checker, auth_config.clone())
    });

    let authz_svc = AuthorizationServiceServer::with_interceptor(
        AuthorizationServiceImpl::new(engine, batch_max_concurrency),
        AuthInterceptor::new(auth_config.clone()),
    );
    // SECFIX-01: UserService and TokenService previously had zero auth —
    // any unauthenticated mesh peer could call GetUser/ValidateCredentials/
    // IntrospectToken. Wrap them with the same AuthInterceptor chokepoint
    // as AuthorizationService so every gRPC call requires a verified bearer JWT.
    let user_svc = UserServiceServer::with_interceptor(
        UserServiceImpl::new(
            user_repo.clone(),
            auth_config.clone(),
            crypto_semaphore,
            lockout_policy,
        ),
        AuthInterceptor::new(auth_config.clone()),
    );
    // UserInfoService: OIDC-style self lookup — identity derived entirely from
    // the interceptor-verified bearer token (no request body), mirroring the
    // REST `/oauth2/userinfo` endpoint. Guarded by the same AuthInterceptor.
    let user_info_svc = UserInfoServiceServer::with_interceptor(
        UserInfoServiceImpl::new(user_repo),
        AuthInterceptor::new(auth_config.clone()),
    );
    let token_svc = TokenServiceServer::with_interceptor(
        TokenServiceImpl::new(auth_config.clone()),
        AuthInterceptor::new(auth_config.clone()),
    );
    // X1 / R2.3 — reactor admin CRUD over gRPC, mirroring the REST
    // `/api/v1/reactors*` surface. Same `AuthInterceptor` chokepoint as every
    // other authenticated service here.
    let reactor_svc = ReactorAdminServiceServer::with_interceptor(
        ReactorAdminServiceImpl::new(
            reactor_repo,
            reactor_engine,
            reactor_audit_repo,
            reactor_routing_invalidator,
            reactor_dispatch_available,
        ),
        AuthInterceptor::new(auth_config),
    );

    // CQ-B20: Apply transport limits to the gRPC server builder.
    // Note: tonic 0.14 does not expose max_decoding_message_size / max_encoding_message_size
    // at the Server level (added in tonic 0.12+ via the Router API). The HTTP/2 frame-size
    // limit (max_frame_size) is the closest available per-connection cap in 0.14. Upgrade
    // to tonic ≥0.12 to use per-service max_decoding_message_size / max_encoding_message_size.
    // Tracked: max_decoding_message_size (CQ-B20, pending tonic upgrade in Phase 19).
    // SECHRD-03 (D-01a/b/c) + run-5 J1: layer ORDER is load-bearing here.
    // Tower's `Server::builder()` runs the FIRST-added layer with the request
    // FIRST (the opposite of actix's last-`.wrap()`-is-outermost rule), so
    // the layer named first below is the OUTERMOST one.
    //
    // Until run 5 the shared-store pre-check was outermost. That inverted the
    // two layers' natural roles and starved every gRPC family: the pre-check
    // charges its whole 60-second window budget the moment it admits a
    // request, but the per-second `governor` behind it then rejected almost
    // all of those requests. A flood therefore burned all 6 000 authz
    // admissions of a window on traffic that was never served, in well under
    // a second, and the window stayed exhausted for its remaining ~59 —
    // measured at 181 admissions/min against a configured 6 000/min, i.e.
    // 1/33 of the ceiling (`claude_dev/improvement-after-run5-benchmark.md`
    // A1/J1).
    //
    // The governor is therefore now OUTERMOST and owns the admission
    // decision, and the shared cross-replica counter sits behind it, counting
    // only traffic that was actually admitted. Both roles are preserved:
    //
    // - single replica — the governor's per-second quota is the binding
    //   constraint and the shared counter (sized `per_sec × 60`) never trips,
    //   so the effective ceiling equals the configured one;
    // - N replicas — each admits its own per-second quota, their sum reaches
    //   the shared window budget, and the shared counter cuts in. That is
    //   exactly the `replicas × limit` multiplication SECHRD-03 exists to
    //   stop, and it is still stopped.
    //
    // Fail-open is unchanged: on a missing key, a disabled shared layer, or a
    // SurrealDB blip the inner layer forwards the request and the governor's
    // decision (already taken, outside it) stands.
    //
    // The REST listener cannot use this ordering — its shared middleware is
    // also what parses `client_id` out of the form body for the client-aware
    // key modes, so it must stay outermost there. It solves the same problem
    // with `SharedRateLimitCounter::refund` instead; see that method's docs.
    // A4/J10: strict revocation, when enabled, sits INSIDE the rate limiters
    // (so a flood of revoked-session calls is throttled before it can touch
    // the session cache) and OUTSIDE the services (so it applies uniformly to
    // every RPC, including any added later). `option_layer` makes the disabled
    // case a genuine no-op rather than a branch in the request path.
    let mut builder = Server::builder()
        .max_frame_size(4 * 1024 * 1024) // CQ-B20: 4 MiB frame cap (tonic-0.14 equivalent of max_decoding_message_size)
        .timeout(Duration::from_secs(30))
        .concurrency_limit_per_connection(256)
        // OUTERMOST (added first = runs first): refunds h2's small-DATA-frame
        // budget for any call the rate limiters below answer without reading
        // its body. Without it the listener GOAWAYs the connection every ~102
        // rejections — see `middleware::drain_rejected`.
        .layer(DrainRejectedBodyLayer)
        .layer(governor_layer)
        .layer(shared_rate_limit_layer)
        .layer(tower::util::option_layer(strict_revocation_layer));

    // R-1 / T-234: the services are registered once, and only *how the bytes
    // arrive* differs between the two modes below. Before this change the whole
    // `add_service` chain was written out twice, once per branch, which is how
    // a service added to one arm and not the other becomes possible.
    let router = builder
        .add_service(authz_svc)
        .add_service(user_svc)
        .add_service(user_info_svc)
        .add_service(token_svc)
        .add_service(reactor_svc);

    match tls {
        GrpcTls::Rustls(tls_config) => {
            // Bound here rather than by `serve()` so the accept loop can be
            // ours: tonic's `serve_with_incoming` consumes a stream of
            // already-connected IO and never binds anything itself.
            let listener = tokio::net::TcpListener::bind(addr).await?;
            // The runbook greps for this exact line (§14.4), and the env-var
            // name in it is the one whose typo is the usual cause of a
            // plaintext listener an operator expected to be encrypted.
            tracing::info!(
                bind = %listener.local_addr().unwrap_or(addr),
                tls_versions = "1.3",
                reloadable_leaf = true,
                max_concurrent_handshakes = crate::tls_incoming::MAX_CONCURRENT_HANDSHAKES,
                "gRPC server TLS enabled (AXIAM__GRPC_TLS_CERT_PATH)"
            );

            // A listener that stops accepting must fail the server task, not
            // return `Ok(())`. `serve_with_incoming` cannot tell us that
            // itself — it treats an exhausted stream as a clean shutdown — so
            // the accept loop reports an unrecoverable error out of band and
            // this select turns it back into the error the caller expects.
            let (fatal_tx, fatal_rx) = tokio::sync::oneshot::channel();
            let incoming = tls_incoming(listener, tls_config, fatal_tx);
            tokio::select! {
                served = router.serve_with_incoming(incoming) => {
                    served.map_err(Into::into)
                }
                Ok(accept_error) = fatal_rx => {
                    Err(Box::new(accept_error) as Box<dyn std::error::Error + Send + Sync>)
                }
            }
        }
        GrpcTls::Plaintext => {
            tracing::warn!(
                "gRPC TLS is DISABLED — set AXIAM__GRPC_TLS_CERT_PATH + \
                 AXIAM__GRPC_TLS_KEY_PATH to enable (acceptable for in-mesh deployments)"
            );
            // Unchanged from before R-1, deliberately: tonic binds, sets
            // TCP_NODELAY, and serves exactly as it always has. The E2E suite
            // and every benchmark that is not the native-TLS overlay run
            // through this arm.
            router.serve(addr).await.map_err(Into::into)
        }
    }
}
