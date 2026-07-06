//! SurrealDB connection management.
//!
//! Uses the **HTTP engine** (`surrealdb::engine::remote::http`) rather than the
//! WebSocket engine. The HTTP engine is stateless per request — namespace,
//! database, and auth are sent on every request — so there is no long-lived
//! session that can be silently lost on an idle reconnect. This sidesteps
//! SurrealDB Rust SDK issue #5750 (Ws reconnect drops `use_ns`/`use_db`),
//! which caused a running server to return "not found" on records that exist
//! after the connection idled. AXIAM uses no live queries, so the WebSocket
//! engine bought us nothing but that failure mode.
//!
//! ## Root-token renewal (CORR-02)
//!
//! SurrealDB mints root signin JWTs with a fixed `DURATION FOR TOKEN`. Left
//! at the SDK default (`1h`), the HTTP engine's cached token expires mid-process
//! and every subsequent request 401s until the process restarts.
//! [`DbManager::connect`] spawns a background task that re-`signin`s the SAME
//! still-authenticated session at a fraction of the TTL (D-04,
//! [`re_signin_interval`]) — this succeeds because the cached token is still
//! valid when the request is sent (see [`DbManager::spawn_proactive_resignin`]
//! doc comment for why this must NOT call `invalidate()` first).
//!
//! [`DbManager::reconnect`] is the reactive "missed window" safety net for
//! when the proactive task didn't run in time. Per the SDK's HTTP transport,
//! a request on an ALREADY-expired handle — including `Signin`/`Invalidate`
//! themselves — is rejected before the RPC dispatcher ever runs, so recovery
//! there means building a brand-new connection, not resuscitating the stale
//! one in place. `health_check` classifies auth failures distinctly
//! ([`DbError::Unhealthy`], D-05) so the readiness probe alarms rather than
//! treating expired/invalid root credentials as an ordinary, possibly
//! transient query error.
//!
//! **Known residual gap (documented, not fixed here):** every repository in
//! `axiam-server` is constructed via `db.client_cloned().await`. Cloning a
//! `Surreal<C>` mints a brand-new session id and copies the CURRENT auth
//! state as a value snapshot — it does not share future re-signins or
//! reconnects with `DbManager`'s own handle. This module's proactive
//! re-signin and reconnect loop therefore only keep `DbManager`'s OWN
//! session (used by `health_check`) alive; the ~30 already-cloned repository
//! sessions each still expire independently on their own original schedule.
//! This matches the phase's locked scope (`26-RESEARCH.md` /
//! `27-RESEARCH.md` Pitfall 2) — there is no connection pool, and threading a
//! shared/swappable handle into the repositories is explicitly out of scope.
//!
//! ## Reconnect loop, full-jitter backoff, poisoned-handle eviction (PERF-04)
//!
//! [`DbManager`]'s own handle is held behind a swappable
//! `Arc<tokio::sync::RwLock<Surreal<Client>>>` (D-12). A background task
//! ([`DbManager::spawn_reconnect_loop`]) polls health through the current
//! handle and, on [`DbError::Unhealthy`], runs a bounded retry loop using
//! [`reconnect_backoff_delay`]'s full-jitter exponential backoff (D-10/D-13 —
//! `uniform(0, min(base_ms * 2^n, ceiling_ms))`, the AWS-documented fix for
//! thundering-herd reconnect storms across replicas after a shared DB blip).
//! On a successful [`DbManager::reconnect`], the old (possibly poisoned)
//! handle is replaced under the write guard and dropped — never recycled or
//! returned to any caller again. On `reconnect_max_retries` exhaustion the
//! manager stays `Unhealthy` and keeps probing at the ceiling interval
//! forever; it never exits the process or crash-loops (D-11).

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use serde::Deserialize;
use surrealdb::Surreal;
use surrealdb::engine::remote::http::{Client, Http};
use surrealdb::opt::auth::Root;
use surrealdb::types::NotAllowedError;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::error::DbError;

/// Cadence at which [`spawn_reconnect_loop`]'s background task polls
/// `health_check` while the connection is believed healthy. Independent of
/// the reconnect-retry backoff parameters below — this is just "how often do
/// we ask" during steady-state, not part of the D-10/D-13 backoff math.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Token lifetime applied to the SurrealDB root user at startup. Represented
/// as a real `Duration` (not just a SurrealQL string literal) so the
/// `DEFINE USER ... DURATION FOR TOKEN` statement AND the proactive
/// re-signin cadence ([`re_signin_interval`]) derive from ONE source of
/// truth and can never drift apart. Four weeks comfortably outlives any
/// normal uptime even without renewal; the renewal mechanism above exists so
/// that ceiling is never actually load-bearing.
const ROOT_TOKEN_DURATION: Duration = Duration::from_secs(4 * 7 * 24 * 3600);

/// Configuration for connecting to SurrealDB.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    /// Server address (e.g., `127.0.0.1:8000`).
    pub url: String,
    /// SurrealDB namespace.
    pub namespace: String,
    /// SurrealDB database name.
    pub database: String,
    /// Root username for authentication.
    pub username: String,
    /// Root password for authentication.
    pub password: String,
    /// Fraction of [`ROOT_TOKEN_DURATION`] at which the proactive re-signin
    /// task fires (D-04). Clamped to `0.05..=0.95` at use (see
    /// [`re_signin_interval`]) — never trusted un-clamped from config.
    /// Overridable via `AXIAM__DB__TOKEN_REFRESH_FRACTION` (D-20); default
    /// ~0.6 leaves a wide safety margin before the token actually expires
    /// while avoiding excessive re-signin traffic.
    pub token_refresh_fraction: f64,
    /// Base delay (milliseconds) for the reconnect loop's full-jitter
    /// exponential backoff (D-10/D-13, PERF-04): `capped = base_ms * 2^n`.
    /// Overridable via `AXIAM__DB__RECONNECT_BASE_MS`; default 250ms.
    pub reconnect_base_ms: u64,
    /// Ceiling (milliseconds) the exponential backoff never exceeds, and the
    /// interval the reconnect loop keeps probing at forever once
    /// `reconnect_max_retries` is exhausted (D-11). Overridable via
    /// `AXIAM__DB__RECONNECT_CEILING_MS`; default 30_000ms (30s).
    pub reconnect_ceiling_ms: u64,
    /// Number of exponential-backoff attempts before the reconnect loop
    /// gives up escalating and falls back to probing at the flat ceiling
    /// interval forever (D-11) — it never exits the process. Overridable via
    /// `AXIAM__DB__RECONNECT_MAX_RETRIES`; default 10.
    pub reconnect_max_retries: u32,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "127.0.0.1:8000".into(),
            namespace: "axiam".into(),
            database: "main".into(),
            username: "root".into(),
            password: "root".into(),
            token_refresh_fraction: 0.6,
            reconnect_base_ms: 250,
            reconnect_ceiling_ms: 30_000,
            reconnect_max_retries: 10,
        }
    }
}

/// Computes a full-jitter exponential backoff delay for reconnect attempt
/// `attempt` (1-indexed): `capped = min(base_ms * 2^(attempt-1), ceiling_ms)`,
/// then the returned delay is `uniform(0, capped)` — full jitter, the
/// AWS-documented fix for thundering-herd reconnect storms across replicas
/// after a shared DB blip (D-10/D-13, PERF-04). Mirrors CORR-03's
/// `webhook_consumer.rs` `base_ms`/`ceiling_ms` naming and `*2^n`
/// clamp-to-ceiling shape, but that backoff has NO jitter (27-RESEARCH.md
/// Pitfall 5) — this adds it.
///
/// Side-effect-free apart from RNG draw, so it's unit-testable without a
/// live server: assert the result is always in `[0, capped]`, never an exact
/// value (the delay is non-deterministic by design).
pub fn reconnect_backoff_delay(attempt: u32, base_ms: u64, ceiling_ms: u64) -> Duration {
    let exponent = attempt.saturating_sub(1);
    let capped = (base_ms as f64 * 2f64.powi(exponent as i32)).min(ceiling_ms as f64);
    let jittered_ms = rand::rng().random::<f64>() * capped;
    Duration::from_millis(jittered_ms as u64)
}

/// Returns the SurrealQL `DURATION FOR TOKEN` literal for the given TTL
/// (e.g. `Duration::from_secs(60)` -> `"60s"`). SurrealQL accepts a bare
/// `<n>s` duration literal, so no duration-string parser is needed — the
/// literal is derived FROM the `Duration`, never the reverse.
fn root_token_duration_surql_literal(ttl: Duration) -> String {
    format!("{}s", ttl.as_secs())
}

/// Interval between proactive re-signin attempts, computed against the
/// given TTL: `ttl * fraction`, with `fraction` clamped to a safe
/// `0.05..=0.95` band (D-04) regardless of what a misconfigured env var
/// supplies.
fn re_signin_interval_for(ttl: Duration, fraction: f64) -> Duration {
    Duration::from_secs_f64(ttl.as_secs_f64() * fraction.clamp(0.05, 0.95))
}

/// Manages a connection to SurrealDB over the stateless HTTP engine.
pub struct DbManager {
    /// SurrealDB client handle (HTTP engine), behind a swappable
    /// `RwLock` (PERF-04, D-12) so the reconnect loop can atomically replace
    /// a poisoned/broken handle with a freshly-authenticated one — the old
    /// handle is dropped on swap and never recycled or returned to any
    /// caller again. `Arc`-shared (not cloned) with the proactive re-signin
    /// and reconnect-loop tasks so all sides observe/refresh the SAME
    /// current handle (see module docs, Pitfall 2).
    db: Arc<RwLock<Surreal<Client>>>,
    /// Handle to the background proactive re-signin task (D-03/D-04),
    /// owned so it is explicitly droppable/abortable rather than a
    /// fire-and-forget detached task.
    refresh_handle: JoinHandle<()>,
    /// Handle to the background reconnect-loop task (D-10/D-11/D-12/D-13,
    /// PERF-04), owned for the same explicit-drop reason as
    /// `refresh_handle`.
    reconnect_handle: JoinHandle<()>,
}

impl DbManager {
    /// Connect to SurrealDB using the provided configuration.
    ///
    /// Authenticates as root and selects the configured namespace and database.
    /// With the HTTP engine these are stored on the client and re-sent on every
    /// request, so the selection cannot be silently lost on reconnect.
    ///
    /// Also spawns the proactive re-signin background task (D-03/D-04) that
    /// keeps this session authenticated well inside the root token's TTL.
    pub async fn connect(config: &DbConfig) -> Result<Self, surrealdb::Error> {
        Self::connect_with_ttl(config, ROOT_TOKEN_DURATION).await
    }

    /// Test-only entry point: identical to [`connect`](Self::connect) but
    /// with an explicit root-token TTL override, so an integration test can
    /// prove recovery from a REAL, short-lived token expiry without waiting
    /// four weeks. Production code should always use [`connect`](Self::connect),
    /// which always passes the fixed [`ROOT_TOKEN_DURATION`].
    pub async fn connect_with_ttl(
        config: &DbConfig,
        ttl: Duration,
    ) -> Result<Self, surrealdb::Error> {
        info!(
            url = %config.url,
            namespace = %config.namespace,
            database = %config.database,
            "Connecting to SurrealDB (HTTP engine)"
        );

        // SurrealDB mints root signin JWTs with a default `DURATION FOR TOKEN 1h`.
        // The HTTP engine caches that JWT and, once it expires, EVERY request 401s
        // (login → "invalid credentials"; audit/cleanup writes fail) until the
        // process restarts. Re-`signin` on an already-authenticated handle is itself
        // rejected with 401, so a background re-auth loop does NOT recover it.
        //
        // Fix: on a short-lived setup handle, extend the root user's token duration,
        // then open the real connection whose FRESH signin mints a long-lived token.
        // The proactive re-signin task spawned below then keeps that token from
        // ever actually reaching this extended TTL.
        Self::extend_root_token_duration(config, ttl).await;

        let db = Surreal::new::<Http>(&config.url).await?;
        db.signin(Root {
            username: config.username.clone(),
            password: config.password.clone(),
        })
        .await?;
        db.use_ns(&config.namespace)
            .use_db(&config.database)
            .await?;

        info!("Successfully connected to SurrealDB");

        let db = Arc::new(RwLock::new(db));
        let refresh_handle = Self::spawn_proactive_resignin(Arc::clone(&db), config, ttl);
        let reconnect_handle = Self::spawn_reconnect_loop(Arc::clone(&db), config.clone());

        Ok(Self {
            db,
            refresh_handle,
            reconnect_handle,
        })
    }

    /// Best-effort: redefine the root user with a long token duration so the
    /// connection's cached JWT does not expire mid-process. Failures are logged
    /// and ignored (the server still starts; it just reverts to the ~1h window).
    /// Idempotent — safe to run on every startup.
    async fn extend_root_token_duration(config: &DbConfig, ttl: Duration) {
        let setup = match Surreal::new::<Http>(&config.url).await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "token-duration setup: connect failed (continuing)");
                return;
            }
        };
        if let Err(e) = setup
            .signin(Root {
                username: config.username.clone(),
                password: config.password.clone(),
            })
            .await
        {
            warn!(error = %e, "token-duration setup: signin failed (continuing)");
            return;
        }
        // SurrealQL string-escape the password (single-quoted literal).
        let escaped_pass = config.password.replace('\\', "\\\\").replace('\'', "\\'");
        let define_user = format!(
            "DEFINE USER OVERWRITE {} ON ROOT PASSWORD '{}' ROLES OWNER \
             DURATION FOR TOKEN {}, FOR SESSION NONE",
            config.username,
            escaped_pass,
            root_token_duration_surql_literal(ttl)
        );
        match setup.query(define_user).await.and_then(|r| r.check()) {
            Ok(_) => info!(
                duration_secs = ttl.as_secs(),
                "Extended SurrealDB root token duration"
            ),
            Err(e) => warn!(error = %e, "token-duration setup: DEFINE USER failed (continuing)"),
        }
    }

    /// Spawn the proactive periodic re-signin task (D-03/D-04) that keeps
    /// this `DbManager`'s own SurrealDB session authenticated well inside
    /// the root token's TTL, so the cached JWT never actually reaches its
    /// expiry under normal operation.
    ///
    /// Re-signs the SAME `Arc`-shared session `db` refers to (not a
    /// `.clone()`d one) at each interval — this succeeds because the
    /// currently-cached token is still valid when the request is sent.
    /// Deliberately does NOT call `invalidate()` first: that request would
    /// itself carry the (still valid) auth header, so it buys nothing on
    /// this path, and calling it on an ALREADY-expired handle would itself
    /// 401 before clearing anything — see `26-RESEARCH.md` Pitfall 3
    /// (the reactive "missed window" safety net, [`DbManager::reconnect`],
    /// is a separate mechanism).
    fn spawn_proactive_resignin(
        db: Arc<RwLock<Surreal<Client>>>,
        config: &DbConfig,
        ttl: Duration,
    ) -> JoinHandle<()> {
        let interval = re_signin_interval_for(ttl, config.token_refresh_fraction);
        let username = config.username.clone();
        let password = config.password.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                // Re-signin only mutates the SAME handle's server-side auth
                // state via a request (`&self`) — it does not need to swap
                // the handle itself, so a read lock is sufficient here. The
                // reconnect loop (spawn_reconnect_loop) is the ONLY task that
                // ever takes a write lock to replace the handle (D-12).
                let guard = db.read().await;
                match guard
                    .signin(Root {
                        username: username.clone(),
                        password: password.clone(),
                    })
                    .await
                {
                    // T-26-02-01: never log the token/JWT/password — only the
                    // outcome (ok/err) and non-secret context.
                    Ok(_) => info!("Proactive SurrealDB root re-signin succeeded"),
                    Err(e) => warn!(
                        error = %e,
                        "Proactive SurrealDB root re-signin failed (a reactive \
                         reconnect path is the safety net for a fully-missed window)"
                    ),
                }
            }
        })
    }

    /// Reactive reconnect seam (D-03) — the "missed window" safety net for
    /// when the proactive re-signin task above did not run in time and the
    /// cached token has ALREADY expired.
    ///
    /// Builds a BRAND-NEW `Surreal::new::<Http>` connection with its own
    /// fresh session and signs in on it, rather than attempting
    /// `invalidate()`+`signin()` on the stale handle: every request on an
    /// already-401ing handle — including `Signin`/`Invalidate` themselves —
    /// carries the stale cached auth header and is rejected by the HTTP
    /// engine's transport-level status check before the RPC dispatcher ever
    /// runs (see module docs).
    ///
    /// This is intentionally a single-attempt primitive — [`spawn_reconnect_loop`]
    /// (PERF-04) wraps a full jittered-backoff reconnect loop and
    /// poisoned-connection eviction around this.
    pub async fn reconnect(config: &DbConfig) -> Result<Surreal<Client>, surrealdb::Error> {
        let db = Surreal::new::<Http>(&config.url).await?;
        db.signin(Root {
            username: config.username.clone(),
            password: config.password.clone(),
        })
        .await?;
        db.use_ns(&config.namespace)
            .use_db(&config.database)
            .await?;
        Ok(db)
    }

    /// Background reconnect loop (D-10/D-11/D-12/D-13, PERF-04): polls
    /// health through the current handle, and on
    /// `DbError::Unhealthy` runs a bounded, full-jitter exponential-backoff
    /// retry loop calling [`DbManager::reconnect`]. On success, the old
    /// handle is atomically replaced under the `RwLock` write guard (D-12 —
    /// the poisoned handle is dropped right there and never recycled or
    /// returned to any caller again) and health polling resumes at the
    /// normal cadence.
    ///
    /// On `reconnect_max_retries` exhaustion, the manager stays `Unhealthy`
    /// (so `/ready` sheds traffic) and this task falls back to probing at
    /// the flat `reconnect_ceiling_ms` interval FOREVER — it never
    /// `break`s/`return`s out of the outer loop and never exits the process
    /// or crash-loops (D-11). A later successful reconnect at that cadence
    /// still swaps the handle and flips health back to `Ok` with no process
    /// restart.
    fn spawn_reconnect_loop(db: Arc<RwLock<Surreal<Client>>>, config: DbConfig) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEALTH_POLL_INTERVAL).await;

                let is_unhealthy = {
                    let guard = db.read().await;
                    let outcome = guard
                        .query("RETURN 1")
                        .await
                        .map_err(Self::classify_query_error)
                        .and_then(|r| r.check().map_err(Self::classify_query_error));
                    matches!(outcome, Err(DbError::Unhealthy(_)))
                };

                if !is_unhealthy {
                    continue;
                }

                warn!(
                    "DbManager: connection detected Unhealthy — entering bounded \
                     full-jitter reconnect retry loop"
                );

                let mut reconnected = false;
                let mut attempt: u32 = 1;
                while attempt <= config.reconnect_max_retries {
                    let delay = reconnect_backoff_delay(
                        attempt,
                        config.reconnect_base_ms,
                        config.reconnect_ceiling_ms,
                    );
                    tokio::time::sleep(delay).await;

                    match Self::reconnect(&config).await {
                        Ok(fresh) => {
                            *db.write().await = fresh;
                            info!(attempt, "DbManager reconnect succeeded — handle swapped");
                            reconnected = true;
                            break;
                        }
                        Err(e) => {
                            warn!(error = %e, attempt, "DbManager reconnect attempt failed");
                            attempt += 1;
                        }
                    }
                }

                if reconnected {
                    continue;
                }

                warn!(
                    max_retries = config.reconnect_max_retries,
                    "DbManager: reconnect retries exhausted — staying Unhealthy and \
                     probing at the ceiling interval forever (never exiting)"
                );
                loop {
                    tokio::time::sleep(Duration::from_millis(config.reconnect_ceiling_ms)).await;
                    match Self::reconnect(&config).await {
                        Ok(fresh) => {
                            *db.write().await = fresh;
                            info!(
                                "DbManager reconnect succeeded after exhaustion — handle \
                                 swapped, resuming normal health polling"
                            );
                            break;
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "DbManager: ceiling-interval reconnect probe still failing"
                            );
                        }
                    }
                }
            }
        })
    }

    /// Returns an owned clone of the CURRENT SurrealDB client handle, read
    /// through the swappable `RwLock` (D-12, PERF-04). Async because
    /// obtaining the current handle requires taking the read lock — a
    /// successful reconnect-loop swap is observed by the very next call.
    ///
    /// Callers may further `.clone()` the returned value to obtain an
    /// additional handle. With the HTTP engine clones share the stored
    /// namespace/database selection, but NOT future re-signin/reconnect
    /// traffic on the manager's own handle — see module docs' "Known
    /// residual gap"; repositories keep their own independent snapshot
    /// exactly as before this migration (RESEARCH Pitfall 2 — out of scope).
    pub async fn client_cloned(&self) -> Surreal<Client> {
        self.db.read().await.clone()
    }

    /// Verify the database connection is alive and queries succeed.
    ///
    /// With the HTTP engine the namespace/database are sent on every request,
    /// so a successful query inherently proves the connection routes to the
    /// configured target — there is no "wrong session" state to detect (the
    /// failure mode the previous WebSocket-based `session::ns()` check tried to
    /// catch no longer exists).
    ///
    /// An authentication failure (expired token, revoked/invalid root
    /// credentials — D-05) classifies distinctly as [`DbError::Unhealthy`]
    /// rather than a bare query error, so the readiness probe alarms.
    ///
    /// Reads the CURRENT handle through the swappable `RwLock` (D-12,
    /// PERF-04) — a successful reconnect-loop swap flips this back to `Ok`
    /// without a process restart.
    pub async fn health_check(&self) -> Result<(), DbError> {
        let guard = self.db.read().await;
        let result = guard
            .query("RETURN 1")
            .await
            .map_err(Self::classify_query_error)?;
        // Surface any statement-level error (HTTP returns 200 even on SQL error).
        result.check().map_err(Self::classify_query_error)?;
        Ok(())
    }

    /// Classify a query/check failure into a [`DbError`], distinguishing an
    /// authentication problem — expired token, invalidated session, or a
    /// genuinely revoked/invalid root credential (ANY `NotAllowed(Auth(..))`
    /// variant, not just token expiry, per T-26-02-02/D-05) — from an
    /// ordinary query error.
    ///
    /// Side-effect-free and public so it can be unit-tested directly against
    /// a synthetic `surrealdb::Error` without a live server.
    pub fn classify_query_error(err: surrealdb::Error) -> DbError {
        if matches!(err.not_allowed_details(), Some(NotAllowedError::Auth(_))) {
            return DbError::Unhealthy(err.to_string());
        }
        DbError::Surreal(err)
    }

    /// Interval between proactive re-signin attempts against the fixed
    /// [`ROOT_TOKEN_DURATION`]: `ROOT_TOKEN_DURATION * fraction`, with
    /// `fraction` clamped to `0.05..=0.95` (D-04). Public so the derivation
    /// can be asserted directly in `connection_resilience_test.rs` without a
    /// live server.
    pub fn re_signin_interval(fraction: f64) -> Duration {
        re_signin_interval_for(ROOT_TOKEN_DURATION, fraction)
    }
}

impl Drop for DbManager {
    fn drop(&mut self) {
        // Explicitly stop both background tasks rather than leaving them
        // detached — in production `DbManager` lives for the process
        // lifetime so this rarely runs, but it keeps tests (which may
        // construct several `DbManager`s) from leaking background tasks.
        self.refresh_handle.abort();
        self.reconnect_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D-10/D-13: the delay must never exceed `capped`, across several
    /// attempts (never assert an exact value — full jitter is
    /// non-deterministic by design, RESEARCH Pitfall 5).
    #[test]
    fn reconnect_backoff_delay_never_exceeds_capped() {
        let base_ms = 250u64;
        let ceiling_ms = 30_000u64;
        for attempt in 1..=12u32 {
            let capped = (base_ms as f64 * 2f64.powi((attempt - 1) as i32)).min(ceiling_ms as f64);
            for _ in 0..50 {
                let delay = reconnect_backoff_delay(attempt, base_ms, ceiling_ms);
                assert!(
                    delay.as_millis() as f64 <= capped,
                    "attempt {attempt}: delay {delay:?} exceeded capped {capped}ms"
                );
            }
        }
    }

    /// The exponential term must clamp to `ceiling_ms` once
    /// `base_ms * 2^(attempt-1)` would otherwise exceed it — otherwise a
    /// large attempt count would produce an unbounded delay.
    #[test]
    fn reconnect_backoff_delay_clamps_to_ceiling_for_large_attempts() {
        let base_ms = 250u64;
        let ceiling_ms = 30_000u64;
        for _ in 0..50 {
            let delay = reconnect_backoff_delay(20, base_ms, ceiling_ms);
            assert!(
                delay.as_millis() as u64 <= ceiling_ms,
                "expected delay clamped to ceiling {ceiling_ms}ms, got {delay:?}"
            );
        }
    }

    /// Over many samples the delay must actually vary (full jitter =
    /// `uniform(0, capped)`, not a fixed deterministic value) — proves the
    /// jitter is real, not accidentally collapsed to a constant.
    #[test]
    fn reconnect_backoff_delay_spans_a_range_not_a_fixed_value() {
        let base_ms = 250u64;
        let ceiling_ms = 30_000u64;
        let attempt = 8; // capped = min(250 * 2^7, 30_000) = 30_000 (already at ceiling)
        let samples: Vec<u128> = (0..200)
            .map(|_| reconnect_backoff_delay(attempt, base_ms, ceiling_ms).as_millis())
            .collect();
        let min = *samples.iter().min().unwrap();
        let max = *samples.iter().max().unwrap();
        assert!(
            max > min,
            "expected the 200 sampled delays to span a range, but all were {min}ms \
             (full jitter must not collapse to a fixed value)"
        );
    }

    /// D-12 proof: after a `RwLock` write-swap replaces the handle, a reader
    /// observes ONLY the new handle — the old (poisoned) handle is never
    /// recycled or returned again.
    ///
    /// Constructing a real `Surreal<Client>` (HTTP engine) always performs a
    /// live network health-check at connect time (see
    /// `engine::remote::http::native::create_client`), so this test proves
    /// the swap/eviction MECHANISM — the exact `Arc<RwLock<Surreal<C>>>`
    /// read/write-guard pattern [`DbManager`] and [`spawn_reconnect_loop`]
    /// use — against the embedded `kv-mem` engine instead, per
    /// 27-RESEARCH.md Open Question 3 ("treat poisoned-connection testing
    /// primarily as a unit-level proof of the swap/eviction, not a real
    /// network-fault simulation"). Two independent in-memory instances stand
    /// in for an "old" (poisoned) and a "new" (freshly reconnected) handle;
    /// each carries a distinguishing marker row so cross-contamination would
    /// be observable.
    #[tokio::test]
    async fn poisoned_handle_is_evicted_and_never_returned_after_swap() {
        use surrealdb::engine::local::{Db, Mem};

        async fn new_marked_db(marker: &str) -> Surreal<Db> {
            let db = Surreal::new::<Mem>(()).await.expect("in-memory connect");
            db.use_ns("test").use_db("test").await.expect("use ns/db");
            db.query(format!("CREATE marker SET value = '{marker}'"))
                .await
                .and_then(|r| r.check())
                .expect("seed marker row");
            db
        }

        async fn read_marker_values(db: &Surreal<Db>) -> Vec<String> {
            let mut result = db
                .query("SELECT VALUE value FROM marker")
                .await
                .and_then(|r| r.check())
                .expect("read marker rows");
            result.take(0).expect("deserialize marker values")
        }

        let old_db = new_marked_db("old-poisoned").await;
        let handle = Arc::new(RwLock::new(old_db));

        // Pre-swap: the current handle is observably the "old" one.
        {
            let pre_swap = handle.read().await.clone();
            let values = read_marker_values(&pre_swap).await;
            assert_eq!(values, vec!["old-poisoned".to_string()]);
        }

        // Simulate a successful reconnect: build a fresh handle and swap it
        // in under the write guard, exactly as spawn_reconnect_loop does
        // (`*db.write().await = fresh`) — the old handle is dropped here.
        let new_db = new_marked_db("new-fresh").await;
        *handle.write().await = new_db;

        // Post-swap: every subsequent reader observes ONLY the new handle.
        let post_swap = handle.read().await.clone();
        let values = read_marker_values(&post_swap).await;
        assert_eq!(
            values,
            vec!["new-fresh".to_string()],
            "the old (poisoned) handle must never be observed after the swap (D-12)"
        );
    }
}
