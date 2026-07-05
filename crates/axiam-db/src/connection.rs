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
//! `axiam-server` is constructed via `db.client().clone()`. Cloning a
//! `Surreal<C>` mints a brand-new session id and copies the CURRENT auth
//! state as a value snapshot — it does not share future re-signins with the
//! original handle. This module's proactive re-signin therefore only keeps
//! `DbManager`'s OWN session (used by `health_check`) alive; the ~30
//! already-cloned repository sessions each still expire independently on
//! their own original schedule. This matches the phase's locked scope
//! (`26-RESEARCH.md` Pitfall 2) and is the same shape of problem Phase 27's
//! PERF-04 ("poisoned-connection eviction") is already slated to address —
//! [`DbManager::reconnect`] is written as a forward-compatible extension
//! seam for that future work (a full jittered-backoff reconnect loop and
//! poisoned-connection eviction), not that full loop itself.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use surrealdb::Surreal;
use surrealdb::engine::remote::http::{Client, Http};
use surrealdb::opt::auth::Root;
use surrealdb::types::NotAllowedError;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::error::DbError;

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
        }
    }
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
    /// SurrealDB client handle (HTTP engine). `Arc`-shared (not cloned) with
    /// the proactive re-signin task so both sides observe/refresh the SAME
    /// session id — a `.clone()`d `Surreal<C>` would mint an independent
    /// session that re-signin traffic on one side would not reach (see
    /// module docs, Pitfall 2).
    db: Arc<Surreal<Client>>,
    /// Handle to the background proactive re-signin task (D-03/D-04),
    /// owned so it is explicitly droppable/abortable rather than a
    /// fire-and-forget detached task.
    refresh_handle: JoinHandle<()>,
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
        Self::extend_root_token_duration(config).await;

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

        let db = Arc::new(db);
        let refresh_handle = Self::spawn_proactive_resignin(Arc::clone(&db), config);

        Ok(Self { db, refresh_handle })
    }

    /// Best-effort: redefine the root user with a long token duration so the
    /// connection's cached JWT does not expire mid-process. Failures are logged
    /// and ignored (the server still starts; it just reverts to the ~1h window).
    /// Idempotent — safe to run on every startup.
    async fn extend_root_token_duration(config: &DbConfig) {
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
            root_token_duration_surql_literal(ROOT_TOKEN_DURATION)
        );
        match setup.query(define_user).await.and_then(|r| r.check()) {
            Ok(_) => info!(
                duration_secs = ROOT_TOKEN_DURATION.as_secs(),
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
    /// (the reactive "missed window" safety net is a separate mechanism).
    fn spawn_proactive_resignin(db: Arc<Surreal<Client>>, config: &DbConfig) -> JoinHandle<()> {
        let interval = re_signin_interval_for(ROOT_TOKEN_DURATION, config.token_refresh_fraction);
        let username = config.username.clone();
        let password = config.password.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match db
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
    /// This is intentionally a single-attempt primitive — the extension seam
    /// PERF-04 (Phase 27) will wrap a full jittered-backoff reconnect loop
    /// and poisoned-connection eviction around this; that loop is NOT built
    /// here.
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

    /// Returns a reference to the underlying SurrealDB client.
    ///
    /// Callers may `.clone()` the returned reference to obtain an additional
    /// handle. With the HTTP engine clones share the stored namespace/database
    /// selection, but NOT future re-signin traffic on the original handle —
    /// see module docs' "Known residual gap".
    pub fn client(&self) -> &Surreal<Client> {
        &self.db
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
    pub async fn health_check(&self) -> Result<(), DbError> {
        let result = self
            .db
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
        // Explicitly stop the proactive re-signin task rather than leaving it
        // detached — in production `DbManager` lives for the process
        // lifetime so this rarely runs, but it keeps tests (which may
        // construct several `DbManager`s) from leaking background tasks.
        self.refresh_handle.abort();
    }
}
