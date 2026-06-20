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

use serde::Deserialize;
use surrealdb::Surreal;
use surrealdb::engine::remote::http::{Client, Http};
use surrealdb::opt::auth::Root;
use tracing::{info, warn};

use crate::error::DbError;

/// Token lifetime applied to the SurrealDB root user at startup (SurrealQL
/// duration literal). The default is `1h`, which expires mid-process and 401s
/// every request until restart; `4w` comfortably outlives any normal uptime.
const ROOT_TOKEN_DURATION: &str = "4w";

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
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "127.0.0.1:8000".into(),
            namespace: "axiam".into(),
            database: "main".into(),
            username: "root".into(),
            password: "root".into(),
        }
    }
}

/// Manages a connection to SurrealDB over the stateless HTTP engine.
pub struct DbManager {
    /// SurrealDB client handle (HTTP engine).
    db: Surreal<Client>,
}

impl DbManager {
    /// Connect to SurrealDB using the provided configuration.
    ///
    /// Authenticates as root and selects the configured namespace and database.
    /// With the HTTP engine these are stored on the client and re-sent on every
    /// request, so the selection cannot be silently lost on reconnect.
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
        // The token is therefore long-lived for the whole process lifetime and is
        // shared by every repository clone taken from this handle.
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

        Ok(Self { db })
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
            config.username, escaped_pass, ROOT_TOKEN_DURATION
        );
        match setup.query(define_user).await.and_then(|r| r.check()) {
            Ok(_) => info!(
                duration = ROOT_TOKEN_DURATION,
                "Extended SurrealDB root token duration"
            ),
            Err(e) => warn!(error = %e, "token-duration setup: DEFINE USER failed (continuing)"),
        }
    }

    /// Returns a reference to the underlying SurrealDB client.
    ///
    /// Callers may `.clone()` the returned reference to obtain an additional
    /// handle. With the HTTP engine, clones share the stored namespace/database
    /// and auth, and every request carries them — there is no per-connection
    /// session to diverge.
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
    pub async fn health_check(&self) -> Result<(), DbError> {
        let result = self.db.query("RETURN 1").await.map_err(DbError::Surreal)?;
        // Surface any statement-level error (HTTP returns 200 even on SQL error).
        result.check().map_err(DbError::Surreal)?;
        Ok(())
    }
}
