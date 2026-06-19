//! SurrealDB connection management.

use std::sync::Arc;

use serde::Deserialize;
use surrealdb::Surreal;
use surrealdb::engine::remote::ws::{Client, Ws};
use surrealdb::opt::auth::Root;
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::error::DbError;

/// Configuration for connecting to SurrealDB.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    /// WebSocket URL (e.g., `127.0.0.1:8000`).
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

/// Manages a connection to SurrealDB.
///
/// The `db` field is wrapped in `Arc` so the background guard task and the
/// health check operate on the SAME `Surreal<Client>` allocation.
///
/// NOTE: `DbManager` does NOT implement `Clone` because `JoinHandle<()>` is
/// not `Clone`. Callers that need to share multiple handles should call
/// `.client()` and clone the returned `&Surreal<Client>` reference.
pub struct DbManager {
    /// Shared SurrealDB client handle.
    db: Arc<Surreal<Client>>,
    /// Stored config for the guard and health_check assertions.
    config: DbConfig,
    /// Background keepalive guard — kept alive by ownership.
    /// Named with leading `_` so Rust does not warn about the unused field,
    /// while still holding ownership (dropping this field aborts the task).
    _guard: tokio::task::JoinHandle<()>,
}

impl DbManager {
    /// Connect to SurrealDB using the provided configuration.
    ///
    /// Authenticates as root, selects the configured namespace and
    /// database, spawns a background guard task that re-asserts the ns/db
    /// selection every 30 seconds, and returns a ready-to-use manager.
    pub async fn connect(config: &DbConfig) -> Result<Self, surrealdb::Error> {
        info!(
            url = %config.url,
            namespace = %config.namespace,
            database = %config.database,
            "Connecting to SurrealDB"
        );

        let db = Surreal::new::<Ws>(&config.url).await?;

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

        // Spawn the background ns/db keepalive guard.
        // The guard holds an Arc clone so it shares the SAME Surreal<Client>
        // session as DbManager.db. On reconnect, the SDK resets the server-side
        // session to unselected (issue #5750). The guard detects this via
        // session::ns()/session::db() and re-asserts the selection proactively.
        //
        // SAFETY NOTE: clones of Surreal<Client> have INDEPENDENT session state
        // (empirically confirmed by the reconnect_regression test). Arc<Surreal>
        // ensures guard and health_check both operate on the same allocation.
        let guard_db = Arc::clone(&db);
        let guard_config = config.clone();

        let _guard = tokio::task::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;

                // Query the server-side active namespace and database.
                // Use match/if-let throughout — never `?` — so a transient
                // error or deserialization failure is logged and the loop
                // continues. The guard must never panic (Pitfall 3).
                let query_result = guard_db
                    .query("RETURN [session::ns(), session::db()]")
                    .await;

                let needs_reselect = match query_result {
                    Err(e) => {
                        warn!(error = %e, "SurrealDB guard: session query failed — will re-select");
                        true
                    }
                    Ok(mut response) => {
                        let take_result: surrealdb::Result<
                            Option<(Option<String>, Option<String>)>,
                        > = response.take(0);
                        match take_result {
                            Ok(Some((ns, db_name)))
                                if ns.as_deref() == Some(guard_config.namespace.as_str())
                                    && db_name.as_deref()
                                        == Some(guard_config.database.as_str()) =>
                            {
                                // Selection is correct — no action needed.
                                false
                            }
                            Ok(row) => {
                                warn!(
                                    row = ?row,
                                    expected_ns = %guard_config.namespace,
                                    expected_db = %guard_config.database,
                                    "SurrealDB session selection lost or wrong — re-selecting"
                                );
                                true
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "SurrealDB guard: failed to parse session result — re-selecting"
                                );
                                true
                            }
                        }
                    }
                };

                if needs_reselect {
                    // Re-issue signin + use_ns + use_db on the SAME Arc-wrapped
                    // Surreal<Client> that DbManager.db and health_check use.
                    let _ = guard_db
                        .signin(Root {
                            username: guard_config.username.clone(),
                            password: guard_config.password.clone(),
                        })
                        .await;
                    let _ = guard_db
                        .use_ns(&guard_config.namespace)
                        .use_db(&guard_config.database)
                        .await;
                    info!(
                        namespace = %guard_config.namespace,
                        database  = %guard_config.database,
                        "SurrealDB session re-selected by guard"
                    );
                }
            }
        });

        Ok(Self {
            db,
            config: config.clone(),
            _guard,
        })
    }

    /// Returns a reference to the underlying SurrealDB client.
    ///
    /// Callers may call `.clone()` on the returned reference to obtain an
    /// independent `Surreal<Client>` handle. Note that clones have independent
    /// session state — they do NOT share ns/db selection with the `DbManager`.
    /// For long-lived handles that must survive idle reconnects, consider
    /// re-cloning periodically or use the DbManager health check to detect
    /// session loss before issuing queries.
    pub fn client(&self) -> &Surreal<Client> {
        &self.db
    }

    /// Verify the database connection is alive AND the session is pointing at
    /// the expected namespace and database.
    ///
    /// Returns `Ok(())` only when both `session::ns()` and `session::db()`
    /// match the configured namespace/database. Returns
    /// `DbError::SessionMismatch` if the session is on the wrong ns/db, or
    /// `DbError::Surreal(e)` if the query itself fails.
    ///
    /// Replaces the previous `RETURN 1` liveness-only check, which was a
    /// false-green — it proved the socket was open but not that queries
    /// were routing to the correct data.
    pub async fn health_check(&self) -> Result<(), DbError> {
        let mut result = self
            .db
            .query("RETURN [session::ns(), session::db()]")
            .await
            .map_err(DbError::Surreal)?;

        let row: Option<(Option<String>, Option<String>)> =
            result.take(0).map_err(DbError::Surreal)?;

        match row {
            Some((ns, db))
                if ns.as_deref() == Some(self.config.namespace.as_str())
                    && db.as_deref() == Some(self.config.database.as_str()) =>
            {
                Ok(())
            }
            Some((actual_ns, actual_db)) => Err(DbError::SessionMismatch {
                expected_ns: self.config.namespace.clone(),
                expected_db: self.config.database.clone(),
                actual_ns,
                actual_db,
            }),
            None => Err(DbError::SessionMismatch {
                expected_ns: self.config.namespace.clone(),
                expected_db: self.config.database.clone(),
                actual_ns: None,
                actual_db: None,
            }),
        }
    }
}
