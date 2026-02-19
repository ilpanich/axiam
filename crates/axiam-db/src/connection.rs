//! SurrealDB connection management.

use surrealdb::Surreal;
use surrealdb::engine::remote::ws::{Client, Ws};
use surrealdb::opt::auth::Root;
use tracing::info;

/// Configuration for connecting to SurrealDB.
#[derive(Debug, Clone)]
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
#[derive(Clone)]
pub struct DbManager {
    db: Surreal<Client>,
}

impl DbManager {
    /// Connect to SurrealDB using the provided configuration.
    ///
    /// Authenticates as root, selects the configured namespace and
    /// database, and returns a ready-to-use manager.
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

        Ok(Self { db })
    }

    /// Returns a reference to the underlying SurrealDB client.
    pub fn client(&self) -> &Surreal<Client> {
        &self.db
    }
}
