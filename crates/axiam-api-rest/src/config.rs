//! REST API server configuration.

use serde::Deserialize;

/// Configuration for the Actix-Web REST API server.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Bind address (default: "127.0.0.1").
    pub host: String,
    /// Bind port (default: 8080).
    pub port: u16,
    /// Allowed CORS origins. Empty means permissive (dev mode).
    pub cors_allowed_origins: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8080,
            cors_allowed_origins: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// Returns the socket bind address as "host:port".
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
