//! Authorization engine configuration.

use serde::Deserialize;

/// Configuration for the authorization engine.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthzConfig {
    /// Bound on concurrent `check_access` evaluations within a single
    /// `BatchCheckAccess` call (gRPC and REST). Kept well under the
    /// ~30-connection SurrealDB handle budget so a batch cannot self-DoS
    /// the connection pool (D-07).
    ///
    /// Configure via `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY` env var.
    pub batch_max_concurrency: usize,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            batch_max_concurrency: 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_batch_max_concurrency_is_16() {
        let cfg = AuthzConfig::default();
        assert_eq!(cfg.batch_max_concurrency, 16);
    }

    #[test]
    fn deserializes_from_partial_json_using_defaults() {
        let cfg: AuthzConfig = serde_json::from_str("{}").expect("empty object must deserialize");
        assert_eq!(cfg.batch_max_concurrency, 16);
    }

    #[test]
    fn deserializes_explicit_override() {
        let cfg: AuthzConfig = serde_json::from_str(r#"{"batch_max_concurrency": 4}"#)
            .expect("explicit override must deserialize");
        assert_eq!(cfg.batch_max_concurrency, 4);
    }
}
