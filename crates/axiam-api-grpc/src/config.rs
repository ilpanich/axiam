//! gRPC server configuration.

use std::net::SocketAddr;

use serde::Deserialize;

/// Configuration for the gRPC server.
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl GrpcConfig {
    pub fn bind_address(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("invalid gRPC bind address")
    }
}

fn default_host() -> String {
    "0.0.0.0".into()
}

fn default_port() -> u16 {
    50051
}
