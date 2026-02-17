//! AXIAM Server — Application entry point.

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("axiam=info".parse().unwrap()))
        .json()
        .init();

    tracing::info!("Starting AXIAM server...");

    // TODO: Load configuration
    // TODO: Initialize SurrealDB connection
    // TODO: Initialize AMQP connection
    // TODO: Start REST API server
    // TODO: Start gRPC server

    tracing::info!("AXIAM server stopped.");
}
