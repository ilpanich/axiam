//! AXIAM gRPC API — Authorization, user, and token services via Tonic.

pub mod config;
pub mod server;
pub mod services;

/// Generated protobuf/gRPC types for the `axiam.v1` package.
pub mod proto {
    tonic::include_proto!("axiam.v1");
}

pub use config::GrpcConfig;
pub use server::start_grpc_server;
