//! Compiles the `AuthorizationService` client stub from the SAME proto file
//! the server ships, rather than a copy — `proto/` is the source of truth
//! per `README.md`'s project structure, and this example reads it in place
//! two directories up (`examples/b3-mesh-delegation-grpc/` -> repo root).
//!
//! Client-only (`build_server(false)`): this example is a caller of
//! `AuthorizationService`, never an implementation of it.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["../../proto/axiam/v1/authorization.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
