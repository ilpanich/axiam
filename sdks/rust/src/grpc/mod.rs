//! gRPC transport: shared `tonic::Channel`, auth + tenant interceptor,
//! and the build.rs/buf-generated stubs under `src/gen/`.
//!
//! CONTRACT.md §5: `x-tenant-id` metadata (UUID form) is injected on every
//! outgoing RPC. CONTRACT.md §6: TLS verification is always strict; the only
//! escape hatch is a custom CA PEM (never an insecure/skip surface).
//! CONTRACT.md §9: `UNAUTHENTICATED` drives the shared single-flight refresh
//! guard from `crate::token`, retried exactly once, from the async call site
//! — never inside the (synchronous) interceptor (RESEARCH.md Pitfall 3).

pub mod channel;
pub mod interceptor;

/// Generated stubs from `build.rs` (`tonic-prost-build`) / the repository's
/// `buf generate` pipeline (`sdks/buf.gen.yaml`) — both target `src/gen/`
/// with the same `neoeinstein-prost`/`neoeinstein-tonic`-equivalent output,
/// producing a single `axiam.v1` module (matches the proto package name in
/// `proto/axiam/v1/*.proto`).
///
/// `#[rustfmt::skip]` prevents `cargo fmt` (stable, no nightly `ignore`
/// config available) from recursing into and reformatting this
/// build-generated, gitignored file — it is never hand-formatted and is
/// regenerated from `proto/axiam/v1/*.proto` on every `grpc`-feature build.
#[rustfmt::skip]
#[path = "../gen/axiam.v1.rs"]
pub mod gen;

pub use channel::{build_channel, GrpcChannelConfig};
pub use interceptor::AuthInterceptor;

// `pub mod client;` (the `check_access`/`batch_check` methods +
// UNAUTHENTICATED-retry wrapper) is added by this plan's Task 2 once
// `src/grpc/client.rs` exists. This state (Task 1) builds and compiles
// standalone with only `channel`/`interceptor`/`gen`.
