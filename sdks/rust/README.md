# axiam-sdk (Rust)

Official Rust client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **Crate:** `axiam-sdk`
- **Registry:** [crates.io/crates/axiam-sdk](https://crates.io/crates/axiam-sdk) _(reserved, not yet published)_
- **License:** Apache-2.0
- **MSRV:** Rust 1.88 (`rust-version = "1.88"` in `Cargo.toml`, enforced in CI)

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

## Features

`axiam-sdk`'s functionality is split into Cargo features so a consumer only pulls in the
dependencies for the transports/integrations it actually uses:

| Feature | Default | Enables |
|---------|---------|---------|
| `rest` | on | `AxiamClient` REST transport: `login`/`verify_mfa`/`refresh`/`logout`, `check_access`/`can`/`batch_check`, cookie-jar session management, local JWKS/EdDSA verification |
| `grpc` | on | `AuthzGrpcClient` gRPC transport: `check_access`/`batch_check` over a shared lazily-connected `tonic::Channel`, with the shared single-flight refresh guard driven on `UNAUTHENTICATED` |
| `amqp` | on | `consume(amqp_url, queue, signing_key, handler)` closure-handler AMQP consumer with mandatory pre-handler HMAC-SHA256 verification (CONTRACT.md §8) |
| `observability` | off | Enables `tracing` instrumentation crate-wide beyond the mandatory AMQP security-event logging (which is always emitted regardless of this flag) |
| `actix` | off | The `AxiamUser` Actix-Web `FromRequest` extractor (CONTRACT.md §10 route guard). Implies `rest` (shares the same `JwksVerifier`) |

To build a REST-only client (no gRPC, no AMQP), disable the default feature set and opt back
into just `rest`:

```toml
[dependencies]
axiam-sdk = { version = "0.1", default-features = false, features = ["rest"] }
```

## Usage

```toml
[dependencies]
axiam-sdk = "0.1"
```

Each capability below has a complete, runnable example under [`examples/`](examples/) — they
are illustrative/compilable (reading connection details from environment variables) and do not
require a live AXIAM server to `cargo build --examples --all-features`.

### Login + MFA (`rest`)

Construct a client with a non-optional tenant identifier (CONTRACT.md §5 — there is no default
tenant), then complete the two-phase login/MFA flow:

```rust,no_run
use axiam_sdk::client::AxiamClient;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = AxiamClient::builder()
    .base_url("https://axiam.example.com")?
    .tenant_slug("acme")
    .build()?;

let login_result = client.login("user@example.com", "password").await?;
if login_result.mfa_required {
    client.verify_mfa("123456").await?;
}
# Ok(())
# }
```

See [`examples/login_mfa.rs`](examples/login_mfa.rs).

### REST authorization checks (`rest`)

```rust,no_run
# use axiam_sdk::client::AxiamClient;
# async fn run(client: &AxiamClient, resource_id: uuid::Uuid) -> Result<(), Box<dyn std::error::Error>> {
let decision = client.check_access("resource:read", resource_id, None).await?;
let allowed = client.can("resource:write", resource_id, None).await?;
# Ok(())
# }
```

See [`examples/rest_check_access.rs`](examples/rest_check_access.rs).

### gRPC authorization checks (`grpc`)

```rust,no_run
use axiam_sdk::grpc::{build_channel, GrpcChannelConfig};

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let channel = build_channel("https://axiam.example.com:9443", &GrpcChannelConfig::default())?;
# Ok(())
# }
```

See [`examples/grpc_check_access.rs`](examples/grpc_check_access.rs) for the full
`AuthzGrpcClient` wiring, including the single-flight refresh guard (§9).

### AMQP consumer (`amqp`)

```rust,no_run
use axiam_sdk::amqp::consume;
use axiam_sdk::Sensitive;

# async fn run(signing_key: Sensitive<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
consume("amqp://guest:guest@localhost:5672", "axiam.authz.request", signing_key, |event| async move {
    println!("verified event: {event}");
})
.await?;
# Ok(())
# }
```

See [`examples/amqp_consumer.rs`](examples/amqp_consumer.rs). Every delivery's HMAC-SHA256
signature (CONTRACT.md §8) is verified before the handler runs; failures are nacked without
requeue.

### Actix-Web route guard (`actix`)

```rust,no_run
use axiam_sdk::middleware::AxiamUser;

async fn protected(user: AxiamUser) -> String {
    format!("hello {}", user.user_id)
}
```

See [`examples/actix_route_guard.rs`](examples/actix_route_guard.rs).

## Security notes

- **`Sensitive<T>`** (§7): all token-carrying values redact their raw contents from `Debug`
  and `Display`. There is no public getter for the raw value.
- **TLS** (§6): strict TLS verification against the system trust store is always on. The only
  escape hatch is `with_custom_ca(pem)` for development environments with self-signed
  certificates — there is no API surface that disables or skips certificate verification.
