//! AMQP consumer with per-tenant HMAC signing key (CONTRACT.md §8, D-07).
//!
//! Demonstrates `axiam_sdk::amqp::consume(amqp_url, queue, signing_key,
//! handler)`: the SDK verifies each delivery's HMAC-SHA256 signature BEFORE
//! the handler closure ever sees the message body, and nacks-without-requeue
//! on any verification failure. The handler here never needs to (and
//! cannot) touch ack/nack directly — that is owned entirely by the SDK.
//!
//! This example is illustrative/compilable — it reads connection details
//! from environment variables and does not require a live AMQP broker to
//! `cargo build --example amqp_consumer --features amqp`. Running it
//! end-to-end requires a reachable RabbitMQ broker at `AMQP_URL`.
//!
//! Run: `cargo run --example amqp_consumer --features amqp`

use axiam_sdk::amqp::consume;
use axiam_sdk::Sensitive;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let amqp_url =
        std::env::var("AMQP_URL").unwrap_or_else(|_| "amqp://guest:guest@localhost:5672".into());
    let queue = std::env::var("AXIAM_AMQP_QUEUE").unwrap_or_else(|_| "axiam.authz.request".into());

    // §8.1: the per-tenant AMQP signing secret MUST be obtained from the
    // AXIAM management API — never hardcoded. This example reads it from an
    // environment variable as a stand-in for that management-API fetch;
    // wrap it in Sensitive<Vec<u8>> immediately so it can never be logged.
    let signing_key_hex = std::env::var("AXIAM_AMQP_SIGNING_KEY_HEX")
        .unwrap_or_else(|_| "00112233445566778899aabbccddeeff".to_string());
    let signing_key_bytes = decode_hex(&signing_key_hex)?;
    let signing_key = Sensitive::new(signing_key_bytes);

    println!("Consuming from '{queue}' — HMAC verification runs before every handler call.");

    // The SDK owns the full ack/nack loop (D-07): `handler` is invoked only
    // after a delivery's HMAC signature has been verified AND the NEW-4 v2
    // replay-protection gates pass (key_version >= 2, fresh issued_at,
    // unseen nonce); any failure is nacked without requeue and logged as a
    // security event that never contains the HMAC value (CONTRACT.md §8.4).
    // `None` below uses the default ±5 minute issued_at freshness window;
    // pass `Some(Duration::from_secs(..))` to override it.
    consume(&amqp_url, &queue, signing_key, None, |event| async move {
        println!("Verified AMQP event: {event}");
    })
    .await?;

    Ok(())
}

/// Minimal hex decoder so this example has no extra dependency beyond what
/// the `amqp` feature already pulls in (`hex` is already a dependency of
/// this crate, but is not part of the SDK's public API surface).
fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !s.len().is_multiple_of(2) {
        return Err("hex signing key must have an even number of characters".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}
