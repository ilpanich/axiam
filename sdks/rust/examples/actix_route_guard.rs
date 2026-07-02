//! Actix-Web route guard using the `AxiamUser` `FromRequest` extractor
//! (CONTRACT.md §10).
//!
//! Demonstrates registering a shared [`axiam_sdk::token::JwksVerifier`] as
//! `app_data` and using [`axiam_sdk::middleware::AxiamUser`] as a handler
//! parameter to guard a route: the extractor reads the session from the
//! `axiam_access` cookie (falling back to `Authorization: Bearer`), verifies
//! it locally against the cached JWKS (no AXIAM-server round-trip), and
//! injects `{ user_id, tenant_id, roles }` — verification failures surface
//! as HTTP 401/403 automatically via `AxiamExtractorError`'s
//! `ResponseError` impl, before the handler body ever runs.
//!
//! This example is illustrative/compilable — it starts a real Actix-Web
//! server bound to `AXIAM_LISTEN_ADDR` (default `127.0.0.1:8080`) and does
//! not require a live AXIAM server to `cargo build --example
//! actix_route_guard --features actix`. Serving real traffic requires the
//! configured `AXIAM_BASE_URL` to be a reachable AXIAM server (for the
//! extractor's JWKS fetch).
//!
//! Run: `cargo run --example actix_route_guard --features actix`

use actix_web::{web, App, HttpServer};
use axiam_sdk::middleware::AxiamUser;
use axiam_sdk::token::JwksVerifier;

/// A route guarded by the `AxiamUser` extractor — Actix rejects the request
/// with 401/403 automatically if extraction fails, before this handler body
/// ever runs (CONTRACT.md §10 closing requirement).
async fn protected_resource(user: AxiamUser) -> String {
    format!(
        "Hello, user {} (tenant {}) — roles: {:?}",
        user.user_id, user.tenant_id, user.roles
    )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let listen_addr =
        std::env::var("AXIAM_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let base_url_parsed = url::Url::parse(&base_url).expect("AXIAM_BASE_URL must be a valid URL");
    let http = reqwest::Client::new();
    let jwks_verifier =
        JwksVerifier::new(http, &base_url_parsed).expect("failed to construct JwksVerifier");

    // `web::Data<T>` is `Arc`-backed: build the verifier once here, then
    // `.clone()` the cheap `web::Data` handle into every worker's factory
    // closure below — all workers share the same underlying JWKS cache and
    // `reqwest::Client` connection pool.
    let jwks_data = web::Data::new(jwks_verifier);

    println!("Listening on http://{listen_addr} — GET /protected requires an AXIAM session");

    HttpServer::new(move || {
        App::new()
            .app_data(jwks_data.clone())
            .route("/protected", web::get().to(protected_resource))
    })
    .bind(&listen_addr)?
    .run()
    .await
}
