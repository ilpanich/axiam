//! REST authorization checks: `check_access` / `can` / `batch_check`
//! (CONTRACT.md §1).
//!
//! Demonstrates the single-check, browser-alias, and batch authz REST
//! endpoints (`POST /api/v1/authz/check`, `POST /api/v1/authz/check/batch`)
//! after a successful login.
//!
//! This example is illustrative/compilable — it reads connection details
//! from environment variables and does not require a live AXIAM server to
//! `cargo build --example rest_check_access --features rest`.
//!
//! Run: `cargo run --example rest_check_access --features rest`

use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::authz::AccessCheckRequest;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_slug = std::env::var("AXIAM_TENANT_SLUG").unwrap_or_else(|_| "acme".to_string());
    let email = std::env::var("AXIAM_EMAIL").unwrap_or_else(|_| "user@example.com".to_string());
    let password = std::env::var("AXIAM_PASSWORD").unwrap_or_else(|_| "changeme".to_string());

    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_slug(tenant_slug)
        .build()?;

    let login_result = client.login(&email, &password).await?;
    if login_result.mfa_required {
        eprintln!("MFA is required for this account — see examples/login_mfa.rs first.");
        return Ok(());
    }

    let resource_id = std::env::var("AXIAM_RESOURCE_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::new_v4);

    // POST /api/v1/authz/check — single access check.
    let decision = client
        .check_access("resource:read", resource_id, None)
        .await?;
    println!(
        "check_access -> allowed: {}, reason: {:?}",
        decision.allowed, decision.reason
    );

    // `can` — the browser/UI-facing alias for check_access (CONTRACT.md §1
    // note); returns a plain bool instead of the full AccessDecision.
    let allowed = client.can("resource:write", resource_id, None).await?;
    println!("can(resource:write) -> {allowed}");

    // POST /api/v1/authz/check/batch — an ordered batch of checks; results
    // preserve input order.
    let batch = vec![
        AccessCheckRequest::new("resource:read", resource_id),
        AccessCheckRequest::new("resource:delete", resource_id).with_scope("admin"),
    ];
    let results = client.batch_check(batch).await?;
    for (i, decision) in results.iter().enumerate() {
        println!("batch_check[{i}] -> allowed: {}", decision.allowed);
    }

    Ok(())
}
