//! Login + MFA two-phase flow (CONTRACT.md §1, §5).
//!
//! Demonstrates:
//! - Constructing an [`axiam_sdk::client::AxiamClient`] with a non-optional
//!   `tenant_slug` (§5 — there is no default tenant).
//! - Calling `login`, branching on `LoginResult.mfa_required`, and calling
//!   `verify_mfa` to complete the two-phase flow when the server challenges
//!   for MFA.
//!
//! This example is illustrative/compilable — it reads connection details
//! from environment variables and does not require a live AXIAM server to
//! `cargo build --example login_mfa --features rest`. Running it end-to-end
//! requires a reachable AXIAM server matching the configured base URL.
//!
//! Run: `cargo run --example login_mfa --features rest`

use axiam_sdk::client::AxiamClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // §14: base_url has no default; §5: tenant_slug/tenant_id is
    // non-optional at construction time.
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_slug = std::env::var("AXIAM_TENANT_SLUG").unwrap_or_else(|_| "acme".to_string());
    let email = std::env::var("AXIAM_EMAIL").unwrap_or_else(|_| "user@example.com".to_string());
    let password = std::env::var("AXIAM_PASSWORD").unwrap_or_else(|_| "changeme".to_string());
    let totp_code = std::env::var("AXIAM_TOTP_CODE").unwrap_or_else(|_| "000000".to_string());

    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_slug(tenant_slug)
        .build()?;

    // POST /api/v1/auth/login (CONTRACT.md §1).
    let login_result = client.login(&email, &password).await?;

    if login_result.mfa_required {
        println!(
            "MFA required — available methods: {:?}",
            login_result.available_methods
        );

        // POST /api/v1/auth/mfa/verify — the challenge token from the
        // preceding login() call is held internally by the client, so
        // verify_mfa needs only the user-supplied code (CONTRACT.md §1's
        // exact `verify_mfa(code)` signature).
        let completed = client.verify_mfa(&totp_code).await?;
        println!(
            "MFA verified — session_id: {:?}, expires_in: {:?}s",
            completed.session_id, completed.expires_in
        );
    } else {
        println!(
            "Login complete (no MFA) — session_id: {:?}, expires_in: {:?}s",
            login_result.session_id, login_result.expires_in
        );
    }

    // The access/refresh tokens are never exposed here (D-05) — they live
    // in the client's cookie jar and internal TokenManager, already
    // wrapped in Sensitive<T> (§7).
    if let Some(tenant_id) = client.resolved_tenant_id().await {
        println!("Resolved tenant_id: {tenant_id}");
    }

    Ok(())
}
