//! gRPC authorization checks: `check_access` / `batch_check` over the shared
//! lazily-connected `tonic::Channel` (CONTRACT.md §1, §5, §9).
//!
//! `AuthzGrpcClient` is transport-decoupled from the REST `AxiamClient`
//! (16-03 design): it owns its own [`TokenManager`] and takes a
//! caller-supplied `RefreshFn` closure that performs the actual
//! `POST /api/v1/auth/refresh` HTTP call. This example shows the
//! `grpc`-only-friendly shape of that wiring: a minimal `reqwest`-based
//! login (holding its own `Arc<reqwest::cookie::Jar>`, mirroring
//! `sdks/rust/src/client.rs`'s own pattern) populates the shared
//! `TokenManager` once, then `AuthzGrpcClient` drives the same instance's
//! single-flight refresh guard (§9) via the closure on any
//! `UNAUTHENTICATED` response.
//!
//! This example is illustrative/compilable — it reads connection details
//! from environment variables and does not require a live AXIAM server to
//! `cargo build --example grpc_check_access --features "rest grpc"`.
//!
//! Run: `cargo run --example grpc_check_access --features "rest grpc"`

use std::sync::Arc;

use axiam_sdk::grpc::{build_channel, AuthzGrpcClient, CheckAccessRequest, GrpcChannelConfig};
use axiam_sdk::token::{Claims, JwksVerifier, TokenManager};
use axiam_sdk::Sensitive;
use reqwest::cookie::CookieStore;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct LoginBody {
    #[allow(dead_code)]
    session_id: Uuid,
}

/// Extract a named cookie value directly out of `jar` for `base_url` —
/// mirrors `sdks/rust/src/token/manager.rs::extract_cookie_from_jar`
/// (crate-private), reproduced here since a `grpc`-only consumer does not
/// go through a `rest`-feature `AxiamClient`.
fn extract_cookie(jar: &reqwest::cookie::Jar, base_url: &url::Url, name: &str) -> Option<String> {
    let header = jar.cookies(base_url)?;
    let raw = header.to_str().ok()?;
    raw.split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        .map(|v| v.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let grpc_url =
        std::env::var("AXIAM_GRPC_URL").unwrap_or_else(|_| "https://localhost:9443".to_string());
    let tenant_slug = std::env::var("AXIAM_TENANT_SLUG").unwrap_or_else(|_| "acme".to_string());
    let email = std::env::var("AXIAM_EMAIL").unwrap_or_else(|_| "user@example.com".to_string());
    let password = std::env::var("AXIAM_PASSWORD").unwrap_or_else(|_| "changeme".to_string());

    let base_url_parsed = url::Url::parse(&base_url)?;
    let jar = Arc::new(reqwest::cookie::Jar::default());
    let http = reqwest::Client::builder()
        .cookie_provider(Arc::clone(&jar))
        .build()?;
    let jwks_verifier = Arc::new(JwksVerifier::new(http.clone(), &base_url_parsed)?);
    let token_manager = Arc::new(TokenManager::new());

    // A minimal login call populating the shared TokenManager — a
    // grpc-only consumer performs an equivalent call against
    // `POST /api/v1/auth/login` using their own minimal HTTP client; the
    // token never needs to pass through a `rest`-enabled AxiamClient.
    let response = http
        .post(base_url_parsed.join("/api/v1/auth/login")?)
        .json(&serde_json::json!({
            "tenant_slug": tenant_slug,
            "username_or_email": email,
            "password": password,
        }))
        .send()
        .await?;
    if response.status().as_u16() == 202 {
        eprintln!("MFA is required for this account — see examples/login_mfa.rs first.");
        return Ok(());
    }
    let _login_body: LoginBody = response.json().await?;

    let access_cookie = extract_cookie(&jar, &base_url_parsed, "axiam_access")
        .ok_or("server response did not set the axiam_access cookie")?;
    let claims: Claims = jwks_verifier.verify(&access_cookie).await?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id)?;

    token_manager
        .set_tokens(
            Sensitive::new(access_cookie.clone()),
            extract_cookie(&jar, &base_url_parsed, "axiam_refresh").map(Sensitive::new),
            Some(claims.exp),
            Some(tenant_id),
        )
        .await;

    // §6: strict TLS is always on; `connect_lazy` performs no network I/O —
    // the actual TCP+TLS handshake happens on the first RPC.
    let channel = build_channel(&grpc_url, &GrpcChannelConfig::default())?;

    // On UNAUTHENTICATED, AuthzGrpcClient drives the shared single-flight
    // refresh (§9) through this closure, which performs the actual
    // `POST /api/v1/auth/refresh` call (the refresh token itself travels
    // via the httpOnly cookie already in `jar`).
    let refresh_http = http.clone();
    let refresh_jar = Arc::clone(&jar);
    let refresh_base_url = base_url_parsed.clone();
    let refresh_jwks = Arc::clone(&jwks_verifier);
    let refresh_fn: axiam_sdk::grpc::RefreshFn = Arc::new(move |_refresh_token_unused| {
        let http = refresh_http.clone();
        let jar = Arc::clone(&refresh_jar);
        let base_url = refresh_base_url.clone();
        let jwks_verifier = Arc::clone(&refresh_jwks);
        Box::pin(async move {
            let response = http
                .post(base_url.join("/api/v1/auth/refresh").unwrap())
                .json(&serde_json::json!({ "tenant_id": tenant_id, "org_id": Uuid::nil() }))
                .send()
                .await
                .map_err(|e| axiam_sdk::AxiamError::Network {
                    message: format!("refresh request failed: {e}"),
                    source: Some(Box::new(e)),
                })?;
            if !response.status().is_success() {
                return Err(axiam_sdk::AxiamError::from_http_status(
                    response.status().as_u16(),
                    "refresh failed".to_string(),
                ));
            }
            let access = extract_cookie(&jar, &base_url, "axiam_access").ok_or_else(|| {
                axiam_sdk::AxiamError::Auth {
                    message: "refresh response did not set axiam_access".into(),
                }
            })?;
            let claims = jwks_verifier.verify(&access).await?;
            Ok(axiam_sdk::token::refresh_guard::RefreshedTokens {
                access: Sensitive::new(access),
                refresh: extract_cookie(&jar, &base_url, "axiam_refresh").map(Sensitive::new),
                exp: Some(claims.exp),
                tenant_id: Uuid::parse_str(&claims.tenant_id).ok(),
            })
        })
    });

    let grpc_client = AuthzGrpcClient::new(channel, token_manager, tenant_id, refresh_fn);

    let resource_id = std::env::var("AXIAM_RESOURCE_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::new_v4);
    let subject_id = std::env::var("AXIAM_SUBJECT_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::new_v4);

    // CheckAccess (CONTRACT.md §1).
    let decision = grpc_client
        .check_access(CheckAccessRequest {
            tenant_id,
            subject_id,
            action: "resource:read".to_string(),
            resource_id,
            scope: None,
        })
        .await?;
    println!(
        "gRPC CheckAccess -> allowed: {}, deny_reason: {:?}",
        decision.allowed, decision.deny_reason
    );

    // BatchCheckAccess — results preserve input order (CONTRACT.md §1).
    let batch = vec![
        CheckAccessRequest {
            tenant_id,
            subject_id,
            action: "resource:read".to_string(),
            resource_id,
            scope: None,
        },
        CheckAccessRequest {
            tenant_id,
            subject_id,
            action: "resource:delete".to_string(),
            resource_id,
            scope: Some("admin".to_string()),
        },
    ];
    let results = grpc_client.batch_check(batch).await?;
    for (i, decision) in results.iter().enumerate() {
        println!(
            "gRPC BatchCheckAccess[{i}] -> allowed: {}",
            decision.allowed
        );
    }

    Ok(())
}
