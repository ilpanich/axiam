//! SC#2 oracle (CONTRACT.md §9): 5 concurrent callers observing the same
//! expired access token trigger EXACTLY 1 refresh HTTP call, and all 5
//! receive the new token.

#![cfg(feature = "rest")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axiam_sdk::token::refresh_guard::RefreshedTokens;
use axiam_sdk::token::TokenManager;
use axiam_sdk::Sensitive;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OLD_ACCESS_TOKEN: &str = "old-access-token";
const OLD_REFRESH_TOKEN: &str = "old-refresh-token";
const NEW_ACCESS_TOKEN: &str = "new-access-token";
const NEW_REFRESH_TOKEN: &str = "new-refresh-token";

/// Seed a `TokenManager` with a known "expired" access token + refresh
/// token, matching the state a real client would be in right before a 401.
async fn seeded_token_manager() -> TokenManager {
    let manager = TokenManager::new();
    manager
        .set_tokens(
            Sensitive::new(OLD_ACCESS_TOKEN.to_string()),
            Some(Sensitive::new(OLD_REFRESH_TOKEN.to_string())),
            Some(0), // already expired
            None,
        )
        .await;
    manager
}

#[tokio::test]
async fn single_flight_refresh_exactly_one_call_under_five_concurrent_callers() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));

    let counter_for_responder = Arc::clone(&call_count);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(move |_req: &wiremock::Request| {
            counter_for_responder.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "expires_in": 900
            }))
        })
        .mount(&mock_server)
        .await;

    let manager = Arc::new(seeded_token_manager().await);
    let http_client = reqwest::Client::new();
    let refresh_url = format!("{}/api/v1/auth/refresh", mock_server.uri());

    let mut handles = Vec::new();
    for _ in 0..5 {
        let manager = Arc::clone(&manager);
        let http_client = http_client.clone();
        let refresh_url = refresh_url.clone();
        handles.push(tokio::spawn(async move {
            manager
                .refresh_if_needed(OLD_ACCESS_TOKEN, |refresh_token| {
                    let http_client = http_client.clone();
                    let refresh_url = refresh_url.clone();
                    async move {
                        // Real refresh implementations send the refresh token via
                        // the httpOnly cookie, not the body; the test only needs
                        // to prove single-flight collapsing, so a minimal request
                        // is sufficient. `refresh_token` is asserted non-empty to
                        // confirm the guard passed the correct value through.
                        assert_eq!(refresh_token, OLD_REFRESH_TOKEN);
                        let resp = http_client
                            .post(&refresh_url)
                            .send()
                            .await
                            .expect("refresh request should succeed against the mock");
                        assert!(resp.status().is_success());
                        Ok::<_, axiam_sdk::AxiamError>(RefreshedTokens {
                            access: Sensitive::new(NEW_ACCESS_TOKEN.to_string()),
                            refresh: Some(Sensitive::new(NEW_REFRESH_TOKEN.to_string())),
                            exp: Some(9_999_999_999),
                            tenant_id: None,
                        })
                    }
                })
                .await
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        results.push(handle.await);
    }

    for join_result in results {
        let refreshed = join_result
            .expect("task should not panic")
            .expect("refresh_if_needed should succeed for every caller");
        assert_eq!(
            format!("{refreshed:?}"),
            "Sensitive(<redacted>)",
            "refreshed token must remain wrapped in Sensitive<T>"
        );
    }

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "exactly one refresh HTTP call must be made across 5 concurrent callers (CONTRACT.md §9 / SC#2)"
    );

    assert_eq!(
        manager.exp().await,
        Some(9_999_999_999),
        "TokenManager state must reflect the single successful refresh"
    );
}
