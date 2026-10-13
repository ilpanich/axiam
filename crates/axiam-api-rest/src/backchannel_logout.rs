//! Back-Channel Logout 1.0 delivery — B5.
//!
//! When a session ends, every client that participated in it and registered a
//! `backchannel_logout_uri` receives a POST carrying a signed logout token.
//!
//! # Delivery is best-effort and never blocks the logout
//!
//! The user's session is gone from AXIAM the moment the request returns,
//! whether or not any RP acknowledged. That is the spec's model
//! (Back-Channel Logout 1.0 §2.6), and the alternative is worse: making logout
//! synchronous on N external HTTP calls would make the feature a hostage to
//! the least reliable RP, so one RP whose endpoint hangs would make logging
//! out of AXIAM hang for the user.
//!
//! # Why this doesn't ride on the webhook pipeline
//!
//! `claude_dev/logout-and-par-design.md` originally proposed reusing the AMQP
//! webhook path for its retry and DLQ. It is delivered here instead, with a
//! small bounded retry of its own, for two reasons: the webhook consumer signs
//! every delivery with the HMAC header scheme of §13, which is exactly what a
//! logout token must **not** carry (the signed JWT *is* the authentication,
//! and offering a second, cheaper check invites an RP to verify that one); and
//! routing through AMQP would make logout notification silently depend on the
//! broker being up, which is a stronger coupling than a best-effort side
//! effect should have. The retry below keeps the property that actually
//! matters — a briefly-unavailable RP still gets told.
//!
//! # The only way out of the process (R101W2-04)
//!
//! The logout token is a signed, session-naming credential, and the URI it goes
//! to was typed by a tenant administrator. Delivery therefore makes **one hop
//! through `ssrf::guarded_fetch_no_redirect`** with `allow_private = false`: the
//! name is resolved fresh, every address must be globally routable, the
//! validated address is pinned into the connection and `https` is required. A
//! `3xx` comes back as a response and is a failed attempt: the token cannot
//! reach a host the client never registered. The URI is also validated when the
//! client is registered (`validate_backchannel_logout_uri`), but a row written
//! under 1.0.0 may hold anything, so the guard here is the one that counts.
//!
//! | The RP answers | Outcome |
//! |---|---|
//! | any `2xx` | delivered |
//! | a `3xx` | failed attempt, retried, never followed |
//! | anything else, a timeout, a refused address, no connection | failed attempt, retried |

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axiam_core::models::oauth2_client::OAuth2Client;
use axiam_federation::ssrf;
use tracing::{debug, warn};

/// Whether delivery may reach a non-public address. `false` unless
/// [`admit_private_networks_for_tests`] was called, which nothing outside the
/// test suites does (a source pin below asserts it).
static ADMIT_PRIVATE_FOR_TESTS: AtomicBool = AtomicBool::new(false);

/// **Test seam, never called by the composition root or any production path.**
///
/// Lets the first hop reach a loopback receiver over plain `http`, the way
/// `WebhookDeliverer::admitting_private_networks_for_tests` and the SSF, SCIM
/// and CIBA-ping deliverers' seams do. Delivery here is a detached task started
/// from a handler, so there is no deliverer value to carry the bit; a test
/// binary that needs a loopback RP calls this once. Redirects stay unfollowed
/// either way.
#[doc(hidden)]
pub fn admit_private_networks_for_tests() {
    ADMIT_PRIVATE_FOR_TESTS.store(true, Ordering::SeqCst);
}

/// How many times a single client's endpoint is tried.
///
/// Three attempts covers a restart or a momentary blip, which is what
/// "SHOULD retry" in §2.6 is for. It deliberately does not cover a sustained
/// outage: an RP that is down for minutes will keep its own session until it
/// expires, and queueing indefinitely would mean holding a session-termination
/// command — a security-relevant instruction — for an unbounded time.
const MAX_ATTEMPTS: usize = 3;

/// Per-attempt timeout. Short, because this runs detached and a hung socket
/// would otherwise pin the task for the client's default timeout.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Backoff before attempt N+1.
const BACKOFF: [Duration; 2] = [Duration::from_millis(500), Duration::from_millis(2000)];

/// One client's delivery target: where to POST, and the token to send.
#[derive(Debug, Clone)]
pub struct LogoutDelivery {
    pub client_id: String,
    pub uri: String,
    pub logout_token: String,
}

/// Select the clients that should be notified.
///
/// Two filters, both load-bearing:
///
/// - **Only clients that participated in the session.** Broadcasting to every
///   registered client would tell clients that were never part of the session
///   that one just ended, which leaks its existence.
/// - **Only clients with a `backchannel_logout_uri`.** A client without one
///   has not opted in; it is skipped, not retried.
///
/// Participation records are deduplicated here rather than constrained in the
/// datastore, because a client legitimately re-authorizes within one session.
pub fn select_targets(
    participants: &[String],
    clients: &[OAuth2Client],
    tokens: impl Fn(&str) -> Option<String>,
) -> Vec<LogoutDelivery> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for client_id in participants {
        if !seen.insert(client_id.clone()) {
            continue;
        }
        let Some(client) = clients.iter().find(|c| &c.client_id == client_id) else {
            continue;
        };
        let Some(uri) = client.backchannel_logout_uri.as_deref() else {
            continue;
        };
        let Some(token) = tokens(client_id) else {
            continue;
        };
        out.push(LogoutDelivery {
            client_id: client_id.clone(),
            uri: uri.to_string(),
            logout_token: token,
        });
    }
    out
}

/// POST one logout token, retrying a bounded number of times.
///
/// One guarded, non-redirecting hop per attempt (R101W2-04). `allow_private` is
/// `false` in production; [`deliver_all`] passes the test seam's value.
///
/// Returns `true` if some attempt got a 2xx. Never panics and never propagates:
/// the caller is a detached task whose failure must not affect the logout that
/// triggered it.
pub async fn deliver_one(delivery: &LogoutDelivery, allow_private: bool) -> bool {
    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(BACKOFF[(attempt - 1).min(BACKOFF.len() - 1)]).await;
        }
        // The resolve and the connect are inside the guard, so the timeout
        // wraps the whole attempt rather than only the request.
        let result = tokio::time::timeout(
            ATTEMPT_TIMEOUT,
            ssrf::guarded_fetch_no_redirect(&delivery.uri, allow_private, |client, target| {
                client
                    .post(target)
                    .timeout(ATTEMPT_TIMEOUT)
                    // Back-Channel Logout 1.0 §2.5: form-encoded, one parameter.
                    .form(&[("logout_token", &delivery.logout_token)])
            }),
        )
        .await;

        match result {
            Ok(Ok(resp)) if resp.status().is_success() => {
                debug!(
                    client_id = %delivery.client_id,
                    attempt = attempt + 1,
                    "back-channel logout delivered"
                );
                return true;
            }
            Ok(Ok(resp)) if resp.status().is_redirection() => {
                // Not followed: the token goes to the host the client
                // registered or nowhere.
                warn!(
                    client_id = %delivery.client_id,
                    status = resp.status().as_u16(),
                    attempt = attempt + 1,
                    "back-channel logout answered with a redirect, which is not followed"
                );
            }
            Ok(Ok(resp)) => {
                // Never log the token: it is a session-termination command,
                // and a log line carrying one is a replayable instruction.
                warn!(
                    client_id = %delivery.client_id,
                    status = resp.status().as_u16(),
                    attempt = attempt + 1,
                    "back-channel logout rejected by RP"
                );
            }
            Ok(Err(e)) => {
                warn!(
                    client_id = %delivery.client_id,
                    error = %e,
                    attempt = attempt + 1,
                    "back-channel logout delivery failed"
                );
            }
            Err(_elapsed) => {
                warn!(
                    client_id = %delivery.client_id,
                    attempt = attempt + 1,
                    "back-channel logout delivery timed out"
                );
            }
        }
    }
    false
}

/// Fan out to every target. Intended to be spawned, not awaited by a handler.
pub async fn deliver_all(deliveries: Vec<LogoutDelivery>) {
    let allow_private = ADMIT_PRIVATE_FOR_TESTS.load(Ordering::SeqCst);
    for delivery in &deliveries {
        // Sequential rather than concurrent: the list is one user's RPs, so it
        // is small, and a slow RP delaying the next one costs nothing that
        // matters — the user is already logged out.
        deliver_one(delivery, allow_private).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::oauth2_client::AuthnRequestParamsMode;
    use chrono::Utc;
    use uuid::Uuid;

    fn client(id: &str, uri: Option<&str>) -> OAuth2Client {
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: id.into(),
            client_secret_hash: String::new(),
            name: id.into(),
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: uri.map(str::to_owned),
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            allowed_resources: Vec::new(),
            managed_by: axiam_core::models::oauth2_client::ManagedBy::Admin,
            last_authorized_at: None,
            ciba: Default::default(),
        }
    }

    fn always_token(_: &str) -> Option<String> {
        Some("tok".into())
    }

    #[test]
    fn only_participating_clients_are_targeted() {
        // The registry holds a client that never joined the session. Telling
        // it a session ended would leak that the session existed at all.
        let clients = vec![
            client("rp-a", Some("https://a.example/logout")),
            client("rp-bystander", Some("https://b.example/logout")),
        ];
        let targets = select_targets(&["rp-a".into()], &clients, always_token);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].client_id, "rp-a");
    }

    #[test]
    fn a_client_without_a_uri_is_skipped() {
        let clients = vec![client("rp-a", None)];
        assert!(select_targets(&["rp-a".into()], &clients, always_token).is_empty());
    }

    #[test]
    fn a_client_that_reauthorized_is_notified_once() {
        // Re-authorizing within one session (a second tab, a refreshed
        // consent) writes a second participation row. It must not produce two
        // logout tokens.
        let clients = vec![client("rp-a", Some("https://a.example/logout"))];
        let targets = select_targets(
            &["rp-a".into(), "rp-a".into(), "rp-a".into()],
            &clients,
            always_token,
        );
        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn a_participant_missing_from_the_registry_is_skipped() {
        // A deleted client can still have participation rows.
        let targets = select_targets(&["rp-gone".into()], &[], always_token);
        assert!(targets.is_empty());
    }

    #[test]
    fn every_target_carries_its_own_token() {
        // `aud` names one client, so tokens are not interchangeable; a shared
        // token would be accepted by whichever RP received it.
        let clients = vec![
            client("rp-a", Some("https://a.example/logout")),
            client("rp-b", Some("https://b.example/logout")),
        ];
        let targets = select_targets(&["rp-a".into(), "rp-b".into()], &clients, |id| {
            Some(format!("token-for-{id}"))
        });
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].logout_token, "token-for-rp-a");
        assert_eq!(targets[1].logout_token, "token-for-rp-b");
    }

    #[test]
    fn a_client_whose_token_could_not_be_issued_is_skipped() {
        // Skipped rather than sent an empty body: an RP receiving a malformed
        // logout token would reject it anyway, and a delivery attempt would
        // only look like a working notification in the logs.
        let clients = vec![client("rp-a", Some("https://a.example/logout"))];
        assert!(select_targets(&["rp-a".into()], &clients, |_| None).is_empty());
    }

    #[test]
    fn retry_bound_is_small_and_finite() {
        const {
            assert!(MAX_ATTEMPTS >= 2);
            assert!(MAX_ATTEMPTS <= 5);
            // Every retry needs a backoff to read from.
            assert!(BACKOFF.len() >= MAX_ATTEMPTS - 1);
        }
    }

    // -----------------------------------------------------------------------
    // R101W2-04 — delivery is one guarded, non-redirecting hop
    // -----------------------------------------------------------------------

    /// The delivery's only way out is the one-hop guard (T-112): pinned against
    /// the source, as `webhook.rs` does, so a plain `reqwest` client or a
    /// redirect-following `guarded_fetch` cannot come back beside it without
    /// this test saying so.
    #[test]
    fn delivery_goes_through_the_no_redirect_guarded_fetch_and_nothing_else() {
        let source = include_str!("backchannel_logout.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the production half of the file");
        assert_eq!(production.matches("guarded_fetch_no_redirect(").count(), 1);
        assert_eq!(production.matches("guarded_fetch(").count(), 0);
        assert_eq!(production.matches("guarded_fetch_with_cap(").count(), 0);
        assert_eq!(production.matches("reqwest::Client").count(), 0);
        assert_eq!(production.matches("Client::builder").count(), 0);
        // The only caller of the test seam's setter is the setter itself.
        assert_eq!(
            production.matches("ADMIT_PRIVATE_FOR_TESTS.store(").count(),
            1
        );
    }

    /// The seam that admits loopback is not reachable from the composition
    /// root: no file of `axiam-server` calls this module's setter. (The boot
    /// options' own `admit_private_networks_for_tests` flag is a different seam,
    /// for the deliverers built there.)
    #[test]
    fn the_composition_root_never_calls_the_test_seam() {
        fn walk(dir: &std::path::Path, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, hits);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && std::fs::read_to_string(&path)
                        .unwrap()
                        .contains("backchannel_logout::admit_private_networks_for_tests")
                {
                    hits.push(path.display().to_string());
                }
            }
        }
        let server = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../axiam-server/src");
        let mut hits = Vec::new();
        walk(&server, &mut hits);
        assert!(hits.is_empty(), "axiam-server names the seam: {hits:?}");
    }

    fn delivery_to(uri: String) -> LogoutDelivery {
        LogoutDelivery {
            client_id: "rp-a".into(),
            uri,
            logout_token: "the-logout-token".into(),
        }
    }

    /// A `307` is a failed attempt and its `Location` is never requested: the
    /// second server, which the first one names, sees nothing.
    #[tokio::test]
    async fn a_redirect_from_the_rp_is_not_followed() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let elsewhere = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&elsewhere)
            .await;
        let rp = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Location", format!("{}/collect", elsewhere.uri())),
            )
            .mount(&rp)
            .await;

        let delivered = deliver_one(&delivery_to(format!("{}/logout", rp.uri())), true).await;

        assert!(!delivered, "a 3xx is a failed delivery");
        let attempts = rp.received_requests().await.unwrap().len();
        assert_eq!(attempts, MAX_ATTEMPTS, "it is retried, not followed");
        assert!(
            elsewhere.received_requests().await.unwrap().is_empty(),
            "the redirect target must see nothing"
        );
    }

    /// The same request answered `200` is delivered: the form carries one
    /// `logout_token` parameter (§2.5), so the refusal above is the redirect
    /// and not a harness fault.
    #[tokio::test]
    async fn a_2xx_delivers_the_token_as_a_form_post() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rp = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&rp)
            .await;

        assert!(deliver_one(&delivery_to(format!("{}/logout", rp.uri())), true).await);

        let requests = rp.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            String::from_utf8(requests[0].body.clone()).unwrap(),
            "logout_token=the-logout-token"
        );
    }

    /// Production posture (`allow_private = false`): a stored URI that points at
    /// a private, loopback, link-local or metadata address, or speaks plain
    /// `http`, reaches nothing. A client registered under 1.0.0 may hold such a
    /// value (registration did not validate it); delivery refuses it.
    #[tokio::test]
    async fn a_stored_uri_at_a_non_public_address_reaches_nothing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        for uri in [
            format!("https://127.0.0.1:{port}/logout"),
            format!("http://127.0.0.1:{port}/logout"),
            "https://10.0.0.8/logout".to_owned(),
            "https://192.168.1.10/logout".to_owned(),
            "https://169.254.169.254/latest/meta-data/".to_owned(),
            "https://[::1]/logout".to_owned(),
        ] {
            // One attempt is enough to show the refusal; the retry loop is
            // exercised by the redirect test above.
            let result = tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                ssrf::guarded_fetch_no_redirect(&uri, false, |c, u| c.post(u)),
            )
            .await
            .expect("a refusal is immediate");
            assert!(result.is_err(), "{uri} must be refused by the guard");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "the loopback listener must see no connection"
        );
        // And through the delivery function itself.
        let uri = format!("https://127.0.0.1:{port}/logout");
        let attempt = tokio::time::timeout(
            Duration::from_secs(10),
            deliver_one(&delivery_to(uri), false),
        )
        .await
        .expect("three refused attempts finish within the backoff schedule");
        assert!(!attempt);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "the loopback listener must still see no connection"
        );
    }
}
