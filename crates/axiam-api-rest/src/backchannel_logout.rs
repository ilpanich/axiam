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

use std::time::Duration;

use axiam_core::models::oauth2_client::OAuth2Client;
use tracing::{debug, warn};

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
/// Returns `true` if some attempt got a 2xx. Never panics and never propagates:
/// the caller is a detached task whose failure must not affect the logout that
/// triggered it.
pub async fn deliver_one(client: &reqwest::Client, delivery: &LogoutDelivery) -> bool {
    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(BACKOFF[(attempt - 1).min(BACKOFF.len() - 1)]).await;
        }
        let result = client
            .post(&delivery.uri)
            .timeout(ATTEMPT_TIMEOUT)
            // Back-Channel Logout 1.0 §2.5: form-encoded, one parameter.
            .form(&[("logout_token", &delivery.logout_token)])
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                debug!(
                    client_id = %delivery.client_id,
                    attempt = attempt + 1,
                    "back-channel logout delivered"
                );
                return true;
            }
            Ok(resp) => {
                // Never log the token: it is a session-termination command,
                // and a log line carrying one is a replayable instruction.
                warn!(
                    client_id = %delivery.client_id,
                    status = resp.status().as_u16(),
                    attempt = attempt + 1,
                    "back-channel logout rejected by RP"
                );
            }
            Err(e) => {
                warn!(
                    client_id = %delivery.client_id,
                    error = %e,
                    attempt = attempt + 1,
                    "back-channel logout delivery failed"
                );
            }
        }
    }
    false
}

/// Fan out to every target. Intended to be spawned, not awaited by a handler.
pub async fn deliver_all(deliveries: Vec<LogoutDelivery>) {
    let Ok(http) = reqwest::Client::builder().timeout(ATTEMPT_TIMEOUT).build() else {
        warn!("could not build HTTP client for back-channel logout");
        return;
    };
    for delivery in &deliveries {
        // Sequential rather than concurrent: the list is one user's RPs, so it
        // is small, and a slow RP delaying the next one costs nothing that
        // matters — the user is already logged out.
        deliver_one(&http, delivery).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
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
}
