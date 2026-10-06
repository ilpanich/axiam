//! The CIBA ping deliverer (G-7, T23.7.2, D-65, D-36): tell a ping-mode client
//! that its request has been decided.
//!
//! [`CibaPingDeliverer`] implements the core [`OutboundDeliverer`] port for
//! [`OutboundKind::CibaPing`], the fourth kind of the shared outbound
//! dispatcher. The retry schedule, the attempt counter, the dead-letter queue
//! and the audit rows (`ciba_ping.delivery_attempt`, `.delivery_succeeded`,
//! `.delivery_failed`) are the dispatcher's; this deliverer **classifies one
//! attempt and decides nothing**.
//!
//! # What travels on the queue
//!
//! [`ping_message`] builds it: the request's **record id** as `target_id`, the
//! tenant, a fresh `delivery_id` and an empty payload. Never the `auth_req_id`
//! (it is the credential the client redeems with) and never the
//! `client_notification_token` (the bearer AXIAM presents): both are sealed in
//! the request row, and the deliverer opens them at the attempt
//! ([`CibaRequestRepository::ping_credentials`]). A queue, a dead-letter queue
//! or a broker dump therefore holds nothing that lets its reader act as the
//! client or as AXIAM.
//!
//! # What one attempt does
//!
//! Level-triggered — it reads the world as it is now:
//!
//! | The request, at the attempt | Outcome |
//! |---|---|
//! | gone (swept) | dead-letter |
//! | `approved` or `denied` | go on |
//! | `redeemed` — the client has already collected the result | delivered; there is nothing left to say |
//! | `pending`, `expired` | dead-letter — nothing was decided, or the decision lapsed |
//! | not a ping-mode request, or its client no longer is one, or has no endpoint | dead-letter |
//!
//! then the sealed credentials are opened, the client is **read again** and the
//! send goes out only if it is the same version whose endpoint was read first
//! (F4 W4 §15: a credential read separately from the endpoint it goes to is
//! re-checked against that endpoint's version), and:
//!
//! # The notification (CIBA Core §10.2)
//!
//! `POST` of `{"auth_req_id": …}`, `Content-Type: application/json`,
//! `Authorization: Bearer <client_notification_token>` (held in `Zeroizing`,
//! marked sensitive on the request), **no redirect followed**, a response body
//! never read and never logged.
//!
//! **The only way out of the process is `guarded_fetch_no_redirect` with
//! `allow_private = false`** (`axiam_pki::ssrf`): the name is resolved fresh,
//! every address must be globally routable, the validated address is pinned
//! into the connection, and `https` is required. An endpoint a client
//! registered that resolves to an internal address is refused here, at
//! delivery, which the write-time policy cannot catch. The fetch makes one hop
//! and returns a `3xx` as a response: the bearer token cannot reach a host the
//! client never named, by construction.
//!
//! | The client answers | Outcome |
//! |---|---|
//! | any `2xx` (CIBA Core: `204`) | delivered |
//! | a `3xx` | retry; never followed |
//! | `408`, `429`, any `5xx`, a timeout, no connection | retry |
//! | any other `4xx` — the endpoint or the token is wrong until someone fixes it | dead-letter, reason `HTTP <status>` |
//! | anything else | retry |
//!
//! A reason string reaches the audit log, so it is one of a fixed vocabulary:
//! never a header, a URL, a response body or a transport error's text (which
//! would carry the endpoint's URL).

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::ciba::{CibaDeliveryMode, CibaPingNotification, CibaRequestStatus};
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
    OutboundMessage,
};
use axiam_core::repository::{CibaRequestRepository, OAuth2ClientRepository};
use axiam_federation::ssrf::{SsrfError, guarded_fetch_no_redirect};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The `event_type` of a ping message. Free text to the dispatcher; it appears
/// in the dispatcher's audit rows.
pub const PING_EVENT_TYPE: &str = "ciba.ping";

/// The message the dispatcher queues for a decided request: the record id and
/// the tenant, a fresh delivery id, and nothing else.
#[must_use]
pub fn ping_message(tenant_id: Uuid, request_id: Uuid) -> OutboundMessage {
    OutboundMessage {
        kind: OutboundKind::CibaPing,
        tenant_id,
        target_id: request_id,
        delivery_id: Uuid::new_v4(),
        event_type: PING_EVENT_TYPE.to_owned(),
        payload: serde_json::Value::Null,
        attempt: 0,
    }
}

/// The deliverer for [`OutboundKind::CibaPing`].
pub struct CibaPingDeliverer<R, C> {
    requests: R,
    clients: C,
    /// The guarded fetch's `allow_private`. **Always `false`** except for the
    /// integration tests' loopback receiver, which turn it on through
    /// [`Self::admitting_private_networks_for_tests`] and nothing else.
    allow_private: bool,
}

impl<R, C> CibaPingDeliverer<R, C>
where
    R: CibaRequestRepository + 'static,
    C: OAuth2ClientRepository + 'static,
{
    /// The production deliverer: every ping goes through
    /// `guarded_fetch_no_redirect` with `allow_private = false`.
    pub fn new(requests: R, clients: C) -> Self {
        Self {
            requests,
            clients,
            allow_private: false,
        }
    }

    /// **Test seam, never used by the composition root.** Lets the first hop
    /// reach a loopback receiver over plain `http`, the way the SSF and SCIM
    /// deliverers' seams do. A deliverer built by [`Self::new`] cannot be
    /// switched afterwards by anything but this call, and production never
    /// makes it.
    #[doc(hidden)]
    #[must_use]
    pub fn admitting_private_networks_for_tests(mut self) -> Self {
        self.allow_private = true;
        self
    }

    async fn attempt(&self, msg: &OutboundMessage) -> Result<DeliveryOutcome, OutboundError> {
        if msg.kind != OutboundKind::CibaPing {
            return Ok(dead("the message is not a CIBA ping"));
        }

        // The request as it is now.
        let request = match self.requests.get_by_id(msg.tenant_id, msg.target_id).await {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(dead("the request no longer exists")),
            Err(_) => {
                return Err(OutboundError::Delivery(
                    "the request could not be read".into(),
                ));
            }
        };
        match request.status {
            CibaRequestStatus::Approved | CibaRequestStatus::Denied => {}
            CibaRequestStatus::Redeemed => {
                // The client collected the result without waiting for the ping.
                return Ok(DeliveryOutcome::Delivered {
                    response_status: None,
                });
            }
            CibaRequestStatus::Pending => return Ok(dead("the request is not decided")),
            CibaRequestStatus::Expired => return Ok(dead("the request expired")),
        }
        if request.delivery_mode != CibaDeliveryMode::Ping {
            return Ok(dead("the request is not a ping-mode request"));
        }

        // The client's endpoint, read first; its version is checked again after
        // the credentials are opened.
        let client = match self
            .clients
            .get_by_client_id(msg.tenant_id, &request.client_id)
            .await
        {
            Ok(client) => client,
            Err(AxiamError::NotFound { .. }) => return Ok(dead("the client no longer exists")),
            Err(_) => {
                return Err(OutboundError::Delivery(
                    "the client could not be read".into(),
                ));
            }
        };
        if client.ciba.backchannel_token_delivery_mode != Some(CibaDeliveryMode::Ping) {
            return Ok(dead("the client no longer receives pings"));
        }
        let Some(endpoint) = client
            .ciba
            .backchannel_client_notification_endpoint
            .clone()
            .filter(|e| !e.trim().is_empty())
        else {
            return Ok(dead("the client has no notification endpoint"));
        };

        let credentials = match self
            .requests
            .ping_credentials(msg.tenant_id, msg.target_id)
            .await
        {
            Ok(Some(credentials)) => credentials,
            Ok(None) => return Ok(dead("the request holds no notification credentials")),
            Err(_) => {
                return Err(OutboundError::Delivery(
                    "the notification credentials could not be opened".into(),
                ));
            }
        };

        // F4 W4 §15 (T-406): the endpoint and the credential are two reads. The
        // client is read once more, and the ping goes out only if it is the
        // same version, with the same endpoint, that was read above.
        match self
            .clients
            .get_by_client_id(msg.tenant_id, &request.client_id)
            .await
        {
            Ok(again)
                if again.updated_at == client.updated_at
                    && again
                        .ciba
                        .backchannel_client_notification_endpoint
                        .as_deref()
                        == Some(endpoint.as_str()) => {}
            Ok(_) => return Ok(retry("the client changed during the attempt")),
            Err(AxiamError::NotFound { .. }) => return Ok(dead("the client no longer exists")),
            Err(_) => {
                return Err(OutboundError::Delivery(
                    "the client could not be read".into(),
                ));
            }
        }

        let body = match serde_json::to_string(&CibaPingNotification {
            auth_req_id: credentials.auth_req_id.clone(),
        }) {
            Ok(body) => Zeroizing::new(body),
            Err(_) => return Ok(dead("the notification could not be encoded")),
        };
        let bearer = Zeroizing::new(format!("Bearer {}", credentials.client_notification_token));
        let Ok(mut header) = HeaderValue::from_str(&bearer) else {
            return Ok(dead("the stored notification token is not a valid header"));
        };
        header.set_sensitive(true);

        self.ping(&endpoint, &body, header).await
    }

    /// The one HTTP exchange, through the shared guard and nothing else.
    async fn ping(
        &self,
        endpoint: &str,
        body: &str,
        authorization: HeaderValue,
    ) -> Result<DeliveryOutcome, OutboundError> {
        // One guarded hop that returns a redirect instead of following it: the
        // bearer token cannot reach a host the client did not register.
        let response =
            match guarded_fetch_no_redirect(endpoint, self.allow_private, |client, target| {
                client
                    .post(target)
                    .header(CONTENT_TYPE, "application/json")
                    .header(AUTHORIZATION, authorization.clone())
                    .body(body.to_owned())
            })
            .await
            {
                Ok(response) => response,
                Err(error) => return Ok(classify_transport(&error)),
            };

        let status = response.status().as_u16();
        Ok(match status {
            200..=299 => DeliveryOutcome::Delivered {
                response_status: Some(status),
            },
            // A 3xx is never followed, and is a retry: the client may fix the
            // endpoint it registered.
            300..=399 => retry("the client answered with a redirect, which is not followed"),
            408 | 429 | 500..=599 => retry(&format!("the client answered HTTP {status}")),
            // Any other 4xx will not change on retry: the endpoint or the token
            // is wrong until somebody fixes it.
            400..=499 => dead(&format!("HTTP {status}")),
            // Anything else (1xx, an unassigned code) retries.
            _ => retry(&format!("the client answered an unexpected HTTP {status}")),
        })
    }
}

impl<R, C> OutboundDeliverer for CibaPingDeliverer<R, C>
where
    R: CibaRequestRepository + 'static,
    C: OAuth2ClientRepository + 'static,
{
    fn kind(&self) -> OutboundKind {
        OutboundKind::CibaPing
    }

    fn deliver_attempt<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
        Box::pin(self.attempt(msg))
    }
}

/// The enqueue half: what [`crate::ciba::CibaService`] holds to queue a ping
/// once a request is decided.
pub type PingPublisher = Arc<dyn axiam_core::outbound::OutboundPublisher>;

fn dead(reason: &str) -> DeliveryOutcome {
    DeliveryOutcome::DeadLetter {
        reason: reason.to_owned(),
    }
}

fn retry(reason: &str) -> DeliveryOutcome {
    DeliveryOutcome::Retry {
        reason: reason.to_owned(),
    }
}

/// The audit-safe reading of a guard error: a fixed phrase, never the error's
/// own text (a transport error names the URL it was fetching).
fn classify_transport(error: &SsrfError) -> DeliveryOutcome {
    match error {
        SsrfError::Blocked => {
            retry("the notification endpoint resolves to an address AXIAM does not connect to")
        }
        SsrfError::ResolveFailed => retry("the notification endpoint's host did not resolve"),
        SsrfError::InsecureScheme => dead("the notification endpoint is not https"),
        SsrfError::InvalidUrl => dead("the notification endpoint is not a valid URL"),
        SsrfError::TooManyRedirects => retry("the client redirected too often"),
        SsrfError::ResponseTooLarge(_) => retry("the client's response was too large"),
        SsrfError::ClientBuildFailed => retry("the HTTP client could not be built"),
        SsrfError::RequestFailed(_) => {
            retry("the client could not be reached or did not answer in time")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_queued_message_holds_a_record_id_and_a_tenant_and_nothing_else() {
        let tenant = Uuid::new_v4();
        let request = Uuid::new_v4();
        let msg = ping_message(tenant, request);
        assert_eq!(msg.kind, OutboundKind::CibaPing);
        assert_eq!(msg.tenant_id, tenant);
        assert_eq!(msg.target_id, request);
        assert_eq!(msg.attempt, 0);
        assert!(msg.payload.is_null());
        let wire = serde_json::to_string(&msg).unwrap();
        assert!(!wire.contains("auth_req_id") && !wire.contains("token"));
        // A fresh delivery id each time, so a retry of the message is one
        // delivery and two requests are two.
        assert_ne!(ping_message(tenant, request).delivery_id, msg.delivery_id);
    }

    #[test]
    fn a_transport_reason_never_carries_the_error_text() {
        let url = "https://rp.example.test/notify?token=abc";
        for error in [
            SsrfError::RequestFailed(format!("error sending request for url ({url})")),
            SsrfError::Blocked,
            SsrfError::ResolveFailed,
            SsrfError::TooManyRedirects,
            SsrfError::ResponseTooLarge(1),
            SsrfError::ClientBuildFailed,
            SsrfError::InsecureScheme,
            SsrfError::InvalidUrl,
        ] {
            let reason = match classify_transport(&error) {
                DeliveryOutcome::Retry { reason } | DeliveryOutcome::DeadLetter { reason } => {
                    reason
                }
                other => panic!("a transport failure is never {other:?}"),
            };
            assert!(!reason.contains("rp.example.test") && !reason.contains("token"));
        }
    }

    /// The deliverer's only way out is the shared guard, with the private-network
    /// admission off. Pinned against the source so that a second HTTP client
    /// cannot be added beside it without this test saying so (T-433).
    #[test]
    fn the_ping_goes_through_the_no_redirect_guarded_fetch_and_nothing_else() {
        let source = include_str!("ciba_ping.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the production half of the file");
        assert_eq!(production.matches("guarded_fetch_no_redirect(").count(), 1);
        assert_eq!(production.matches("guarded_fetch(").count(), 0);
        assert_eq!(
            production
                .matches("guarded_fetch_no_redirect(endpoint, self.allow_private")
                .count(),
            1
        );
        for forbidden in [
            "reqwest::Client",
            "Client::new",
            "Client::builder",
            "reqwest::get",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }
        // The flag starts false and only the hidden test seam sets it.
        assert_eq!(production.matches("allow_private: false").count(), 1);
        assert_eq!(production.matches("self.allow_private = true").count(), 1);
    }
}
