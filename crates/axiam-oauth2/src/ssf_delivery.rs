//! Shared Signals Framework delivery: the push deliverer (RFC 8935) and the
//! outbox that routes a produced event (G-5, T23.5.3, D-36, D-48, D-49, D-51).
//!
//! Two pieces, one on each side of the shared outbound dispatcher:
//!
//! * [`SsfOutboxService`] implements the core [`SsfOutbox`] port **producers**
//!   call: an enabled push stream's event becomes one
//!   [`OutboundKind::SsfPush`] message on the dispatcher; an enabled poll
//!   stream's, and any paused stream's, goes to the stream's bounded buffer; a
//!   disabled stream's is refused ([`SsfOutboxError::Disabled`]).
//! * [`SsfPushDeliverer`] implements the core [`OutboundDeliverer`] port the
//!   dispatcher's consumer calls: **one attempt** to push one event.
//!
//! The retry schedule, the attempt counter, the dead-letter queue and the
//! audit rows (`ssf_push.delivery_succeeded`, `.delivery_attempt`,
//! `.delivery_failed`) are the dispatcher's. A deliverer classifies; it does
//! not decide.
//!
//! # What one attempt does
//!
//! The queued message holds the **unsigned** event (D-48), so the attempt
//! starts by reading the stream *as it is now* and signs only against that
//! (D-51):
//!
//! | The stream, at the attempt | Outcome |
//! |---|---|
//! | gone | dead-letter |
//! | `disabled` | dead-letter — nothing is signed or sent |
//! | `paused`, or now a poll stream | the event goes to the buffer; the message is acknowledged |
//! | `enabled`, event no longer carried | dead-letter |
//! | `enabled` | sign with [`sign_set`], then push |
//!
//! The one exception is a **stream-updated** announcement (SSF §8.1.5), whose
//! whole point is to follow a status change: it is not refused for the status
//! it announces, and [`sign_set`] signs it only while that is still the
//! stream's status.
//!
//! # The push (D-49)
//!
//! `POST` of the compact SET, `Content-Type: application/secevent+jwt`,
//! `Accept: application/json`, the stored `Authorization` header (opened by
//! `decrypt_authorization_header`, held in `Zeroizing` and marked sensitive on
//! the request), ten seconds, **no redirect followed**, a response body read
//! to at most 64 KiB and never logged.
//!
//! **The only way out of the process is `guarded_fetch_no_redirect` with
//! `allow_private = false`** (`axiam_pki::ssrf`, D-53 (9)): the name is resolved
//! fresh, every address must be globally routable, the validated address is
//! pinned into the connection, and `https` is required. A name an administrator
//! registered that resolves to an internal address is refused here, at delivery,
//! which is what the write-time policy cannot catch (T-392). The fetch makes
//! **one hop and returns a `3xx` as a response**: a redirect is never followed,
//! so neither the SET nor the credential can reach a host the administrator
//! never named — by construction, not by inspecting a later hop.
//!
//! | The receiver answers | Outcome |
//! |---|---|
//! | any `2xx` (RFC 8935: `202`) | delivered |
//! | `400` with an RFC 8935 `err` | dead-letter, the code in the audit row |
//! | `401`, `403` | dead-letter: the credential is wrong until someone fixes it |
//! | `404`, `408`, `429`, `5xx`, a timeout, no connection | retry |
//! | a `3xx` | retry; it is never followed |
//! | any other `4xx` (a `400` without a known code, `410`, `422` …) | dead-letter, reason `HTTP <status>`: it will not change on retry (D-53 (8)) |
//! | anything else | retry |
//!
//! A reason string reaches the audit log, so it is one of a fixed vocabulary:
//! never a header, a URL, a response body or a transport error's text (which
//! would carry the endpoint's URL).

use std::sync::Arc;

use axiam_auth::config::AuthConfig;
use axiam_core::error::AxiamError;
use axiam_core::models::ssf::{
    STREAM_UPDATED_EVENT_URI, SsfDeliveryMethod, SsfFuture, SsfOutbox, SsfOutboxError,
    SsfPendingEvent, SsfStream, SsfStreamStatus,
};
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
    OutboundMessage, OutboundPublisher,
};
use axiam_core::repository::{SsfEventBufferRepository, SsfStreamRepository};
use axiam_federation::ssrf::{SsrfError, guarded_fetch_no_redirect, read_capped_body};
use chrono::Utc;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};

use crate::ssf::{SsfError, delivery_id_of, sign_set};

/// RFC 8935 §2: the media type of a pushed SET.
pub const SET_CONTENT_TYPE: &str = "application/secevent+jwt";

/// The most of a receiver's response body that is read (D-49).
pub const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// The `err` codes of RFC 8935 §2.4. Only these are ever copied into an audit
/// row; any other value a receiver sends is not a code.
pub const RFC_8935_ERROR_CODES: [&str; 6] = [
    "invalid_request",
    "invalid_key",
    "invalid_issuer",
    "invalid_audience",
    "authentication_failed",
    "access_denied",
];

/// The longest drain of a held backlog in one [`SsfOutbox::resume`]: ten
/// batches of 100, one more than the buffer's bound (1 000) can fill.
const RESUME_BATCH: usize = 100;
const RESUME_MAX_BATCHES: usize = 11;

// ---------------------------------------------------------------------------
// The outbox
// ---------------------------------------------------------------------------

/// The [`SsfOutbox`] a deployment runs: routes by the stream's status and
/// method (D-48, D-51).
///
/// | Status | Method | |
/// |---|---|---|
/// | `enabled` | push | one [`OutboundKind::SsfPush`] message, unsigned event as payload |
/// | `enabled` | poll | the stream's buffer |
/// | `paused` | either | the stream's buffer (held) |
/// | `disabled` | either | [`SsfOutboxError::Disabled`]; nothing is kept |
///
/// A stream-updated announcement of a push stream is the exception to the last
/// two rows: it is enqueued whatever the status it announces, since telling the
/// receiver of a pause or a disable is the event's job and [`sign_set`] will
/// sign it only while it is true.
pub struct SsfOutboxService<B> {
    buffer: B,
    publisher: Arc<dyn OutboundPublisher>,
}

impl<B: SsfEventBufferRepository + 'static> SsfOutboxService<B> {
    /// An outbox over `buffer` and the dispatcher's publisher.
    pub fn new(buffer: B, publisher: Arc<dyn OutboundPublisher>) -> Self {
        Self { buffer, publisher }
    }

    fn message(
        stream: &SsfStream,
        event: &SsfPendingEvent,
    ) -> Result<OutboundMessage, SsfOutboxError> {
        let delivery_id = delivery_id_of(event)
            .ok_or_else(|| SsfOutboxError::Failed("the event has no valid jti".into()))?;
        let payload = serde_json::to_value(event)
            .map_err(|_| SsfOutboxError::Failed("the event could not be encoded".into()))?;
        Ok(OutboundMessage {
            kind: OutboundKind::SsfPush,
            tenant_id: stream.tenant_id,
            target_id: stream.id,
            delivery_id,
            event_type: event.event_uri.clone(),
            payload,
            attempt: 0,
        })
    }

    async fn enqueue(
        &self,
        stream: &SsfStream,
        event: &SsfPendingEvent,
    ) -> Result<(), SsfOutboxError> {
        let message = Self::message(stream, event)?;
        self.publisher.enqueue(&message).await.map_err(|error| {
            tracing::warn!(
                target: "axiam::ssf",
                tenant_id = %stream.tenant_id,
                stream_id = %stream.id,
                %error,
                "an SSF push could not be enqueued"
            );
            SsfOutboxError::Failed("the event could not be enqueued".into())
        })
    }

    async fn hold(
        &self,
        stream: &SsfStream,
        event: &SsfPendingEvent,
    ) -> Result<(), SsfOutboxError> {
        self.buffer
            .push(stream.tenant_id, stream.id, event, Utc::now())
            .await
            .map_err(|error| {
                tracing::warn!(
                    target: "axiam::ssf",
                    tenant_id = %stream.tenant_id,
                    stream_id = %stream.id,
                    %error,
                    "an SSF event could not be buffered"
                );
                SsfOutboxError::Failed("the event could not be buffered".into())
            })
    }
}

impl<B: SsfEventBufferRepository + 'static> SsfOutbox for SsfOutboxService<B> {
    fn submit<'a>(
        &'a self,
        stream: &'a SsfStream,
        event: &'a SsfPendingEvent,
    ) -> SsfFuture<'a, Result<(), SsfOutboxError>> {
        Box::pin(async move {
            let announcement = event.event_uri == STREAM_UPDATED_EVENT_URI;
            match (stream.status, stream.delivery_method) {
                // The announcement of the change itself: it is what tells the
                // receiver, so it goes out whatever the new status is.
                (_, SsfDeliveryMethod::Push) if announcement => self.enqueue(stream, event).await,
                (SsfStreamStatus::Disabled, _) => Err(SsfOutboxError::Disabled),
                (SsfStreamStatus::Paused, _) => self.hold(stream, event).await,
                (SsfStreamStatus::Enabled, SsfDeliveryMethod::Push) => {
                    self.enqueue(stream, event).await
                }
                (SsfStreamStatus::Enabled, SsfDeliveryMethod::Poll) => {
                    self.hold(stream, event).await
                }
            }
        })
    }

    fn resume<'a>(&'a self, stream: &'a SsfStream) -> SsfFuture<'a, Result<usize, SsfOutboxError>> {
        Box::pin(async move {
            if stream.delivery_method != SsfDeliveryMethod::Push
                || stream.status != SsfStreamStatus::Enabled
            {
                return Ok(0);
            }
            let mut released = 0usize;
            for _ in 0..RESUME_MAX_BATCHES {
                let batch = self
                    .buffer
                    .list_oldest(stream.tenant_id, stream.id, RESUME_BATCH, Utc::now())
                    .await
                    .map_err(|_| {
                        SsfOutboxError::Failed("the held events could not be read".into())
                    })?;
                if batch.is_empty() {
                    break;
                }
                // Oldest first, and a row is removed only once its message is
                // durably queued: a failure part-way leaves the rest held, and
                // a crash between the two repeats one event, which carries one
                // `jti` the receiver de-duplicates.
                let mut done = Vec::with_capacity(batch.len());
                let mut failure = None;
                for event in &batch {
                    match self.enqueue(stream, event).await {
                        Ok(()) => done.push(event.jti.clone()),
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    }
                }
                released += done.len();
                self.buffer
                    .delete_by_jti(stream.tenant_id, stream.id, &done)
                    .await
                    .map_err(|_| {
                        SsfOutboxError::Failed("the released events could not be removed".into())
                    })?;
                if let Some(error) = failure {
                    return Err(error);
                }
            }
            Ok(released)
        })
    }
}

// ---------------------------------------------------------------------------
// The push deliverer
// ---------------------------------------------------------------------------

/// The [`OutboundDeliverer`] of [`OutboundKind::SsfPush`]: one RFC 8935 push of
/// one event. See the module documentation for the whole contract.
pub struct SsfPushDeliverer<S, B> {
    streams: S,
    buffer: B,
    auth_config: AuthConfig,
    /// The guarded fetch's `allow_private`. **Always `false`** except for the
    /// integration tests' loopback receiver, which turn it on through
    /// [`Self::admitting_private_networks_for_tests`] and nothing else.
    allow_private: bool,
}

impl<S, B> SsfPushDeliverer<S, B>
where
    S: SsfStreamRepository + 'static,
    B: SsfEventBufferRepository + 'static,
{
    /// The production deliverer: every push goes through `guarded_fetch_no_redirect` with
    /// `allow_private = false`.
    pub fn new(streams: S, buffer: B, auth_config: AuthConfig) -> Self {
        Self {
            streams,
            buffer,
            auth_config,
            allow_private: false,
        }
    }

    /// **Test seam, never used by the composition root.** Lets the first hop
    /// reach a loopback receiver over plain `http`, the way
    /// `JwksCache::new_allow_private_networks` and the CIMD policy do for their
    /// tests. A deliverer built by [`Self::new`] cannot be switched afterwards
    /// by anything but this call, and production never makes it.
    #[doc(hidden)]
    #[must_use]
    pub fn admitting_private_networks_for_tests(mut self) -> Self {
        self.allow_private = true;
        self
    }

    async fn attempt(&self, msg: &OutboundMessage) -> Result<DeliveryOutcome, OutboundError> {
        if msg.kind != OutboundKind::SsfPush {
            return Ok(dead("the message is not an SSF push"));
        }
        let Ok(pending) = serde_json::from_value::<SsfPendingEvent>(msg.payload.clone()) else {
            return Ok(dead("the queued event is malformed"));
        };
        if delivery_id_of(&pending) != Some(msg.delivery_id) {
            return Ok(dead("the queued event does not match its delivery id"));
        }

        // The stream as it is now (D-48, D-51).
        let stream = match self.streams.get(msg.tenant_id, msg.target_id).await {
            Ok(stream) => stream,
            Err(AxiamError::NotFound { .. }) => return Ok(dead("the stream no longer exists")),
            Err(_) => {
                return Err(OutboundError::Delivery(
                    "the stream could not be read".into(),
                ));
            }
        };

        let announcement = pending.event_uri == STREAM_UPDATED_EVENT_URI;
        if !announcement {
            match stream.status {
                SsfStreamStatus::Disabled => return Ok(dead("the stream is disabled")),
                SsfStreamStatus::Paused => return self.hold(&stream, &pending).await,
                SsfStreamStatus::Enabled => {}
            }
        }
        if stream.delivery_method != SsfDeliveryMethod::Push {
            // The stream became a poll stream while the message was queued.
            if stream.status == SsfStreamStatus::Disabled {
                return Ok(dead("the stream is disabled"));
            }
            return self.hold(&stream, &pending).await;
        }

        // Signed against the stream as it is *now*, or not at all.
        let set = match sign_set(&self.auth_config, &stream, &pending) {
            Ok(set) => zeroize::Zeroizing::new(set),
            Err(SsfError::Signing(_)) => {
                return Err(OutboundError::Delivery(
                    "the SET could not be signed".into(),
                ));
            }
            Err(_) => return Ok(dead("the stream no longer carries this event")),
        };
        let Some(endpoint) = stream.endpoint_url.clone() else {
            return Ok(dead("the push stream has no endpoint"));
        };
        let authorization = match self
            .streams
            .decrypt_authorization_header(msg.tenant_id, msg.target_id)
            .await
        {
            Ok(value) => value,
            Err(AxiamError::NotFound { .. }) => return Ok(dead("the stream no longer exists")),
            Err(_) => {
                return Err(OutboundError::Delivery(
                    "the stream's push credential could not be opened".into(),
                ));
            }
        };
        let authorization = match authorization {
            None => None,
            Some(value) => match HeaderValue::from_str(&value) {
                Ok(mut header) => {
                    header.set_sensitive(true);
                    Some(header)
                }
                Err(_) => return Ok(dead("the stored push credential is not a valid header")),
            },
        };

        self.push(&endpoint, &set, authorization).await
    }

    async fn hold(
        &self,
        stream: &SsfStream,
        pending: &SsfPendingEvent,
    ) -> Result<DeliveryOutcome, OutboundError> {
        self.buffer
            .push(stream.tenant_id, stream.id, pending, Utc::now())
            .await
            .map_err(|_| OutboundError::Delivery("the event could not be buffered".into()))?;
        Ok(DeliveryOutcome::Delivered {
            response_status: None,
        })
    }

    /// The one HTTP exchange, through the shared guard and nothing else.
    async fn push(
        &self,
        endpoint: &str,
        set: &str,
        authorization: Option<HeaderValue>,
    ) -> Result<DeliveryOutcome, OutboundError> {
        // One guarded hop that returns a redirect instead of following it
        // (D-53 (9)): neither the SET nor the credential can reach a host the
        // administrator did not name, by construction.
        let response =
            match guarded_fetch_no_redirect(endpoint, self.allow_private, |client, target| {
                let mut request = client
                    .post(target)
                    .header(CONTENT_TYPE, SET_CONTENT_TYPE)
                    .header(ACCEPT, "application/json")
                    .body(set.to_owned());
                if let Some(value) = &authorization {
                    request = request.header(AUTHORIZATION, value.clone());
                }
                request
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
            // A 3xx is never followed, and is a retry: the administrator may
            // fix the endpoint.
            300..=399 => retry("the receiver answered with a redirect, which is not followed"),
            400 => match read_capped_body(response, MAX_RESPONSE_BODY_BYTES)
                .await
                .ok()
                .as_deref()
                .and_then(rfc_8935_error)
            {
                Some(code) => dead(&format!("the receiver rejected the SET: {code}")),
                // A 400 without a known code will not change on retry either.
                None => dead("HTTP 400"),
            },
            // The one 4xx that says the credential is wrong until someone fixes it.
            401 | 403 => dead(&format!(
                "the receiver refused the push credential (HTTP {status})"
            )),
            404 | 408 | 429 | 500..=599 => retry(&format!("the receiver answered HTTP {status}")),
            // Any other 4xx will not change on retry (D-53 (8)).
            400..=499 => dead(&format!("HTTP {status}")),
            // Anything else (1xx, an unassigned code) retries.
            _ => retry(&format!(
                "the receiver answered an unexpected HTTP {status}"
            )),
        })
    }
}

impl<S, B> OutboundDeliverer for SsfPushDeliverer<S, B>
where
    S: SsfStreamRepository + 'static,
    B: SsfEventBufferRepository + 'static,
{
    fn kind(&self) -> OutboundKind {
        OutboundKind::SsfPush
    }

    fn deliver_attempt<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
        Box::pin(self.attempt(msg))
    }
}

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
            retry("the push endpoint resolves to an address AXIAM does not connect to")
        }
        SsrfError::ResolveFailed => retry("the push endpoint's host did not resolve"),
        SsrfError::InsecureScheme => dead("the push endpoint is not https"),
        SsrfError::InvalidUrl => dead("the push endpoint is not a valid URL"),
        SsrfError::TooManyRedirects => retry("the receiver redirected too often"),
        SsrfError::ResponseTooLarge(_) => retry("the receiver's response was too large"),
        SsrfError::ClientBuildFailed => retry("the HTTP client could not be built"),
        SsrfError::RequestFailed(_) => {
            retry("the receiver could not be reached or did not answer in time")
        }
    }
}

/// The RFC 8935 §2.4 error code in a `400` body, if it names one.
fn rfc_8935_error(body: &[u8]) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let code = value.get("err")?.as_str()?;
    RFC_8935_ERROR_CODES
        .into_iter()
        .find(|known| *known == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_rfc_8935_code_is_read_from_a_400_body() {
        for code in RFC_8935_ERROR_CODES {
            let body = serde_json::json!({ "err": code, "description": "free text" }).to_string();
            assert_eq!(rfc_8935_error(body.as_bytes()), Some(code));
        }
        for body in [
            r#"{"err":"something_else"}"#,
            r#"{"err":7}"#,
            r#"{"error":"invalid_key"}"#,
            r#"[]"#,
            r#"not json"#,
            r#""#,
        ] {
            assert_eq!(rfc_8935_error(body.as_bytes()), None, "{body}");
        }
    }

    #[test]
    fn a_transport_reason_never_carries_the_error_text() {
        let url = "https://rp.example.test/hook?token=abc";
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
    /// cannot be added beside it without this test saying so.
    #[test]
    fn push_goes_through_the_no_redirect_guarded_fetch_and_nothing_else() {
        let source = include_str!("ssf_delivery.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the production half of the file");
        // One call, of the variant that returns a redirect; the following
        // `guarded_fetch` is not used at all.
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
