//! AMQP consumer for async authorization requests.

use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::error::AxiamError;
use axiam_core::repository::{
    AmqpNonceRepository, GroupRepository, PermissionRepository, ResourceRepository, RoleRepository,
    ScopeRepository,
};
use chrono::Utc;
use futures_lite::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Confirmation};
use tracing::{error, info, warn};

use crate::connection::queues;
use crate::messages::{
    AuthzRequest, AuthzResponse, MIN_ACCEPTED_KEY_VERSION, is_fresh, verify_tenant_signature,
};

/// Outcome of processing a single AMQP authorization-request delivery.
///
/// This is the return type of the broker-free [`process_authz_request`] seam:
/// the pure decode/verify/replay/evaluate logic decides what should happen to
/// the delivery, and the thin consumer loop translates that decision into
/// channel I/O (publish + ack/nack). Keeping the decision separate from the
/// `lapin::Channel`/`Acker` I/O makes every rejection and evaluation branch
/// unit-testable without a live RabbitMQ broker.
#[derive(Debug)]
pub enum AuthzOutcome {
    /// The delivery must be rejected with `nack(requeue: false)` — malformed
    /// payload, unsigned/invalid signature, key_version below the minimum,
    /// stale/future `issued_at`, a replayed nonce, a nonce-store error, or a
    /// (practically unreachable) response-serialization failure. Every one of
    /// these mapped to the same `requeue: false` nack in the original loop, so
    /// they collapse to a single outcome here without changing behavior.
    NackDrop,
    /// The request was accepted and evaluated; the caller must publish this
    /// serialized [`AuthzResponse`] payload to `axiam.authz.response`, then ack
    /// the original delivery once the broker confirms the publish.
    Publish(Vec<u8>),
}

/// Decode, verify, replay-check, and evaluate a single serialized
/// [`AuthzRequest`], returning the [`AuthzOutcome`] the consumer loop should
/// enact. This is a behavior-preserving extraction of the per-message body of
/// [`start_authz_consumer`]'s `while let` loop — the loop now only performs
/// channel I/O (consume, publish, ack/nack) around this function.
///
/// `now` is injected (the loop passes `Utc::now()`) so the NEW-4 freshness gate
/// is deterministically testable. All rejection paths return
/// [`AuthzOutcome::NackDrop`], matching the original `nack(requeue: false)`
/// (and the two `nack(BasicNackOptions::default())`, whose `requeue` also
/// defaults to `false`) branches exactly.
pub async fn process_authz_request<R, P, Res, S, G, N>(
    raw: &[u8],
    engine: &AuthorizationEngine<R, P, Res, S, G>,
    master_signing_key: &[u8],
    nonce_repo: &N,
    replay_skew: chrono::Duration,
    now: chrono::DateTime<Utc>,
) -> AuthzOutcome
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
    N: AmqpNonceRepository,
{
    // Deserialize request. Bad payload → nack requeue:false (not re-deliverable).
    let mut request: AuthzRequest = match serde_json::from_slice(raw) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Invalid authz request payload, nacking");
            return AuthzOutcome::NackDrop;
        }
    };

    // SEC-022/SECHRD-08: Verify the per-tenant derived HMAC signature.
    // Unsigned or invalid-signature messages are always rejected —
    // there is no fail-open path (D-05c, T-25-20).
    // Extract the signature before building the canonical form (signature = None).
    let received_sig = request.hmac_signature.take();
    let tenant_id = request.tenant_id;
    let key_version = request.key_version;

    // Canonical payload has hmac_signature = None to reproduce what was signed.
    let canonical_bytes = serde_json::to_vec(&request).unwrap_or_else(|_| raw.to_vec());

    let valid = verify_tenant_signature(
        master_signing_key,
        tenant_id,
        key_version,
        &canonical_bytes,
        received_sig.as_deref(),
    );

    if !valid {
        warn!(
            tenant_id = %tenant_id,
            "AuthzRequest unsigned or HMAC verification failed — rejecting (SEC-022/SECHRD-08)"
        );
        return AuthzOutcome::NackDrop;
    }

    // NEW-4 (hard cutover): reject pre-v2 messages that predate the
    // mandatory nonce/issued_at replay-protection fields.
    if key_version < MIN_ACCEPTED_KEY_VERSION {
        warn!(
            tenant_id = %tenant_id,
            key_version,
            "AuthzRequest key_version below minimum — rejecting (NEW-4 replay protection)"
        );
        return AuthzOutcome::NackDrop;
    }

    // NEW-4: reject stale/future messages outside the freshness window.
    if !is_fresh(request.issued_at, now, replay_skew) {
        warn!(
            tenant_id = %tenant_id,
            issued_at = %request.issued_at,
            "AuthzRequest issued_at outside freshness window — rejecting (NEW-4)"
        );
        return AuthzOutcome::NackDrop;
    }

    // NEW-4: durable nonce dedup. Insert-or-conflict; a ReplayDetected
    // conflict means this exact signed message was already consumed. The
    // nonce only needs to outlive the freshness window (issued_at + skew).
    let nonce_expires_at = request.issued_at + replay_skew;
    match nonce_repo
        .insert_nonce(tenant_id, request.nonce, nonce_expires_at)
        .await
    {
        Ok(()) => {}
        Err(AxiamError::ReplayDetected) => {
            warn!(
                tenant_id = %tenant_id,
                nonce = %request.nonce,
                "AuthzRequest nonce replay detected — rejecting (NEW-4)"
            );
            return AuthzOutcome::NackDrop;
        }
        Err(e) => {
            error!(
                error = %e,
                tenant_id = %tenant_id,
                "Failed to record AuthzRequest nonce — rejecting (dead-letter, NEW-4)"
            );
            return AuthzOutcome::NackDrop;
        }
    }

    let correlation_id = request.correlation_id;

    // Build access request and evaluate.
    let access_request = AccessRequest {
        tenant_id: request.tenant_id,
        subject_id: request.subject_id,
        action: request.action,
        resource_id: request.resource_id,
        scope: request.scope,
    };

    let response = match engine.check_access(&access_request).await {
        Ok(AccessDecision::Allow) => AuthzResponse {
            correlation_id,
            allowed: true,
            reason: None,
        },
        Ok(AccessDecision::Deny(reason)) => AuthzResponse {
            correlation_id,
            allowed: false,
            reason: Some(reason),
        },
        Err(e) => {
            error!(
                error = %e,
                correlation_id = %correlation_id,
                "Authorization engine error"
            );
            AuthzResponse {
                correlation_id,
                allowed: false,
                reason: Some("internal error".to_string()),
            }
        }
    };

    // Serialize response. (Serializing an AuthzResponse is effectively
    // infallible; a failure maps to the same requeue:false nack as before.)
    match serde_json::to_vec(&response) {
        Ok(p) => AuthzOutcome::Publish(p),
        Err(e) => {
            error!(error = %e, "Failed to serialize authz response");
            AuthzOutcome::NackDrop
        }
    }
}

/// Start consuming authorization requests from the `axiam.authz.request` queue.
///
/// Each message is deserialized, evaluated through the authorization engine,
/// and the result is published to `axiam.authz.response`. Messages are
/// acknowledged on success or nacked on failure.
///
/// SEC-022/SECHRD-08: Every `AuthzRequest` is verified before processing —
/// the per-tenant subkey is derived from `master_signing_key` + the
/// message's `tenant_id` + `key_version`, then the `hmac_signature` is
/// checked against it. Messages with an invalid or missing signature are
/// nacked and never processed; there is no fail-open path (D-05c).
///
/// NEW-4 (hard cutover): after a valid signature, the message is additionally
/// rejected (nack, requeue:false) when its `key_version` is below
/// [`MIN_ACCEPTED_KEY_VERSION`], its `issued_at` is outside the ±`replay_skew`
/// freshness window, or its `nonce` has already been consumed (a duplicate in
/// the durable `nonce_repo` store is a replay). There is no v1 grace path.
pub async fn start_authz_consumer<R, P, Res, S, G, N>(
    channel: Channel,
    engine: AuthorizationEngine<R, P, Res, S, G>,
    master_signing_key: Vec<u8>,
    nonce_repo: N,
    replay_skew: chrono::Duration,
) where
    R: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
    N: AmqpNonceRepository + 'static,
{
    info!("Starting authorization AMQP consumer");

    let mut consumer = match channel
        .basic_consume(
            queues::AUTHZ_REQUEST.into(),
            "axiam-authz-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to start authz consumer");
            return;
        }
    };

    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "Error receiving AMQP delivery");
                continue;
            }
        };

        let tag = delivery.delivery_tag;

        // Decode/verify/replay-check/evaluate off the channel (broker-free,
        // unit-tested via `process_authz_request`). The loop only translates
        // the returned outcome into channel I/O below.
        let payload = match process_authz_request(
            &delivery.data,
            &engine,
            &master_signing_key,
            &nonce_repo,
            replay_skew,
            Utc::now(),
        )
        .await
        {
            AuthzOutcome::Publish(payload) => payload,
            AuthzOutcome::NackDrop => {
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                continue;
            }
        };

        let confirm = match channel
            .basic_publish(
                "".into(),
                queues::AUTHZ_RESPONSE.into(),
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await
        {
            Ok(confirm) => confirm,
            Err(e) => {
                error!(
                    error = %e,
                    delivery_tag = tag,
                    "Failed to publish authz response"
                );
                let _ = delivery.acker.nack(BasicNackOptions::default()).await;
                continue;
            }
        };

        let confirmed = match confirm.await {
            Ok(Confirmation::Nack(_)) => {
                warn!(
                    delivery_tag = tag,
                    "Authz response publish was nacked by broker"
                );
                false
            }
            Err(e) => {
                error!(
                    error = %e,
                    delivery_tag = tag,
                    "Authz response publish not confirmed by broker"
                );
                false
            }
            Ok(_) => true,
        };

        if confirmed {
            if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
                error!(error = %e, delivery_tag = tag, "Failed to ack delivery");
            }
        } else {
            // requeue: false — dead-letter the poison message instead of
            // hot-looping (CQ-B05 / REQ-14 AC-5).
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
        }
    }

    warn!("Authorization AMQP consumer stream ended");
}
