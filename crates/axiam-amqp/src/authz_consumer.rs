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

        // Deserialize request.
        let mut request: AuthzRequest = match serde_json::from_slice(&delivery.data) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    error = %e,
                    delivery_tag = tag,
                    "Invalid authz request payload, nacking"
                );
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

        // SEC-022/SECHRD-08: Verify the per-tenant derived HMAC signature.
        // Unsigned or invalid-signature messages are always rejected —
        // there is no fail-open path (D-05c, T-25-20).
        // Extract the signature before building the canonical form (signature = None).
        let received_sig = request.hmac_signature.take();
        let tenant_id = request.tenant_id;
        let key_version = request.key_version;

        // Canonical payload has hmac_signature = None to reproduce what was signed.
        let canonical_bytes =
            serde_json::to_vec(&request).unwrap_or_else(|_| delivery.data.clone());

        let valid = verify_tenant_signature(
            &master_signing_key,
            tenant_id,
            key_version,
            &canonical_bytes,
            received_sig.as_deref(),
        );

        if !valid {
            warn!(
                delivery_tag = tag,
                tenant_id = %tenant_id,
                "AuthzRequest unsigned or HMAC verification failed — rejecting (SEC-022/SECHRD-08)"
            );
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            continue;
        }

        // NEW-4 (hard cutover): reject pre-v2 messages that predate the
        // mandatory nonce/issued_at replay-protection fields.
        if key_version < MIN_ACCEPTED_KEY_VERSION {
            warn!(
                delivery_tag = tag,
                tenant_id = %tenant_id,
                key_version,
                "AuthzRequest key_version below minimum — rejecting (NEW-4 replay protection)"
            );
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            continue;
        }

        // NEW-4: reject stale/future messages outside the freshness window.
        let now = Utc::now();
        if !is_fresh(request.issued_at, now, replay_skew) {
            warn!(
                delivery_tag = tag,
                tenant_id = %tenant_id,
                issued_at = %request.issued_at,
                "AuthzRequest issued_at outside freshness window — rejecting (NEW-4)"
            );
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            continue;
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
                    delivery_tag = tag,
                    tenant_id = %tenant_id,
                    nonce = %request.nonce,
                    "AuthzRequest nonce replay detected — rejecting (NEW-4)"
                );
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                continue;
            }
            Err(e) => {
                error!(
                    error = %e,
                    delivery_tag = tag,
                    tenant_id = %tenant_id,
                    "Failed to record AuthzRequest nonce — rejecting (dead-letter, NEW-4)"
                );
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                continue;
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

        // Publish response.
        let payload = match serde_json::to_vec(&response) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "Failed to serialize authz response");
                let _ = delivery.acker.nack(BasicNackOptions::default()).await;
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
                    correlation_id = %correlation_id,
                    "Failed to publish authz response"
                );
                let _ = delivery.acker.nack(BasicNackOptions::default()).await;
                continue;
            }
        };

        let confirmed = match confirm.await {
            Ok(Confirmation::Nack(_)) => {
                warn!(
                    correlation_id = %correlation_id,
                    "Authz response publish was nacked by broker"
                );
                false
            }
            Err(e) => {
                error!(
                    error = %e,
                    correlation_id = %correlation_id,
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
