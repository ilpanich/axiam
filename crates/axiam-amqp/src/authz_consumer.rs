//! AMQP consumer for async authorization requests.

use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
};
use futures_lite::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel};
use tracing::{error, info, warn};

use crate::connection::queues;
use crate::messages::{AuthzRequest, AuthzResponse};

/// Start consuming authorization requests from the `axiam.authz.request` queue.
///
/// Each message is deserialized, evaluated through the authorization engine,
/// and the result is published to `axiam.authz.response`. Messages are
/// acknowledged on success or nacked on failure.
pub async fn start_authz_consumer<R, P, Res, S, G>(
    channel: Channel,
    engine: AuthorizationEngine<R, P, Res, S, G>,
) where
    R: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
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
        let request: AuthzRequest = match serde_json::from_slice(&delivery.data) {
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
                    reason: Some(format!("internal error: {e}")),
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

        if let Err(e) = channel
            .basic_publish(
                "".into(),
                queues::AUTHZ_RESPONSE.into(),
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default().with_content_type("application/json".into()),
            )
            .await
        {
            error!(
                error = %e,
                correlation_id = %correlation_id,
                "Failed to publish authz response"
            );
            let _ = delivery.acker.nack(BasicNackOptions::default()).await;
            continue;
        }

        if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
            error!(error = %e, delivery_tag = tag, "Failed to ack delivery");
        }
    }

    warn!("Authorization AMQP consumer stream ended");
}
