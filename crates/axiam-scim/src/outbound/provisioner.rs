//! The provisioning **source**: [`ScimProvisioner`] turns a repository's
//! committed-change report into one reference per enabled target (D-57).
//!
//! What travels is `{resource_type, axiam_id}` and nothing else. The deliverer
//! computes what to send from the data as it is at the attempt, so a queued
//! message — or a dead-lettered one, which lives for seven days — names a
//! resource by id and tells nobody anything about the person.

use std::sync::Arc;

use axiam_core::models::scim_target::{ScimResourceType, ScimTarget, ScimTargetScope};
use axiam_core::outbound::{OutboundKind, OutboundMessage, OutboundPublisher};
use axiam_core::provisioning::{ProvisioningFuture, ProvisioningSink};
use axiam_core::repository::ScimTargetRepository;
use serde_json::json;
use uuid::Uuid;

/// The `event_type` of a user reference.
pub const USER_EVENT_TYPE: &str = "scim.user";
/// The `event_type` of a group reference.
pub const GROUP_EVENT_TYPE: &str = "scim.group";

/// The message that tells a target's deliverer to re-sync one resource.
///
/// A fresh `delivery_id` per message; `attempt` is `0`, as for every producer
/// of the dispatcher (the consumer loop owns the counter).
#[must_use]
pub fn reference_message(
    tenant_id: Uuid,
    target_id: Uuid,
    resource_type: ScimResourceType,
    axiam_id: Uuid,
) -> OutboundMessage {
    OutboundMessage {
        kind: OutboundKind::ScimPush,
        tenant_id,
        target_id,
        delivery_id: Uuid::new_v4(),
        event_type: match resource_type {
            ScimResourceType::User => USER_EVENT_TYPE,
            ScimResourceType::Group => GROUP_EVENT_TYPE,
        }
        .to_owned(),
        payload: json!({
            "resource_type": resource_type.as_str(),
            "axiam_id": axiam_id.to_string(),
        }),
        attempt: 0,
    }
}

/// Whether `target` pushes `group_id`: `push_groups` is on, and the group is in
/// scope (every group for `all_users`, the listed ones otherwise — D-57).
#[must_use]
pub fn group_in_scope(target: &ScimTarget, group_id: Uuid) -> bool {
    target.push_groups
        && match &target.scope {
            ScimTargetScope::AllUsers => true,
            ScimTargetScope::Groups(listed) => listed.contains(&group_id),
        }
}

/// The [`ProvisioningSink`] a deployment binds: for each **enabled** target of
/// the tenant, one reference per affected resource on the shared outbound
/// dispatcher.
///
/// | Report | Enqueued, per enabled target |
/// |---|---|
/// | `user_changed` | the user |
/// | `group_changed` | the group, when the target pushes it (`push_groups`, in scope) |
/// | `membership_changed` | the user (its scope may have changed) and, when the target pushes it, the group |
///
/// A failure to list the targets or to enqueue is logged once per report and
/// never reaches the repository that reported: the write it follows has
/// committed, and the next change of the resource (or reconciliation) converges.
pub struct ScimProvisioner<T> {
    targets: T,
    publisher: Arc<dyn OutboundPublisher>,
}

impl<T: ScimTargetRepository + 'static> ScimProvisioner<T> {
    /// A provisioner over the target registry and the dispatcher's publisher.
    pub fn new(targets: T, publisher: Arc<dyn OutboundPublisher>) -> Self {
        Self { targets, publisher }
    }

    /// Enqueue `wanted(target)` for every enabled target of the tenant.
    async fn fan_out(
        &self,
        tenant_id: Uuid,
        wanted: impl Fn(&ScimTarget) -> Vec<(ScimResourceType, Uuid)>,
    ) {
        let targets = match self.targets.list_enabled(tenant_id).await {
            Ok(targets) => targets,
            Err(error) => {
                tracing::warn!(
                    target: "axiam::scim_push",
                    %tenant_id,
                    %error,
                    "the SCIM targets could not be listed; a provisioning change was not queued"
                );
                return;
            }
        };
        let mut failed = 0usize;
        for target in &targets {
            for (resource_type, axiam_id) in wanted(target) {
                let message = reference_message(tenant_id, target.id, resource_type, axiam_id);
                if self.publisher.enqueue(&message).await.is_err() {
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            // Once per report, not once per message: a broker outage must not
            // write a line for every target of every change.
            tracing::warn!(
                target: "axiam::scim_push",
                %tenant_id,
                failed,
                "SCIM provisioning references could not be enqueued"
            );
        }
    }
}

impl<T: ScimTargetRepository + 'static> ProvisioningSink for ScimProvisioner<T> {
    fn user_changed(&self, tenant_id: Uuid, user_id: Uuid) -> ProvisioningFuture<'_, ()> {
        Box::pin(async move {
            self.fan_out(tenant_id, |_| vec![(ScimResourceType::User, user_id)])
                .await;
        })
    }

    fn group_changed(&self, tenant_id: Uuid, group_id: Uuid) -> ProvisioningFuture<'_, ()> {
        Box::pin(async move {
            self.fan_out(tenant_id, |target| {
                if group_in_scope(target, group_id) {
                    vec![(ScimResourceType::Group, group_id)]
                } else {
                    Vec::new()
                }
            })
            .await;
        })
    }

    fn membership_changed(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> ProvisioningFuture<'_, ()> {
        Box::pin(async move {
            self.fan_out(tenant_id, |target| {
                let mut refs = vec![(ScimResourceType::User, user_id)];
                if group_in_scope(target, group_id) {
                    refs.push((ScimResourceType::Group, group_id));
                }
                refs
            })
            .await;
        })
    }
}
