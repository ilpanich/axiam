//! The provisioning **source** of outbound SCIM (T23.6.2, G-6, D-57): what
//! [`ScimProvisioner`] enqueues for each report a repository makes.
//!
//! The envelope is pinned here: kind, event type, a payload of `{resource_type,
//! axiam_id}` and nothing else, a fresh delivery id per message and `attempt`
//! zero (the consumer loop owns the counter).

mod support;

use std::sync::Arc;

use axiam_core::models::scim_target::{NewScimTarget, ScimResourceType, ScimTargetScope};
use axiam_core::outbound::{
    OutboundError, OutboundFuture, OutboundKind, OutboundMessage, OutboundPublisher,
};
use axiam_core::provisioning::ProvisioningSink;
use axiam_core::repository::ScimTargetRepository;
use axiam_scim::outbound::{ScimProvisioner, group_in_scope};
use serde_json::json;
use support::{Queue, World};
use uuid::Uuid;

fn refs(queue: &Queue) -> Vec<(Uuid, ScimResourceType, Uuid)> {
    queue
        .all()
        .into_iter()
        .map(|m| {
            let payload = m.payload.as_object().unwrap();
            (
                m.target_id,
                ScimResourceType::from_wire(payload["resource_type"].as_str().unwrap()).unwrap(),
                Uuid::parse_str(payload["axiam_id"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

async fn another_target(
    w: &World,
    tenant_id: Uuid,
    tweak: impl FnOnce(&mut NewScimTarget),
) -> axiam_core::models::scim_target::ScimTarget {
    let mut input = NewScimTarget {
        tenant_id,
        name: "other".into(),
        base_url: w.server.base_url(),
        enabled: true,
        auth: axiam_core::models::scim_target::ScimTargetAuth::Bearer,
        credential: zeroize::Zeroizing::new(support::generated("cred")),
        scope: ScimTargetScope::AllUsers,
        push_groups: false,
        user_name_from: Default::default(),
        deprovision: Default::default(),
    };
    tweak(&mut input);
    w.targets.create(input).await.unwrap()
}

fn provisioner(
    w: &World,
) -> ScimProvisioner<axiam_db::repository::SurrealScimTargetRepository<surrealdb::engine::local::Db>>
{
    ScimProvisioner::new(w.targets.clone(), w.queue.clone())
}

#[actix_rt::test]
async fn a_user_change_enqueues_one_reference_per_enabled_target_of_the_tenant() {
    let w = World::new().await;
    let enabled_a = w.add_target(|_| {}).await;
    let enabled_b = w.add_target(|_| {}).await;
    let _disabled = w.add_target(|t| t.enabled = false).await;
    let _foreign = another_target(&w, Uuid::new_v4(), |_| {}).await;
    let p = provisioner(&w);
    let user = Uuid::new_v4();

    p.user_changed(w.tenant_id, user).await;

    let got = refs(&w.queue);
    assert_eq!(got.len(), 2, "one per enabled target, none for the others");
    assert!(got.contains(&(enabled_a.id, ScimResourceType::User, user)));
    assert!(got.contains(&(enabled_b.id, ScimResourceType::User, user)));
}

#[actix_rt::test]
async fn the_envelope_is_a_reference_with_a_fresh_delivery_id_and_attempt_zero() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let p = provisioner(&w);
    let user = Uuid::new_v4();
    p.user_changed(w.tenant_id, user).await;
    p.user_changed(w.tenant_id, user).await;

    let messages: Vec<OutboundMessage> = w.queue.all();
    assert_eq!(messages.len(), 2);
    for message in &messages {
        assert_eq!(message.kind, OutboundKind::ScimPush);
        assert_eq!(message.tenant_id, w.tenant_id);
        assert_eq!(message.target_id, target.id);
        assert_eq!(message.event_type, "scim.user");
        assert_eq!(message.attempt, 0);
        assert_eq!(
            message.payload,
            json!({"resource_type": "user", "axiam_id": user.to_string()})
        );
    }
    assert_ne!(messages[0].delivery_id, messages[1].delivery_id);
    // What would be serialised onto the queue names ids and nothing else.
    let wire = serde_json::to_value(&messages[0]).unwrap();
    let mut keys: Vec<_> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "attempt",
            "delivery_id",
            "event_type",
            "kind",
            "payload",
            "target_id",
            "tenant_id"
        ]
    );
}

#[actix_rt::test]
async fn a_group_change_goes_only_to_targets_that_push_that_group() {
    let w = World::new().await;
    let listed = Uuid::new_v4();
    let unlisted = Uuid::new_v4();
    let no_groups = w.add_target(|_| {}).await;
    let all_groups = w.add_target(|t| t.push_groups = true).await;
    let some_groups = w
        .add_target(|t| {
            t.push_groups = true;
            t.scope = ScimTargetScope::Groups(vec![listed]);
        })
        .await;
    let p = provisioner(&w);

    p.group_changed(w.tenant_id, listed).await;
    let mut targets: Vec<Uuid> = refs(&w.queue).into_iter().map(|(t, _, _)| t).collect();
    targets.sort();
    let mut want = vec![all_groups.id, some_groups.id];
    want.sort();
    assert_eq!(targets, want);
    assert!(
        refs(&w.queue)
            .iter()
            .all(|(_, ty, id)| *ty == ScimResourceType::Group && *id == listed)
    );
    assert!(!targets.contains(&no_groups.id));

    w.queue.clear();
    p.group_changed(w.tenant_id, unlisted).await;
    let targets: Vec<Uuid> = refs(&w.queue).into_iter().map(|(t, _, _)| t).collect();
    assert_eq!(
        targets,
        [all_groups.id],
        "an unlisted group goes to nobody else"
    );
    assert_eq!(
        w.queue.all()[0].event_type,
        "scim.group",
        "the event type names the resource"
    );
}

#[actix_rt::test]
async fn a_membership_change_enqueues_the_user_and_the_group_where_it_is_pushed() {
    let w = World::new().await;
    let group = Uuid::new_v4();
    let user = Uuid::new_v4();
    let users_only = w.add_target(|_| {}).await;
    let with_groups = w.add_target(|t| t.push_groups = true).await;
    let p = provisioner(&w);

    p.membership_changed(w.tenant_id, group, user).await;

    let got = refs(&w.queue);
    assert_eq!(got.len(), 3);
    assert!(got.contains(&(users_only.id, ScimResourceType::User, user)));
    assert!(got.contains(&(with_groups.id, ScimResourceType::User, user)));
    assert!(got.contains(&(with_groups.id, ScimResourceType::Group, group)));
    assert!(!got.contains(&(users_only.id, ScimResourceType::Group, group)));
}

#[actix_rt::test]
async fn group_in_scope_is_push_groups_and_the_scope() {
    let w = World::new().await;
    let g = Uuid::new_v4();
    let off = w.add_target(|_| {}).await;
    let all = w.add_target(|t| t.push_groups = true).await;
    let listed = w
        .add_target(|t| {
            t.push_groups = true;
            t.scope = ScimTargetScope::Groups(vec![g]);
        })
        .await;
    assert!(!group_in_scope(&off, g));
    assert!(group_in_scope(&all, g));
    assert!(group_in_scope(&listed, g));
    assert!(!group_in_scope(&listed, Uuid::new_v4()));
}

#[actix_rt::test]
async fn a_tenant_with_no_target_enqueues_nothing() {
    let w = World::new().await;
    provisioner(&w)
        .user_changed(w.tenant_id, Uuid::new_v4())
        .await;
    provisioner(&w)
        .membership_changed(w.tenant_id, Uuid::new_v4(), Uuid::new_v4())
        .await;
    assert!(w.queue.all().is_empty());
}

struct BrokerDown;

impl OutboundPublisher for BrokerDown {
    fn enqueue<'a>(
        &'a self,
        _msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async { Err(OutboundError::Enqueue("broker down".into())) })
    }
}

#[actix_rt::test]
async fn a_broker_that_is_down_never_fails_the_report() {
    let w = World::new().await;
    w.add_target(|_| {}).await;
    w.add_target(|_| {}).await;
    let p = ScimProvisioner::new(w.targets.clone(), Arc::new(BrokerDown));
    // Returns normally: the write the report follows has already committed.
    p.user_changed(w.tenant_id, Uuid::new_v4()).await;
    p.group_changed(w.tenant_id, Uuid::new_v4()).await;
    p.membership_changed(w.tenant_id, Uuid::new_v4(), Uuid::new_v4())
        .await;
}
