//! **T23.6.2** — outbound SCIM provisioning against a loopback SCIM 2.0 service
//! provider (G-6, D-57).
//!
//! The wiring is `axiam-server`'s: the user and group repositories report every
//! change to one `Late` sink bound to a [`ScimProvisioner`], which enqueues
//! references on an in-process dispatcher; the tests drain it through the real
//! [`ScimPushDeliverer`] and read what the service provider received and what
//! AXIAM recorded. The service provider is the oracle: it stores Users and
//! Groups, honours `filter=externalId eq "…"`, answers a chosen status on
//! demand, and records every request.
//!
//! Credentials are generated at run time; no assertion message formats one.

mod support;

use axiam_core::models::group::UpdateGroup;
use axiam_core::models::scim_target::{
    DeprovisionPolicy, ScimLinkState, ScimResourceType, ScimTarget, ScimTargetAuth,
    ScimTargetScope, ScimTargetUpdate,
};
use axiam_core::models::user::{UpdateUser, UserStatus};
use axiam_core::outbound::{DeliveryOutcome, OutboundKind, OutboundMessage};
use axiam_core::repository::{
    GroupRepository, ScimTargetLinkRepository, ScimTargetRepository, ScimTargetStateRepository,
    UserRepository,
};
use axiam_scim::outbound::reference_message;
use serde_json::{Value, json};
use support::{TestScimServer, World, all_delivered, only};
use uuid::Uuid;
use zeroize::Zeroizing;

fn retry_reason(outcome: &DeliveryOutcome) -> &str {
    match outcome {
        DeliveryOutcome::Retry { reason } => reason,
        other => panic!("a retry was expected, got {}", kind_of(other)),
    }
}

fn dead_reason(outcome: &DeliveryOutcome) -> &str {
    match outcome {
        DeliveryOutcome::DeadLetter { reason } => reason,
        other => panic!("a dead letter was expected, got {}", kind_of(other)),
    }
}

fn kind_of(outcome: &DeliveryOutcome) -> &'static str {
    match outcome {
        DeliveryOutcome::Delivered { .. } => "a delivery",
        DeliveryOutcome::Retry { .. } => "a retry",
        DeliveryOutcome::DeadLetter { .. } => "a dead letter",
    }
}

async fn link(
    w: &World,
    target: &ScimTarget,
    kind: ScimResourceType,
    id: Uuid,
) -> Option<axiam_core::models::scim_target::ScimTargetLink> {
    w.links.get(w.tenant_id, target.id, kind, id).await.unwrap()
}

/// Set up a target and one synced active user; returns them with the queue
/// empty and the server's request log cleared.
async fn synced_user(
    w: &World,
    tweak: impl FnOnce(&mut axiam_core::models::scim_target::NewScimTarget),
) -> (ScimTarget, axiam_core::models::user::User) {
    let target = w.add_target(tweak).await;
    let user = w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    w.server.clear_requests();
    w.queue.clear();
    (target, user)
}

fn operations(body: &Value) -> Vec<(String, Value)> {
    body["Operations"]
        .as_array()
        .expect("operations")
        .iter()
        .map(|o| {
            assert_eq!(o["op"], "replace");
            (o["path"].as_str().unwrap().to_owned(), o["value"].clone())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Create, rename, unchanged
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn create_propagates_as_post_with_the_axiam_id_as_external_id() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;

    let outcomes = w.sync().await;
    assert!(all_delivered(&outcomes));

    let posts = w.server.requests_of("POST", "/scim/v2/Users");
    assert_eq!(posts.len(), 1, "one POST for one user");
    assert!(w.server.requests_of("PATCH", "/scim/v2/Users").is_empty());
    let request = &posts[0];
    assert_eq!(
        request.content_type.as_deref(),
        Some("application/scim+json")
    );
    assert_eq!(request.accept.as_deref(), Some("application/scim+json"));
    assert_eq!(request.authorization_scheme.as_deref(), Some("Bearer"));
    let sent = &request.body;
    assert_eq!(sent["externalId"], user.id.to_string());
    assert_eq!(sent["userName"], "alice");
    assert_eq!(sent["active"], true);
    assert_eq!(sent["name"]["givenName"], "Given");
    assert_eq!(sent["name"]["familyName"], "Family");
    assert_eq!(sent["displayName"], "Given Family");
    assert_eq!(
        sent["emails"],
        json!([{"value": "alice@example.com", "primary": true}])
    );

    // The service provider holds it, and AXIAM kept the link.
    let downstream = w.server.user_by_external_id(&user.id.to_string()).unwrap();
    let link = link(&w, &target, ScimResourceType::User, user.id)
        .await
        .expect("a link");
    assert_eq!(link.downstream_id, downstream["id"].as_str().unwrap());
    assert!(link.synced_digest.is_some());
    assert_eq!(link.state, ScimLinkState::Active);

    // A success is recorded on the target's state.
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert!(state.last_success_at.is_some());
    assert_eq!(state.consecutive_failures, 0);
}

#[actix_rt::test]
async fn the_user_name_follows_the_targets_mapping() {
    let w = World::new().await;
    w.add_target(|t| t.user_name_from = axiam_core::models::scim_target::UserNameSource::Email)
        .await;
    w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    let posts = w.server.requests_of("POST", "/scim/v2/Users");
    assert_eq!(posts[0].body["userName"], "alice@example.com");
}

#[actix_rt::test]
async fn rename_propagates_as_patch_and_an_unchanged_resync_sends_nothing() {
    let w = World::new().await;
    let (target, user) = synced_user(&w, |_| {}).await;
    let before = link(&w, &target, ScimResourceType::User, user.id)
        .await
        .unwrap();

    w.users
        .update(
            w.tenant_id,
            user.id,
            UpdateUser {
                username: Some("alice2".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));

    assert!(w.server.requests_of("POST", "/scim/v2/Users").is_empty());
    let patches = w.server.requests_of("PATCH", "/scim/v2/Users/");
    assert_eq!(patches.len(), 1);
    assert_eq!(
        patches[0].path,
        format!("/scim/v2/Users/{}", before.downstream_id)
    );
    let ops = operations(&patches[0].body);
    assert!(ops.contains(&("userName".to_owned(), json!("alice2"))));
    assert!(ops.contains(&("active".to_owned(), json!(true))));
    assert!(ops.contains(&("externalId".to_owned(), json!(user.id.to_string()))));
    // `replace` operations on the mapped attributes only.
    for (path, _) in &ops {
        assert!(
            [
                "userName",
                "name.givenName",
                "name.familyName",
                "displayName",
                "emails",
                "active",
                "externalId"
            ]
            .contains(&path.as_str()),
            "{path}"
        );
    }
    assert_eq!(
        w.server.user_by_external_id(&user.id.to_string()).unwrap()["userName"],
        "alice2"
    );
    let after = link(&w, &target, ScimResourceType::User, user.id)
        .await
        .unwrap();
    assert_ne!(after.synced_digest, before.synced_digest);
    assert_eq!(after.downstream_id, before.downstream_id);

    // Same state, synced again: the digest is the link's, nothing is sent.
    w.server.clear_requests();
    w.queue.clear();
    use axiam_core::outbound::OutboundPublisher;
    w.queue
        .enqueue(&reference_message(
            w.tenant_id,
            target.id,
            ScimResourceType::User,
            user.id,
        ))
        .await
        .unwrap();
    let outcomes = w.sync().await;
    assert_eq!(
        only(outcomes),
        DeliveryOutcome::Delivered {
            response_status: None
        }
    );
    assert!(w.server.requests().is_empty(), "no request at all");
}

#[actix_rt::test]
async fn a_change_to_a_name_the_mapping_carries_is_sent_and_one_it_does_not_is_not() {
    let w = World::new().await;
    let (_target, user) = synced_user(&w, |_| {}).await;

    // metadata the mapping carries
    w.users
        .update(
            w.tenant_id,
            user.id,
            UpdateUser {
                metadata: Some(json!({"scim": {"givenName": "Alicia", "familyName": "Family", "formatted": "Alicia Family"}})),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    let patches = w.server.requests_of("PATCH", "/scim/v2/Users/");
    assert_eq!(patches.len(), 1);
    assert!(operations(&patches[0].body).contains(&("name.givenName".to_owned(), json!("Alicia"))));

    // metadata the mapping does not carry: a report is made, nothing is sent.
    w.server.clear_requests();
    w.users
        .update(
            w.tenant_id,
            user.id,
            UpdateUser {
                metadata: Some(json!({"scim": {"givenName": "Alicia", "familyName": "Family", "formatted": "Alicia Family"}, "app": {"note": 1}})),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert!(w.server.requests().is_empty());
}

// ---------------------------------------------------------------------------
// Groups and scope
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn group_membership_change_propagates_as_a_group_patch_of_linked_members() {
    let w = World::new().await;
    let target = w.add_target(|t| t.push_groups = true).await;
    let alice = w.active_user("alice").await;
    // Not active, so never linked: skipped from `members`.
    let bob = w
        .users
        .create(axiam_core::models::user::CreateUser {
            tenant_id: w.tenant_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    let staff = w.group("staff").await;
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    w.groups
        .add_member(w.tenant_id, bob.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));

    let alice_link = link(&w, &target, ScimResourceType::User, alice.id)
        .await
        .unwrap();
    assert!(
        link(&w, &target, ScimResourceType::User, bob.id)
            .await
            .is_none()
    );
    let group = w
        .server
        .group_by_external_id(&staff.to_string())
        .expect("the group was created downstream");
    assert_eq!(group["displayName"], "staff");
    assert_eq!(
        group["members"],
        json!([{"value": alice_link.downstream_id}]),
        "linked members only"
    );
    assert_eq!(
        w.server.requests_of("POST", "/scim/v2/Groups").len(),
        1,
        "one group POST"
    );

    // Alice leaves: the group is patched with the whole (now empty) list.
    w.server.clear_requests();
    w.queue.clear();
    w.groups
        .remove_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    let patches = w.server.requests_of("PATCH", "/scim/v2/Groups/");
    assert_eq!(patches.len(), 1);
    assert!(operations(&patches[0].body).contains(&("members".to_owned(), json!([]))));
    assert_eq!(
        w.server.group_by_external_id(&staff.to_string()).unwrap()["members"],
        json!([])
    );

    // Alice joins again; a rename of the group travels as displayName.
    w.server.clear_requests();
    w.queue.clear();
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    w.groups
        .update(
            w.tenant_id,
            staff,
            UpdateGroup {
                name: Some("employees".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    let group = w.server.group_by_external_id(&staff.to_string()).unwrap();
    assert_eq!(group["displayName"], "employees");
    assert_eq!(
        group["members"],
        json!([{"value": alice_link.downstream_id}])
    );
}

#[actix_rt::test]
async fn linking_a_user_converges_the_groups_that_were_pushed_before_it_existed_downstream() {
    let w = World::new().await;
    let target = w.add_target(|t| t.push_groups = true).await;
    let staff = w.group("staff").await;
    assert!(all_delivered(&w.sync().await));
    // The group exists downstream with no members.
    assert_eq!(
        w.server.group_by_external_id(&staff.to_string()).unwrap()["members"],
        json!([])
    );
    w.server.clear_requests();
    w.queue.clear();

    // The user is created and joins before any user message has been served.
    let alice = w.active_user("alice").await;
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    w.queue.clear();
    // Only the user's own reference is queued: the group is not.
    use axiam_core::outbound::OutboundPublisher;
    w.queue
        .enqueue(&reference_message(
            w.tenant_id,
            target.id,
            ScimResourceType::User,
            alice.id,
        ))
        .await
        .unwrap();
    let results = w.sync().await;
    assert!(all_delivered(&results));
    // Linking enqueued the group, and it was served in the same drain.
    assert_eq!(results.len(), 2, "the user, then the group it converged");
    let linked = link(&w, &target, ScimResourceType::User, alice.id)
        .await
        .unwrap();
    assert_eq!(
        w.server.group_by_external_id(&staff.to_string()).unwrap()["members"],
        json!([{"value": linked.downstream_id}])
    );
}

#[actix_rt::test]
async fn a_user_entering_and_leaving_a_groups_scope_is_created_and_deprovisioned() {
    let w = World::new().await;
    let staff = w.group("staff").await;
    let target = w
        .add_target(|t| t.scope = ScimTargetScope::Groups(vec![staff]))
        .await;
    let alice = w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    // Out of scope and never linked: nothing is created downstream.
    assert!(w.server.requests().is_empty());
    assert!(
        link(&w, &target, ScimResourceType::User, alice.id)
            .await
            .is_none()
    );

    // Enters the scope: created.
    w.queue.clear();
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.requests_of("POST", "/scim/v2/Users").len(), 1);
    assert_eq!(
        w.server.user_by_external_id(&alice.id.to_string()).unwrap()["active"],
        true
    );

    // Leaves it: deprovisioned per policy (deactivate).
    w.server.clear_requests();
    w.queue.clear();
    w.groups
        .remove_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    let patches = w.server.requests_of("PATCH", "/scim/v2/Users/");
    assert_eq!(patches.len(), 1);
    assert!(operations(&patches[0].body).contains(&("active".to_owned(), json!(false))));
    assert_eq!(
        link(&w, &target, ScimResourceType::User, alice.id)
            .await
            .unwrap()
            .state,
        ScimLinkState::Deprovisioned
    );
}

#[actix_rt::test]
async fn a_user_leaving_a_groups_scope_is_deleted_when_the_policy_says_delete() {
    let w = World::new().await;
    let staff = w.group("staff").await;
    let target = w
        .add_target(|t| {
            t.scope = ScimTargetScope::Groups(vec![staff]);
            t.deprovision = DeprovisionPolicy::Delete;
        })
        .await;
    let alice = w.active_user("alice").await;
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.users().len(), 1);

    w.server.clear_requests();
    w.queue.clear();
    w.groups
        .remove_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.requests_of("DELETE", "/scim/v2/Users/").len(), 1);
    assert!(w.server.users().is_empty());
    assert!(
        link(&w, &target, ScimResourceType::User, alice.id)
            .await
            .is_none(),
        "the link is removed with the resource"
    );
}

#[actix_rt::test]
async fn deleting_a_listed_group_takes_its_members_out_of_scope_and_the_group_downstream() {
    let w = World::new().await;
    let staff = w.group("staff").await;
    let target = w
        .add_target(|t| {
            t.scope = ScimTargetScope::Groups(vec![staff]);
            t.push_groups = true;
        })
        .await;
    let alice = w.active_user("alice").await;
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.groups().len(), 1);

    w.server.clear_requests();
    w.queue.clear();
    w.groups.delete(w.tenant_id, staff).await.unwrap();
    assert!(all_delivered(&w.sync().await));
    assert!(
        w.server.groups().is_empty(),
        "the group is deleted downstream"
    );
    assert!(
        link(&w, &target, ScimResourceType::Group, staff)
            .await
            .is_none()
    );
    // Alice lost her only scope: deactivated.
    assert_eq!(
        w.server.user_by_external_id(&alice.id.to_string()).unwrap()["active"],
        false
    );
}

// ---------------------------------------------------------------------------
// Disable, delete, erase
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn disable_sets_active_false_under_the_deactivate_policy_and_enable_restores_it() {
    let w = World::new().await;
    let (target, user) = synced_user(&w, |_| {}).await;

    w.set_status(user.id, UserStatus::Inactive).await;
    assert!(all_delivered(&w.sync().await));
    let patches = w.server.requests_of("PATCH", "/scim/v2/Users/");
    assert_eq!(patches.len(), 1);
    assert!(operations(&patches[0].body).contains(&("active".to_owned(), json!(false))));
    assert!(w.server.requests_of("DELETE", "/scim/v2/Users/").is_empty());
    assert_eq!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .unwrap()
            .state,
        ScimLinkState::Deprovisioned
    );

    // Disabled again with nothing changed: skipped.
    w.server.clear_requests();
    w.queue.clear();
    w.set_status(user.id, UserStatus::Inactive).await;
    assert!(all_delivered(&w.sync().await));
    assert!(w.server.requests().is_empty());

    // Enabled: back to active.
    w.queue.clear();
    w.set_status(user.id, UserStatus::Active).await;
    assert!(all_delivered(&w.sync().await));
    assert_eq!(
        w.server.user_by_external_id(&user.id.to_string()).unwrap()["active"],
        true
    );
    assert_eq!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .unwrap()
            .state,
        ScimLinkState::Active
    );
}

#[actix_rt::test]
async fn disable_deletes_under_the_delete_policy_and_enable_creates_again() {
    let w = World::new().await;
    let (target, user) = synced_user(&w, |t| t.deprovision = DeprovisionPolicy::Delete).await;

    w.set_status(user.id, UserStatus::Inactive).await;
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.requests_of("DELETE", "/scim/v2/Users/").len(), 1);
    assert!(w.server.users().is_empty());
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none()
    );

    w.server.clear_requests();
    w.queue.clear();
    w.set_status(user.id, UserStatus::Active).await;
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.requests_of("POST", "/scim/v2/Users").len(), 1);
    assert_eq!(w.server.users().len(), 1);
}

#[actix_rt::test]
async fn a_deleted_user_is_deleted_downstream_whatever_the_policy_and_the_link_goes() {
    let w = World::new().await;
    // Policy: deactivate.
    let (target, user) = synced_user(&w, |_| {}).await;
    w.users.delete(w.tenant_id, user.id).await.unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.requests_of("DELETE", "/scim/v2/Users/").len(), 1);
    assert!(
        w.server.requests_of("PATCH", "/scim/v2/Users/").is_empty(),
        "an erasure is never a deactivation"
    );
    assert!(w.server.users().is_empty());
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none()
    );
}

#[actix_rt::test]
async fn an_anonymized_user_is_deleted_downstream_whatever_the_policy_and_the_link_goes() {
    let w = World::new().await;
    let (target, user) = synced_user(&w, |_| {}).await;
    w.users
        .anonymize_user(
            w.tenant_id,
            user.id,
            &Uuid::new_v4().simple().to_string(),
            "DELETED_USER_x",
        )
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.requests_of("DELETE", "/scim/v2/Users/").len(), 1);
    assert!(w.server.requests_of("PATCH", "/scim/v2/Users/").is_empty());
    assert!(w.server.users().is_empty());
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none()
    );
}

#[actix_rt::test]
async fn a_downstream_that_already_lost_the_user_counts_an_erasure_delete_as_done() {
    let w = World::new().await;
    let (target, user) = synced_user(&w, |_| {}).await;
    let downstream_id = link(&w, &target, ScimResourceType::User, user.id)
        .await
        .unwrap()
        .downstream_id;
    w.server.forget_user(&downstream_id);
    w.users.delete(w.tenant_id, user.id).await.unwrap();
    let outcomes = w.sync().await;
    assert!(all_delivered(&outcomes), "404 on DELETE is done");
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// The status mapping
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_5xx_and_a_429_retry_and_are_recorded_as_failures() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    w.active_user("alice").await;
    w.queue.clear();
    let user = w.users.get_by_username(w.tenant_id, "alice").await.unwrap();
    use axiam_core::outbound::OutboundPublisher;
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);

    for status in [503u16, 500, 429, 408] {
        w.server.fail_next(1, status);
        w.queue.enqueue(&message).await.unwrap();
        let outcome = only(w.sync().await);
        assert!(
            retry_reason(&outcome).contains(&status.to_string()),
            "{status}"
        );
    }
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(state.consecutive_failures, 4);
    assert!(state.last_failure_at.is_some());
    assert_eq!(state.dead_lettered_total, 0);
    // Nothing was created by the failed attempts; the next one succeeds.
    assert!(w.server.users().is_empty());
}

#[actix_rt::test]
async fn a_400_and_a_403_and_a_401_on_bearer_dead_letter_and_are_recorded() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    use axiam_core::outbound::OutboundPublisher;
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);

    for status in [400u16, 403, 401, 404, 422] {
        w.server.fail_next(1, status);
        w.queue.enqueue(&message).await.unwrap();
        let outcome = only(w.sync().await);
        assert!(
            dead_reason(&outcome).contains(&status.to_string()),
            "{status}"
        );
    }
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(state.dead_lettered_total, 5);
    assert!(state.last_failure_reason.is_some());
    // The next healthy attempt still works: nothing was poisoned.
    w.queue.enqueue(&message).await.unwrap();
    assert!(all_delivered(&w.sync().await));
}

#[actix_rt::test]
async fn a_redirect_is_a_retry_and_is_never_followed() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    // The Location server is another host the administrator never named.
    let elsewhere = TestScimServer::start();
    use axiam_core::outbound::OutboundPublisher;
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);

    for status in [301u16, 302, 307, 308] {
        w.server.redirect_next(
            1,
            status,
            &format!("http://127.0.0.1:{}/scim/v2/Users", elsewhere.port),
        );
        w.queue.enqueue(&message).await.unwrap();
        let outcome = only(w.sync().await);
        assert!(retry_reason(&outcome).contains("redirect"), "{status}");
    }
    assert!(
        elsewhere.requests().is_empty(),
        "neither the credential nor the person's attributes reached the Location"
    );
}

#[actix_rt::test]
async fn a_409_on_post_adopts_the_resource_that_carries_our_external_id() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    // The downstream already holds this user (e.g. from a previous link).
    let downstream_id = w.server.seed_user(json!({
        "externalId": user.id.to_string(),
        "userName": "alice",
        "active": true,
    }));
    assert!(all_delivered(&w.sync().await));

    assert_eq!(w.server.requests_of("POST", "/scim/v2/Users").len(), 1);
    let lookups = w.server.requests_of("GET", "/scim/v2/Users");
    assert_eq!(lookups.len(), 1);
    assert!(lookups[0].query.contains("externalId"));
    assert_eq!(w.server.users().len(), 1, "no duplicate was created");
    let link = link(&w, &target, ScimResourceType::User, user.id)
        .await
        .unwrap();
    assert_eq!(link.downstream_id, downstream_id);
    // The adopted resource was brought to the state we want.
    let patches = w.server.requests_of("PATCH", "/scim/v2/Users/");
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].path, format!("/scim/v2/Users/{downstream_id}"));
    assert_eq!(
        w.server.users()[0]["name"]["givenName"],
        "Given",
        "the mapped attributes were replaced"
    );
}

#[actix_rt::test]
async fn a_409_with_no_resource_of_ours_dead_letters_as_a_conflict() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    // Someone else's account holds the user name.
    w.server.seed_user(json!({
        "externalId": Uuid::new_v4().to_string(),
        "userName": "alice",
    }));
    let outcome = only({
        w.queue.clear();
        use axiam_core::outbound::OutboundPublisher;
        w.queue
            .enqueue(&reference_message(
                w.tenant_id,
                target.id,
                ScimResourceType::User,
                user.id,
            ))
            .await
            .unwrap();
        w.sync().await
    });
    assert_eq!(dead_reason(&outcome), "conflict");
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none(),
        "an account AXIAM did not create is not adopted"
    );
    assert_eq!(w.server.users().len(), 1, "and it was not touched");
    assert!(w.server.requests_of("PATCH", "/scim/v2/Users/").is_empty());
}

#[actix_rt::test]
async fn a_404_on_patch_drops_the_link_and_retries_then_recreates() {
    let w = World::new().await;
    let (target, user) = synced_user(&w, |_| {}).await;
    let downstream_id = link(&w, &target, ScimResourceType::User, user.id)
        .await
        .unwrap()
        .downstream_id;
    // Gone behind AXIAM's back.
    w.server.forget_user(&downstream_id);

    w.users
        .update(
            w.tenant_id,
            user.id,
            UpdateUser {
                username: Some("alice2".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let outcome = only(w.sync().await);
    assert_eq!(retry_reason(&outcome), "the downstream resource is gone");
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none(),
        "the link is dropped"
    );

    // The retry re-creates it.
    w.server.clear_requests();
    use axiam_core::outbound::OutboundPublisher;
    w.queue
        .enqueue(&reference_message(
            w.tenant_id,
            target.id,
            ScimResourceType::User,
            user.id,
        ))
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.requests_of("POST", "/scim/v2/Users").len(), 1);
    let relinked = link(&w, &target, ScimResourceType::User, user.id)
        .await
        .unwrap();
    assert_ne!(relinked.downstream_id, downstream_id);
    assert_eq!(w.server.users()[0]["userName"], "alice2");
}

// ---------------------------------------------------------------------------
// Client credentials
// ---------------------------------------------------------------------------

fn client_credentials(
    w: &World,
) -> impl FnOnce(&mut axiam_core::models::scim_target::NewScimTarget) {
    let token_url = w.server.token_url();
    move |t| {
        t.auth = ScimTargetAuth::OAuth2ClientCredentials {
            token_url,
            client_id: "axiam".into(),
            scope: Some("scim".into()),
        };
    }
}

#[actix_rt::test]
async fn the_client_credentials_token_is_fetched_once_and_reused() {
    let w = World::new().await;
    let target = w.add_target(client_credentials(&w)).await;
    let alice = w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    w.queue.clear();
    let bob = w.active_user("bob").await;
    assert!(all_delivered(&w.sync().await));

    assert_eq!(w.server.users().len(), 2);
    assert_eq!(w.server.tokens_issued(), 1, "one token for every request");
    let token_requests = w.server.requests_of("POST", "/oauth/token");
    assert_eq!(token_requests.len(), 1);
    // HTTP Basic client authentication and a form body with the grant and scope.
    assert_eq!(
        token_requests[0].authorization_scheme.as_deref(),
        Some("Basic")
    );
    let form = token_requests[0].body.as_str().expect("a form body");
    assert!(form.contains("grant_type=client_credentials"));
    assert!(form.contains("scope=scim"));
    // Every SCIM call carried a Bearer.
    for request in w.server.requests_of("POST", "/scim/v2/Users") {
        assert_eq!(request.authorization_scheme.as_deref(), Some("Bearer"));
    }
    assert!(
        link(&w, &target, ScimResourceType::User, alice.id)
            .await
            .is_some()
    );
    assert!(
        link(&w, &target, ScimResourceType::User, bob.id)
            .await
            .is_some()
    );
}

#[actix_rt::test]
async fn a_401_on_a_client_credentials_target_flushes_the_token_and_retries() {
    let w = World::new().await;
    let target = w.add_target(client_credentials(&w)).await;
    let alice = w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.tokens_issued(), 1);

    // The access token is revoked downstream.
    w.server.revoke_all_tokens();
    w.queue.clear();
    w.users
        .update(
            w.tenant_id,
            alice.id,
            UpdateUser {
                username: Some("alice2".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let outcome = only(w.sync().await);
    assert!(
        retry_reason(&outcome).contains("401"),
        "a 401 on client credentials is a retry, not a dead letter"
    );

    // The retry gets a new token and succeeds.
    w.queue.clear();
    use axiam_core::outbound::OutboundPublisher;
    w.queue
        .enqueue(&reference_message(
            w.tenant_id,
            target.id,
            ScimResourceType::User,
            alice.id,
        ))
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.tokens_issued(), 2, "the stale token was flushed");
    assert_eq!(w.server.users()[0]["userName"], "alice2");
}

#[actix_rt::test]
async fn expires_in_is_honoured() {
    let w = World::new().await;
    w.add_target(client_credentials(&w)).await;
    w.server.set_token_expires_in(0);
    w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    w.queue.clear();
    w.active_user("bob").await;
    assert!(all_delivered(&w.sync().await));
    assert!(
        w.server.tokens_issued() >= 2,
        "a token that expires at once is not reused"
    );
}

#[actix_rt::test]
async fn a_token_endpoint_that_refuses_the_credentials_dead_letters() {
    let w = World::new().await;
    let target = w.add_target(client_credentials(&w)).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    w.server.fail_next_on("POST", "/oauth/token", 1, 401);
    // The forced status targets /scim/v2 by default; the token endpoint is
    // answered by the server itself, so make the deliverer face a 401 there by
    // pointing the target at a token URL that does not exist.
    let mut update = ScimTargetUpdate::from_target(&target);
    update.auth = ScimTargetAuth::OAuth2ClientCredentials {
        token_url: format!("{}/missing", w.server.token_url()),
        client_id: "axiam".into(),
        scope: None,
    };
    update.credential = Some(Zeroizing::new(support::generated("cred")));
    w.targets
        .update(w.tenant_id, target.id, update)
        .await
        .unwrap();
    use axiam_core::outbound::OutboundPublisher;
    w.queue
        .enqueue(&reference_message(
            w.tenant_id,
            target.id,
            ScimResourceType::User,
            user.id,
        ))
        .await
        .unwrap();
    let outcome = only(w.sync().await);
    assert!(
        dead_reason(&outcome).contains("token endpoint"),
        "a wrong token URL is the administrator's to fix"
    );
    assert!(w.server.users().is_empty());
}

// ---------------------------------------------------------------------------
// The target, as read
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_disabled_target_and_a_deleted_one_dead_letter() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    use axiam_core::outbound::OutboundPublisher;
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);

    let mut update = ScimTargetUpdate::from_target(&target);
    update.enabled = false;
    w.targets
        .update(w.tenant_id, target.id, update)
        .await
        .unwrap();
    w.queue.enqueue(&message).await.unwrap();
    assert_eq!(dead_reason(&only(w.sync().await)), "target disabled");

    w.targets.delete(w.tenant_id, target.id).await.unwrap();
    w.queue.enqueue(&message).await.unwrap();
    assert_eq!(dead_reason(&only(w.sync().await)), "target not found");
    assert!(w.server.requests().is_empty(), "nothing was sent");
}

#[actix_rt::test]
async fn a_malformed_reference_and_a_foreign_kind_dead_letter() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    w.queue.clear();
    use axiam_core::outbound::OutboundPublisher;
    let mut messages: Vec<OutboundMessage> = [
        json!({"resource_type": "role", "axiam_id": Uuid::new_v4().to_string()}),
        json!({"resource_type": "user", "axiam_id": "not-a-uuid"}),
        json!({"resource_type": "user"}),
        json!(null),
    ]
    .into_iter()
    .map(|payload| {
        let mut m = reference_message(w.tenant_id, target.id, ScimResourceType::User, Uuid::nil());
        m.payload = payload;
        m
    })
    .collect();
    let mut foreign =
        reference_message(w.tenant_id, target.id, ScimResourceType::User, Uuid::nil());
    foreign.kind = OutboundKind::Webhook;
    messages.push(foreign);
    for message in &messages {
        w.queue.enqueue(message).await.unwrap();
        let outcome = only(w.sync().await);
        assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    }
    assert!(w.server.requests().is_empty());
}

/// A target registry that has the target **change between the attempt's read
/// and the send**: the credential is opened first, and an administrator's write
/// lands just before the second read.
mod changing {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::scim_target::{NewScimTarget, ScimTargetUpdate};
    use axiam_core::repository::{PaginatedResult, Pagination};
    use axiam_db::repository::SurrealScimTargetRepository;
    use std::future::Future;
    use std::sync::Mutex;
    use surrealdb::engine::local::Db;

    pub struct ChangingTargets {
        pub inner: SurrealScimTargetRepository<Db>,
        pub on_decrypt: Mutex<Option<ScimTargetUpdate>>,
    }

    impl ScimTargetRepository for ChangingTargets {
        fn create(
            &self,
            input: NewScimTarget,
        ) -> impl Future<Output = AxiamResult<ScimTarget>> + Send {
            self.inner.create(input)
        }
        fn get(
            &self,
            tenant_id: Uuid,
            id: Uuid,
        ) -> impl Future<Output = AxiamResult<ScimTarget>> + Send {
            self.inner.get(tenant_id, id)
        }
        fn list_page(
            &self,
            tenant_id: Uuid,
            pagination: Pagination,
        ) -> impl Future<Output = AxiamResult<PaginatedResult<ScimTarget>>> + Send {
            self.inner.list_page(tenant_id, pagination)
        }
        fn list_enabled(
            &self,
            tenant_id: Uuid,
        ) -> impl Future<Output = AxiamResult<Vec<ScimTarget>>> + Send {
            self.inner.list_enabled(tenant_id)
        }
        fn list_all_enabled(&self) -> impl Future<Output = AxiamResult<Vec<ScimTarget>>> + Send {
            self.inner.list_all_enabled()
        }
        fn update(
            &self,
            tenant_id: Uuid,
            id: Uuid,
            update: ScimTargetUpdate,
        ) -> impl Future<Output = AxiamResult<ScimTarget>> + Send {
            self.inner.update(tenant_id, id, update)
        }
        async fn decrypt_credential(
            &self,
            tenant_id: Uuid,
            id: Uuid,
        ) -> AxiamResult<Option<Zeroizing<String>>> {
            let pending = self.on_decrypt.lock().unwrap().take();
            if let Some(update) = pending {
                self.inner.update(tenant_id, id, update).await?;
            }
            self.inner.decrypt_credential(tenant_id, id).await
        }
        fn delete(
            &self,
            tenant_id: Uuid,
            id: Uuid,
        ) -> impl Future<Output = AxiamResult<()>> + Send {
            self.inner.delete(tenant_id, id)
        }
    }
}

#[actix_rt::test]
async fn a_target_changed_between_the_read_and_the_send_is_a_retry_and_sends_nothing() {
    use axiam_scim::outbound::ScimPushDeliverer;
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();

    // An administrator moves the target to another URL mid-attempt.
    let mut moved = ScimTargetUpdate::from_target(&target);
    moved.name = "renamed".into();
    moved.expected_updated_at = None;
    let wrapper = changing::ChangingTargets {
        inner: w.targets.clone(),
        on_decrypt: std::sync::Mutex::new(Some(moved)),
    };
    let deliverer = ScimPushDeliverer::new(
        wrapper,
        w.links.clone(),
        w.states.clone(),
        w.users.clone(),
        w.groups.clone(),
        w.queue.clone(),
    )
    .admitting_private_networks_for_tests();

    use axiam_core::outbound::OutboundDeliverer;
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);
    let outcome = deliverer.deliver_attempt(&message).await.unwrap();
    assert_eq!(
        retry_reason(&outcome),
        "the target changed during the attempt"
    );
    assert!(
        w.server.requests().is_empty(),
        "the credential never left, and nor did anything else"
    );
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none()
    );

    // The next attempt reads the new version and delivers.
    let outcome = deliverer.deliver_attempt(&message).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Delivered { .. }));
}

// ---------------------------------------------------------------------------
// Transport and secrecy
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_production_deliverer_refuses_a_loopback_endpoint() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    use axiam_core::outbound::{OutboundDeliverer, OutboundPublisher};
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);
    let outcome = w
        .production_deliverer()
        .deliver_attempt(&message)
        .await
        .unwrap();
    assert!(
        !matches!(outcome, DeliveryOutcome::Delivered { .. }),
        "allow_private is off in production"
    );
    assert!(
        w.server.requests().is_empty(),
        "nothing reached the loopback"
    );
    let _ = w.queue.enqueue(&message).await;
}

#[actix_rt::test]
async fn no_reason_state_row_or_message_carries_a_credential_or_a_person() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    use axiam_core::outbound::OutboundPublisher;
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);

    let mut reasons = Vec::new();
    for status in [503u16, 400, 302] {
        w.server.fail_next(1, status);
        w.queue.enqueue(&message).await.unwrap();
        match only(w.sync().await) {
            DeliveryOutcome::Retry { reason } | DeliveryOutcome::DeadLetter { reason } => {
                reasons.push(reason)
            }
            DeliveryOutcome::Delivered { .. } => panic!("a failure was expected"),
        }
    }
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    reasons.extend(state.last_failure_reason);

    let credentials = w.credentials.lock().unwrap().clone();
    let url_host = format!("127.0.0.1:{}", w.server.port);
    for reason in &reasons {
        for credential in &credentials {
            assert!(
                !reason.contains(credential.as_str()),
                "a credential in a reason"
            );
        }
        assert!(
            !reason.contains(&url_host) && !reason.contains("alice") && !reason.contains("http://"),
            "a URL or a name in a reason"
        );
    }
}

#[actix_rt::test]
async fn no_attribute_of_a_person_is_ever_enqueued() {
    let w = World::new().await;
    let target = w.add_target(|t| t.push_groups = true).await;
    let alice = w.active_user("alice").await;
    let staff = w.group("staff").await;
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    w.users
        .update(
            w.tenant_id,
            alice.id,
            UpdateUser {
                username: Some("alice2".into()),
                email: Some("alice2@example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    w.users.delete(w.tenant_id, alice.id).await.unwrap();
    // Serve everything, including what the deliverer itself enqueues.
    w.sync().await;

    let messages = w.queue.all();
    assert!(!messages.is_empty());
    for message in &messages {
        let wire = serde_json::to_string(message).unwrap();
        for forbidden in [
            "alice",
            "example.com",
            "Given",
            "Family",
            "staff",
            "username",
            "email",
            "password",
        ] {
            assert!(!wire.contains(forbidden), "{forbidden}");
        }
        // The envelope: a reference and ids.
        assert_eq!(message.kind, OutboundKind::ScimPush);
        assert_eq!(message.target_id, target.id);
        assert_eq!(message.tenant_id, w.tenant_id);
        assert_eq!(message.attempt, 0);
        let payload = message.payload.as_object().unwrap();
        let mut keys: Vec<_> = payload.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["axiam_id", "resource_type"]);
        assert!(Uuid::parse_str(payload["axiam_id"].as_str().unwrap()).is_ok());
        assert!(["user", "group"].contains(&payload["resource_type"].as_str().unwrap()));
        assert!(["scim.user", "scim.group"].contains(&message.event_type.as_str()));
    }
}

// ---------------------------------------------------------------------------
// The per-target breaker and the group bound (#550, T-414)
// ---------------------------------------------------------------------------

/// A downstream that accepts every connection and never answers: the tarpit of
/// #550. Counts the connections it was offered and holds each one open.
struct Tarpit {
    port: u16,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Tarpit {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                held.push(stream);
            }
        });
        Self { port, accepted }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/scim/v2", self.port)
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The deliverer's per-request timeout (`client::REQUEST_TIMEOUT`).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Put the target's breaker where `BREAKER_THRESHOLD` timed-out attempts would
/// leave it: the failures are recorded the way the deliverer records them, now.
async fn trip(w: &World, target: &ScimTarget) {
    for _ in 0..axiam_scim::outbound::BREAKER_THRESHOLD {
        w.states
            .record_failure(
                w.tenant_id,
                target.id,
                "the receiver could not be reached or did not answer in time",
            )
            .await
            .unwrap();
    }
}

#[actix_rt::test]
async fn a_healthy_target_is_served_within_one_timeout_behind_ten_references_to_a_tarpit() {
    let w = World::new().await;
    let mut users = Vec::new();
    for i in 0..10 {
        users.push(w.active_user(&format!("user{i}")).await);
    }
    let tarpit = Tarpit::start();
    let failing = w.add_target(|t| t.base_url = tarpit.base_url()).await;
    let healthy = w.add_target(|_| {}).await;
    trip(&w, &failing).await;
    w.queue.clear();

    // Ten references for the tarpit ahead of one for the healthy target, on
    // the replica's one consumer.
    use axiam_core::outbound::OutboundPublisher;
    for user in &users {
        let message = reference_message(w.tenant_id, failing.id, ScimResourceType::User, user.id);
        w.queue.enqueue(&message).await.unwrap();
    }
    let message = reference_message(w.tenant_id, healthy.id, ScimResourceType::User, users[0].id);
    w.queue.enqueue(&message).await.unwrap();

    let started = std::time::Instant::now();
    let outcomes = w.sync().await;
    let elapsed = started.elapsed();

    assert_eq!(outcomes.len(), 11);
    for outcome in &outcomes[..10] {
        assert_eq!(retry_reason(outcome), "target is failing; backing off");
    }
    assert!(matches!(outcomes[10], DeliveryOutcome::Delivered { .. }));
    assert!(
        elapsed < REQUEST_TIMEOUT,
        "the healthy delivery waited behind the tarpit for {elapsed:?}"
    );
    assert_eq!(tarpit.accepted(), 0, "the open breaker made no connection");
    assert_eq!(w.server.users().len(), 1);
    assert!(
        link(&w, &healthy, ScimResourceType::User, users[0].id)
            .await
            .is_some()
    );
}

#[actix_rt::test]
async fn an_open_breaker_makes_no_network_call_and_records_no_failure() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    trip(&w, &target).await;
    let before = w.states.get(w.tenant_id, target.id).await.unwrap();

    use axiam_core::outbound::OutboundPublisher;
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);
    for _ in 0..3 {
        w.queue.enqueue(&message).await.unwrap();
        let outcome = only(w.sync().await);
        assert_eq!(retry_reason(&outcome), "target is failing; backing off");
    }
    assert!(
        w.server.requests().is_empty(),
        "no request, not even a token"
    );
    let after = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(
        after, before,
        "a refused delivery neither counts a failure nor moves the window"
    );
    assert!(
        link(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none()
    );
}

#[actix_rt::test]
async fn a_breaker_below_the_threshold_or_past_its_window_lets_the_attempt_through() {
    use axiam_core::outbound::OutboundDeliverer;
    use axiam_scim::outbound::ScimPushDeliverer;
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);

    // One failure short of the threshold: attempted, and failing again.
    for _ in 1..axiam_scim::outbound::BREAKER_THRESHOLD {
        w.server.fail_next(1, 503);
        let outcome = support::outcome(w.deliverer.deliver_attempt(&message).await);
        assert!(retry_reason(&outcome).contains("503"));
    }
    assert_eq!(w.server.requests().len(), 4);
    // The fifth failure opens it.
    w.server.fail_next(1, 503);
    let outcome = support::outcome(w.deliverer.deliver_attempt(&message).await);
    assert!(retry_reason(&outcome).contains("503"));
    let outcome = support::outcome(w.deliverer.deliver_attempt(&message).await);
    assert_eq!(retry_reason(&outcome), "target is failing; backing off");
    assert_eq!(w.server.requests().len(), 5);

    // With a window already passed (a schedule of a millisecond), the next
    // reference is attempted, and its success closes the breaker.
    let deliverer = ScimPushDeliverer::new(
        w.targets.clone(),
        w.links.clone(),
        w.states.clone(),
        w.users.clone(),
        w.groups.clone(),
        w.queue.clone(),
    )
    .admitting_private_networks_for_tests()
    .with_backoff(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(1),
    );
    actix_rt::time::sleep(std::time::Duration::from_millis(5)).await;
    let outcome = support::outcome(deliverer.deliver_attempt(&message).await);
    assert!(matches!(outcome, DeliveryOutcome::Delivered { .. }));
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(state.consecutive_failures, 0);
}

#[actix_rt::test]
async fn a_refused_delivery_on_the_last_attempt_is_counted_without_extending_the_window() {
    use axiam_core::outbound::OutboundDeliverer;
    use axiam_scim::outbound::ScimPushDeliverer;
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    trip(&w, &target).await;
    let before = w.states.get(w.tenant_id, target.id).await.unwrap();
    let deliverer = ScimPushDeliverer::new(
        w.targets.clone(),
        w.links.clone(),
        w.states.clone(),
        w.users.clone(),
        w.groups.clone(),
        w.queue.clone(),
    )
    .admitting_private_networks_for_tests()
    .with_max_attempts(3);

    let mut message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);
    message.attempt = 2;
    let outcome = support::outcome(deliverer.deliver_attempt(&message).await);
    assert_eq!(retry_reason(&outcome), "target is failing; backing off");
    let after = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(after.dead_lettered_total, before.dead_lettered_total + 1);
    assert_eq!(after.consecutive_failures, before.consecutive_failures);
    assert_eq!(after.last_failure_at, before.last_failure_at);
    assert_eq!(after.last_failure_reason, before.last_failure_reason);
    assert!(w.server.requests().is_empty());
}

/// A group repository that reports one more member than a push carries.
mod crowded {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::group::{CreateGroup, Group};
    use axiam_core::models::user::User;
    use axiam_core::repository::{PaginatedResult, Pagination};
    use axiam_db::repository::SurrealGroupRepository;
    use std::future::Future;
    use surrealdb::engine::local::Db;

    pub const REPORTED_MEMBERS: u64 = 10_001;

    pub struct CrowdedGroups {
        pub inner: SurrealGroupRepository<Db>,
    }

    impl GroupRepository for CrowdedGroups {
        fn create(&self, input: CreateGroup) -> impl Future<Output = AxiamResult<Group>> + Send {
            self.inner.create(input)
        }
        fn get_by_id(
            &self,
            tenant_id: Uuid,
            id: Uuid,
        ) -> impl Future<Output = AxiamResult<Group>> + Send {
            self.inner.get_by_id(tenant_id, id)
        }
        fn update(
            &self,
            tenant_id: Uuid,
            id: Uuid,
            input: UpdateGroup,
        ) -> impl Future<Output = AxiamResult<Group>> + Send {
            self.inner.update(tenant_id, id, input)
        }
        fn delete(
            &self,
            tenant_id: Uuid,
            id: Uuid,
        ) -> impl Future<Output = AxiamResult<()>> + Send {
            self.inner.delete(tenant_id, id)
        }
        fn list(
            &self,
            tenant_id: Uuid,
            pagination: Pagination,
        ) -> impl Future<Output = AxiamResult<PaginatedResult<Group>>> + Send {
            self.inner.list(tenant_id, pagination)
        }
        fn add_member(
            &self,
            tenant_id: Uuid,
            user_id: Uuid,
            group_id: Uuid,
        ) -> impl Future<Output = AxiamResult<()>> + Send {
            self.inner.add_member(tenant_id, user_id, group_id)
        }
        fn remove_member(
            &self,
            tenant_id: Uuid,
            user_id: Uuid,
            group_id: Uuid,
        ) -> impl Future<Output = AxiamResult<()>> + Send {
            self.inner.remove_member(tenant_id, user_id, group_id)
        }
        async fn get_members(
            &self,
            tenant_id: Uuid,
            group_id: Uuid,
            pagination: Pagination,
        ) -> AxiamResult<PaginatedResult<User>> {
            let mut page = self
                .inner
                .get_members(tenant_id, group_id, pagination)
                .await?;
            page.total = REPORTED_MEMBERS;
            Ok(page)
        }
        fn get_user_groups(
            &self,
            tenant_id: Uuid,
            user_id: Uuid,
        ) -> impl Future<Output = AxiamResult<Vec<Group>>> + Send {
            self.inner.get_user_groups(tenant_id, user_id)
        }
    }
}

#[actix_rt::test]
async fn a_group_reporting_ten_thousand_and_one_members_dead_letters_with_the_fixed_reason() {
    use axiam_core::outbound::OutboundDeliverer;
    use axiam_scim::outbound::ScimPushDeliverer;
    let w = World::new().await;
    let target = w.add_target(|t| t.push_groups = true).await;
    let alice = w.active_user("alice").await;
    let staff = w.group("staff").await;
    w.groups
        .add_member(w.tenant_id, alice.id, staff)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    w.server.clear_requests();
    w.queue.clear();

    let deliverer = ScimPushDeliverer::new(
        w.targets.clone(),
        w.links.clone(),
        w.states.clone(),
        w.users.clone(),
        crowded::CrowdedGroups {
            inner: w.groups.clone(),
        },
        w.queue.clone(),
    )
    .admitting_private_networks_for_tests();
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::Group, staff);
    let outcome = support::outcome(deliverer.deliver_attempt(&message).await);
    assert_eq!(
        dead_reason(&outcome),
        "the group has more members than a push carries"
    );
    assert!(w.server.requests().is_empty(), "nothing was sent for it");
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(state.dead_lettered_total, 1);
    assert_eq!(
        state.last_failure_reason.as_deref(),
        Some("the group has more members than a push carries")
    );
}
