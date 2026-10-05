//! **T23.6.3** — reconciliation of an outbound SCIM target against a loopback
//! SCIM 2.0 service provider (G-6, D-58).
//!
//! The wiring is the one of `outbound_scim_test.rs` (the harness is shared): the
//! repositories report to a provisioner that enqueues references on an
//! in-process dispatcher, the tests drain it through the real deliverer, and the
//! service provider is the oracle. Reconciliation is the deliverer's own method
//! set, so it goes out through the same guarded path (`reconcile_now`) — or, for
//! the scheduled job, through the object-safe [`ScimReconciliation`] port the
//! cleanup loop holds.
//!
//! Credentials are generated at run time; no assertion message formats one.

mod support;

use axiam_core::models::group::CreateGroup;
use axiam_core::models::scim_target::{
    DeprovisionPolicy, ScimLinkState, ScimResourceType, ScimTarget, ScimTargetScope,
};
use axiam_core::models::user::{CreateUser, User, UserStatus};
use axiam_core::outbound::{DeliveryOutcome, OutboundDeliverer};
use axiam_core::repository::{
    GroupRepository, ScimTargetLinkRepository, ScimTargetStateRepository, UserRepository,
};
use axiam_scim::outbound::{
    Listing, RECONCILE_MAX_PAGES, ReconcileOutcome, ReconcileReport, ScimPushDeliverer,
    ScimReconciliation, reference_message,
};
use serde_json::json;
use support::{TestScimServer, World, all_delivered, only};
use uuid::Uuid;

async fn ran(w: &World, target: &ScimTarget) -> ReconcileReport {
    match w
        .deliverer
        .reconcile_now(w.tenant_id, target.id)
        .await
        .expect("a reconciliation")
    {
        ReconcileOutcome::Ran(report) => report,
        other => panic!("a run was expected, got {other:?}"),
    }
}

async fn link_of(
    w: &World,
    target: &ScimTarget,
    kind: ScimResourceType,
    id: Uuid,
) -> Option<axiam_core::models::scim_target::ScimTargetLink> {
    w.links.get(w.tenant_id, target.id, kind, id).await.unwrap()
}

/// A target and one synced active user, with the queue and request log cleared.
async fn synced_user(
    w: &World,
    tweak: impl FnOnce(&mut axiam_core::models::scim_target::NewScimTarget),
) -> (ScimTarget, User, String) {
    let target = w.add_target(tweak).await;
    let user = w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    let downstream_id = link_of(w, &target, ScimResourceType::User, user.id)
        .await
        .expect("linked")
        .downstream_id;
    w.server.clear_requests();
    w.queue.clear();
    (target, user, downstream_id)
}

/// An account the downstream's own application created: `externalId` as given
/// (or absent).
fn seed_foreign(server: &TestScimServer, external_id: Option<&str>, name: &str) -> String {
    let mut resource = json!({"userName": name, "active": true});
    if let Some(external_id) = external_id {
        resource["externalId"] = json!(external_id);
    }
    server.seed_user(resource)
}

fn touched(server: &TestScimServer, downstream_id: &str) -> usize {
    server
        .requests()
        .into_iter()
        .filter(|r| {
            r.path.ends_with(&format!("/{downstream_id}"))
                && matches!(r.method.as_str(), "PATCH" | "DELETE" | "PUT")
        })
        .count()
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn an_edited_downstream_user_has_its_digest_cleared_and_the_next_sync_patches_it_back() {
    let w = World::new().await;
    let (target, user, downstream_id) = synced_user(&w, |_| {}).await;
    w.server
        .edit_user(&downstream_id, "userName", json!("mallory"));

    let report = ran(&w, &target).await;
    assert_eq!(report.drift_cleared, 1);
    assert_eq!(report.listing, Listing::Complete);
    assert!(!report.is_failure());
    assert!(
        link_of(&w, &target, ScimResourceType::User, user.id)
            .await
            .unwrap()
            .synced_digest
            .is_none(),
        "the digest is cleared so that the next sync sends"
    );
    // Reconciliation sent nothing itself: it only reads, queues and repairs the
    // link.
    assert!(w.server.requests_of("PATCH", "/scim/v2/").is_empty());

    assert!(all_delivered(&w.sync().await));
    let patches = w.server.requests_of("PATCH", "/scim/v2/Users/");
    assert_eq!(patches.len(), 1, "one PATCH, not one per reference");
    assert_eq!(w.server.user(&downstream_id).unwrap()["userName"], "alice");
    assert!(
        link_of(&w, &target, ScimResourceType::User, user.id)
            .await
            .unwrap()
            .synced_digest
            .is_some()
    );
}

#[actix_rt::test]
async fn an_unchanged_downstream_is_not_patched_and_attributes_it_owns_are_not_drift() {
    let w = World::new().await;
    let (target, _user, downstream_id) = synced_user(&w, |_| {}).await;
    w.server
        .edit_user(&downstream_id, "title", json!("Engineer"));

    let report = ran(&w, &target).await;
    assert_eq!(report.drift_cleared, 0);
    assert_eq!(report.links_dropped, 0);
    assert_eq!(report.deprovisioned, 0);
    assert!(all_delivered(&w.sync().await));
    assert!(
        w.server.requests_of("PATCH", "/scim/v2/").is_empty(),
        "nothing differs in a mapped attribute"
    );
    assert_eq!(
        w.server.user(&downstream_id).unwrap()["title"],
        "Engineer",
        "the downstream's own attribute is left alone"
    );
}

#[actix_rt::test]
async fn a_pushed_group_that_drifted_is_repaired() {
    let w = World::new().await;
    let target = w
        .add_target(|t| {
            t.push_groups = true;
        })
        .await;
    let alice = w.active_user("alice").await;
    let group = w.group("staff").await;
    w.groups
        .add_member(w.tenant_id, alice.id, group)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    let group_link = link_of(&w, &target, ScimResourceType::Group, group)
        .await
        .expect("group linked");
    w.server.clear_requests();
    w.queue.clear();

    // The downstream's administrator empties the group.
    let downstream = w.server.group_by_external_id(&group.to_string()).unwrap();
    assert_eq!(downstream["id"], group_link.downstream_id);
    assert_eq!(downstream["members"].as_array().unwrap().len(), 1);
    w.server
        .edit_group(&group_link.downstream_id, "members", json!([]));

    let report = ran(&w, &target).await;
    assert_eq!(report.drift_cleared, 1);
    assert!(all_delivered(&w.sync().await));
    let restored = w.server.group_by_external_id(&group.to_string()).unwrap();
    assert_eq!(restored["members"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Gone downstream
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_downstream_resource_that_is_gone_loses_its_link_and_is_created_again() {
    let w = World::new().await;
    let (target, user, downstream_id) = synced_user(&w, |_| {}).await;
    w.server.forget_user(&downstream_id);

    let report = ran(&w, &target).await;
    assert_eq!(report.links_dropped, 1);
    assert!(
        link_of(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none()
    );

    assert!(all_delivered(&w.sync().await));
    assert_eq!(
        w.server.requests_of("POST", "/scim/v2/Users").len(),
        1,
        "re-created once"
    );
    let again = link_of(&w, &target, ScimResourceType::User, user.id)
        .await
        .expect("linked again");
    assert_ne!(again.downstream_id, downstream_id);
    assert!(w.server.user(&again.downstream_id).is_some());
}

// ---------------------------------------------------------------------------
// What reconciliation never touches
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_downstream_user_with_a_foreign_or_missing_external_id_is_never_touched() {
    let w = World::new().await;
    let (target, _user, _) = synced_user(&w, |_| {}).await;
    // The application's own accounts: no externalId, one that is no UUID, a UUID
    // that is nobody's, and one that is an AXIAM id of a user that does not exist.
    let foreign = [
        seed_foreign(&w.server, None, "app-admin"),
        seed_foreign(&w.server, Some("legacy-4711"), "legacy"),
        seed_foreign(&w.server, Some(&Uuid::new_v4().to_string()), "random-uuid"),
        seed_foreign(&w.server, Some(""), "empty"),
    ];

    let report = ran(&w, &target).await;
    assert_eq!(report.deprovisioned, 0);
    assert_eq!(report.links_dropped, 0);
    assert!(all_delivered(&w.sync().await));
    for id in &foreign {
        assert_eq!(
            touched(&w.server, id),
            0,
            "no write to an account of the app"
        );
        assert!(w.server.user(id).is_some());
        assert!(
            w.links
                .get_by_downstream_id(w.tenant_id, target.id, ScimResourceType::User, id)
                .await
                .unwrap()
                .is_none(),
            "and no link is made to it"
        );
    }
}

#[actix_rt::test]
async fn a_downstream_user_whose_external_id_is_a_user_of_another_tenant_is_untouched() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    // A user of **another** tenant, disabled (so it would be deprovisioned if it
    // were ours), and one that is erased.
    let other_tenant = Uuid::new_v4();
    let create = |name: &str| CreateUser {
        tenant_id: other_tenant,
        username: name.into(),
        email: format!("{name}@example.com"),
        password: axiam_test_support::test_password(),
        metadata: None,
    };
    let disabled = w.users.create(create("mallory")).await.unwrap();
    let erased = w.users.create(create("trent")).await.unwrap();
    w.users
        .anonymize_user(
            other_tenant,
            erased.id,
            &Uuid::new_v4().simple().to_string(),
            "DELETED_USER_x",
        )
        .await
        .unwrap();
    w.queue.clear();
    let theirs = [
        seed_foreign(&w.server, Some(&disabled.id.to_string()), "mallory"),
        seed_foreign(&w.server, Some(&erased.id.to_string()), "trent"),
    ];

    let report = ran(&w, &target).await;
    assert_eq!(report.deprovisioned, 0);
    assert!(all_delivered(&w.sync().await));
    for id in &theirs {
        assert_eq!(touched(&w.server, id), 0);
        assert_eq!(w.server.user(id).unwrap()["active"], true);
    }
    assert!(w.server.requests_of("DELETE", "/scim/v2/").is_empty());
    assert!(w.server.requests_of("PATCH", "/scim/v2/").is_empty());
}

// ---------------------------------------------------------------------------
// What it deprovisions
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_downstream_user_that_is_an_out_of_scope_user_of_this_tenant_is_deprovisioned() {
    let w = World::new().await;
    let group = w.group("provisioned").await;
    let target = w
        .add_target(|t| {
            t.scope = ScimTargetScope::Groups(vec![group]);
        })
        .await;
    let outsider = w.active_user("outsider").await;
    w.queue.clear();
    // Somebody created the account downstream by hand, with our id.
    let downstream_id = seed_foreign(&w.server, Some(&outsider.id.to_string()), "outsider");

    let report = ran(&w, &target).await;
    assert_eq!(report.deprovisioned, 1);
    assert!(all_delivered(&w.sync().await));

    // Deactivated, not deleted (the target's policy), and now linked.
    let patches = w
        .server
        .requests_of("PATCH", &format!("/scim/v2/Users/{downstream_id}"));
    assert_eq!(patches.len(), 1);
    assert_eq!(w.server.user(&downstream_id).unwrap()["active"], false);
    let link = link_of(&w, &target, ScimResourceType::User, outsider.id)
        .await
        .expect("adopted");
    assert_eq!(link.downstream_id, downstream_id);
    assert_eq!(link.state, ScimLinkState::Deprovisioned);

    // A second run finds it deactivated and does nothing more.
    w.server.clear_requests();
    w.queue.clear();
    let _ = w.states.get(w.tenant_id, target.id).await.unwrap();
    expire_claim(&w, &target).await;
    let again = ran(&w, &target).await;
    assert_eq!(again.deprovisioned, 0);
    assert!(all_delivered(&w.sync().await));
    assert!(w.server.requests_of("PATCH", "/scim/v2/").is_empty());
}

#[actix_rt::test]
async fn under_the_delete_policy_an_out_of_scope_user_is_deleted_downstream() {
    let w = World::new().await;
    let group = w.group("provisioned").await;
    let target = w
        .add_target(|t| {
            t.scope = ScimTargetScope::Groups(vec![group]);
            t.deprovision = DeprovisionPolicy::Delete;
        })
        .await;
    let outsider = w.active_user("outsider").await;
    w.queue.clear();
    let downstream_id = seed_foreign(&w.server, Some(&outsider.id.to_string()), "outsider");

    let report = ran(&w, &target).await;
    assert_eq!(report.deprovisioned, 1);
    assert!(all_delivered(&w.sync().await));
    assert!(w.server.user(&downstream_id).is_none());
    assert!(
        link_of(&w, &target, ScimResourceType::User, outsider.id)
            .await
            .is_none()
    );
}

#[actix_rt::test]
async fn a_disabled_user_that_is_still_active_downstream_is_deactivated() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    // Disabled before it was ever pushed (the report was lost, say): it only
    // exists downstream because somebody made it there.
    w.set_status(user.id, UserStatus::Inactive).await;
    w.queue.clear();
    let downstream_id = seed_foreign(&w.server, Some(&user.id.to_string()), "alice");

    let report = ran(&w, &target).await;
    assert_eq!(report.deprovisioned, 1);
    assert!(all_delivered(&w.sync().await));
    assert_eq!(w.server.user(&downstream_id).unwrap()["active"], false);
}

#[actix_rt::test]
async fn an_erased_user_of_this_tenant_that_survives_downstream_is_deleted() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    w.users
        .anonymize_user(
            w.tenant_id,
            user.id,
            &Uuid::new_v4().simple().to_string(),
            "DELETED_USER_x",
        )
        .await
        .unwrap();
    w.queue.clear();
    let downstream_id = seed_foreign(&w.server, Some(&user.id.to_string()), "alice");

    let report = ran(&w, &target).await;
    assert_eq!(report.deprovisioned, 1);
    assert!(all_delivered(&w.sync().await));
    assert!(w.server.user(&downstream_id).is_none());
}

// ---------------------------------------------------------------------------
// Pending erasures
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_pending_erasure_is_retried_by_reconciliation_until_the_delete_succeeds() {
    let w = World::new().await;
    let (target, user, downstream_id) = synced_user(&w, |_| {}).await;
    w.users
        .anonymize_user(
            w.tenant_id,
            user.id,
            &Uuid::new_v4().simple().to_string(),
            "DELETED_USER_x",
        )
        .await
        .unwrap();
    // The downstream refuses the erasure for good: a dead letter.
    w.server.fail_next_on("DELETE", "/scim/v2/Users/", 1, 403);
    let outcome = only(w.sync().await);
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));
    let pending = link_of(&w, &target, ScimResourceType::User, user.id)
        .await
        .expect("the link survives the refused erasure");
    assert!(pending.erase_pending);
    assert_eq!(pending.state, ScimLinkState::Deprovisioned);
    assert!(w.server.user(&downstream_id).is_some());

    // The downstream is healthy again; the nightly run finds the pending link.
    w.queue.clear();
    let report = ran(&w, &target).await;
    assert_eq!(report.erase_retried, 1);
    assert!(all_delivered(&w.sync().await));
    assert!(w.server.user(&downstream_id).is_none());
    assert!(
        link_of(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_none(),
        "the link goes with the successful DELETE"
    );
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------

/// Make the target claimable again, as if the last run were old.
async fn expire_claim(w: &World, target: &ScimTarget) {
    w.db.query(
        "UPDATE type::record('scim_target_state', $id) SET \
         last_reconciled_at = time::now() - 25h, reconcile_claimed_at = time::now() - 25h",
    )
    .bind(("id", target.id.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
}

#[actix_rt::test]
async fn a_second_run_within_the_interval_is_already_claimed_and_does_nothing() {
    let w = World::new().await;
    let (target, _user, _) = synced_user(&w, |_| {}).await;

    assert!(matches!(
        w.deliverer
            .reconcile_now(w.tenant_id, target.id)
            .await
            .unwrap(),
        ReconcileOutcome::Ran(_)
    ));
    w.server.clear_requests();
    w.queue.clear();
    assert_eq!(
        w.deliverer
            .reconcile_now(w.tenant_id, target.id)
            .await
            .unwrap(),
        ReconcileOutcome::AlreadyClaimed
    );
    assert!(
        w.server.requests().is_empty(),
        "a claimed run reads nothing from the downstream"
    );
    assert_eq!(w.queue.pending_len(), 0, "and queues nothing");

    // The state shows the claim.
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert!(state.last_reconciled_at.is_some());
    assert!(state.reconcile_claimed_at.is_some());
}

#[actix_rt::test]
async fn two_concurrent_requests_make_one_run() {
    let w = World::new().await;
    let (target, _user, _) = synced_user(&w, |_| {}).await;
    let (a, b) = tokio::join!(
        w.deliverer.reconcile_now(w.tenant_id, target.id),
        w.deliverer.reconcile_now(w.tenant_id, target.id),
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    let runs = outcomes
        .iter()
        .filter(|o| matches!(o, ReconcileOutcome::Ran(_)))
        .count();
    assert_eq!(runs, 1, "exactly one of two concurrent callers runs");
    assert!(outcomes.contains(&ReconcileOutcome::AlreadyClaimed));
}

#[actix_rt::test]
async fn the_scheduled_job_runs_a_due_target_once_a_day_and_the_on_demand_entry_sees_its_claim() {
    let w = World::new().await;
    let (target, _user, _) = synced_user(&w, |_| {}).await;
    let never = || false;

    // Due (never run): the scheduled pass runs it.
    let sweep = w.deliverer.run_due(&never).await.unwrap();
    assert_eq!((sweep.reconciled, sweep.failed), (1, 0));
    // A moment later: not due, and an on-demand request is claimed too.
    let again = w.deliverer.run_due(&never).await.unwrap();
    assert_eq!(again.reconciled, 0);
    assert_eq!(
        w.deliverer
            .reconcile_now(w.tenant_id, target.id)
            .await
            .unwrap(),
        ReconcileOutcome::AlreadyClaimed
    );
    // A day later, due again.
    w.db.query(
        "UPDATE type::record('scim_target_state', $id) SET \
         last_reconciled_at = time::now() - 25h",
    )
    .bind(("id", target.id.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    let next = w.deliverer.run_due(&never).await.unwrap();
    assert_eq!(next.reconciled, 1);

    // A stop request ends the pass before any target.
    w.db.query(
        "UPDATE type::record('scim_target_state', $id) SET \
         last_reconciled_at = time::now() - 25h",
    )
    .bind(("id", target.id.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    let stopped = w.deliverer.run_due(&|| true).await.unwrap();
    assert_eq!(stopped.reconciled, 0);
}

#[actix_rt::test]
async fn a_disabled_target_is_not_reconciled_and_its_claim_is_not_taken() {
    let w = World::new().await;
    let target = w
        .add_target(|t| {
            t.enabled = false;
        })
        .await;
    assert_eq!(
        w.deliverer
            .reconcile_now(w.tenant_id, target.id)
            .await
            .unwrap(),
        ReconcileOutcome::TargetDisabled
    );
    assert!(
        w.states
            .get(w.tenant_id, target.id)
            .await
            .unwrap()
            .last_reconciled_at
            .is_none()
    );
    // Scheduled pass: not even listed.
    let sweep = w.deliverer.run_due(&|| false).await.unwrap();
    assert_eq!(sweep.reconciled, 0);
    // A target that does not exist (or is another tenant's) is `NotFound`.
    assert!(matches!(
        w.deliverer
            .reconcile_now(Uuid::new_v4(), target.id)
            .await
            .unwrap_err(),
        axiam_core::error::AxiamError::NotFound { .. }
    ));
}

// ---------------------------------------------------------------------------
// Budgets and failures
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_downstream_with_endless_pages_is_read_to_the_page_budget_and_no_link_is_dropped_for_it()
{
    let w = World::new().await;
    let (target, user, downstream_id) = synced_user(&w, |_| {}).await;
    w.server.set_endless_lists();

    let report = ran(&w, &target).await;
    assert_eq!(report.listing, Listing::BudgetExhausted);
    assert_eq!(report.pages, RECONCILE_MAX_PAGES);
    assert!(
        !report.is_failure(),
        "a budget is a partial audit, not a failure"
    );
    let lists = w.server.requests_of("GET", "/scim/v2/Users");
    assert_eq!(
        lists.len() as u32,
        RECONCILE_MAX_PAGES,
        "the budget bounds the requests"
    );
    assert!(lists[0].query.contains("startIndex=1") && lists[0].query.contains("count=100"));
    assert!(lists[1].query.contains("startIndex=101"));

    // The listing was cut short, so the linked user's absence from it means
    // nothing: its link stays.
    assert_eq!(report.links_dropped, 0);
    assert_eq!(
        link_of(&w, &target, ScimResourceType::User, user.id)
            .await
            .unwrap()
            .downstream_id,
        downstream_id
    );
}

#[actix_rt::test]
async fn a_large_downstream_is_read_in_pages_of_a_hundred() {
    let w = World::new().await;
    let (target, _user, _) = synced_user(&w, |_| {}).await;
    for n in 0..230 {
        seed_foreign(&w.server, Some(&format!("app-{n}")), &format!("app-{n}"));
    }
    let report = ran(&w, &target).await;
    assert_eq!(report.listing, Listing::Complete);
    // 231 users: three pages.
    assert_eq!(report.pages, 3);
    let queries: Vec<String> = w
        .server
        .requests_of("GET", "/scim/v2/Users")
        .into_iter()
        .map(|r| r.query)
        .collect();
    assert_eq!(queries.len(), 3);
    assert!(queries[2].contains("startIndex=201"));
    assert_eq!(report.links_dropped, 0, "a linked user on page one is seen");
}

#[actix_rt::test]
async fn an_unreachable_downstream_fails_the_run_without_dropping_anything() {
    let w = World::new().await;
    let (target, user, _) = synced_user(&w, |_| {}).await;
    w.server.fail_next_on("GET", "/scim/v2/Users", 1, 500);

    let report = ran(&w, &target).await;
    assert!(matches!(report.listing, Listing::Failed(_)));
    assert!(report.is_failure());
    assert_eq!(report.links_dropped, 0);
    assert!(
        link_of(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_some()
    );
    // A fixed phrase: no URL, no body.
    if let Listing::Failed(reason) = &report.listing {
        assert!(!reason.contains("127.0.0.1") && !reason.contains("scim/v2"));
    }
    // The scheduled pass reports it as an incomplete run.
    expire_claim(&w, &target).await;
    w.server.fail_next_on("GET", "/scim/v2/Users", 1, 500);
    let sweep = w.deliverer.run_due(&|| false).await.unwrap();
    assert_eq!((sweep.reconciled, sweep.failed), (1, 1));
}

#[actix_rt::test]
async fn every_request_of_a_run_is_a_credentialed_scim_list_call() {
    let w = World::new().await;
    let (target, _user, _) = synced_user(&w, |t| {
        t.push_groups = true;
    })
    .await;
    ran(&w, &target).await;
    let requests = w.server.requests();
    assert!(!requests.is_empty());
    for request in &requests {
        assert_eq!(request.method, "GET", "reconciliation only reads");
        assert_eq!(request.authorization_scheme.as_deref(), Some("Bearer"));
        assert_eq!(request.accept.as_deref(), Some("application/scim+json"));
    }
    assert!(!w.server.requests_of("GET", "/scim/v2/Groups").is_empty());
}

#[actix_rt::test]
async fn the_production_deliverer_reads_no_loopback_downstream() {
    let w = World::new().await;
    let (target, user, _) = synced_user(&w, |_| {}).await;
    let production = w.production_deliverer();
    let report = match production
        .reconcile_now(w.tenant_id, target.id)
        .await
        .unwrap()
    {
        ReconcileOutcome::Ran(report) => report,
        other => panic!("a run was expected, got {other:?}"),
    };
    assert!(matches!(report.listing, Listing::Failed(_)));
    assert!(
        w.server.requests().is_empty(),
        "nothing reached the loopback"
    );
    assert!(
        link_of(&w, &target, ScimResourceType::User, user.id)
            .await
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// Dead letters are counted once
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_dead_letter_writes_the_counter_and_the_reason_once() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
    w.server.fail_next(1, 403);
    let message = reference_message(w.tenant_id, target.id, ScimResourceType::User, user.id);
    let outcome = support::outcome(w.deliverer.deliver_attempt(&message).await);
    assert!(matches!(outcome, DeliveryOutcome::DeadLetter { .. }));

    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(state.dead_lettered_total, 1, "once, not once per layer");
    assert!(state.last_failure_at.is_some());
    assert!(
        state
            .last_failure_reason
            .as_deref()
            .is_some_and(|r| r.contains("403"))
    );
    assert_eq!(state.consecutive_failures, 0);
}

#[actix_rt::test]
async fn the_last_retryable_attempt_is_counted_as_the_dead_letter_the_consumer_makes_of_it() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    w.queue.clear();
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
    // Attempts 1 and 2 of 3: failures that will be retried.
    for attempt in [0u32, 1] {
        message.attempt = attempt;
        w.server.fail_next(1, 503);
        let outcome = support::outcome(deliverer.deliver_attempt(&message).await);
        assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
    }
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(
        (state.consecutive_failures, state.dead_lettered_total),
        (2, 0)
    );

    // Attempt 3 of 3: the consumer dead-letters whatever the deliverer says.
    message.attempt = 2;
    w.server.fail_next(1, 503);
    let outcome = support::outcome(deliverer.deliver_attempt(&message).await);
    assert!(matches!(outcome, DeliveryOutcome::Retry { .. }));
    let state = w.states.get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(
        (state.consecutive_failures, state.dead_lettered_total),
        (2, 1),
        "counted as a dead letter, once, and not as one more failure"
    );
}

// ---------------------------------------------------------------------------
// Nothing about a person is kept
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn reconciliation_queues_references_only() {
    let w = World::new().await;
    let group = w
        .groups
        .create(CreateGroup {
            tenant_id: w.tenant_id,
            name: "staff".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap();
    let target = w
        .add_target(|t| {
            t.push_groups = true;
        })
        .await;
    let alice = w.active_user("alice").await;
    w.groups
        .add_member(w.tenant_id, alice.id, group.id)
        .await
        .unwrap();
    assert!(all_delivered(&w.sync().await));
    w.queue.clear();

    ran(&w, &target).await;
    let queued = w.queue.all();
    assert!(!queued.is_empty());
    for message in &queued {
        let payload = message.payload.as_object().unwrap();
        let mut members: Vec<&str> = payload.keys().map(String::as_str).collect();
        members.sort_unstable();
        assert_eq!(members, ["axiam_id", "resource_type"]);
        assert_eq!(message.attempt, 0);
    }
    let text = serde_json::to_string(&queued).unwrap();
    for person in ["alice", "example.com", "Given"] {
        assert!(!text.contains(person), "{person}");
    }
    // One reference per resource (the user and the group), each queued once.
    assert_eq!(queued.len(), 2);
}
