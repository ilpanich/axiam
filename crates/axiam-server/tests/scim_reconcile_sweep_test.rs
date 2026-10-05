//! **T23.6.3** — the cleanup loop's `scim_reconcile` sweep (G-6, D-58) over the
//! real deliverer and the loopback SCIM server of `axiam-scim`'s harness.

#[path = "../../axiam-scim/tests/support/mod.rs"]
mod support;

use axiam_core::models::scim_target::ScimResourceType;
use axiam_core::repository::ScimTargetLinkRepository;
use axiam_server::cleanup::sweep_scim_reconciliation;
use support::{World, all_delivered};
use tokio::sync::watch;

#[actix_rt::test]
async fn the_sweep_reconciles_a_due_target_once_and_reports_a_failed_run() {
    let w = World::new().await;
    let target = w.add_target(|_| {}).await;
    let user = w.active_user("alice").await;
    assert!(all_delivered(&w.sync().await));
    let (_stop, shutdown) = watch::channel(false);

    // A drift the downstream's administrator made: the sweep finds the target
    // due (it was never reconciled), runs it and repairs the link.
    let linked = w
        .links
        .get(w.tenant_id, target.id, ScimResourceType::User, user.id)
        .await
        .unwrap()
        .expect("linked");
    w.server.edit_user(
        &linked.downstream_id,
        "userName",
        serde_json::json!("mallory"),
    );
    assert_eq!(
        sweep_scim_reconciliation(&w.deliverer, &shutdown)
            .await
            .unwrap(),
        1
    );
    assert!(all_delivered(&w.sync().await));
    assert_eq!(
        w.server.user(&linked.downstream_id).unwrap()["userName"],
        "alice"
    );

    // Not due again within the day: the claim refuses, the sweep counts none.
    assert_eq!(
        sweep_scim_reconciliation(&w.deliverer, &shutdown)
            .await
            .unwrap(),
        0
    );
}

#[actix_rt::test]
async fn a_run_that_could_not_read_the_downstream_fails_the_sweep_and_a_shutdown_stops_it() {
    let w = World::new().await;
    w.add_target(|_| {}).await;
    let (stop, shutdown) = watch::channel(false);

    // A stop signalled before the pass starts runs no target.
    stop.send(true).unwrap();
    assert_eq!(
        sweep_scim_reconciliation(&w.deliverer, &shutdown)
            .await
            .unwrap(),
        0
    );
    stop.send(false).unwrap();

    w.server.fail_next_on("GET", "/scim/v2/Users", 1, 403);
    let failed = sweep_scim_reconciliation(&w.deliverer, &shutdown).await;
    let message = failed
        .expect_err("an incomplete run fails the sweep")
        .to_string();
    assert!(message.contains("incomplete"), "{message}");
}
