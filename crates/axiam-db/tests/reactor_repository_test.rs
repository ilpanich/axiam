//! Integration tests for [`SurrealReactorRepository`] (X1) against a real
//! in-memory SurrealDB with the v29 migration applied.
//!
//! The point of running these against the database rather than a double is the
//! half that only the database can enforce: the v29 `ASSERT`s, the UNIQUE index
//! on `(tenant_id, name)`, and the ordering the dispatcher's chain depends on.

use axiam_core::models::reactor::{
    CreateReactor, FailurePolicy, MAX_TIMEOUT_MS, ReactorMode, UpdateReactor,
};
use axiam_core::repository::{Pagination, ReactorRepository};
use axiam_db::repository::SurrealReactorRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> (SurrealReactorRepository<Db>, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    (SurrealReactorRepository::new(db), Uuid::new_v4())
}

fn create(tenant_id: Uuid, name: &str, events: &[&str], mode: ReactorMode) -> CreateReactor {
    CreateReactor {
        tenant_id,
        name: name.into(),
        description: String::new(),
        events: events.iter().map(|e| e.to_string()).collect(),
        mode,
        priority: 0,
        timeout_ms: None,
        failure_policy: None,
        enabled: true,
    }
}

#[tokio::test]
async fn a_reactor_round_trips_through_create_and_get() {
    let (repo, tenant) = setup().await;

    let made = repo
        .create(create(
            tenant,
            "hr-enrichment",
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await
        .unwrap();

    let fetched = repo.get_by_id(tenant, made.id).await.unwrap();
    assert_eq!(fetched.id, made.id);
    assert_eq!(fetched.name, "hr-enrichment");
    assert_eq!(fetched.events, vec!["token.pre_issue"]);
    assert_eq!(fetched.mode, ReactorMode::Intercept);
    assert!(fetched.enabled);
    assert!(
        fetched.last_seen_at.is_none(),
        "a reactor that has never connected must be distinguishable from one that has"
    );
}

/// An omitted `failure_policy` takes the strictest default among the events —
/// asserted end to end, because the default is computed in the repository and
/// a caller registering a veto hook must not have to know to ask for
/// fail_closed.
#[tokio::test]
async fn an_omitted_failure_policy_takes_the_strictest_event_default() {
    let (repo, tenant) = setup().await;

    let enrich = repo
        .create(create(
            tenant,
            "enrich-only",
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await
        .unwrap();
    assert_eq!(enrich.failure_policy, FailurePolicy::FailOpen);

    let mixed = repo
        .create(create(
            tenant,
            "enrich-and-veto",
            &["token.pre_issue", "login.post_auth"],
            ReactorMode::Intercept,
        ))
        .await
        .unwrap();
    assert_eq!(
        mixed.failure_policy,
        FailurePolicy::FailClosed,
        "a reactor that can veto a login must fail closed even though it also enriches tokens"
    );
}

/// The v29 `ASSERT` is what keeps the column honest when a write bypasses the
/// API. This asserts the database refuses it, not that the API happens not to
/// send it.
#[tokio::test]
async fn the_schema_refuses_an_out_of_range_timeout_and_a_bogus_mode() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let base = "CREATE type::record('reactor', $id) SET \
                tenant_id = 't', name = $name, description = '', \
                events = ['token.pre_issue'], mode = $mode, priority = 0, \
                timeout_ms = $timeout, failure_policy = $policy, enabled = true, \
                created_at = time::now(), updated_at = time::now()";

    let over_ceiling = db
        .query(base)
        .bind(("id", Uuid::new_v4().to_string()))
        .bind(("name", "too-slow"))
        .bind(("mode", "intercept"))
        .bind(("timeout", i64::from(MAX_TIMEOUT_MS) + 1))
        .bind(("policy", "fail_closed"))
        .await
        .and_then(|r| r.check());
    assert!(
        over_ceiling.is_err(),
        "the schema must refuse a timeout above MAX_TIMEOUT_MS ({MAX_TIMEOUT_MS})"
    );

    let bogus_mode = db
        .query(base)
        .bind(("id", Uuid::new_v4().to_string()))
        .bind(("name", "confused"))
        .bind(("mode", "supervisor"))
        .bind(("timeout", 500_i64))
        .bind(("policy", "fail_closed"))
        .await
        .and_then(|r| r.check());
    assert!(
        bogus_mode.is_err(),
        "the schema must refuse an unknown mode"
    );

    let bogus_policy = db
        .query(base)
        .bind(("id", Uuid::new_v4().to_string()))
        .bind(("name", "hopeful"))
        .bind(("mode", "intercept"))
        .bind(("timeout", 500_i64))
        .bind(("policy", "fail_maybe"))
        .await
        .and_then(|r| r.check());
    assert!(
        bogus_policy.is_err(),
        "the schema must refuse an unknown failure_policy"
    );
}

/// A duplicate name must not silently double the interceptor chain.
#[tokio::test]
async fn a_tenants_reactor_names_are_unique() {
    let (repo, tenant) = setup().await;

    repo.create(create(
        tenant,
        "dedupe-me",
        &["token.pre_issue"],
        ReactorMode::Intercept,
    ))
    .await
    .unwrap();

    let again = repo
        .create(create(
            tenant,
            "dedupe-me",
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await;
    assert!(
        again.is_err(),
        "a duplicate name within a tenant must be refused"
    );

    // …but the same name in another tenant is a different reactor.
    let other_tenant = Uuid::new_v4();
    assert!(
        repo.create(create(
            other_tenant,
            "dedupe-me",
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await
        .is_ok()
    );
}

/// The order this returns IS the order interceptors run in, so it has to be a
/// total order — priority first, then id. Two reactors at the same priority
/// must not chain differently on different replicas.
#[tokio::test]
async fn enabled_by_event_returns_a_total_order_and_excludes_the_disabled() {
    let (repo, tenant) = setup().await;

    let mut low = create(tenant, "low", &["token.pre_issue"], ReactorMode::Intercept);
    low.priority = 1;
    let low = repo.create(low).await.unwrap();

    let mut high = create(tenant, "high", &["token.pre_issue"], ReactorMode::Intercept);
    high.priority = 9;
    let high = repo.create(high).await.unwrap();

    let mut off = create(tenant, "off", &["token.pre_issue"], ReactorMode::Intercept);
    off.enabled = false;
    off.priority = 0;
    repo.create(off).await.unwrap();

    // Subscribed to a different event entirely.
    repo.create(create(
        tenant,
        "elsewhere",
        &["grant.pre_assign"],
        ReactorMode::Intercept,
    ))
    .await
    .unwrap();

    let chain = repo
        .get_enabled_by_event(tenant, "token.pre_issue")
        .await
        .unwrap();

    let names: Vec<&str> = chain.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["low", "high"],
        "disabled and other-event reactors must not appear, and priority must order the rest"
    );
    assert_eq!(chain[0].id, low.id);
    assert_eq!(chain[1].id, high.id);
}

/// Ties break by id, so the same rule set produces the same chain twice.
#[tokio::test]
async fn reactors_at_equal_priority_chain_in_a_stable_order() {
    let (repo, tenant) = setup().await;

    for name in ["c", "a", "b", "d"] {
        repo.create(create(
            tenant,
            name,
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await
        .unwrap();
    }

    let first = repo
        .get_enabled_by_event(tenant, "token.pre_issue")
        .await
        .unwrap();
    let second = repo
        .get_enabled_by_event(tenant, "token.pre_issue")
        .await
        .unwrap();

    let ids =
        |v: &[axiam_core::models::reactor::Reactor]| v.iter().map(|r| r.id).collect::<Vec<_>>();
    assert_eq!(ids(&first), ids(&second));
    assert_eq!(first.len(), 4);
}

/// Cross-tenant isolation on the path the dispatcher actually uses.
#[tokio::test]
async fn a_reactor_is_invisible_to_another_tenant() {
    let (repo, tenant) = setup().await;
    let intruder = Uuid::new_v4();

    let mine = repo
        .create(create(
            tenant,
            "mine",
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await
        .unwrap();

    assert!(repo.get_by_id(intruder, mine.id).await.is_err());
    assert!(
        repo.get_enabled_by_event(intruder, "token.pre_issue")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(repo.delete(intruder, mine.id).await.is_err());
    // …and the failed cross-tenant delete really did not delete it.
    assert!(repo.get_by_id(tenant, mine.id).await.is_ok());
}

#[tokio::test]
async fn update_changes_only_the_fields_it_names() {
    let (repo, tenant) = setup().await;

    let made = repo
        .create(create(
            tenant,
            "before",
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant,
            made.id,
            UpdateReactor {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(!updated.enabled);
    assert_eq!(
        updated.name, "before",
        "an unnamed field must be left alone"
    );
    assert_eq!(updated.events, made.events);
    assert_eq!(updated.timeout_ms, made.timeout_ms);
}

/// The heartbeat writes `last_seen_at` without touching `updated_at` — an
/// operator reading "last modified" wants the last configuration change.
#[tokio::test]
async fn touching_last_seen_does_not_bump_updated_at() {
    let (repo, tenant) = setup().await;

    let made = repo
        .create(create(
            tenant,
            "heartbeat",
            &["token.pre_issue"],
            ReactorMode::Listen,
        ))
        .await
        .unwrap();

    repo.touch_last_seen(tenant, made.id).await.unwrap();
    let after = repo.get_by_id(tenant, made.id).await.unwrap();

    assert!(after.last_seen_at.is_some());
    assert_eq!(
        after.updated_at, made.updated_at,
        "a heartbeat is not a configuration change"
    );
}

/// The heartbeat races with deletion by construction — the consumer may be
/// mid-message when an admin removes the registration. That must not become a
/// logged error on every subsequent message.
#[tokio::test]
async fn touching_a_deleted_reactor_is_not_an_error() {
    let (repo, tenant) = setup().await;
    assert!(repo.touch_last_seen(tenant, Uuid::new_v4()).await.is_ok());
}

#[tokio::test]
async fn delete_removes_it_and_is_not_idempotent() {
    let (repo, tenant) = setup().await;

    let made = repo
        .create(create(
            tenant,
            "temporary",
            &["token.pre_issue"],
            ReactorMode::Intercept,
        ))
        .await
        .unwrap();

    repo.delete(tenant, made.id).await.unwrap();
    assert!(repo.get_by_id(tenant, made.id).await.is_err());
    assert!(
        repo.delete(tenant, made.id).await.is_err(),
        "deleting what is not there is a 404, not a success"
    );
}

#[tokio::test]
async fn list_paginates_within_the_tenant() {
    let (repo, tenant) = setup().await;

    for i in 0..5 {
        let mut input = create(
            tenant,
            &format!("r{i}"),
            &["token.pre_issue"],
            ReactorMode::Listen,
        );
        input.priority = i;
        repo.create(input).await.unwrap();
    }
    repo.create(create(
        Uuid::new_v4(),
        "someone-elses",
        &["token.pre_issue"],
        ReactorMode::Listen,
    ))
    .await
    .unwrap();

    let page = repo
        .list(
            tenant,
            Pagination {
                limit: 2,
                offset: 0,
            },
        )
        .await
        .unwrap();

    assert_eq!(page.items.len(), 2);
    assert_eq!(
        page.total, 5,
        "another tenant's reactor must not be counted"
    );
    assert_eq!(page.items[0].name, "r0");
    assert_eq!(page.items[1].name, "r1");
}
