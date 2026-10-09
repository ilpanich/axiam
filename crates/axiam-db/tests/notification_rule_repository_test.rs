//! Integration tests for `SurrealNotificationRuleRepository` CRUD and the
//! `get_by_event`/`get_by_events` matching branches, using in-memory
//! SurrealDB.

use axiam_core::models::notification_rule::{
    CreateNotificationRule, DEFAULT_NOTIFICATION_WINDOW_MINUTES, NotificationEventType,
    NotificationWindowClaim, UpdateNotificationRule,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    NotificationRuleRepository, NotificationWindowRepository, OrganizationRepository, Pagination,
    TenantRepository,
};
use axiam_db::repository::{
    SurrealNotificationRuleRepository, SurrealNotificationWindowRepository,
    SurrealOrganizationRepository, SurrealTenantRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org-nr".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: "tenant-nr".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id)
}

fn create_input(
    tenant_id: Uuid,
    name: &str,
    events: Vec<NotificationEventType>,
) -> CreateNotificationRule {
    CreateNotificationRule {
        tenant_id,
        name: name.into(),
        description: "d".into(),
        events,
        recipient_emails: vec!["admin@example.com".into()],
        window_minutes: None,
    }
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_by_id() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let rule = repo
        .create(create_input(
            tenant_id,
            "on-login-failure",
            vec![NotificationEventType::LoginFailure],
        ))
        .await
        .unwrap();
    assert!(rule.enabled, "newly created rules default to enabled");

    let got = repo.get_by_id(tenant_id, rule.id).await.unwrap();
    assert_eq!(got.name, "on-login-failure");
    assert_eq!(got.events, vec![NotificationEventType::LoginFailure]);
}

#[tokio::test]
async fn get_by_id_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let result = repo.get_by_id(tenant_id, Uuid::new_v4()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn update_partial_fields() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let rule = repo
        .create(create_input(
            tenant_id,
            "to-update",
            vec![NotificationEventType::UserCreated],
        ))
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            rule.id,
            UpdateNotificationRule {
                name: Some("renamed".into()),
                enabled: Some(false),
                events: Some(vec![
                    NotificationEventType::UserCreated,
                    NotificationEventType::UserDeleted,
                ]),
                recipient_emails: Some(vec!["ops@example.com".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.name, "renamed");
    assert!(!updated.enabled);
    assert_eq!(
        updated.recipient_emails,
        vec!["ops@example.com".to_string()]
    );
    assert_eq!(updated.events.len(), 2);
}

#[tokio::test]
async fn update_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let result = repo
        .update(
            tenant_id,
            Uuid::new_v4(),
            UpdateNotificationRule {
                name: Some("x".into()),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn delete_removes_rule() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let rule = repo
        .create(create_input(
            tenant_id,
            "to-delete",
            vec![NotificationEventType::RoleAssigned],
        ))
        .await
        .unwrap();

    repo.delete(tenant_id, rule.id).await.unwrap();
    assert!(repo.get_by_id(tenant_id, rule.id).await.is_err());
}

#[tokio::test]
async fn delete_not_found_errors() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let result = repo.delete(tenant_id, Uuid::new_v4()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn list_with_pagination() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    for i in 0..3 {
        repo.create(create_input(
            tenant_id,
            &format!("rule-{i}"),
            vec![NotificationEventType::UserUpdated],
        ))
        .await
        .unwrap();
    }

    let page = repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 2,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 2);
}

// ---------------------------------------------------------------------------
// get_by_event / get_by_events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_event_matches_enabled_rules_only() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let matching = repo
        .create(create_input(
            tenant_id,
            "matching",
            vec![NotificationEventType::CertificateRevoked],
        ))
        .await
        .unwrap();

    let disabled = repo
        .create(create_input(
            tenant_id,
            "disabled-rule",
            vec![NotificationEventType::CertificateRevoked],
        ))
        .await
        .unwrap();
    repo.update(
        tenant_id,
        disabled.id,
        UpdateNotificationRule {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let results = repo
        .get_by_event(tenant_id, "certificate_revoked")
        .await
        .unwrap();
    let ids: Vec<Uuid> = results.iter().map(|r| r.id).collect();
    assert!(ids.contains(&matching.id));
    assert!(
        !ids.contains(&disabled.id),
        "disabled rules must not be returned"
    );
}

#[tokio::test]
async fn get_by_event_no_match_returns_empty() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    repo.create(create_input(
        tenant_id,
        "unrelated",
        vec![NotificationEventType::UserCreated],
    ))
    .await
    .unwrap();

    let results = repo
        .get_by_event(tenant_id, "certificate_revoked")
        .await
        .unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn get_by_events_empty_input_returns_empty_without_querying() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    repo.create(create_input(
        tenant_id,
        "any-rule",
        vec![NotificationEventType::UserCreated],
    ))
    .await
    .unwrap();

    let results = repo.get_by_events(tenant_id, &[]).await.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn get_by_events_matches_any_shared_event() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db);

    let rule = repo
        .create(create_input(
            tenant_id,
            "multi-event-rule",
            vec![
                NotificationEventType::UserCreated,
                NotificationEventType::UserDeleted,
            ],
        ))
        .await
        .unwrap();

    let results = repo
        .get_by_events(
            tenant_id,
            &["user_deleted".to_string(), "role_assigned".to_string()],
        )
        .await
        .unwrap();
    assert!(results.iter().any(|r| r.id == rule.id));
}

// ---------------------------------------------------------------------------
// The notification window (#551, T-117)
// ---------------------------------------------------------------------------

/// A rule stores its window; one created without one has the default, and an
/// update changes it. A rule written before schema v85 (no column) reads the
/// default.
#[tokio::test]
async fn a_rule_stores_its_window_and_defaults_it() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db.clone());

    let default = repo
        .create(create_input(
            tenant_id,
            "default-window",
            vec![NotificationEventType::LoginFailure],
        ))
        .await
        .unwrap();
    assert_eq!(default.window_minutes, DEFAULT_NOTIFICATION_WINDOW_MINUTES);

    let mut input = create_input(
        tenant_id,
        "hourly",
        vec![NotificationEventType::LoginFailure],
    );
    input.window_minutes = Some(60);
    let hourly = repo.create(input).await.unwrap();
    assert_eq!(hourly.window_minutes, 60);
    assert_eq!(
        repo.get_by_id(tenant_id, hourly.id)
            .await
            .unwrap()
            .window_minutes,
        60
    );

    let updated = repo
        .update(
            tenant_id,
            hourly.id,
            UpdateNotificationRule {
                window_minutes: Some(5),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.window_minutes, 5);

    // As a rule written before v85 is stored: no window at all.
    db.query("UPDATE type::record('notification_rule', $id) SET window_minutes = NONE")
        .bind(("id", default.id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rules = repo
        .get_by_events(tenant_id, &["login_failure".to_string()])
        .await
        .unwrap();
    let legacy = rules.iter().find(|r| r.id == default.id).unwrap();
    assert_eq!(legacy.window_minutes, DEFAULT_NOTIFICATION_WINDOW_MINUTES);
}

/// The first claim opens the window; the claims inside it are counted; the
/// first claim after it opens the next one and carries the count. Another
/// rule, another event or another tenant is its own window.
#[tokio::test]
async fn a_window_is_claimed_once_and_carries_its_count_into_the_next() {
    let (db, tenant_id) = setup().await;
    let windows = SurrealNotificationWindowRepository::new(db);
    let rule = Uuid::new_v4();
    let now = Utc::now();
    let window = 15 * 60;

    assert_eq!(
        windows
            .claim(tenant_id, rule, "login_failure", now, window)
            .await
            .unwrap(),
        NotificationWindowClaim::Opened { suppressed: 0 }
    );
    for later in [1, 60, window - 1] {
        assert_eq!(
            windows
                .claim(
                    tenant_id,
                    rule,
                    "login_failure",
                    now + Duration::seconds(later),
                    window,
                )
                .await
                .unwrap(),
            NotificationWindowClaim::Counted
        );
    }

    // Each of these is a window of its own.
    for (tenant, rule, event) in [
        (tenant_id, Uuid::new_v4(), "login_failure"),
        (tenant_id, rule, "account_locked"),
        (Uuid::new_v4(), rule, "login_failure"),
    ] {
        assert_eq!(
            windows
                .claim(tenant, rule, event, now, window)
                .await
                .unwrap(),
            NotificationWindowClaim::Opened { suppressed: 0 }
        );
    }

    // The window has run: the next event opens a new one with the count.
    let next = now + Duration::seconds(window);
    assert_eq!(
        windows
            .claim(tenant_id, rule, "login_failure", next, window)
            .await
            .unwrap(),
        NotificationWindowClaim::Opened { suppressed: 3 }
    );
    // And that count was reported: a quiet window carries nothing.
    assert_eq!(
        windows
            .claim(
                tenant_id,
                rule,
                "login_failure",
                next + Duration::seconds(window),
                window,
            )
            .await
            .unwrap(),
        NotificationWindowClaim::Opened { suppressed: 0 }
    );
}

/// Concurrent claimants on one datastore — replicas — open a window once,
/// and every other claim is counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claims_open_a_window_once() {
    let (db, tenant_id) = setup().await;
    let rule = Uuid::new_v4();
    let now = Utc::now();
    let mut claims = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let windows = SurrealNotificationWindowRepository::new(db.clone());
        claims.spawn(async move {
            windows
                .claim(tenant_id, rule, "login_failure", now, 900)
                .await
                .unwrap()
        });
    }
    let claims = claims.join_all().await;
    let opened = claims
        .iter()
        .filter(|c| matches!(c, NotificationWindowClaim::Opened { .. }))
        .count();
    assert_eq!(opened, 1, "{claims:?}");

    // The fifteen others were counted, and the next window reports them.
    assert_eq!(
        SurrealNotificationWindowRepository::new(db)
            .claim(
                tenant_id,
                rule,
                "login_failure",
                now + Duration::seconds(900),
                900,
            )
            .await
            .unwrap(),
        NotificationWindowClaim::Opened { suppressed: 15 }
    );
}

/// Deleting a rule deletes its windows.
#[tokio::test]
async fn deleting_a_rule_deletes_its_windows() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealNotificationRuleRepository::new(db.clone());
    let windows = SurrealNotificationWindowRepository::new(db.clone());
    let rule = repo
        .create(create_input(
            tenant_id,
            "r",
            vec![NotificationEventType::LoginFailure],
        ))
        .await
        .unwrap();
    windows
        .claim(tenant_id, rule.id, "login_failure", Utc::now(), 900)
        .await
        .unwrap();
    repo.delete(tenant_id, rule.id).await.unwrap();
    let mut left = db
        .query("SELECT count() AS n FROM notification_window GROUP ALL")
        .await
        .unwrap();
    let n: Option<i64> = left.take("n").unwrap();
    assert_eq!(n.unwrap_or(0), 0);
}
