//! Integration tests for `SurrealNotificationRuleRepository` CRUD and the
//! `get_by_event`/`get_by_events` matching branches, using in-memory
//! SurrealDB.

use axiam_core::models::notification_rule::{
    CreateNotificationRule, NotificationEventType, UpdateNotificationRule,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{
    NotificationRuleRepository, OrganizationRepository, Pagination, TenantRepository,
};
use axiam_db::repository::{
    SurrealNotificationRuleRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
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
            name: "Tenant".into(),
            slug: "tenant-nr".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id)
}

fn create_input(tenant_id: Uuid, name: &str, events: Vec<NotificationEventType>) -> CreateNotificationRule {
    CreateNotificationRule {
        tenant_id,
        name: name.into(),
        description: "d".into(),
        events,
        recipient_emails: vec!["admin@example.com".into()],
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
    assert_eq!(updated.recipient_emails, vec!["ops@example.com".to_string()]);
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
