//! CRUD + filter + GDPR pseudonymization coverage for
//! `SurrealAuditLogRepository` — this repository carried NO direct tests
//! before this file. Uses the in-memory SurrealDB engine — no external
//! services required.

use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, TenantRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealTenantRepository,
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
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id)
}

fn entry(
    tenant_id: Uuid,
    actor_id: Uuid,
    action: &str,
    outcome: AuditOutcome,
    resource_id: Option<Uuid>,
) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id,
        actor_id,
        actor_type: ActorType::User,
        action: action.into(),
        resource_id,
        outcome,
        ip_address: Some("203.0.113.5".into()),
        metadata: Some(serde_json::json!({"email": "actor@example.com"})),
    }
}

#[tokio::test]
async fn append_and_get_by_ids_preserves_order() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let actor_id = Uuid::new_v4();

    let e1 = repo
        .append(entry(
            tenant_id,
            actor_id,
            "user.login",
            AuditOutcome::Success,
            None,
        ))
        .await
        .unwrap();
    let e2 = repo
        .append(entry(
            tenant_id,
            actor_id,
            "user.logout",
            AuditOutcome::Success,
            None,
        ))
        .await
        .unwrap();
    let e3 = repo
        .append(entry(
            tenant_id,
            actor_id,
            "user.delete",
            AuditOutcome::Denied,
            None,
        ))
        .await
        .unwrap();

    // Query in a deliberately shuffled order — result must mirror caller order.
    let found = repo
        .get_by_ids(tenant_id, &[e3.id, e1.id, e2.id])
        .await
        .unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(found[0].id, e3.id);
    assert_eq!(found[1].id, e1.id);
    assert_eq!(found[2].id, e2.id);
    assert_eq!(found[0].outcome, AuditOutcome::Denied);
}

#[tokio::test]
async fn get_by_ids_silently_skips_unknown_and_cross_tenant_ids() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let actor_id = Uuid::new_v4();

    let e1 = repo
        .append(entry(
            tenant_id,
            actor_id,
            "user.login",
            AuditOutcome::Success,
            None,
        ))
        .await
        .unwrap();

    let unknown = Uuid::new_v4();
    let found = repo.get_by_ids(tenant_id, &[e1.id, unknown]).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, e1.id);

    // Entry exists but under a different tenant — must not be returned.
    let other_tenant = Uuid::new_v4();
    let none_found = repo.get_by_ids(other_tenant, &[e1.id]).await.unwrap();
    assert!(none_found.is_empty());
}

#[tokio::test]
async fn get_by_ids_empty_input_returns_empty() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let found = repo.get_by_ids(tenant_id, &[]).await.unwrap();
    assert!(found.is_empty());
}

#[tokio::test]
async fn list_filters_by_actor_action_outcome_resource_and_time_range() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let actor_a = Uuid::new_v4();
    let actor_b = Uuid::new_v4();
    let resource_x = Uuid::new_v4();

    repo.append(entry(
        tenant_id,
        actor_a,
        "role.create",
        AuditOutcome::Success,
        Some(resource_x),
    ))
    .await
    .unwrap();
    repo.append(entry(
        tenant_id,
        actor_b,
        "role.create",
        AuditOutcome::Failure,
        None,
    ))
    .await
    .unwrap();
    repo.append(entry(
        tenant_id,
        actor_a,
        "role.delete",
        AuditOutcome::Denied,
        Some(resource_x),
    ))
    .await
    .unwrap();

    // actor_id filter
    let by_actor = repo
        .list(
            tenant_id,
            AuditLogFilter {
                actor_id: Some(actor_a),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_actor.total, 2);

    // action filter
    let by_action = repo
        .list(
            tenant_id,
            AuditLogFilter {
                action: Some("role.delete".into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_action.total, 1);
    assert_eq!(by_action.items[0].action, "role.delete");

    // outcome filter
    let by_outcome = repo
        .list(
            tenant_id,
            AuditLogFilter {
                outcome: Some(AuditOutcome::Denied),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_outcome.total, 1);
    assert_eq!(by_outcome.items[0].outcome, AuditOutcome::Denied);

    // resource_id filter
    let by_resource = repo
        .list(
            tenant_id,
            AuditLogFilter {
                resource_id: Some(resource_x),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_resource.total, 2);

    // time-range filter (from/to) — bracket around "now" catches everything.
    let from = Utc::now() - Duration::hours(1);
    let to = Utc::now() + Duration::hours(1);
    let by_range = repo
        .list(
            tenant_id,
            AuditLogFilter {
                from: Some(from),
                to: Some(to),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_range.total, 3);

    // A `to` in the past excludes everything.
    let excluded = repo
        .list(
            tenant_id,
            AuditLogFilter {
                to: Some(Utc::now() - Duration::days(1)),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(excluded.total, 0);
}

#[tokio::test]
async fn list_system_uses_nil_tenant_id() {
    let (db, _tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let actor_id = Uuid::new_v4();

    // System/unauthenticated entries are stored with nil tenant_id.
    repo.append(entry(
        Uuid::nil(),
        actor_id,
        "auth.failed_login",
        AuditOutcome::Failure,
        None,
    ))
    .await
    .unwrap();

    let system_entries = repo
        .list_system(AuditLogFilter::default(), Pagination::default())
        .await
        .unwrap();
    assert_eq!(system_entries.total, 1);
    assert_eq!(system_entries.items[0].action, "auth.failed_login");
}

#[tokio::test]
async fn append_supports_service_account_and_system_actor_types() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);

    let svc = repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::ServiceAccount,
            action: "webhook.deliver".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        })
        .await
        .unwrap();
    assert_eq!(svc.actor_type, ActorType::ServiceAccount);

    let sys = repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::System,
            action: "cleanup.sweep".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        })
        .await
        .unwrap();
    assert_eq!(sys.actor_type, ActorType::System);
    // metadata defaults to an empty object when omitted.
    assert_eq!(sys.metadata, serde_json::json!({}));
}

#[tokio::test]
async fn pseudonymize_actor_scrubs_pii_and_relinks_resource() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let user_id = Uuid::new_v4();
    let other_actor = Uuid::new_v4();

    // Entry authored BY the user (actor_id = user_id).
    let authored = repo
        .append(entry(
            tenant_id,
            user_id,
            "profile.update",
            AuditOutcome::Success,
            None,
        ))
        .await
        .unwrap();

    // Entry authored by someone else ABOUT the user (resource_id = user_id).
    let about = repo
        .append(entry(
            tenant_id,
            other_actor,
            "user.suspend",
            AuditOutcome::Success,
            Some(user_id),
        ))
        .await
        .unwrap();

    let pseudonym = "DELETED_USER_deadbeef";
    let count = repo
        .pseudonymize_actor(tenant_id, user_id, pseudonym)
        .await
        .unwrap();
    assert_eq!(count, 1, "one entry now carries the nil actor_id");

    let refreshed = repo
        .get_by_ids(tenant_id, &[authored.id, about.id])
        .await
        .unwrap();
    let authored_after = refreshed.iter().find(|e| e.id == authored.id).unwrap();
    let about_after = refreshed.iter().find(|e| e.id == about.id).unwrap();

    assert_eq!(authored_after.actor_id, Uuid::nil());
    assert!(authored_after.ip_address.is_none());
    assert_eq!(
        authored_after.metadata["actor_pseudonym"],
        serde_json::json!(pseudonym)
    );
    assert_eq!(
        authored_after.metadata["email"],
        serde_json::json!("[redacted]")
    );

    // The "about" entry's actor is untouched, but its resource_id is nulled.
    assert_eq!(about_after.actor_id, other_actor);
    assert_eq!(about_after.resource_id, Some(Uuid::nil()));
}
