//! The tenant tombstone and purge against the real datastore (#523,
//! P23W2-04, D-4).
//!
//! What lives here rather than in the REST test of the same issue: the
//! repository-level rules — a tombstoned tenant leaves every read, keeps its
//! slug until purged, cannot be updated; the purge refuses a live tenant; and
//! the orphan sweep finds and purges the rows a pre-tombstone deletion left,
//! keeping their audit trail for the retention sweep.

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::settings::TenantSettingsOverride;
use axiam_core::models::tenant::{CreateTenant, TenantKind, UpdateTenant};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AuditLogRepository, OrganizationRepository, Pagination, SessionRepository, SettingsRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::tenant_purge::{TENANT_PURGE_ORDER, TenantKey};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealSessionRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{CountRow, SessionValidationCache};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> (Surreal<Db>, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "tenant-purge".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    (db, org)
}

async fn tenant(db: &Surreal<Db>, org: Uuid, slug: &str) -> Uuid {
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org,
            kind: TenantKind::Standard,
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// A user, a session and one audit entry in `tenant_id`.
async fn populate(db: &Surreal<Db>, tenant_id: Uuid) -> Uuid {
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id: user.id,
            token_hash: format!("refresh-{tenant_id}"),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            amr: Vec::new(),
            browser_token_hash: None,
        })
        .await
        .unwrap();
    SurrealAuditLogRepository::new(db.clone())
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: user.id,
            actor_type: ActorType::User,
            action: "user.signed_in".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        })
        .await
        .unwrap();
    user.id
}

/// Rows naming `tenant_id` in `table` (keyed as the purge keys it).
async fn rows(db: &Surreal<Db>, table: &str, tenant_id: Uuid) -> u64 {
    let step = TENANT_PURGE_ORDER
        .iter()
        .find(|s| s.table == table)
        .expect("a purged table");
    let filter = match step.key {
        TenantKey::TenantId => "tenant_id = $tenant",
        TenantKey::Scope => "scope = 'tenant' AND scope_id = $tenant",
    };
    let mut result = db
        .query(format!(
            "SELECT count() AS total FROM {table} WHERE {filter} GROUP ALL"
        ))
        .bind(("tenant", tenant_id.to_string()))
        .await
        .unwrap();
    let counted: Vec<CountRow> = result.take(0).unwrap();
    counted.first().map_or(0, |r| r.total)
}

/// A tombstoned tenant is gone from every read the repository answers — by
/// id, by slug, in the organization's list, as an update target, in the SSF
/// tenant count and in the settings lookup — while its rows are still there.
#[tokio::test]
async fn a_tombstoned_tenant_leaves_every_read_path_at_once() {
    use axiam_core::models::ssf::DeploymentTenants;

    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let doomed = tenant(&db, org, "doomed").await;
    let kept = tenant(&db, org, "kept").await;
    populate(&db, doomed).await;
    let settings = SurrealSettingsRepository::new(db.clone());
    settings
        .set_tenant_override(doomed, TenantSettingsOverride::default())
        .await
        .unwrap();
    let before = tenants.count_for_shared_issuer().await.unwrap();

    tenants.delete(doomed).await.unwrap();

    assert!(matches!(
        tenants.get_by_id(doomed).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(tenants.get_by_slug(org, "doomed").await.is_err());
    let listed = tenants
        .list_by_organization(
            org,
            Pagination {
                offset: 0,
                limit: 50,
                search: None,
            },
        )
        .await
        .unwrap();
    assert!(listed.items.iter().all(|t| t.id != doomed));
    assert!(listed.items.iter().any(|t| t.id == kept));
    assert_eq!(listed.total, listed.items.len() as u64);
    assert!(
        tenants
            .update(
                doomed,
                UpdateTenant {
                    name: Some("revived".into()),
                    ..Default::default()
                },
            )
            .await
            .is_err(),
        "a tombstoned tenant cannot be updated back to life"
    );
    assert_eq!(tenants.count_for_shared_issuer().await.unwrap(), before - 1);
    assert!(settings.get_tenant_override(doomed).await.is_err());

    // In the same transaction its sessions went; its data waits for the purge.
    assert_eq!(rows(&db, "session", doomed).await, 0);
    assert_eq!(rows(&db, "user", doomed).await, 1);
    assert_eq!(tenants.list_tombstoned().await.unwrap(), vec![doomed]);
    assert!(tenants.get_by_id(kept).await.is_ok());
}

/// The handler's first step: every session of the tenant is revoked and
/// dropped from the validity cache, and no other tenant's.
#[tokio::test]
async fn a_tenants_sessions_are_revoked_in_bulk_and_leave_the_validity_cache() {
    let (db, org) = setup().await;
    let doomed = tenant(&db, org, "doomed").await;
    let kept = tenant(&db, org, "kept").await;
    populate(&db, doomed).await;
    populate(&db, kept).await;

    let cache = std::sync::Arc::new(SessionValidationCache::new(std::time::Duration::from_secs(
        60,
    )));
    let sessions = SurrealSessionRepository::new(db.clone()).with_validation_cache(cache.clone());
    let doomed_user = SurrealUserRepository::new(db.clone())
        .get_by_username(doomed, "alice")
        .await
        .unwrap();
    let session = sessions
        .list_by_user(doomed, doomed_user.id)
        .await
        .unwrap()
        .remove(0);
    assert!(sessions.is_session_active_checked(doomed, session.id).await);
    assert_eq!(cache.get(doomed, session.id), Some(true));

    assert_eq!(
        sessions.invalidate_tenant_sessions(doomed).await.unwrap(),
        1
    );

    assert_eq!(cache.get(doomed, session.id), None);
    assert!(!sessions.is_session_active_checked(doomed, session.id).await);
    assert_eq!(rows(&db, "session", doomed).await, 0);
    assert_eq!(rows(&db, "session", kept).await, 1);
}

/// The slug of a tombstoned tenant stays claimed until the purge: a second
/// tenant asking for it is refused as already existing (`409` at the API),
/// and after the purge it is free.
#[tokio::test]
async fn a_tombstoned_tenants_slug_is_not_reused_until_it_is_purged() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let doomed = tenant(&db, org, "acme").await;
    tenants.delete(doomed).await.unwrap();

    let again = CreateTenant {
        organization_id: org,
        kind: TenantKind::Standard,
        name: "acme".into(),
        slug: "acme".into(),
        metadata: None,
    };
    assert!(matches!(
        tenants.create(again.clone()).await,
        Err(AxiamError::AlreadyExists { .. })
    ));
    tenants.purge_tombstoned(doomed).await.unwrap();
    assert!(tenants.create(again).await.is_ok());
}

/// The purge never removes a live tenant, and removes a tombstoned one's rows
/// — its audit trail included — and then its row, leaving the system log and
/// another tenant alone.
#[tokio::test]
async fn the_purge_refuses_a_live_tenant_and_empties_a_tombstoned_one() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let doomed = tenant(&db, org, "doomed").await;
    let kept = tenant(&db, org, "kept").await;
    populate(&db, doomed).await;
    populate(&db, kept).await;
    let audit = SurrealAuditLogRepository::new(db.clone());
    audit
        .append(CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "tenants.deleted".into(),
            resource_id: Some(doomed),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        })
        .await
        .unwrap();

    assert!(matches!(
        tenants.purge_tombstoned(doomed).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(
        rows(&db, "user", doomed).await,
        1,
        "a live tenant is untouched"
    );

    tenants.delete(doomed).await.unwrap();
    tenants.purge_tombstoned(doomed).await.unwrap();

    for step in TENANT_PURGE_ORDER {
        assert_eq!(rows(&db, step.table, doomed).await, 0, "{}", step.table);
    }
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    assert_eq!(rows(&db, "user", kept).await, 1);
    assert_eq!(rows(&db, "audit_log", kept).await, 1);
    assert_eq!(
        rows(&db, "audit_log", Uuid::nil()).await,
        1,
        "system log kept"
    );
    // Purging again finds nothing to purge.
    assert!(tenants.purge_tombstoned(doomed).await.is_err());
}

/// An upgrader's residue (#523): a deletion made before the tombstone removed
/// the tenant row and nothing else. The orphan sweep finds that tenant id —
/// never a live or tombstoned tenant's, never the system log's — and purges its
/// rows, except its audit trail, which the retention sweep governs.
#[tokio::test]
async fn an_orphaned_tenants_rows_are_found_and_purged_but_its_audit_trail_is_kept() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let orphan = tenant(&db, org, "deleted-long-ago").await;
    let live = tenant(&db, org, "live").await;
    let tombstoned = tenant(&db, org, "tombstoned").await;
    for t in [orphan, live, tombstoned] {
        populate(&db, t).await;
    }
    tenants.delete(tombstoned).await.unwrap();
    // What `SurrealTenantRepository::delete` did before #523.
    db.query("DELETE type::record('tenant', $id)")
        .bind(("id", orphan.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();

    assert_eq!(tenants.orphaned_tenant_ids().await.unwrap(), vec![orphan]);
    assert!(matches!(
        tenants.purge_orphan(live).await,
        Err(AxiamError::Conflict { .. })
    ));
    assert!(matches!(
        tenants.purge_orphan(tombstoned).await,
        Err(AxiamError::Conflict { .. })
    ));

    tenants.purge_orphan(orphan).await.unwrap();
    for step in TENANT_PURGE_ORDER {
        let expected = u64::from(step.table == "audit_log");
        assert_eq!(
            rows(&db, step.table, orphan).await,
            expected,
            "{}",
            step.table
        );
    }
    assert!(tenants.orphaned_tenant_ids().await.unwrap().is_empty());
    assert_eq!(rows(&db, "user", live).await, 1);
    assert_eq!(rows(&db, "user", tombstoned).await, 1);
}
