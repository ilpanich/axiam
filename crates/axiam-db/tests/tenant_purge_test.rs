//! The tenant tombstone and purge against the real datastore (#523,
//! P23W2-04, D-4).
//!
//! What lives here rather than in the REST test of the same issue: the
//! repository-level rules — a tombstoned tenant leaves every read, keeps its
//! slug until purged, cannot be updated; the purge refuses a live tenant; and
//! the orphan sweep finds and purges the rows a pre-tombstone deletion left,
//! keeping their audit trail for the retention sweep; and the purge deletes
//! only the audit rows the export the deletion required holds (R1W1-04, #602).

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::settings::TenantSettingsOverride;
use axiam_core::models::tenant::{CreateTenant, TenantKind, UpdateTenant};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AuditLogRepository, OAuth2ClientRepository, OrganizationRepository, Pagination,
    SessionRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::tenant_purge::{
    AUDIT_EXPORT_ACTION, TENANT_PURGE_ORDER, TenantKey, TenantPurgeReport,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_db::{CountRow, SessionValidationCache};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

mod common;

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

/// Now, once the clock has moved on from every row written so far — and
/// before it reaches any row written next.
async fn after_a_tick() -> chrono::DateTime<Utc> {
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let now = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    now
}

/// The `tenants.deleted` metadata the deletion handler writes, naming the
/// `receipt` of an export that covered up to `exported_through`.
fn deletion_metadata(exported_through: chrono::DateTime<Utc>, receipt: Uuid) -> serde_json::Value {
    serde_json::json!({
        "audit_export_receipt_id": receipt,
        "audit_exported_at": exported_through + Duration::seconds(1),
        "audit_exported_through": exported_through,
    })
}

/// The export receipt in `tenant_id`'s own log, as the export writes it — or,
/// with an `exported_through` after its own write, as no export does.
async fn export_receipt(
    db: &Surreal<Db>,
    tenant_id: Uuid,
    exported_through: chrono::DateTime<Utc>,
) -> AuditLogEntry {
    SurrealAuditLogRepository::new(db.clone())
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::User,
            action: AUDIT_EXPORT_ACTION.into(),
            resource_id: Some(tenant_id),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "record_count": 1,
                "exported_through": exported_through,
            })),
        })
        .await
        .unwrap()
}

/// The system-log record of `tenant_id`'s deletion, with `metadata`.
async fn record_deletion(db: &Surreal<Db>, tenant_id: Uuid, metadata: serde_json::Value) {
    SurrealAuditLogRepository::new(db.clone())
        .append(CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::User,
            action: "tenants.deleted".into(),
            resource_id: Some(tenant_id),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(metadata),
        })
        .await
        .unwrap();
}

/// One audit entry of `tenant_id`, returning its id.
async fn audit_entry(db: &Surreal<Db>, tenant_id: Uuid, action: &str) -> Uuid {
    SurrealAuditLogRepository::new(db.clone())
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: action.into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// An `audit_signature` row of `tenant_id` over `entries`.
async fn signature(db: &Surreal<Db>, tenant_id: Uuid, entries: &[Uuid]) {
    db.query(
        "CREATE audit_signature SET tenant_id = $tenant, signing_key_id = 'key', \
         entry_ids = $entries, signature_armored = 'sig'",
    )
    .bind(("tenant", tenant_id.to_string()))
    .bind((
        "entries",
        entries.iter().map(Uuid::to_string).collect::<Vec<_>>(),
    ))
    .await
    .unwrap()
    .check()
    .unwrap();
}

/// The `action`s of `tenant_id`'s audit rows, sorted.
async fn audit_actions(db: &Surreal<Db>, tenant_id: Uuid) -> Vec<String> {
    let mut result = db
        .query("SELECT VALUE action FROM audit_log WHERE tenant_id = $tenant")
        .bind(("tenant", tenant_id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let mut actions: Vec<String> = result.take(0).unwrap();
    actions.sort();
    actions
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
    // R1W1-03 (#601): the tenant's OAuth2 client. Its row is not among the
    // rows the tombstone transaction removes, so the client reader still
    // answers for it after the delete — which is why client authentication has
    // to ask the tenant reader, and why `get_by_id` refusing the tombstoned
    // tenant (below) is what it relies on.
    let clients = SurrealOAuth2ClientRepository::new(db.clone());
    let client_input: CreateOAuth2Client = serde_json::from_value(serde_json::json!({
        "tenant_id": doomed,
        "name": "portal",
        "redirect_uris": ["https://portal.example.com/cb"],
        "grant_types": ["client_credentials"],
        "scopes": ["openid"],
    }))
    .unwrap();
    let (client, _secret) = clients.create(client_input).await.unwrap();
    let settings = SurrealSettingsRepository::new(db.clone());
    settings
        .set_tenant_override(doomed, TenantSettingsOverride::default())
        .await
        .unwrap();
    let before = tenants.count_for_shared_issuer().await.unwrap();

    tenants.delete(doomed).await.unwrap();

    assert!(
        clients
            .get_by_client_id(doomed, &client.client_id)
            .await
            .is_ok(),
        "the client row survives the tombstone until the purge"
    );

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
/// — its audit trail included, all of it written before the export, but for
/// the export's receipt, written after it — and then its row, leaving the
/// system log and another tenant alone.
#[tokio::test]
async fn the_purge_refuses_a_live_tenant_and_empties_a_tombstoned_one() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let doomed = tenant(&db, org, "doomed").await;
    let kept = tenant(&db, org, "kept").await;
    populate(&db, doomed).await;
    populate(&db, kept).await;
    let exported_through = after_a_tick().await;
    let receipt = export_receipt(&db, doomed, exported_through).await;
    record_deletion(&db, doomed, deletion_metadata(exported_through, receipt.id)).await;

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
    let report = tenants.purge_tombstoned(doomed).await.unwrap();

    for step in TENANT_PURGE_ORDER {
        if step.table != "audit_log" {
            assert_eq!(rows(&db, step.table, doomed).await, 0, "{}", step.table);
        }
    }
    assert_eq!(audit_actions(&db, doomed).await, [AUDIT_EXPORT_ACTION]);
    assert_eq!(
        report,
        TenantPurgeReport {
            audit_exported_through: Some(exported_through),
            audit_rows_deleted: 1,
            audit_rows_kept: 1,
        }
    );
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

/// #610: one replica purges a tombstoned tenant. Of eight concurrent claims
/// exactly one wins; a live tenant cannot be claimed; a claim holds for its
/// lease and is taken over after it, or at once when released; and a purge
/// that finds the tenant row already removed answers `NotFound`, so the caller
/// records the purge once.
#[tokio::test]
async fn one_replica_claims_a_tombstoned_tenants_purge_and_a_second_purge_is_not_found() {
    // The engine production runs: `kv-mem` may admit two winners (common/).
    let db = common::serialising_db().await;
    let org = SurrealOrganizationRepository::new(db.handle())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "purge-claim".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let tenants = SurrealTenantRepository::new(db.handle());
    let doomed = tenant(&db, org, "doomed").await;
    populate(&db, doomed).await;
    let lease = Duration::hours(1);
    let now = Utc::now();

    assert!(
        !tenants.claim_purge(doomed, now, lease).await.unwrap(),
        "a live tenant is never claimed"
    );
    tenants.delete(doomed).await.unwrap();

    // Eight replicas that see the same tombstone: one claim wins.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let tenants = tenants.clone();
        tasks.push(tokio::spawn(async move {
            tenants.claim_purge(doomed, now, lease).await.unwrap()
        }));
    }
    let mut won = 0;
    for task in tasks {
        won += usize::from(task.await.unwrap());
    }
    assert_eq!(won, 1, "exactly one concurrent claim wins");

    // The claim holds for its lease, and is taken over once it has run out.
    let later = now + Duration::minutes(59);
    assert!(!tenants.claim_purge(doomed, later, lease).await.unwrap());
    let lapsed = now + Duration::minutes(61);
    assert!(tenants.claim_purge(doomed, lapsed, lease).await.unwrap());
    // A release with another replica's stamp leaves the claim alone; with its
    // own, the tenant is claimable at once.
    tenants.release_purge_claim(doomed, now).await.unwrap();
    assert!(!tenants.claim_purge(doomed, lapsed, lease).await.unwrap());
    tenants.release_purge_claim(doomed, lapsed).await.unwrap();
    assert!(tenants.claim_purge(doomed, lapsed, lease).await.unwrap());

    // The first purge removes the row; one that comes after it, or overlaps
    // it and loses the final delete, is `NotFound` — never a second success.
    tenants.purge_tombstoned(doomed).await.unwrap();
    assert!(matches!(
        tenants.purge_tombstoned(doomed).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(
        !tenants.claim_purge(doomed, lapsed, lease).await.unwrap(),
        "a purged tenant is never claimed"
    );
    assert_eq!(rows(&db, "user", doomed).await, 0);
}

/// The issue's test (R1W1-04, #602, D-5): the purge deletes the audit rows at
/// or before the export the deletion required and keeps every later one —
/// the receipt, what happened before the deletion, what the deletion and the
/// wait for the purge produced — under the tenant id. A signature over deleted
/// entries only goes; one that also signs a kept entry stays. The kept rows do
/// not make the tenant id an orphan, and the audit retention sweep removes them
/// once they are past the window. Before the fix every row went.
#[tokio::test]
async fn a_row_written_after_the_export_survives_the_purge() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let audit = SurrealAuditLogRepository::new(db.clone());
    let doomed = tenant(&db, org, "doomed").await;
    populate(&db, doomed).await;
    let exported = audit_entry(&db, doomed, "users.updated").await;
    let exported_through = after_a_tick().await;
    let receipt = audit_entry(&db, doomed, "tenants.audit_exported").await;
    let late = audit_entry(&db, doomed, "users.created").await;
    tenants.delete(doomed).await.unwrap();
    record_deletion(&db, doomed, deletion_metadata(exported_through, receipt)).await;
    audit_entry(&db, doomed, "auth.login_failed").await;
    signature(&db, doomed, &[exported]).await;
    signature(&db, doomed, &[exported, late]).await;
    signature(&db, doomed, &[receipt]).await;

    let report = tenants.purge_tombstoned(doomed).await.unwrap();

    assert_eq!(
        audit_actions(&db, doomed).await,
        [
            "auth.login_failed",
            "tenants.audit_exported",
            "users.created"
        ],
        "only the rows after the export survive, under the tenant id"
    );
    assert_eq!(
        report,
        TenantPurgeReport {
            audit_exported_through: Some(exported_through),
            audit_rows_deleted: 2,
            audit_rows_kept: 3,
        }
    );
    assert_eq!(
        rows(&db, "audit_signature", doomed).await,
        2,
        "the signature over exported entries only went; the two signing a kept entry stayed"
    );
    for step in TENANT_PURGE_ORDER {
        if step.stage != axiam_db::repository::tenant_purge::PurgeStage::AuditTrail {
            assert_eq!(rows(&db, step.table, doomed).await, 0, "{}", step.table);
        }
    }
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    assert!(
        tenants.orphaned_tenant_ids().await.unwrap().is_empty(),
        "kept audit rows do not make the tenant id an orphan"
    );

    // The audit retention sweep (T-119) deletes a kept row like any other,
    // tenant or no tenant, once it is past the window.
    db.query("UPDATE audit_log SET timestamp = time::now() - 400d WHERE tenant_id = $tenant")
        .bind(("tenant", doomed.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(
        audit
            .prune_older_than(Utc::now() - Duration::days(365))
            .await
            .unwrap(),
        3
    );
    assert_eq!(rows(&db, "audit_log", doomed).await, 0);
}

/// Fail-safe: with no export time to go by — no `tenants.deleted` record (its
/// write was dead-lettered, or the purge ran before it landed), or one without
/// the time — the purge deletes no audit row and no signature of the tenant,
/// and says so. A record written before `audit_exported_through` existed is
/// answered from the receipt it names.
#[tokio::test]
async fn without_an_export_time_the_purge_keeps_the_whole_audit_trail() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());

    // No deletion record at all.
    let unrecorded = tenant(&db, org, "unrecorded").await;
    let entry = audit_entry(&db, unrecorded, "users.created").await;
    signature(&db, unrecorded, &[entry]).await;
    tenants.delete(unrecorded).await.unwrap();
    let report = tenants.purge_tombstoned(unrecorded).await.unwrap();
    assert_eq!(
        report,
        TenantPurgeReport {
            audit_exported_through: None,
            audit_rows_deleted: 0,
            audit_rows_kept: 1,
        }
    );
    assert_eq!(rows(&db, "audit_signature", unrecorded).await, 1);
    assert_eq!(rows(&db, "user", unrecorded).await, 0);

    // A record without an export time, or with one that does not parse.
    for (slug, metadata) in [
        ("no-time", serde_json::json!({ "tenant_slug": "no-time" })),
        (
            "bad-time",
            serde_json::json!({ "audit_exported_through": "yesterday" }),
        ),
    ] {
        let t = tenant(&db, org, slug).await;
        audit_entry(&db, t, "users.created").await;
        tenants.delete(t).await.unwrap();
        record_deletion(&db, t, metadata).await;
        let report = tenants.purge_tombstoned(t).await.unwrap();
        assert_eq!(report.audit_exported_through, None, "{slug}");
        assert_eq!(report.audit_rows_kept, 1, "{slug}");
    }

    // A 1.0.0 deletion record: only the receipt id. The receipt's own
    // `exported_through` is the export time.
    let legacy = tenant(&db, org, "legacy").await;
    audit_entry(&db, legacy, "users.created").await;
    let exported_through = after_a_tick().await;
    let receipt = SurrealAuditLogRepository::new(db.clone())
        .append(CreateAuditLogEntry {
            tenant_id: legacy,
            actor_id: Uuid::nil(),
            actor_type: ActorType::User,
            action: "tenants.audit_exported".into(),
            resource_id: Some(legacy),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "record_count": 1,
                "exported_through": exported_through,
            })),
        })
        .await
        .unwrap();
    tenants.delete(legacy).await.unwrap();
    record_deletion(
        &db,
        legacy,
        serde_json::json!({ "audit_export_receipt_id": receipt.id }),
    )
    .await;
    let report = tenants.purge_tombstoned(legacy).await.unwrap();
    assert_eq!(
        report,
        TenantPurgeReport {
            audit_exported_through: Some(exported_through),
            audit_rows_deleted: 1,
            audit_rows_kept: 1,
        }
    );
    assert_eq!(audit_actions(&db, legacy).await, ["tenants.audit_exported"]);
}

/// The issue's test (R101W3-03, #637): a receipt that claims to cover rows
/// written after it — `exported_through` far in the future, as a message
/// through the AMQP audit ingestion could set before the fix — bounds the
/// purge at the receipt's own datastore `timestamp`, never later. The rows
/// after the receipt, and those after the deletion, survive; so it is for a
/// 1.0.1 deletion record that copied the claim, and for a record that names
/// only the receipt. Before the fix the purge took the claim as its bound and
/// deleted every audit row of the tenant (the review's probe: bound
/// 2100-01-01, 4 deleted, 0 kept).
#[tokio::test]
async fn the_purge_bound_never_exceeds_the_receipts_timestamp() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let far_future = Utc::now() + Duration::days(365 * 75);

    for (slug, copies_the_claim) in [("copied", true), ("named-only", false)] {
        let doomed = tenant(&db, org, slug).await;
        audit_entry(&db, doomed, "users.updated").await;
        let receipt = export_receipt(&db, doomed, far_future).await;
        audit_entry(&db, doomed, "users.created").await;
        tenants.delete(doomed).await.unwrap();
        let metadata = if copies_the_claim {
            deletion_metadata(far_future, receipt.id)
        } else {
            serde_json::json!({ "audit_export_receipt_id": receipt.id })
        };
        record_deletion(&db, doomed, metadata).await;
        audit_entry(&db, doomed, "auth.login_failed").await;

        let report = tenants.purge_tombstoned(doomed).await.unwrap();

        assert_eq!(
            report,
            TenantPurgeReport {
                audit_exported_through: Some(receipt.timestamp),
                audit_rows_deleted: 2,
                audit_rows_kept: 2,
            },
            "{slug}: the bound is the receipt's timestamp, not its claim"
        );
        assert_eq!(
            audit_actions(&db, doomed).await,
            ["auth.login_failed", "users.created"],
            "{slug}: every row written after the receipt survives"
        );
    }
}

/// The receipt the bound is clamped to must be the one the deletion named, in
/// the deleted tenant's own log (R101W3-03, #637). A record naming a receipt
/// that is not there — another tenant's, or one already gone (a purge resumed
/// after a clamped pass deleted it) — leaves nothing to clamp to, and the purge
/// keeps the whole trail, as it does without an export time.
#[tokio::test]
async fn a_deletion_whose_receipt_is_not_in_the_tenants_log_keeps_the_whole_trail() {
    let (db, org) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let other = tenant(&db, org, "other").await;
    let exported_through = after_a_tick().await;
    let foreign = export_receipt(&db, other, exported_through).await;

    for (slug, named) in [("foreign", foreign.id), ("missing", Uuid::new_v4())] {
        let doomed = tenant(&db, org, slug).await;
        audit_entry(&db, doomed, "users.updated").await;
        tenants.delete(doomed).await.unwrap();
        record_deletion(&db, doomed, deletion_metadata(Utc::now(), named)).await;

        let report = tenants.purge_tombstoned(doomed).await.unwrap();

        assert_eq!(
            report,
            TenantPurgeReport {
                audit_exported_through: None,
                audit_rows_deleted: 0,
                audit_rows_kept: 1,
            },
            "{slug}"
        );
    }
    assert_eq!(
        rows(&db, "audit_log", other).await,
        1,
        "the other tenant's receipt stays"
    );
}
