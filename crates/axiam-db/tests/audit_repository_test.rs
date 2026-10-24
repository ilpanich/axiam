//! CRUD + filter + GDPR pseudonymization coverage for
//! `SurrealAuditLogRepository` — this repository carried NO direct tests
//! before this file. Uses the in-memory SurrealDB engine — no external
//! services required.

use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, TenantRepository,
};
use axiam_db::repository::{
    SurrealAccountDeletionRepository, SurrealAuditLogRepository, SurrealOrganizationRepository,
    SurrealTenantRepository,
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
            kind: TenantKind::Standard,
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

/// #794: the request row's claimed client address (`forwarded_for_claimed`,
/// #752) is personal data like `ip_address`, so the scrub removes it from the
/// erased user's rows, and only from theirs.
#[tokio::test]
async fn pseudonymize_actor_removes_the_claimed_forwarded_address() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let (user_id, other) = (Uuid::new_v4(), Uuid::new_v4());
    let row = |actor: Uuid| {
        let mut e = entry(
            tenant_id,
            actor,
            "GET /api/v1/users",
            AuditOutcome::Success,
            None,
        );
        e.metadata = Some(serde_json::json!({
            "http_status": 200,
            "authenticated": true,
            "forwarded_for_claimed": "198.51.100.23",
        }));
        e
    };
    let mine = repo.append(row(user_id)).await.unwrap().id;
    let theirs = repo.append(row(other)).await.unwrap().id;

    repo.pseudonymize_actor(tenant_id, user_id, "DELETED_USER_deadbeef")
        .await
        .unwrap();

    let rows = repo.get_by_ids(tenant_id, &[mine, theirs]).await.unwrap();
    let mine = rows.iter().find(|r| r.id == mine).unwrap();
    let theirs = rows.iter().find(|r| r.id == theirs).unwrap();
    assert!(mine.ip_address.is_none());
    assert!(
        mine.metadata.get("forwarded_for_claimed").is_none(),
        "the erased user's claimed address must not survive the scrub"
    );
    assert_eq!(mine.metadata["http_status"], 200);
    assert_eq!(theirs.metadata["forwarded_for_claimed"], "198.51.100.23");
    assert_eq!(theirs.ip_address.as_deref(), Some("203.0.113.5"));
}

/// #758 (e): the grantee of a `network_role.assigned` / `.unassigned` row is
/// the erased subject whoever wrote the row; its id is cleared, a stranger's
/// is not, and a second run changes nothing.
#[tokio::test]
async fn pseudonymize_actor_clears_the_grantee_id_of_network_role_rows() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let (user_id, stranger, admin) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let row = |action: &str, grantee: Uuid, kind: &str| {
        let mut e = entry(tenant_id, admin, action, AuditOutcome::Success, None);
        e.metadata = Some(serde_json::json!({
            "role": "net-admin",
            "grantee": { "kind": kind, "id": grantee },
            "node": "none",
        }));
        e
    };
    let mut ids = Vec::new();
    for e in [
        row("network_role.assigned", user_id, "user"),
        row("network_role.unassigned", user_id, "user"),
        row("network_role.assigned", stranger, "user"),
        // A service account that happens to share the id is not the subject.
        row("network_role.assigned", user_id, "service_account"),
    ] {
        ids.push(repo.append(e).await.unwrap().id);
    }

    for _ in 0..2 {
        repo.pseudonymize_actor(tenant_id, user_id, "DELETED_USER_deadbeef")
            .await
            .unwrap();
        let rows = repo.get_by_ids(tenant_id, &ids).await.unwrap();
        let grantee = |i: usize| {
            let r = rows.iter().find(|r| r.id == ids[i]).unwrap();
            r.metadata["grantee"]["id"].clone()
        };
        let nil = serde_json::json!(Uuid::nil());
        assert_eq!(grantee(0), nil);
        assert_eq!(grantee(1), nil);
        assert_eq!(grantee(2), serde_json::json!(stranger));
        assert_eq!(grantee(3), serde_json::json!(user_id));
        // The rest of the row is left as it was.
        let kept = rows.iter().find(|r| r.id == ids[0]).unwrap();
        assert_eq!(kept.metadata["role"], "net-admin");
        assert_eq!(kept.metadata["grantee"]["kind"], "user");
        assert_eq!(kept.actor_id, admin);
    }
}

/// #802 (R112-09 (a)): the gate's refusal rows name a user grantee by the
/// refused write's `(kind, id)` pair, in `metadata.after` for an assignment
/// and in `metadata.before` for an unassignment; the erasure clears that id as
/// it clears a success row's `grantee.id`. A stranger's, a service account's
/// and another action's value are left, and a second run changes nothing.
#[tokio::test]
async fn pseudonymize_actor_clears_the_user_of_network_role_refusal_rows() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let (user_id, stranger, admin) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    // `side` is where the gate puts the grantee: "after" for an assignment,
    // "before" for an unassignment.
    let row = |action: &str, side: &str, kind: &str, who: Uuid| {
        let mut e = entry(tenant_id, admin, action, AuditOutcome::Denied, None);
        let mut named = serde_json::Map::new();
        named.insert("role_id".into(), serde_json::json!(Uuid::new_v4()));
        named.insert("role".into(), serde_json::json!("net-admin"));
        named.insert(kind.into(), serde_json::json!(who.to_string()));
        named.insert("node".into(), serde_json::json!("none"));
        let other = if side == "after" { "before" } else { "after" };
        let mut metadata = serde_json::Map::new();
        metadata.insert("rule".into(), serde_json::json!("H6"));
        metadata.insert(side.into(), serde_json::Value::Object(named));
        metadata.insert(other.into(), serde_json::json!({ "assignments": "none" }));
        e.metadata = Some(serde_json::Value::Object(metadata));
        e
    };
    let rows_written = [
        ("network_role.assign_refused", "after", "user", user_id),
        ("network_role.unassign_refused", "before", "user", user_id),
        ("network_role.assign_refused", "after", "user", stranger),
        (
            "network_role.unassign_refused",
            "before",
            "service_account",
            user_id,
        ),
        ("network_role.grant_refused", "after", "user", user_id),
    ];
    let mut ids = Vec::new();
    for (action, side, kind, who) in rows_written {
        ids.push(repo.append(row(action, side, kind, who)).await.unwrap().id);
    }

    let nil = serde_json::json!(Uuid::nil().to_string());
    let mine = serde_json::json!(user_id.to_string());
    for _ in 0..2 {
        repo.pseudonymize_actor(tenant_id, user_id, "DELETED_USER_deadbeef")
            .await
            .unwrap();
        let rows = repo.get_by_ids(tenant_id, &ids).await.unwrap();
        let named = |i: usize| {
            let (_, side, kind, _) = rows_written[i];
            let r = rows.iter().find(|r| r.id == ids[i]).unwrap();
            r.metadata[side][kind].clone()
        };
        assert_eq!(named(0), nil);
        assert_eq!(named(1), nil);
        assert_eq!(named(2), serde_json::json!(stranger.to_string()));
        assert_eq!(named(3), mine);
        assert_eq!(named(4), mine);
        // The rest of the row is left as it was.
        let kept = rows.iter().find(|r| r.id == ids[1]).unwrap();
        assert_eq!(kept.metadata["before"]["role"], "net-admin");
        assert_eq!(kept.metadata["after"]["assignments"], "none");
    }
}

/// R112W1-03: `erasure_recorded` reads the record by its actor (the account)
/// and, failing that, by the nil actor a scrub leaves with the pseudonym
/// still in the metadata; another account's record, the same account's other
/// actions and another tenant's trail are not it.
#[tokio::test]
async fn erasure_recorded_finds_the_record_by_actor_or_by_pseudonym_only() {
    const ACTION: &str = "gdpr.user_pseudonymized";
    let (db, tenant_id) = setup().await;
    let audit = SurrealAuditLogRepository::new(db.clone());
    let deletions = SurrealAccountDeletionRepository::new(db);
    let (by_actor, by_pseudonym, never) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let record = |actor: Uuid, action: &str, pseudonym: &str| {
        let mut e = entry(tenant_id, actor, action, AuditOutcome::Success, None);
        e.metadata = Some(serde_json::json!({ "pseudonym": pseudonym }));
        e
    };
    // Written for the account, and the one a stalled unit's scrub left with
    // the nil actor.
    audit
        .append(record(by_actor, ACTION, "DELETED_USER_aaaa"))
        .await
        .unwrap();
    audit
        .append(record(Uuid::nil(), ACTION, "DELETED_USER_bbbb"))
        .await
        .unwrap();
    // The account's row of another action is not its record.
    audit
        .append(record(never, "auth.login", "DELETED_USER_cccc"))
        .await
        .unwrap();

    let found = |user: Uuid, pseudonym: &'static str, action: &'static str| {
        let deletions = &deletions;
        async move {
            deletions
                .erasure_recorded(tenant_id, user, pseudonym, action)
                .await
                .unwrap()
        }
    };
    assert!(found(by_actor, "DELETED_USER_aaaa", ACTION).await);
    assert!(
        found(by_actor, "a pseudonym nobody carries", ACTION).await,
        "the actor alone names it"
    );
    assert!(found(by_pseudonym, "DELETED_USER_bbbb", ACTION).await);
    assert!(!found(by_pseudonym, "DELETED_USER_other", ACTION).await);
    assert!(!found(never, "DELETED_USER_cccc", ACTION).await);
    assert!(!found(never, "DELETED_USER_zzzz", ACTION).await);
    // Another tenant's trail holds none of them.
    assert!(
        !deletions
            .erasure_recorded(Uuid::new_v4(), by_actor, "DELETED_USER_aaaa", ACTION)
            .await
            .unwrap()
    );
}

/// #784: the scrub leaves the erasure's own record alone. A unit stalled past
/// its claim's lease that scrubs after its successor erased and recorded the
/// account used to nil that record's actor for good. The record is matched by
/// its action and its pseudonym: a `gdpr.user_pseudonymized` row naming another
/// pseudonym — no erasure's record of this account — is scrubbed as any other.
#[tokio::test]
async fn pseudonymize_actor_leaves_the_erasures_own_record() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealAuditLogRepository::new(db);
    let user_id = Uuid::new_v4();
    let pseudonym = "DELETED_USER_record000001";
    let record = |pseudonym: &str| CreateAuditLogEntry {
        tenant_id,
        actor_id: user_id,
        actor_type: ActorType::System,
        action: "gdpr.user_pseudonymized".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: Some(serde_json::json!({
            "pseudonym": pseudonym,
            "certificates_revoked": 0,
        })),
    };
    let login = repo
        .append(entry(
            tenant_id,
            user_id,
            "user.login",
            AuditOutcome::Success,
            None,
        ))
        .await
        .unwrap()
        .id;
    let own = repo.append(record(pseudonym)).await.unwrap().id;
    let other = repo
        .append(record("DELETED_USER_other0000001"))
        .await
        .unwrap()
        .id;

    repo.pseudonymize_actor(tenant_id, user_id, pseudonym)
        .await
        .unwrap();
    let rows = repo
        .get_by_ids(tenant_id, &[login, own, other])
        .await
        .unwrap();
    let row = |id: Uuid| rows.iter().find(|r| r.id == id).unwrap();
    assert_eq!(
        row(login).actor_id,
        Uuid::nil(),
        "the account's own row is scrubbed"
    );
    assert_eq!(
        row(own).actor_id,
        user_id,
        "the erasure's record keeps its actor"
    );
    assert_eq!(row(own).metadata["pseudonym"], pseudonym);
    assert!(row(own).metadata.get("actor_pseudonym").is_none());
    assert_eq!(
        row(other).actor_id,
        Uuid::nil(),
        "another pseudonym's row is not the record"
    );
}
