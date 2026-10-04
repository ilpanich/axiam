//! The session-revocation port against the real datastore (T23.5.3, G-5,
//! D-52): which delete paths report a `session-revoked`, and which must not.
//!
//! The same three paths that publish to the revocation feed report — `invalidate`,
//! `invalidate_user_sessions`, `invalidate_user_sessions_except` — whether or
//! not the feed is on. `consume`, `consume_by_token_hash` (redemptions) and
//! expiry never do: a redemption is not a revocation, and a sweep is not an
//! administrator's decision.

use std::sync::{Arc, Mutex};

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{CreateSession, Session};
use axiam_core::models::ssf::{Late, SessionRevocationSink, SsfFuture};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealRevokedSessionRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

type Handle = Surreal<Db>;

#[derive(Default)]
struct Recording {
    inactive: bool,
    calls: Mutex<Vec<(Uuid, Uuid, Vec<Uuid>)>>,
}

impl SessionRevocationSink for Recording {
    fn is_active(&self) -> bool {
        !self.inactive
    }

    fn sessions_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        session_ids: &'a [Uuid],
    ) -> SsfFuture<'a, ()> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((tenant_id, user_id, session_ids.to_vec()));
        })
    }
}

impl Recording {
    fn calls(&self) -> Vec<(Uuid, Uuid, Vec<Uuid>)> {
        self.calls.lock().unwrap().clone()
    }
}

async fn setup() -> (Handle, Uuid, Uuid) {
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
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "subject".into(),
            email: "subject@example.test".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id, user.id)
}

async fn session(db: &Handle, tenant_id: Uuid, user_id: Uuid, expires_in: Duration) -> Session {
    let hash = Uuid::new_v4().simple().to_string();
    SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: hash.clone(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + expires_in,
            authenticated_at: Utc::now(),
            amr: Vec::new(),
            browser_token_hash: Some(hash),
        })
        .await
        .unwrap()
}

fn repo_with(db: &Handle, sink: &Arc<Recording>) -> SurrealSessionRepository<Db> {
    SurrealSessionRepository::new(db.clone())
        .with_revocation_sink(sink.clone() as Arc<dyn SessionRevocationSink>)
}

#[tokio::test]
async fn a_logout_reports_the_session_and_its_user() {
    let (db, tenant, user) = setup().await;
    let sink = Arc::new(Recording::default());
    let s = session(&db, tenant, user, Duration::days(1)).await;
    repo_with(&db, &sink)
        .invalidate(tenant, s.id)
        .await
        .unwrap();
    assert_eq!(sink.calls(), vec![(tenant, user, vec![s.id])]);
}

/// The sink does not depend on the revocation feed: the feed is off here and
/// stays empty, while the sink was told.
#[tokio::test]
async fn the_sink_is_independent_of_the_revocation_feed() {
    let (db, tenant, user) = setup().await;
    let sink = Arc::new(Recording::default());
    let s = session(&db, tenant, user, Duration::days(1)).await;
    repo_with(&db, &sink)
        .invalidate(tenant, s.id)
        .await
        .unwrap();
    assert_eq!(sink.calls().len(), 1);
    assert!(
        SurrealRevokedSessionRepository::new(db.clone())
            .list_live(Utc::now())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn revoking_a_session_that_is_not_there_reports_nothing() {
    let (db, tenant, user) = setup().await;
    let sink = Arc::new(Recording::default());
    let s = session(&db, tenant, user, Duration::days(1)).await;
    let repo = repo_with(&db, &sink);
    repo.invalidate(tenant, s.id).await.unwrap();
    repo.invalidate(tenant, s.id).await.unwrap();
    repo.invalidate(tenant, Uuid::new_v4()).await.unwrap();
    // Another tenant's id for a real session matches nothing and reports nothing.
    let live = session(&db, tenant, user, Duration::days(1)).await;
    repo.invalidate(Uuid::new_v4(), live.id).await.unwrap();
    assert_eq!(sink.calls().len(), 1);
}

#[tokio::test]
async fn a_bulk_revocation_reports_every_session_it_removed() {
    let (db, tenant, user) = setup().await;
    let sink = Arc::new(Recording::default());
    let a = session(&db, tenant, user, Duration::days(1)).await;
    let b = session(&db, tenant, user, Duration::days(1)).await;
    repo_with(&db, &sink)
        .invalidate_user_sessions(tenant, user)
        .await
        .unwrap();
    let calls = sink.calls();
    assert_eq!(calls.len(), 1);
    let (t, u, mut ids) = calls[0].clone();
    assert_eq!((t, u), (tenant, user));
    ids.sort();
    let mut expected = vec![a.id, b.id];
    expected.sort();
    assert_eq!(ids, expected);
}

#[tokio::test]
async fn the_session_a_reset_keeps_is_not_reported() {
    let (db, tenant, user) = setup().await;
    let sink = Arc::new(Recording::default());
    let kept = session(&db, tenant, user, Duration::days(1)).await;
    let other = session(&db, tenant, user, Duration::days(1)).await;
    repo_with(&db, &sink)
        .invalidate_user_sessions_except(tenant, user, kept.id)
        .await
        .unwrap();
    assert_eq!(sink.calls(), vec![(tenant, user, vec![other.id])]);
}

#[tokio::test]
async fn a_user_with_no_session_reports_nothing() {
    let (db, tenant, user) = setup().await;
    let sink = Arc::new(Recording::default());
    let repo = repo_with(&db, &sink);
    repo.invalidate_user_sessions(tenant, user).await.unwrap();
    repo.invalidate_user_sessions_except(tenant, user, Uuid::new_v4())
        .await
        .unwrap();
    assert!(sink.calls().is_empty());
}

/// D-52: a redemption is not a revocation, and neither is expiry.
#[tokio::test]
async fn consume_consume_by_token_hash_and_expiry_never_report() {
    let (db, tenant, user) = setup().await;
    let sink = Arc::new(Recording::default());
    let repo = repo_with(&db, &sink);

    let a = session(&db, tenant, user, Duration::days(1)).await;
    assert!(repo.consume(tenant, a.id).await.unwrap());

    let b = session(&db, tenant, user, Duration::days(1)).await;
    assert!(
        repo.consume_by_token_hash(tenant, &b.token_hash)
            .await
            .unwrap()
            .is_some()
    );

    let _expired = session(&db, tenant, user, Duration::seconds(-60)).await;
    assert_eq!(repo.cleanup_expired(tenant).await.unwrap(), 1);

    assert!(
        sink.calls().is_empty(),
        "no redemption or expiry is a revocation"
    );
}

#[tokio::test]
async fn an_inactive_or_unbound_sink_changes_nothing() {
    let (db, tenant, user) = setup().await;
    let a = session(&db, tenant, user, Duration::days(1)).await;
    let b = session(&db, tenant, user, Duration::days(1)).await;

    // Inactive: the revocation works and nothing is reported.
    let inactive = Arc::new(Recording {
        inactive: true,
        ..Recording::default()
    });
    let repo = repo_with(&db, &inactive);
    repo.invalidate(tenant, a.id).await.unwrap();
    assert!(repo.get_by_id(tenant, a.id).await.is_err());
    assert!(inactive.calls().is_empty());

    // Unbound `Late` handle: inactive until bound, then forwards.
    let late: Arc<Late<dyn SessionRevocationSink>> = Arc::new(Late::default());
    let repo = SurrealSessionRepository::new(db.clone())
        .with_revocation_sink(late.clone() as Arc<dyn SessionRevocationSink>);
    assert!(!late.is_active());
    repo.invalidate(tenant, b.id).await.unwrap();
    assert!(repo.get_by_id(tenant, b.id).await.is_err());

    let recording = Arc::new(Recording::default());
    assert!(late.bind(recording.clone() as Arc<dyn SessionRevocationSink>));
    assert!(!late.bind(Arc::new(Recording::default()) as Arc<dyn SessionRevocationSink>));
    assert!(late.is_active());
    let c = session(&db, tenant, user, Duration::days(1)).await;
    repo.invalidate(tenant, c.id).await.unwrap();
    assert_eq!(recording.calls(), vec![(tenant, user, vec![c.id])]);
}
