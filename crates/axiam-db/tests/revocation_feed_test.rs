//! T-39 / T-143 — the revocation feed's write, read and prune sides against a
//! real datastore.
//!
//! # What these prove that a unit test cannot
//!
//! The write side is a side effect of five delete paths, three of which
//! publish and two of which deliberately do not. Which ones publish is a
//! decision about false rejections, not about plumbing: a feed that lists a
//! session whose grant is proceeding normally would have a guard reject a
//! caller who did nothing wrong, and that is a worse control than the
//! fifteen-minute window it narrows.
//!
//! The off case is asserted as hard as the on case. A feature that is off by
//! default has to be *off*: no row written, nothing to prune, and no trace for
//! an operator to trip over.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_core::revocation_feed::revocation_hash;
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealRevokedSessionRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid, Uuid) {
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

/// One access-token lifetime, the value the composition root passes.
fn ttl() -> Duration {
    Duration::seconds(900)
}

fn with_feed(db: &Db) -> SurrealSessionRepository<surrealdb::engine::local::Db> {
    SurrealSessionRepository::new(db.clone()).with_revocation_feed(ttl())
}

async fn a_session(
    db: &Db,
    tenant_id: Uuid,
    user_id: Uuid,
    token_hash: &str,
) -> axiam_core::models::session::Session {
    SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: token_hash.to_owned(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::days(1),
            authenticated_at: Utc::now(),
            amr: Vec::new(),
            browser_token_hash: None,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_logout_publishes_the_session_hash_and_nothing_else() {
    let (db, tenant_id, user_id) = setup().await;
    let session = a_session(&db, tenant_id, user_id, "feed-logout").await;

    with_feed(&db)
        .invalidate(tenant_id, session.id)
        .await
        .unwrap();

    let feed = SurrealRevokedSessionRepository::new(db.clone());
    let entries = feed.list_live(Utc::now()).await.unwrap();
    assert_eq!(entries, vec![revocation_hash(session.id)]);

    // The entry is a hash, and the row holds nothing else that could identify
    // anybody. Asserted against the raw row rather than the repository, because
    // the repository projects one column and would hide a second one.
    let mut raw = db.query("SELECT * FROM revoked_session").await.unwrap();
    let rows: Option<serde_json::Value> = raw.take(0usize).unwrap();
    let row = rows.expect("one row");
    let text = row.to_string();
    for leak in [
        session.id.to_string(),
        tenant_id.to_string(),
        user_id.to_string(),
    ] {
        assert!(
            !text.contains(&leak),
            "the feed row must identify nothing: found {leak} in {text}"
        );
    }
}

/// A password or MFA reset revokes the whole family, and every one of them
/// reaches the feed — the case the feed exists for, since this is what a
/// compromised-credential recovery does.
#[tokio::test]
async fn a_reset_publishes_every_session_it_revoked() {
    let (db, tenant_id, user_id) = setup().await;
    let a = a_session(&db, tenant_id, user_id, "feed-reset-a").await;
    let b = a_session(&db, tenant_id, user_id, "feed-reset-b").await;

    with_feed(&db)
        .invalidate_user_sessions(tenant_id, user_id)
        .await
        .unwrap();

    let mut entries = SurrealRevokedSessionRepository::new(db.clone())
        .list_live(Utc::now())
        .await
        .unwrap();
    entries.sort();
    let mut expected = vec![revocation_hash(a.id), revocation_hash(b.id)];
    expected.sort();
    assert_eq!(entries, expected);
}

/// "Log out everywhere else" keeps the current session, and the feed must
/// agree — publishing it would have the caller's own guard reject the request
/// that performed the sign-out.
#[tokio::test]
async fn the_session_a_reset_deliberately_keeps_is_not_published() {
    let (db, tenant_id, user_id) = setup().await;
    let kept = a_session(&db, tenant_id, user_id, "feed-kept").await;
    let other = a_session(&db, tenant_id, user_id, "feed-other").await;

    let n = with_feed(&db)
        .invalidate_user_sessions_except(tenant_id, user_id, kept.id)
        .await
        .unwrap();
    assert_eq!(n, 1);

    let entries = SurrealRevokedSessionRepository::new(db.clone())
        .list_live(Utc::now())
        .await
        .unwrap();
    assert_eq!(entries, vec![revocation_hash(other.id)]);
}

/// A session revoked twice — a logout racing a password reset — is one entry.
/// Without the upsert the unique index turns the second revocation into an
/// error on a path that has nothing useful to do with one.
#[tokio::test]
async fn revoking_the_same_session_twice_is_one_entry() {
    let (db, tenant_id, user_id) = setup().await;
    let session = a_session(&db, tenant_id, user_id, "feed-twice").await;
    let repo = with_feed(&db);

    repo.invalidate(tenant_id, session.id).await.unwrap();
    repo.invalidate(tenant_id, session.id).await.unwrap();

    let entries = SurrealRevokedSessionRepository::new(db.clone())
        .list_live(Utc::now())
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
}

/// The bound. An entry stops being published once every token naming the
/// session has expired on its own `exp` — filtered on **read**, so a late
/// sweep cannot make the document untruthful, only large.
#[tokio::test]
async fn an_entry_stops_being_published_when_its_tokens_have_expired() {
    let (db, tenant_id, user_id) = setup().await;
    let session = a_session(&db, tenant_id, user_id, "feed-expiry").await;
    with_feed(&db)
        .invalidate(tenant_id, session.id)
        .await
        .unwrap();

    let feed = SurrealRevokedSessionRepository::new(db.clone());
    assert_eq!(feed.list_live(Utc::now()).await.unwrap().len(), 1);
    // One second past the TTL.
    let after = Utc::now() + ttl() + Duration::seconds(1);
    assert!(feed.list_live(after).await.unwrap().is_empty());

    // And the sweep removes it, which bounds the table's size rather than the
    // document's truth.
    assert_eq!(feed.prune_expired(after).await.unwrap(), 1);
    assert!(feed.list_live(after).await.unwrap().is_empty());
}

/// The sweep must not remove an entry that is still doing its job.
#[tokio::test]
async fn the_sweep_keeps_a_live_entry() {
    let (db, tenant_id, user_id) = setup().await;
    let session = a_session(&db, tenant_id, user_id, "feed-live").await;
    with_feed(&db)
        .invalidate(tenant_id, session.id)
        .await
        .unwrap();

    let feed = SurrealRevokedSessionRepository::new(db.clone());
    assert_eq!(feed.prune_expired(Utc::now()).await.unwrap(), 0);
    assert_eq!(feed.list_live(Utc::now()).await.unwrap().len(), 1);
}

/// **I4 twin, and the one that matters most.** With the feed off, every
/// revocation path behaves exactly as it did before the feed existed: the
/// session is gone and **no row is written**. A feature that is off by default
/// has to leave no trace, or it is not off.
#[tokio::test]
async fn with_the_feed_off_no_row_is_ever_written() {
    let (db, tenant_id, user_id) = setup().await;
    let one = a_session(&db, tenant_id, user_id, "feed-off-a").await;
    let two = a_session(&db, tenant_id, user_id, "feed-off-b").await;
    let three = a_session(&db, tenant_id, user_id, "feed-off-c").await;
    let repo = SurrealSessionRepository::new(db.clone());

    repo.invalidate(tenant_id, one.id).await.unwrap();
    repo.invalidate_user_sessions_except(tenant_id, user_id, three.id)
        .await
        .unwrap();
    repo.invalidate_user_sessions(tenant_id, user_id)
        .await
        .unwrap();

    assert!(
        SurrealRevokedSessionRepository::new(db.clone())
            .list_live(Utc::now())
            .await
            .unwrap()
            .is_empty(),
        "a deployment that did not opt in must write nothing"
    );
    // And the revocations themselves still happened.
    for id in [one.id, two.id, three.id] {
        assert!(
            SurrealSessionRepository::new(db.clone())
                .get_by_id(tenant_id, id)
                .await
                .is_err(),
            "the session must be gone whether or not the feed is on"
        );
    }
}

/// The single-use redemption paths deliberately do **not** publish. A handoff
/// being exchanged is not a session being withdrawn, and publishing it would
/// have a guard reject a caller whose own grant is proceeding normally — a
/// false rejection, which is worse than the window the feed narrows.
#[tokio::test]
async fn a_consumed_session_is_not_published_as_a_revocation() {
    let (db, tenant_id, user_id) = setup().await;
    let session = a_session(&db, tenant_id, user_id, "feed-consume").await;

    assert!(with_feed(&db).consume(tenant_id, session.id).await.unwrap());

    assert!(
        SurrealRevokedSessionRepository::new(db.clone())
            .list_live(Utc::now())
            .await
            .unwrap()
            .is_empty(),
        "a redemption is not a revocation"
    );
}
