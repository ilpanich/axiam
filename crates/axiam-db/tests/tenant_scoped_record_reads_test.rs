//! The single-record reads on every authenticated request —
//! `SessionRepository::get_by_id` (the revocation check) and
//! `UserRepository::get_by_id` — check the row's tenant in the repository
//! instead of in a `WHERE` on the fetch (see
//! `claude_dev/db-query-optimization.md`). The answer must be what the
//! predicate gave: the row in its own tenant, and `NotFound` — never the row —
//! when asked from any other tenant.

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_test_support::test_password;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> (Surreal<Db>, Uuid, Uuid) {
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
        .unwrap()
        .id;
    let tenants = SurrealTenantRepository::new(db.clone());
    let mut ids = Vec::new();
    for slug in ["a", "b"] {
        ids.push(
            tenants
                .create(CreateTenant {
                    organization_id: org,
                    kind: TenantKind::Standard,
                    name: slug.into(),
                    slug: slug.into(),
                    metadata: None,
                })
                .await
                .unwrap()
                .id,
        );
    }
    (db, ids[0], ids[1])
}

#[tokio::test]
async fn a_user_is_read_in_its_own_tenant_only() {
    let (db, a, b) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id: a,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let read = users.get_by_id(a, user.id).await.unwrap();
    assert_eq!((read.id, read.tenant_id), (user.id, a));

    for wrong in [b, Uuid::new_v4(), Uuid::nil()] {
        assert!(
            matches!(
                users.get_by_id(wrong, user.id).await,
                Err(AxiamError::NotFound { .. })
            ),
            "tenant {wrong} must not read tenant {a}'s user"
        );
    }
    assert!(matches!(
        users.get_by_id(a, Uuid::new_v4()).await,
        Err(AxiamError::NotFound { .. })
    ));
}

#[tokio::test]
async fn a_session_is_read_and_validated_in_its_own_tenant_only() {
    let (db, a, b) = setup().await;
    let sessions = SurrealSessionRepository::new(db.clone());
    let session = sessions
        .create(CreateSession {
            tenant_id: a,
            user_id: Uuid::new_v4(),
            token_hash: "h".into(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            amr: vec![Amr::Pwd],
            browser_token_hash: None,
            lineage_id: None,
        })
        .await
        .unwrap();

    assert_eq!(
        sessions.get_by_id(a, session.id).await.unwrap().id,
        session.id
    );
    assert!(sessions.is_session_active_checked(a, session.id).await);

    for wrong in [b, Uuid::new_v4(), Uuid::nil()] {
        assert!(matches!(
            sessions.get_by_id(wrong, session.id).await,
            Err(AxiamError::NotFound { .. })
        ));
        assert!(
            !sessions.is_session_active_checked(wrong, session.id).await,
            "a session is never active for another tenant"
        );
    }
}
