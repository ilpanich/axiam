//! **T2.5 (plan §4.3)** — refresh rotation carries the authentication event
//! forward instead of restamping it.
//!
//! # What would go wrong without this
//!
//! Refresh rotation does not update a session row, it *creates* one
//! (`AuthService::refresh`, the `session_repo.create` at step 4). Every field
//! it does not deliberately copy therefore starts again from whatever the new
//! row's defaults are. For `created_at` that is correct — the row really is
//! new. For `authenticated_at` it would be a lie, and a self-renewing one:
//! a client refreshing every fifteen minutes would keep a session that reports
//! itself as freshly authenticated forever, and `max_age` — the one parameter
//! a relying party has for demanding a *recent* login — would be satisfied by
//! a login from last month.
//!
//! It is also the mechanism behind OpenID Connect Core §12.2: the `auth_time`
//! of an ID token minted on refresh must equal the original's. AXIAM emits no
//! `auth_time` yet (X7.2 lands the record, not the claim), so the property is
//! asserted here, at the source the claim will be derived from, where it is a
//! statement about stored evidence rather than about a token nobody receives.
//!
//! The sibling assertion — that the claim is a function of the evidence and
//! not of the clock — is `axiam_auth::token`'s
//! `auth_time_follows_the_evidence_and_never_the_clock`.

use std::sync::Arc;

use axiam_auth::{AuthConfig, AuthService, LoginInput, LoginResult, RefreshInput};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::Amr;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

fn test_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----".into(), // nosemgrep: generic.secrets.security.detected-private-key
        jwt_public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----".into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        ..AuthConfig::default()
    }
}

#[tokio::test]
async fn refresh_rotation_preserves_the_authentication_event() {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory surreal");
    db.use_ns("test").use_db("test").await.expect("ns/db");
    axiam_db::run_migrations(&db).await.expect("migrations");

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());
    let session_repo = SurrealSessionRepository::new(db.clone());

    let org = org_repo
        .create(CreateOrganization {
            name: "Evidence Org".into(),
            slug: "evidence-org".into(),
            metadata: None,
        })
        .await
        .expect("org");
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Evidence Tenant".into(),
            slug: "evidence-tenant".into(),
            metadata: None,
        })
        .await
        .expect("tenant");

    let password = test_password();
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "evidence".into(),
            email: "evidence@example.com".into(),
            password: password.clone(),
            metadata: None,
        })
        .await
        .expect("user");
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .expect("activate");

    let svc = AuthService::new(
        user_repo,
        session_repo.clone(),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let login = match svc
        .login(LoginInput {
            tenant_id: tenant.id,
            org_id: org.id,
            username_or_email: "evidence".into(),
            password: password.clone(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .expect("login")
    {
        LoginResult::Success(out) => out,
        other => panic!("expected Success, got {other:?}"),
    };

    let original = session_repo
        .get_by_id(tenant.id, login.session_id)
        .await
        .expect("the login's session");

    // The password path records what it actually verified, and nothing more.
    assert_eq!(
        original.amr,
        vec![Amr::Pwd],
        "a password login is `pwd`: no `mfa`, because no second factor happened"
    );
    assert!(
        (original.authenticated_at - original.created_at)
            .num_seconds()
            .abs()
            < 5,
        "on the session the login created, the two timestamps agree"
    );

    // A refresh a moment later. The sleep is what makes the assertion mean
    // something: without it a restamped `authenticated_at` would be
    // indistinguishable from a copied one.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let refreshed = svc
        .refresh(RefreshInput {
            tenant_id: tenant.id,
            org_id: org.id,
            raw_refresh_token: login.refresh_token.clone(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .expect("refresh");

    assert_ne!(
        refreshed.session_id, login.session_id,
        "rotation must genuinely have created a new session row — otherwise \
         this test proves nothing about copying"
    );

    let rotated = session_repo
        .get_by_id(tenant.id, refreshed.session_id)
        .await
        .expect("the rotated session");

    assert_eq!(
        rotated.authenticated_at, original.authenticated_at,
        "authenticated_at must be COPIED across rotation: a refresh is not an \
         authentication event, and OIDC Core §12.2 requires a refreshed \
         auth_time to equal the original"
    );
    assert_eq!(
        rotated.amr, original.amr,
        "the methods that were verified do not change because a token rotated"
    );
    assert!(
        rotated.created_at > rotated.authenticated_at,
        "the new row really is newer than the authentication it descends from \
         ({} vs {}) — which is exactly why created_at cannot stand in for \
         auth_time",
        rotated.created_at,
        rotated.authenticated_at
    );

    // Two rotations, to rule out "copied once, then restamped": the freshness
    // a relying party is told about must not creep forward with usage.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let again = svc
        .refresh(RefreshInput {
            tenant_id: tenant.id,
            org_id: org.id,
            raw_refresh_token: refreshed.refresh_token.clone(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .expect("second refresh");
    let twice_rotated = session_repo
        .get_by_id(tenant.id, again.session_id)
        .await
        .expect("the twice-rotated session");
    assert_eq!(
        twice_rotated.authenticated_at, original.authenticated_at,
        "a session that is never re-authenticated never gets younger, however \
         many times it is refreshed"
    );
    assert_eq!(twice_rotated.amr, original.amr);
}
