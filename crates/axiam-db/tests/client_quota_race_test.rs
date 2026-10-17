//! Item 6 of the 1.1.0 atomicity audit: `dcr_max_clients` holds against
//! registrations sent together.
//!
//! The DCR endpoint counted the tenant's `dcr` rows, and created the client in
//! a later statement; the CIMD resolve counted its `cimd` rows before the
//! fetch and upserted after it. N requests sent together each counted
//! `max - 1` and all created. Each create now counts again inside its own
//! transaction and claims the tenant row there.
//!
//! The race runs on `surrealkv` (`tests/common`), the engine production runs.
//! Each round, N callers make the read their handler makes first (the count,
//! which every one of them sees under the ceiling), wait at a barrier, and
//! then create at once — the interleaving the audit describes, made certain
//! rather than likely. The tenant must never end above its ceiling.

mod common;

use std::sync::Arc;

use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OAuth2ClientRepository, OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use uuid::Uuid;

/// The tenant's ceiling. Each round starts one below it.
const MAX: u32 = 3;
/// Requests sent together.
const N: usize = 6;
/// Rounds per run; the test was also run 20 times in a row.
const ROUNDS: usize = 8;

async fn tenant(db: &Surreal<Db>, n: usize) -> Uuid {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {n}"),
            slug: format!("org-{n}"),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {n}"),
            slug: format!("tenant-{n}"),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

fn client(tenant_id: Uuid, managed_by: ManagedBy, name: &str) -> CreateOAuth2Client {
    CreateOAuth2Client {
        tenant_id,
        name: name.into(),
        redirect_uris: vec!["http://127.0.0.1/callback".into()],
        grant_types: vec!["authorization_code".into()],
        scopes: vec!["openid".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: ClientProfile::Standard,
        token_endpoint_auth_method: ClientAuthMethod::None,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: Vec::new(),
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: AuthnRequestParamsMode::Ignore,
        browser_sso: false,
        allowed_resources: vec!["https://mcp.example.com/mcp".into()],
        managed_by,
        ciba: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registrations_sent_together_never_exceed_dcr_max_clients() {
    let db = common::serialising_db().await;
    for round in 0..ROUNDS {
        let tenant_id = tenant(&db, round).await;
        let repo = SurrealOAuth2ClientRepository::new(db.handle());
        for n in 0..MAX - 1 {
            repo.create_with_registration_access_token(
                client(tenant_id, ManagedBy::Dcr, "seed"),
                &format!("seed-{round}-{n}"),
                MAX,
            )
            .await
            .unwrap()
            .expect("under the ceiling");
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let mut racers = Vec::new();
        for n in 0..N {
            let (repo, barrier) = (
                SurrealOAuth2ClientRepository::new(db.handle()),
                barrier.clone(),
            );
            racers.push(tokio::spawn(async move {
                // The handler's step 4: every racer sees room for one more.
                let held = repo
                    .count_by_managed_by(tenant_id, ManagedBy::Dcr)
                    .await
                    .unwrap();
                assert_eq!(held, u64::from(MAX - 1), "round {round}: the read");
                barrier.wait().await;
                repo.create_with_registration_access_token(
                    client(tenant_id, ManagedBy::Dcr, "racer"),
                    &format!("racer-{round}-{n}"),
                    MAX,
                )
                .await
                .unwrap()
            }));
        }
        let mut landed = 0;
        for racer in racers {
            if racer.await.unwrap().is_some() {
                landed += 1;
            }
        }
        assert_eq!(
            landed, 1,
            "round {round}: exactly the one free slot is taken"
        );
        assert_eq!(
            repo.count_by_managed_by(tenant_id, ManagedBy::Dcr)
                .await
                .unwrap(),
            u64::from(MAX),
            "round {round}: the tenant ends at its ceiling, not above it"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_cimd_appearances_sent_together_never_exceed_the_ceiling() {
    let db = common::serialising_db().await;
    for round in 0..ROUNDS {
        let tenant_id = tenant(&db, round).await;
        let repo = SurrealOAuth2ClientRepository::new(db.handle());
        for n in 0..MAX - 1 {
            let url = format!("https://seed.example/{round}/{n}.json");
            repo.upsert_cimd_client(&url, client(tenant_id, ManagedBy::Cimd, &url), MAX)
                .await
                .unwrap()
                .expect("under the ceiling");
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let mut racers = Vec::new();
        for n in 0..N {
            let (repo, barrier) = (
                SurrealOAuth2ClientRepository::new(db.handle()),
                barrier.clone(),
            );
            racers.push(tokio::spawn(async move {
                // `cimd::materialise`'s step 3, before the fetch: every racer
                // sees room for one more, and each names a different document.
                let held = repo
                    .count_by_managed_by(tenant_id, ManagedBy::Cimd)
                    .await
                    .unwrap();
                assert_eq!(held, u64::from(MAX - 1), "round {round}: the read");
                barrier.wait().await;
                let url = format!("https://racer.example/{round}/{n}.json");
                repo.upsert_cimd_client(&url, client(tenant_id, ManagedBy::Cimd, &url), MAX)
                    .await
                    .unwrap()
            }));
        }
        let mut landed = 0;
        for racer in racers {
            if racer.await.unwrap().is_some() {
                landed += 1;
            }
        }
        assert_eq!(
            landed, 1,
            "round {round}: exactly the one free slot is taken"
        );
        assert_eq!(
            repo.count_by_managed_by(tenant_id, ManagedBy::Cimd)
                .await
                .unwrap(),
            u64::from(MAX),
            "round {round}: the tenant ends at its ceiling, not above it"
        );
    }
}
