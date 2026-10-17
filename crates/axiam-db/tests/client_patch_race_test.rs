//! Item 9 of the 1.1.0 atomicity audit: two administrator patches of one
//! OAuth2 client never both land on a row neither validated.
//!
//! `PUT /api/v1/oauth2-clients/{id}` validated each patch against a read of
//! the row and then wrote only the patch's own fields. Two patches validated
//! against the same row could both land: here, one adds `authorization_code`
//! (legal: the row has a redirect URI) while the other clears the redirect URIs
//! (legal: the row has no `authorization_code`), and the merged row is a code
//! client with nowhere to send the code. The handler now writes through
//! `update_if_unchanged`, conditional on the version it read.
//!
//! The race runs on `surrealkv` (`tests/common`), the engine production runs.
//! Each round, both patches read the row (the handler's one read), wait at a
//! barrier, then write at once. Exactly one may land; the other is `Conflict`.

mod common;

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
    UpdateOAuth2Client,
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

fn client(tenant_id: Uuid) -> CreateOAuth2Client {
    CreateOAuth2Client {
        tenant_id,
        name: "patched".into(),
        redirect_uris: vec!["http://127.0.0.1/callback".into()],
        grant_types: vec!["refresh_token".into()],
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
        allowed_resources: Vec::new(),
        managed_by: ManagedBy::Admin,
        ciba: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_patches_validated_against_one_read_never_both_land() {
    let db = common::serialising_db().await;
    for round in 0..ROUNDS {
        let tenant_id = tenant(&db, round).await;
        let repo = SurrealOAuth2ClientRepository::new(db.handle());
        let (created, _) = repo.create(client(tenant_id)).await.unwrap();

        let patches = [
            // Legal against the row read: it has a redirect URI.
            UpdateOAuth2Client {
                grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
                ..Default::default()
            },
            // Legal against the row read: it has no `authorization_code`.
            UpdateOAuth2Client {
                redirect_uris: Some(Vec::new()),
                ..Default::default()
            },
        ];
        let barrier = Arc::new(tokio::sync::Barrier::new(patches.len()));
        let mut racers = Vec::new();
        for patch in patches {
            let (repo, barrier) = (
                SurrealOAuth2ClientRepository::new(db.handle()),
                barrier.clone(),
            );
            racers.push(tokio::spawn(async move {
                // The handler's one read, which every rule is checked against.
                let stored = repo.get_by_id(tenant_id, created.id).await.unwrap();
                assert!(!stored.redirect_uris.is_empty(), "round {round}: the read");
                assert!(
                    !stored.grant_types.iter().any(|g| g == "authorization_code"),
                    "round {round}: the read"
                );
                barrier.wait().await;
                repo.update_if_unchanged(tenant_id, created.id, patch, stored.updated_at)
                    .await
            }));
        }
        let mut landed = 0;
        for racer in racers {
            match racer.await.unwrap() {
                Ok(_) => landed += 1,
                Err(AxiamError::Conflict { reason }) => assert!(
                    reason.contains("changed since it was read"),
                    "round {round}: {reason}"
                ),
                Err(other) => panic!("round {round}: unexpected refusal {other:?}"),
            }
        }
        assert_eq!(landed, 1, "round {round}: exactly one patch lands");
        let after = repo.get_by_id(tenant_id, created.id).await.unwrap();
        assert!(
            !(after.grant_types.iter().any(|g| g == "authorization_code")
                && after.redirect_uris.is_empty()),
            "round {round}: the row is one a patch was validated against: {after:?}"
        );
    }
}

/// Sequentially: a patch whose read is stale is `Conflict` and writes nothing;
/// a patch of a deleted client is `NotFound`; one on a current read lands.
#[tokio::test]
async fn a_patch_on_a_stale_read_is_conflict_and_writes_nothing() {
    let db = common::serialising_db().await;
    let tenant_id = tenant(&db, 0).await;
    let repo = SurrealOAuth2ClientRepository::new(db.handle());
    let (created, _) = repo.create(client(tenant_id)).await.unwrap();
    let read = repo.get_by_id(tenant_id, created.id).await.unwrap();

    repo.update(
        tenant_id,
        created.id,
        UpdateOAuth2Client {
            name: Some("renamed elsewhere".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let stale = repo
        .update_if_unchanged(
            tenant_id,
            created.id,
            UpdateOAuth2Client {
                name: Some("from a stale read".into()),
                ..Default::default()
            },
            read.updated_at,
        )
        .await;
    assert!(
        matches!(stale, Err(AxiamError::Conflict { .. })),
        "{stale:?}"
    );
    let now = repo.get_by_id(tenant_id, created.id).await.unwrap();
    assert_eq!(now.name, "renamed elsewhere");

    let fresh = repo
        .update_if_unchanged(
            tenant_id,
            created.id,
            UpdateOAuth2Client {
                name: Some("from a fresh read".into()),
                ..Default::default()
            },
            now.updated_at,
        )
        .await
        .unwrap();
    assert_eq!(fresh.name, "from a fresh read");

    repo.delete(tenant_id, created.id).await.unwrap();
    let gone = repo
        .update_if_unchanged(
            tenant_id,
            created.id,
            UpdateOAuth2Client::default(),
            fresh.updated_at,
        )
        .await;
    assert!(matches!(gone, Err(AxiamError::NotFound { .. })), "{gone:?}");
}
