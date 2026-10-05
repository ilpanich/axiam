//! The outbound SCIM target registry, link rows and delivery state against the
//! real datastore (T23.6.1, G-6, schema v79).
//!
//! What lives in the datastore rather than in plain Rust: the sealed
//! credential (D-57), the version-conditional update and the URL binding of the
//! credential, tenant isolation on every verb, the two unique indexes of the
//! link table, the atomic state increments and the reconciliation claim, and
//! the delete cascades.
//!
//! No credential literal appears here: the sealing key and every credential
//! value are generated at run time, and no assertion message formats either.

use std::sync::OnceLock;

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::scim_target::{
    DeprovisionPolicy, NewScimTarget, NewScimTargetLink, ScimLinkState, ScimResourceType,
    ScimTargetAuth, ScimTargetScope, ScimTargetUpdate, UserNameSource,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    OrganizationRepository, Pagination, ScimTargetLinkRepository, ScimTargetRepository,
    ScimTargetStateRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealScimTargetLinkRepository, SurrealScimTargetRepository,
    SurrealScimTargetStateRepository, SurrealTenantRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A sealing key generated once per test binary, never written down.
fn sealing() -> [u8; 32] {
    static SEALING: OnceLock<[u8; 32]> = OnceLock::new();
    *SEALING.get_or_init(|| {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        out
    })
}

/// A credential value made at run time.
fn credential_value() -> Zeroizing<String> {
    Zeroizing::new(format!("c-{}", Uuid::new_v4().simple()))
}

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn targets(db: &Surreal<Db>) -> SurrealScimTargetRepository<Db> {
    SurrealScimTargetRepository::new(db.clone(), Some(sealing()))
}

fn links(db: &Surreal<Db>) -> SurrealScimTargetLinkRepository<Db> {
    SurrealScimTargetLinkRepository::new(db.clone())
}

fn states(db: &Surreal<Db>) -> SurrealScimTargetStateRepository<Db> {
    SurrealScimTargetStateRepository::new(db.clone())
}

fn bearer_input(tenant_id: Uuid) -> NewScimTarget {
    NewScimTarget {
        tenant_id,
        name: "Directory".into(),
        base_url: "https://scim.example.com/v2".into(),
        enabled: true,
        auth: ScimTargetAuth::Bearer,
        credential: credential_value(),
        scope: ScimTargetScope::AllUsers,
        push_groups: false,
        user_name_from: UserNameSource::Username,
        deprovision: DeprovisionPolicy::Deactivate,
    }
}

fn cc_input(tenant_id: Uuid) -> NewScimTarget {
    NewScimTarget {
        tenant_id,
        name: "Directory CC".into(),
        base_url: "https://scim.example.com/v2".into(),
        enabled: true,
        auth: ScimTargetAuth::OAuth2ClientCredentials {
            token_url: "https://auth.example.com/token".into(),
            client_id: "axiam".into(),
            scope: Some("scim".into()),
        },
        credential: credential_value(),
        scope: ScimTargetScope::Groups(vec![Uuid::new_v4(), Uuid::new_v4()]),
        push_groups: true,
        user_name_from: UserNameSource::Email,
        deprovision: DeprovisionPolicy::Delete,
    }
}

fn link_input(tenant_id: Uuid, target_id: Uuid, downstream: &str) -> NewScimTargetLink {
    NewScimTargetLink {
        tenant_id,
        target_id,
        resource_type: ScimResourceType::User,
        axiam_id: Uuid::new_v4(),
        downstream_id: downstream.into(),
    }
}

fn is_not_found<T: std::fmt::Debug>(r: Result<T, AxiamError>) -> bool {
    matches!(r, Err(AxiamError::NotFound { .. }))
}

// ---------------------------------------------------------------------------
// Create, read, credential (acceptance 3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_round_trips_every_field_and_never_reads_the_credential_back() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let input = cc_input(tenant);
    let marker = input.credential.to_string();
    let created = repo.create(input.clone()).await.unwrap();

    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.name, "Directory CC");
    assert_eq!(created.base_url, input.base_url);
    assert!(created.enabled);
    assert_eq!(created.auth, input.auth);
    assert_eq!(created.scope, input.scope);
    assert!(created.push_groups);
    assert_eq!(created.user_name_from, UserNameSource::Email);
    assert_eq!(created.deprovision, DeprovisionPolicy::Delete);

    // The read model has no credential member, and the credential's value is
    // nowhere in any projection of the row.
    let fetched = repo.get(tenant, created.id).await.unwrap();
    assert_eq!(fetched, created);
    let json = serde_json::to_string(&fetched).unwrap();
    assert!(!json.contains(&marker));
    assert!(!format!("{fetched:?}").contains(&marker));
    for page_item in repo
        .list_page(tenant, Pagination::default())
        .await
        .unwrap()
        .items
    {
        assert!(!serde_json::to_string(&page_item).unwrap().contains(&marker));
    }

    // The datastore holds ciphertext, not the value.
    let mut raw = db.query("SELECT * FROM scim_target").await.unwrap();
    let rows: Vec<serde_json::Value> = raw.take(0).unwrap();
    assert!(!serde_json::to_string(&rows).unwrap().contains(&marker));
}

#[tokio::test]
async fn bearer_target_round_trips_and_defaults_hold() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(bearer_input(tenant)).await.unwrap();
    assert_eq!(created.auth, ScimTargetAuth::Bearer);
    assert_eq!(created.scope, ScimTargetScope::AllUsers);
    assert!(!created.push_groups);
    assert_eq!(created.user_name_from, UserNameSource::Username);
    assert_eq!(created.deprovision, DeprovisionPolicy::Deactivate);
}

#[tokio::test]
async fn decrypt_credential_round_trips() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let input = bearer_input(tenant);
    let expected = input.credential.clone();
    let created = repo.create(input).await.unwrap();
    let opened = repo
        .decrypt_credential(tenant, created.id)
        .await
        .unwrap()
        .expect("a credential is stored");
    assert_eq!(opened.as_str(), expected.as_str());
}

#[tokio::test]
async fn create_without_the_key_fails_closed_and_stores_nothing() {
    let db = setup().await;
    let repo = SurrealScimTargetRepository::new(db.clone(), None);
    assert!(!repo.has_encryption_key());
    let tenant = Uuid::new_v4();
    let outcome = repo.create(bearer_input(tenant)).await;
    assert!(matches!(outcome, Err(AxiamError::ServiceUnavailable(_))));
    let page = repo.list_page(tenant, Pagination::default()).await.unwrap();
    assert_eq!(page.total, 0);
    let mut raw = db.query("SELECT * FROM scim_target_state").await.unwrap();
    let rows: Vec<serde_json::Value> = raw.take(0).unwrap();
    assert!(rows.is_empty(), "no state row without a target");
}

#[tokio::test]
async fn a_credential_sealed_under_another_key_does_not_open() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let created = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let mut other = sealing();
    other[0] ^= 0xff;
    let wrong = SurrealScimTargetRepository::new(db.clone(), Some(other));
    assert!(matches!(
        wrong.decrypt_credential(tenant, created.id).await,
        Err(AxiamError::Crypto(_))
    ));
    let keyless = SurrealScimTargetRepository::new(db.clone(), None);
    assert!(matches!(
        keyless.decrypt_credential(tenant, created.id).await,
        Err(AxiamError::ServiceUnavailable(_))
    ));
}

// ---------------------------------------------------------------------------
// Tenant isolation, listing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_verb_is_tenant_scoped() {
    let db = setup().await;
    let repo = targets(&db);
    let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());
    let created = repo.create(bearer_input(mine)).await.unwrap();

    assert!(is_not_found(repo.get(theirs, created.id).await));
    assert!(is_not_found(
        repo.decrypt_credential(theirs, created.id).await
    ));
    assert!(is_not_found(repo.delete(theirs, created.id).await));
    let update = ScimTargetUpdate::from_target(&created);
    assert!(is_not_found(repo.update(theirs, created.id, update).await));
    assert_eq!(
        repo.list_page(theirs, Pagination::default())
            .await
            .unwrap()
            .total,
        0
    );
    assert!(repo.list_enabled(theirs).await.unwrap().is_empty());

    // The state and the links of a foreign tenant's target are equally invisible.
    assert!(is_not_found(states(&db).get(theirs, created.id).await));
    assert!(is_not_found(
        states(&db)
            .record_dead_letter(theirs, created.id, "reason")
            .await
    ));
    assert!(is_not_found(
        links(&db)
            .create(link_input(theirs, created.id, "d-1"))
            .await
    ));
    // ... and nothing leaked into the real owner's state.
    let state = states(&db).get(mine, created.id).await.unwrap();
    assert_eq!(state.dead_lettered_total, 0);

    // Still there for its owner.
    assert_eq!(repo.get(mine, created.id).await.unwrap().id, created.id);
}

#[tokio::test]
async fn list_page_pages_and_list_enabled_skips_disabled_targets() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let a = repo.create(bearer_input(tenant)).await.unwrap();
    let mut disabled = bearer_input(tenant);
    disabled.enabled = false;
    disabled.name = "Off".into();
    let b = repo.create(disabled).await.unwrap();
    let c = repo.create(cc_input(tenant)).await.unwrap();

    let first = repo
        .list_page(
            tenant,
            Pagination {
                offset: 0,
                limit: 2,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(first.total, 3);
    assert_eq!(first.items.len(), 2);
    let rest = repo
        .list_page(
            tenant,
            Pagination {
                offset: 2,
                limit: 2,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(rest.items.len(), 1);
    let all: Vec<Uuid> = first
        .items
        .iter()
        .chain(&rest.items)
        .map(|t| t.id)
        .collect();
    assert_eq!(all, vec![a.id, b.id, c.id]);

    let enabled: Vec<Uuid> = repo
        .list_enabled(tenant)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.id)
        .collect();
    assert_eq!(enabled, vec![a.id, c.id]);
}

// ---------------------------------------------------------------------------
// Conditional update (acceptance 4) and URL binding (acceptance 5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_with_the_current_version_writes_and_moves_the_version() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(bearer_input(tenant)).await.unwrap();

    let mut update = ScimTargetUpdate::from_target(&created);
    update.name = "Renamed".into();
    update.enabled = false;
    update.push_groups = true;
    update.scope = ScimTargetScope::Groups(vec![Uuid::new_v4()]);
    let written = repo.update(tenant, created.id, update).await.unwrap();
    assert_eq!(written.name, "Renamed");
    assert!(!written.enabled);
    assert!(written.push_groups);
    assert!(written.updated_at > created.updated_at);
    // The credential was kept.
    assert!(
        repo.decrypt_credential(tenant, created.id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_stale_expected_updated_at_is_a_conflict_and_writes_nothing() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(bearer_input(tenant)).await.unwrap();

    // Another writer gets in first.
    let mut first = ScimTargetUpdate::from_target(&created);
    first.name = "First".into();
    repo.update(tenant, created.id, first).await.unwrap();

    // The second was prepared from the version before.
    let mut second = ScimTargetUpdate::from_target(&created);
    second.name = "Second".into();
    let outcome = repo.update(tenant, created.id, second).await;
    assert!(matches!(outcome, Err(AxiamError::Conflict { .. })));
    assert_eq!(repo.get(tenant, created.id).await.unwrap().name, "First");
}

#[tokio::test]
async fn an_update_of_a_missing_target_is_not_found_not_a_conflict() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(bearer_input(tenant)).await.unwrap();
    let update = ScimTargetUpdate::from_target(&created);
    assert!(is_not_found(
        repo.update(tenant, Uuid::new_v4(), update).await
    ));
}

#[tokio::test]
async fn an_unconditional_update_still_checks_the_url_binding() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(bearer_input(tenant)).await.unwrap();
    let mut update = ScimTargetUpdate::from_target(&created);
    update.expected_updated_at = None;
    update.base_url = "https://elsewhere.example.net/v2".into();
    assert!(matches!(
        repo.update(tenant, created.id, update).await,
        Err(AxiamError::Validation { .. })
    ));
}

#[tokio::test]
async fn changing_a_bearer_targets_base_url_needs_the_credential() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(bearer_input(tenant)).await.unwrap();

    let mut update = ScimTargetUpdate::from_target(&created);
    update.base_url = "https://elsewhere.example.net/v2".into();
    assert!(matches!(
        repo.update(tenant, created.id, update.clone()).await,
        Err(AxiamError::Validation { .. })
    ));
    // Refused means untouched.
    let unchanged = repo.get(tenant, created.id).await.unwrap();
    assert_eq!(unchanged.base_url, created.base_url);
    assert_eq!(unchanged.updated_at, created.updated_at);

    // With a new credential in the same write: accepted, and the new one is
    // what is stored.
    let fresh = credential_value();
    update.credential = Some(fresh.clone());
    let written = repo.update(tenant, created.id, update).await.unwrap();
    assert_eq!(written.base_url, "https://elsewhere.example.net/v2");
    let opened = repo
        .decrypt_credential(tenant, created.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.as_str(), fresh.as_str());
}

#[tokio::test]
async fn changing_a_client_credentials_token_url_needs_the_credential() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(cc_input(tenant)).await.unwrap();

    let moved = ScimTargetAuth::OAuth2ClientCredentials {
        token_url: "https://evil.example.net/token".into(),
        client_id: "axiam".into(),
        scope: Some("scim".into()),
    };
    let mut update = ScimTargetUpdate::from_target(&created);
    update.auth = moved.clone();
    assert!(matches!(
        repo.update(tenant, created.id, update.clone()).await,
        Err(AxiamError::Validation { .. })
    ));
    update.credential = Some(credential_value());
    let written = repo.update(tenant, created.id, update).await.unwrap();
    assert_eq!(written.auth, moved);
}

#[tokio::test]
async fn a_client_credentials_base_url_may_change_without_the_credential() {
    // The client secret goes to `token_url`, not to `base_url`; only the access
    // token it yields (never persisted) goes to the SCIM base.
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();
    let created = repo.create(cc_input(tenant)).await.unwrap();
    let mut update = ScimTargetUpdate::from_target(&created);
    update.base_url = "https://scim2.example.com/v2".into();
    let written = repo.update(tenant, created.id, update).await.unwrap();
    assert_eq!(written.base_url, "https://scim2.example.com/v2");
}

#[tokio::test]
async fn switching_the_auth_kind_needs_the_credential_both_ways() {
    let db = setup().await;
    let repo = targets(&db);
    let tenant = Uuid::new_v4();

    let bearer = repo.create(bearer_input(tenant)).await.unwrap();
    let mut to_cc = ScimTargetUpdate::from_target(&bearer);
    to_cc.auth = ScimTargetAuth::OAuth2ClientCredentials {
        token_url: "https://auth.example.com/token".into(),
        client_id: "axiam".into(),
        scope: None,
    };
    assert!(matches!(
        repo.update(tenant, bearer.id, to_cc.clone()).await,
        Err(AxiamError::Validation { .. })
    ));
    to_cc.credential = Some(credential_value());
    let switched = repo.update(tenant, bearer.id, to_cc).await.unwrap();
    assert!(matches!(
        switched.auth,
        ScimTargetAuth::OAuth2ClientCredentials { .. }
    ));

    let cc = repo.create(cc_input(tenant)).await.unwrap();
    let mut to_bearer = ScimTargetUpdate::from_target(&cc);
    to_bearer.auth = ScimTargetAuth::Bearer;
    assert!(matches!(
        repo.update(tenant, cc.id, to_bearer.clone()).await,
        Err(AxiamError::Validation { .. })
    ));
    to_bearer.credential = Some(credential_value());
    let switched = repo.update(tenant, cc.id, to_bearer).await.unwrap();
    assert_eq!(switched.auth, ScimTargetAuth::Bearer);
}

#[tokio::test]
async fn an_update_that_supplies_a_credential_without_the_key_fails_closed() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let created = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let keyless = SurrealScimTargetRepository::new(db.clone(), None);
    let mut update = ScimTargetUpdate::from_target(&created);
    update.credential = Some(credential_value());
    assert!(matches!(
        keyless.update(tenant, created.id, update).await,
        Err(AxiamError::ServiceUnavailable(_))
    ));
    // Without a credential in the write, the keyless repository still serves it.
    let mut rename = ScimTargetUpdate::from_target(&created);
    rename.name = "Renamed".into();
    assert_eq!(
        keyless
            .update(tenant, created.id, rename)
            .await
            .unwrap()
            .name,
        "Renamed"
    );
}

// ---------------------------------------------------------------------------
// Links (acceptance 6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn link_create_and_both_lookups() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = links(&db);

    let input = link_input(tenant, target.id, "down-1");
    let created = repo.create(input.clone()).await.unwrap();
    assert_eq!(created.axiam_id, input.axiam_id);
    assert_eq!(created.downstream_id, "down-1");
    assert_eq!(created.state, ScimLinkState::Active);
    assert!(created.synced_digest.is_none());
    assert!(!created.erase_pending);

    let by_axiam = repo
        .get(tenant, target.id, ScimResourceType::User, input.axiam_id)
        .await
        .unwrap();
    assert_eq!(by_axiam, Some(created.clone()));
    let by_down = repo
        .get_by_downstream_id(tenant, target.id, ScimResourceType::User, "down-1")
        .await
        .unwrap();
    assert_eq!(by_down, Some(created));
    // The same ids as a group are another resource entirely.
    assert!(
        repo.get(tenant, target.id, ScimResourceType::Group, input.axiam_id)
            .await
            .unwrap()
            .is_none()
    );
    // A foreign tenant sees nothing.
    assert!(
        repo.get(
            Uuid::new_v4(),
            target.id,
            ScimResourceType::User,
            input.axiam_id
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[tokio::test]
async fn the_link_unique_indexes_hold_on_both_axes() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let other_target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = links(&db);

    let first = link_input(tenant, target.id, "down-1");
    repo.create(first.clone()).await.unwrap();

    // (target, type, axiam_id): the same resource cannot be linked twice.
    let mut same_resource = link_input(tenant, target.id, "down-2");
    same_resource.axiam_id = first.axiam_id;
    assert!(matches!(
        repo.create(same_resource).await,
        Err(AxiamError::AlreadyExists { .. })
    ));

    // (target, type, downstream_id): one downstream id, one resource.
    let same_downstream = link_input(tenant, target.id, "down-1");
    assert!(matches!(
        repo.create(same_downstream.clone()).await,
        Err(AxiamError::AlreadyExists { .. })
    ));

    // The same downstream id as a group, or on another target, is fine.
    let mut as_group = same_downstream.clone();
    as_group.resource_type = ScimResourceType::Group;
    repo.create(as_group).await.unwrap();
    let mut elsewhere = same_downstream;
    elsewhere.target_id = other_target.id;
    repo.create(elsewhere).await.unwrap();
}

#[tokio::test]
async fn upsert_creates_then_repoints_and_honours_the_downstream_index() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = links(&db);

    let input = link_input(tenant, target.id, "down-1");
    let created = repo.upsert(input.clone()).await.unwrap();
    assert_eq!(created.downstream_id, "down-1");

    // Dirty it, then upsert to a new downstream id: repointed and reset.
    repo.set_digest(
        tenant,
        target.id,
        ScimResourceType::User,
        input.axiam_id,
        Some("ab".repeat(32)),
    )
    .await
    .unwrap();
    repo.set_state(
        tenant,
        target.id,
        ScimResourceType::User,
        input.axiam_id,
        ScimLinkState::Deprovisioned,
        true,
    )
    .await
    .unwrap();
    let mut repoint = input.clone();
    repoint.downstream_id = "down-2".into();
    let repointed = repo.upsert(repoint).await.unwrap();
    assert_eq!(repointed.downstream_id, "down-2");
    assert!(repointed.synced_digest.is_none());
    assert_eq!(repointed.state, ScimLinkState::Active);
    assert!(!repointed.erase_pending);
    assert_eq!(repointed.created_at, created.created_at);
    assert_eq!(
        repo.list_by_target(tenant, target.id, None, Pagination::default())
            .await
            .unwrap()
            .total,
        1,
        "an upsert never duplicates"
    );

    // Pointing a *different* resource at a taken downstream id is refused.
    let other = link_input(tenant, target.id, "down-2");
    assert!(matches!(
        repo.upsert(other).await,
        Err(AxiamError::AlreadyExists { .. })
    ));
}

#[tokio::test]
async fn link_setters_delete_and_listing() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = links(&db);

    let user = link_input(tenant, target.id, "u-1");
    let mut group = link_input(tenant, target.id, "g-1");
    group.resource_type = ScimResourceType::Group;
    repo.create(user.clone()).await.unwrap();
    repo.create(group.clone()).await.unwrap();

    let digest = "cd".repeat(32);
    repo.set_digest(
        tenant,
        target.id,
        ScimResourceType::User,
        user.axiam_id,
        Some(digest.clone()),
    )
    .await
    .unwrap();
    repo.set_state(
        tenant,
        target.id,
        ScimResourceType::User,
        user.axiam_id,
        ScimLinkState::Deprovisioned,
        true,
    )
    .await
    .unwrap();
    let read = repo
        .get(tenant, target.id, ScimResourceType::User, user.axiam_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.synced_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(read.state, ScimLinkState::Deprovisioned);
    assert!(read.erase_pending);
    repo.set_digest(
        tenant,
        target.id,
        ScimResourceType::User,
        user.axiam_id,
        None,
    )
    .await
    .unwrap();
    assert!(
        repo.get(tenant, target.id, ScimResourceType::User, user.axiam_id)
            .await
            .unwrap()
            .unwrap()
            .synced_digest
            .is_none()
    );

    // A setter on a link that is not there, or is another tenant's, is NotFound.
    assert!(is_not_found(
        repo.set_digest(
            tenant,
            target.id,
            ScimResourceType::User,
            Uuid::new_v4(),
            None
        )
        .await
    ));
    assert!(is_not_found(
        repo.set_state(
            Uuid::new_v4(),
            target.id,
            ScimResourceType::User,
            user.axiam_id,
            ScimLinkState::Active,
            false
        )
        .await
    ));

    // Paged listing, optionally by type.
    let all = repo
        .list_by_target(tenant, target.id, None, Pagination::default())
        .await
        .unwrap();
    assert_eq!(all.total, 2);
    let users = repo
        .list_by_target(
            tenant,
            target.id,
            Some(ScimResourceType::User),
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(users.total, 1);
    assert_eq!(users.items[0].axiam_id, user.axiam_id);
    let page = repo
        .list_by_target(
            tenant,
            target.id,
            None,
            Pagination {
                offset: 1,
                limit: 1,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!((page.total, page.items.len()), (2, 1));

    // Delete: true once, false after; a foreign tenant removes nothing.
    assert!(
        !repo
            .delete(
                Uuid::new_v4(),
                target.id,
                ScimResourceType::User,
                user.axiam_id
            )
            .await
            .unwrap()
    );
    assert!(
        repo.delete(tenant, target.id, ScimResourceType::User, user.axiam_id)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .delete(tenant, target.id, ScimResourceType::User, user.axiam_id)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.delete_all_for_target(Uuid::new_v4(), target.id)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        repo.delete_all_for_target(tenant, target.id).await.unwrap(),
        1
    );
}

// ---------------------------------------------------------------------------
// State (acceptance 6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_new_targets_state_is_empty() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let state = states(&db).get(tenant, target.id).await.unwrap();
    assert_eq!(state.target_id, target.id);
    assert_eq!(state.tenant_id, tenant);
    assert_eq!(state.consecutive_failures, 0);
    assert_eq!(state.dead_lettered_total, 0);
    assert!(state.last_success_at.is_none());
    assert!(state.last_failure_at.is_none());
    assert!(state.last_failure_reason.is_none());
    assert!(state.last_reconciled_at.is_none());
    assert!(state.reconcile_claimed_at.is_none());
}

#[tokio::test]
async fn success_failure_and_dead_letter_write_their_own_columns() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = states(&db);

    repo.record_failure(tenant, target.id, "server error")
        .await
        .unwrap();
    repo.record_failure(tenant, target.id, "timeout")
        .await
        .unwrap();
    let s = repo.get(tenant, target.id).await.unwrap();
    assert_eq!(s.consecutive_failures, 2);
    assert_eq!(s.last_failure_reason.as_deref(), Some("timeout"));
    assert!(s.last_failure_at.is_some());
    assert_eq!(s.dead_lettered_total, 0);

    repo.record_dead_letter(tenant, target.id, "unauthorized")
        .await
        .unwrap();
    let s = repo.get(tenant, target.id).await.unwrap();
    assert_eq!(s.dead_lettered_total, 1);
    assert_eq!(s.consecutive_failures, 2, "a dead-letter is not a retry");
    assert_eq!(s.last_failure_reason.as_deref(), Some("unauthorized"));

    repo.record_success(tenant, target.id).await.unwrap();
    let s = repo.get(tenant, target.id).await.unwrap();
    assert_eq!(s.consecutive_failures, 0);
    assert!(s.last_success_at.is_some());
    assert_eq!(
        s.dead_lettered_total, 1,
        "lifetime total survives a success"
    );
    assert_eq!(
        s.last_failure_reason.as_deref(),
        Some("unauthorized"),
        "the last failure stays on record"
    );
}

#[tokio::test]
async fn an_overlong_failure_reason_is_truncated_not_refused() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = states(&db);
    repo.record_failure(tenant, target.id, &"x".repeat(1000))
        .await
        .unwrap();
    let s = repo.get(tenant, target.id).await.unwrap();
    assert_eq!(s.last_failure_reason.unwrap().chars().count(), 256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_dead_letters_are_all_counted() {
    const N: u64 = 24;
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = states(&db);

    let mut tasks = Vec::new();
    for _ in 0..N {
        let repo = repo.clone();
        let target_id = target.id;
        tasks.push(tokio::spawn(async move {
            repo.record_dead_letter(tenant, target_id, "rejected").await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let s = repo.get(tenant, target.id).await.unwrap();
    assert_eq!(s.dead_lettered_total, N);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_failures_are_all_counted() {
    const N: u64 = 24;
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = states(&db);

    let mut tasks = Vec::new();
    for _ in 0..N {
        let repo = repo.clone();
        let target_id = target.id;
        tasks.push(tokio::spawn(async move {
            repo.record_failure(tenant, target_id, "server error").await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(
        repo.get(tenant, target.id)
            .await
            .unwrap()
            .consecutive_failures,
        N
    );
}

#[tokio::test]
async fn claim_reconciliation_succeeds_once_within_the_interval() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = states(&db);
    let now = Utc::now();
    let day = 24 * 3600;

    assert!(
        repo.claim_reconciliation(tenant, target.id, now, day)
            .await
            .unwrap()
    );
    let s = repo.get(tenant, target.id).await.unwrap();
    assert!(s.last_reconciled_at.is_some());
    assert!(s.reconcile_claimed_at.is_some());

    // Within the interval: refused, once or many times over.
    for later in [1, 60, day - 1] {
        assert!(
            !repo
                .claim_reconciliation(tenant, target.id, now + Duration::seconds(later), day)
                .await
                .unwrap()
        );
    }
    // After the interval: claimable again.
    assert!(
        repo.claim_reconciliation(tenant, target.id, now + Duration::seconds(day + 1), day)
            .await
            .unwrap()
    );

    // Not yours is NotFound, not "too soon".
    assert!(is_not_found(
        repo.claim_reconciliation(Uuid::new_v4(), target.id, now, day)
            .await
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claims_have_one_winner() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let target = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let repo = states(&db);
    let now = Utc::now();

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let repo = repo.clone();
        let target_id = target.id;
        tasks.push(tokio::spawn(async move {
            repo.claim_reconciliation(tenant, target_id, now, 3600)
                .await
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap().unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

// ---------------------------------------------------------------------------
// Cascades
// ---------------------------------------------------------------------------

async fn rows(db: &Surreal<Db>, table: &str) -> usize {
    let mut raw = db.query(format!("SELECT * FROM {table}")).await.unwrap();
    let rows: Vec<serde_json::Value> = raw.take(0).unwrap();
    rows.len()
}

#[tokio::test]
async fn deleting_a_target_removes_its_links_and_state_and_only_its_own() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let doomed = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let kept = targets(&db).create(bearer_input(tenant)).await.unwrap();
    let link_repo = links(&db);
    link_repo
        .create(link_input(tenant, doomed.id, "d-1"))
        .await
        .unwrap();
    link_repo
        .create(link_input(tenant, doomed.id, "d-2"))
        .await
        .unwrap();
    link_repo
        .create(link_input(tenant, kept.id, "k-1"))
        .await
        .unwrap();

    targets(&db).delete(tenant, doomed.id).await.unwrap();

    assert!(is_not_found(targets(&db).get(tenant, doomed.id).await));
    assert!(is_not_found(states(&db).get(tenant, doomed.id).await));
    assert_eq!(
        link_repo
            .list_by_target(tenant, doomed.id, None, Pagination::default())
            .await
            .unwrap()
            .total,
        0
    );
    assert_eq!(rows(&db, "scim_target").await, 1);
    assert_eq!(rows(&db, "scim_target_state").await, 1);
    assert_eq!(rows(&db, "scim_target_link").await, 1);
    assert!(
        states(&db).get(tenant, kept.id).await.is_ok(),
        "the other target keeps its state"
    );
    // A second delete is NotFound.
    assert!(is_not_found(targets(&db).delete(tenant, doomed.id).await));
}

#[tokio::test]
async fn the_tenant_delete_takes_the_tenants_scim_rows_and_only_those() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let mk = |slug: String| CreateTenant {
        organization_id: org.id,
        name: slug.clone(),
        slug,
        metadata: None,
        kind: TenantKind::Standard,
    };
    let doomed = tenants
        .create(mk(format!("t-{}", Uuid::new_v4().simple())))
        .await
        .unwrap();
    let survivor = tenants
        .create(mk(format!("t-{}", Uuid::new_v4().simple())))
        .await
        .unwrap();

    let gone = targets(&db).create(bearer_input(doomed.id)).await.unwrap();
    let stays = targets(&db)
        .create(bearer_input(survivor.id))
        .await
        .unwrap();
    links(&db)
        .create(link_input(doomed.id, gone.id, "d-1"))
        .await
        .unwrap();
    links(&db)
        .create(link_input(survivor.id, stays.id, "s-1"))
        .await
        .unwrap();

    tenants.delete(doomed.id).await.unwrap();

    assert_eq!(rows(&db, "scim_target").await, 1);
    assert_eq!(rows(&db, "scim_target_state").await, 1);
    assert_eq!(rows(&db, "scim_target_link").await, 1);
    assert_eq!(
        targets(&db).get(survivor.id, stays.id).await.unwrap().id,
        stays.id
    );
}
