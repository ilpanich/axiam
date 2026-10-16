//! Network segments, reply profiles and the tenant's session cap against the
//! real datastore (RADIUS D4, W6.1, schema v100;
//! `claude_dev/radius-reply-profile-design.md` §3 and §4).
//!
//! What lives in the datastore rather than in plain Rust, and is pinned here: a
//! segment is a node of the reserved `/network` subtree of the resource tree
//! (D-5) and is refused anywhere else; a profile is checked against the
//! envelope of the segment row it is written under (§5.2 H3); every write is
//! conditional on the version read; another tenant's rows are invisible; and a
//! profile's `Session-Timeout` is clamped to the tenant's *current* cap at read.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::network::{
    NetworkPolicy, NetworkSegment, NetworkSegmentKind, NetworkSegmentUpdate, NetworkWriteClearance,
    NetworkWriteTarget, NewNetworkSegment, NewReplyProfile, RESOURCE_TYPE_NETWORK_BRANCH,
    RESOURCE_TYPE_NETWORK_ROOT, RESOURCE_TYPE_NETWORK_SEGMENT, RESOURCE_TYPE_NETWORK_SITE,
    ReplyProfile, ReplyProfileReplace, SetNetworkPolicy,
};
use axiam_core::models::radius_reply::{
    REPLY_DICTIONARY_V1, ReplyProfileInput, ServiceType, TerminationAction,
};
use axiam_core::models::resource::CreateResource;
use axiam_core::repository::{
    NetworkPolicyRepository, NetworkSegmentRepository, PaginatedResult, Pagination,
    ReplyProfileRepository, ResourceRepository,
};
use axiam_db::repository::{
    SurrealNetworkPolicyRepository, SurrealNetworkSegmentRepository, SurrealReplyProfileRepository,
    SurrealResourceRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

mod common;

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn segments(db: &Surreal<Db>) -> Cleared<SurrealNetworkSegmentRepository<Db>> {
    Cleared(SurrealNetworkSegmentRepository::new(db.clone()))
}

fn profiles(db: &Surreal<Db>) -> Cleared<SurrealReplyProfileRepository<Db>> {
    Cleared(SurrealReplyProfileRepository::new(db.clone()))
}

/// The repositories as the authorization function's caller sees them.
///
/// Every write method takes the `NetworkWriteClearance` that
/// `axiam_authz::network_gate` issues for exactly that write (W6.2). This file
/// tests what the *data* decides, so it stands in for the function and mints
/// the matching clearance itself; what the function decides is tested in
/// `axiam-authz` and `axiam-api-rest`. `the_repository_refuses_a_clearance_for_another_write`
/// below pins that a mismatched one writes nothing.
struct Cleared<R>(R);

fn cleared(tenant_id: Uuid, actor: Uuid, target: NetworkWriteTarget) -> NetworkWriteClearance {
    NetworkWriteClearance::issued_by_the_network_gate(tenant_id, actor, target)
}

impl Cleared<SurrealNetworkSegmentRepository<Db>> {
    async fn create(&self, input: NewNetworkSegment) -> AxiamResult<NetworkSegment> {
        let c = cleared(
            input.tenant_id,
            input.actor,
            NetworkWriteTarget::SegmentCreate {
                path: input.path.clone(),
            },
        );
        self.0.create(input, &c).await
    }
    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        update: NetworkSegmentUpdate,
    ) -> AxiamResult<NetworkSegment> {
        let c = cleared(
            tenant_id,
            update.actor,
            NetworkWriteTarget::SegmentUpdate { segment_id: id },
        );
        self.0.update(tenant_id, id, update, &c).await
    }
    /// As the gate clears a replace it did not check `network:grant` for
    /// (R110W6-03): the placement of a profiled segment is frozen.
    async fn update_frozen(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        update: NetworkSegmentUpdate,
    ) -> AxiamResult<NetworkSegment> {
        let c = cleared(
            tenant_id,
            update.actor,
            NetworkWriteTarget::SegmentUpdate { segment_id: id },
        )
        .freeze_profiled_placement();
        self.0.update(tenant_id, id, update, &c).await
    }
    async fn delete(&self, tenant_id: Uuid, id: Uuid, expected_version: u64) -> AxiamResult<()> {
        let c = cleared(
            tenant_id,
            Uuid::new_v4(),
            NetworkWriteTarget::SegmentDelete { segment_id: id },
        );
        self.0.delete(tenant_id, id, expected_version, &c).await
    }
    /// As the gate clears a delete it did not check `network:grant` for (the
    /// decision of 2026-10-16: it read no profile): a profiled segment is not
    /// deleted.
    async fn delete_frozen(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_version: u64,
    ) -> AxiamResult<()> {
        let c = cleared(
            tenant_id,
            Uuid::new_v4(),
            NetworkWriteTarget::SegmentDelete { segment_id: id },
        )
        .freeze_profiled_placement();
        self.0.delete(tenant_id, id, expected_version, &c).await
    }
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<NetworkSegment> {
        self.0.get(tenant_id, id).await
    }
    async fn get_by_path(&self, tenant_id: Uuid, path: &str) -> AxiamResult<NetworkSegment> {
        self.0.get_by_path(tenant_id, path).await
    }
    async fn list_page(
        &self,
        tenant_id: Uuid,
        site_key: Option<&str>,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<NetworkSegment>> {
        self.0.list_page(tenant_id, site_key, pagination).await
    }
}

impl Cleared<SurrealReplyProfileRepository<Db>> {
    async fn create(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        input: NewReplyProfile,
    ) -> AxiamResult<ReplyProfile> {
        let c = cleared(
            tenant_id,
            input.actor,
            NetworkWriteTarget::ProfileWrite { segment_id },
        );
        self.0.create(tenant_id, segment_id, input, &c).await
    }
    async fn replace(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        input: ReplyProfileReplace,
    ) -> AxiamResult<ReplyProfile> {
        let c = cleared(
            tenant_id,
            input.actor,
            NetworkWriteTarget::ProfileWrite { segment_id },
        );
        self.0.replace(tenant_id, segment_id, input, &c).await
    }
    async fn delete(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        expected_version: u64,
    ) -> AxiamResult<()> {
        let c = cleared(
            tenant_id,
            Uuid::new_v4(),
            NetworkWriteTarget::ProfileDelete { segment_id },
        );
        self.0
            .delete(tenant_id, segment_id, expected_version, &c)
            .await
    }
    async fn get_by_segment(&self, tenant_id: Uuid, segment_id: Uuid) -> AxiamResult<ReplyProfile> {
        self.0.get_by_segment(tenant_id, segment_id).await
    }
    async fn list_page(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<ReplyProfile>> {
        self.0.list_page(tenant_id, pagination).await
    }
}

fn policies(db: &Surreal<Db>) -> Cleared<SurrealNetworkPolicyRepository<Db>> {
    Cleared(SurrealNetworkPolicyRepository::new(db.clone()))
}

impl Cleared<SurrealNetworkPolicyRepository<Db>> {
    async fn get(&self, tenant_id: Uuid) -> AxiamResult<NetworkPolicy> {
        self.0.get(tenant_id).await
    }
    async fn set(&self, tenant_id: Uuid, input: SetNetworkPolicy) -> AxiamResult<NetworkPolicy> {
        let c = cleared(tenant_id, input.actor, NetworkWriteTarget::PolicyWrite);
        self.0.set(tenant_id, input, &c).await
    }
}

fn resources(db: &Surreal<Db>) -> SurrealResourceRepository<Db> {
    SurrealResourceRepository::new(db.clone())
}

fn page() -> Pagination {
    Pagination {
        offset: 0,
        limit: 100,
        search: None,
    }
}

fn corp(tenant_id: Uuid) -> NewNetworkSegment {
    NewNetworkSegment {
        tenant_id,
        path: "/network/zones/hq/corp".into(),
        kind: NetworkSegmentKind::Access,
        vlan_id: 10,
        filter_ids: vec!["corp-acl".into(), "guest-acl".into()],
        rank: Some(10),
        enabled: true,
        actor: Uuid::new_v4(),
    }
}

fn profile() -> ReplyProfileInput {
    ReplyProfileInput {
        dictionary: REPLY_DICTIONARY_V1.into(),
        session_timeout_secs: 900,
        termination_action: TerminationAction::RadiusRequest,
        idle_timeout_secs: Some(120),
        filter_id: Some("corp-acl".into()),
        service_type: Some(ServiceType::FramedUser),
    }
}

fn new_profile(segment_version: u64, p: ReplyProfileInput) -> NewReplyProfile {
    NewReplyProfile {
        expected_segment_version: segment_version,
        profile: p,
        actor: Uuid::new_v4(),
    }
}

/// How many `resource` rows a tenant has: what a refused segment must not leave
/// behind.
async fn resource_count(db: &Surreal<Db>, tenant_id: Uuid) -> usize {
    resources(db)
        .list(tenant_id, page())
        .await
        .unwrap()
        .items
        .len()
}

fn is_validation(e: &AxiamError) -> bool {
    matches!(e, AxiamError::Validation { .. })
}

fn is_conflict(e: &AxiamError) -> bool {
    matches!(e, AxiamError::Conflict { .. })
}

// ---------------------------------------------------------------------------
// The oracle of the row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_segment_outside_network_is_refused_and_leaves_nothing() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    for bad in [
        "/corp/zones/hq/corp",
        "/networks/zones/hq/corp",
        "/Network/zones/hq/corp",
        "network/zones/hq/corp",
        "/network",
        "/network/zones/hq",
        "/network/zones/hq/corp/extra",
        "/network/zones/../hq/corp",
        "/network/elsewhere/hq/corp",
        "/network/zones//corp",
        "",
        "/",
    ] {
        let mut input = corp(tenant);
        input.path = bad.into();
        let err = segments(&db).create(input).await.unwrap_err();
        assert!(is_validation(&err), "{bad:?} must be refused: {err:?}");
    }
    // No node of any kind was made on the way to a refusal.
    assert_eq!(resource_count(&db, tenant).await, 0);
    assert_eq!(
        segments(&db)
            .list_page(tenant, None, page())
            .await
            .unwrap()
            .total,
        0
    );
}

#[tokio::test]
async fn quarantine_is_a_sibling_branch_and_a_kind_that_disagrees_with_its_branch_is_refused() {
    let db = setup().await;
    let tenant = Uuid::new_v4();

    // An access segment under the quarantine branch, and a quarantine segment
    // under the access branch: the correct placement is the only placement.
    let mut wrong = corp(tenant);
    wrong.path = "/network/quarantine/hq/q".into();
    assert!(is_validation(
        &segments(&db).create(wrong).await.unwrap_err()
    ));
    let mut wrong = corp(tenant);
    wrong.path = "/network/zones/hq/q".into();
    wrong.kind = NetworkSegmentKind::Quarantine;
    wrong.rank = None;
    assert!(is_validation(
        &segments(&db).create(wrong).await.unwrap_err()
    ));
    assert_eq!(resource_count(&db, tenant).await, 0);

    // The right one: a quarantine segment, no rank, under its own branch.
    let q = segments(&db)
        .create(NewNetworkSegment {
            tenant_id: tenant,
            path: "/network/quarantine/hq/q".into(),
            kind: NetworkSegmentKind::Quarantine,
            vlan_id: 999,
            filter_ids: vec![],
            rank: None,
            enabled: true,
            actor: Uuid::new_v4(),
        })
        .await
        .unwrap();
    assert_eq!(q.kind, NetworkSegmentKind::Quarantine);
    assert_eq!(q.rank, None);
    assert_eq!(q.path(), "/network/quarantine/hq/q");

    // The quarantine branch is a sibling of `zones`, never beneath it.
    let ancestors = resources(&db).get_ancestors(tenant, q.id).await.unwrap();
    let names: Vec<&str> = ancestors.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["hq", "quarantine", "network"]);
}

#[tokio::test]
async fn a_profile_filter_id_outside_its_segments_envelope_is_refused() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();

    let mut outside = profile();
    outside.filter_id = Some("admin-acl".into());
    let err = profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, outside.clone()))
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");
    assert!(
        matches!(
            profiles(&db).get_by_segment(tenant, seg.id).await,
            Err(AxiamError::NotFound { .. })
        ),
        "a refused profile is not stored"
    );

    // The same value is refused on replace, and the stored profile is untouched.
    let stored = profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap();
    let err = profiles(&db)
        .replace(
            tenant,
            seg.id,
            ReplyProfileReplace {
                expected_version: stored.version,
                expected_segment_version: seg.version,
                profile: outside,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");
    let after = profiles(&db).get_by_segment(tenant, seg.id).await.unwrap();
    assert_eq!(after.filter_id.as_deref(), Some("corp-acl"));
    assert_eq!(after.version, stored.version);
}

#[tokio::test]
async fn a_profile_cannot_carry_a_value_outside_the_dictionary() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();

    for mutate in [
        |p: &mut ReplyProfileInput| p.session_timeout_secs = 0,
        |p: &mut ReplyProfileInput| p.session_timeout_secs = 299,
        |p: &mut ReplyProfileInput| p.session_timeout_secs = 3601,
        |p: &mut ReplyProfileInput| p.idle_timeout_secs = Some(30),
        |p: &mut ReplyProfileInput| p.idle_timeout_secs = Some(901),
        |p: &mut ReplyProfileInput| p.service_type = Some(ServiceType::AdministrativeUser),
        |p: &mut ReplyProfileInput| p.dictionary = "axiam-radius-reply/2".into(),
    ] {
        let mut p = profile();
        mutate(&mut p);
        let err = profiles(&db)
            .create(tenant, seg.id, new_profile(seg.version, p))
            .await
            .unwrap_err();
        assert!(is_validation(&err), "{err:?}");
    }
}

// ---------------------------------------------------------------------------
// CRUD round trips
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_segment_round_trips_and_lives_in_the_resource_tree() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let mut input = corp(tenant);
    input.actor = actor;
    let seg = segments(&db).create(input).await.unwrap();

    assert_eq!(seg.version, 1);
    assert_eq!(seg.tenant_id, tenant);
    assert_eq!((seg.name.as_str(), seg.site_key.as_str()), ("corp", "hq"));
    assert_eq!(seg.kind, NetworkSegmentKind::Access);
    assert_eq!((seg.vlan_id, seg.rank, seg.enabled), (10, Some(10), true));
    assert_eq!(seg.filter_ids, ["corp-acl", "guest-acl"]);
    assert_eq!((seg.created_by, seg.updated_by), (actor, actor));
    assert_eq!(seg.path(), "/network/zones/hq/corp");

    // Reads agree.
    assert_eq!(segments(&db).get(tenant, seg.id).await.unwrap(), seg);
    assert_eq!(
        segments(&db)
            .get_by_path(tenant, "/network/zones/hq/corp")
            .await
            .unwrap(),
        seg
    );

    // D-5: the segment is a resource, under reserved nodes of reserved types, so
    // the engine's cascade and deny-override reach it unchanged.
    let node = resources(&db).get_by_id(tenant, seg.id).await.unwrap();
    assert_eq!(node.resource_type, RESOURCE_TYPE_NETWORK_SEGMENT);
    assert_eq!(node.name, "corp");
    let chain: Vec<(String, String)> = resources(&db)
        .get_ancestors(tenant, seg.id)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.name, r.resource_type))
        .collect();
    assert_eq!(
        chain,
        [
            ("hq".to_owned(), RESOURCE_TYPE_NETWORK_SITE.to_owned()),
            ("zones".to_owned(), RESOURCE_TYPE_NETWORK_BRANCH.to_owned()),
            ("network".to_owned(), RESOURCE_TYPE_NETWORK_ROOT.to_owned()),
        ]
    );

    // List, narrowed by site.
    let mut second = corp(tenant);
    second.path = "/network/zones/hq/iot".into();
    second.vlan_id = 20;
    second.rank = Some(20);
    segments(&db).create(second).await.unwrap();
    let mut elsewhere = corp(tenant);
    elsewhere.path = "/network/zones/branch/corp".into();
    segments(&db).create(elsewhere).await.unwrap();

    let all = segments(&db).list_page(tenant, None, page()).await.unwrap();
    assert_eq!(all.total, 3);
    let hq = segments(&db)
        .list_page(tenant, Some("hq"), page())
        .await
        .unwrap();
    assert_eq!(hq.total, 2);
    let names: Vec<&str> = hq.items.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["corp", "iot"], "by rank within the site");

    // Update: a new envelope, the version moves, the kind and place do not.
    let updated = segments(&db)
        .update(
            tenant,
            seg.id,
            NetworkSegmentUpdate {
                expected_version: seg.version,
                vlan_id: 11,
                filter_ids: vec!["corp-acl".into()],
                rank: Some(5),
                enabled: false,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.version, 2);
    assert_eq!(
        (updated.vlan_id, updated.rank, updated.enabled),
        (11, Some(5), false)
    );
    assert_eq!(updated.filter_ids, ["corp-acl"]);
    assert_eq!(updated.kind, seg.kind);
    assert_eq!(updated.path(), seg.path());
    assert_eq!(updated.created_by, actor);
    assert_ne!(updated.updated_by, actor);

    // Delete takes the resource node with it, and no other.
    segments(&db)
        .delete(tenant, seg.id, updated.version)
        .await
        .unwrap();
    assert!(matches!(
        segments(&db).get(tenant, seg.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        resources(&db).get_by_id(tenant, seg.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(
        segments(&db)
            .list_page(tenant, Some("hq"), page())
            .await
            .unwrap()
            .total,
        1
    );
}

#[tokio::test]
async fn the_reserved_nodes_are_made_once_and_shared() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    segments(&db).create(corp(tenant)).await.unwrap();
    let mut iot = corp(tenant);
    iot.path = "/network/zones/hq/iot".into();
    iot.vlan_id = 20;
    iot.rank = Some(20);
    segments(&db).create(iot).await.unwrap();

    let nodes = resources(&db).list(tenant, page()).await.unwrap().items;
    let count = |t: &str| nodes.iter().filter(|r| r.resource_type == t).count();
    assert_eq!(
        count(RESOURCE_TYPE_NETWORK_ROOT),
        1,
        "one /network per tenant"
    );
    assert_eq!(count(RESOURCE_TYPE_NETWORK_BRANCH), 1);
    assert_eq!(count(RESOURCE_TYPE_NETWORK_SITE), 1);
    assert_eq!(count(RESOURCE_TYPE_NETWORK_SEGMENT), 2);
}

#[tokio::test]
async fn a_profile_round_trips() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();
    let actor = Uuid::new_v4();

    let created = profiles(&db)
        .create(
            tenant,
            seg.id,
            NewReplyProfile {
                expected_segment_version: seg.version,
                profile: profile(),
                actor,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.segment_id, seg.id);
    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.dictionary, REPLY_DICTIONARY_V1);
    assert_eq!(created.session_timeout_secs, 900);
    assert!(!created.session_timeout_clamped);
    assert_eq!(created.termination_action, TerminationAction::RadiusRequest);
    assert_eq!(created.idle_timeout_secs, Some(120));
    assert_eq!(created.filter_id.as_deref(), Some("corp-acl"));
    assert_eq!(created.service_type, Some(ServiceType::FramedUser));
    assert_eq!((created.version, created.created_by), (1, actor));
    assert_eq!(
        profiles(&db).get_by_segment(tenant, seg.id).await.unwrap(),
        created
    );

    // One profile per segment, at most.
    let again = profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap_err();
    assert!(
        matches!(again, AxiamError::AlreadyExists { .. }),
        "{again:?}"
    );

    // Replace, with every optional field dropped.
    let replaced = profiles(&db)
        .replace(
            tenant,
            seg.id,
            ReplyProfileReplace {
                expected_version: created.version,
                expected_segment_version: seg.version,
                profile: ReplyProfileInput {
                    dictionary: REPLY_DICTIONARY_V1.into(),
                    session_timeout_secs: 1800,
                    termination_action: TerminationAction::Default,
                    idle_timeout_secs: None,
                    filter_id: None,
                    service_type: None,
                },
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    assert_eq!(replaced.version, 2);
    assert_eq!(replaced.session_timeout_secs, 1800);
    assert_eq!(replaced.termination_action, TerminationAction::Default);
    assert_eq!(
        (
            replaced.idle_timeout_secs,
            replaced.filter_id.clone(),
            replaced.service_type
        ),
        (None, None, None)
    );
    assert_eq!(replaced.created_by, actor);

    // Delete.
    profiles(&db)
        .delete(tenant, seg.id, replaced.version)
        .await
        .unwrap();
    assert!(matches!(
        profiles(&db).get_by_segment(tenant, seg.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        profiles(&db).delete(tenant, seg.id, 1).await,
        Err(AxiamError::NotFound { .. })
    ));
}

#[tokio::test]
async fn deleting_a_segment_takes_its_profile_and_refuses_while_it_has_children() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();
    profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap();

    let child = resources(&db)
        .create(CreateResource {
            tenant_id: tenant,
            name: "child".into(),
            resource_type: "project".into(),
            parent_id: Some(seg.id),
            metadata: None,
        })
        .await
        .unwrap();
    let err = segments(&db)
        .delete(tenant, seg.id, seg.version)
        .await
        .unwrap_err();
    assert!(is_conflict(&err), "{err:?}");
    assert!(
        profiles(&db).get_by_segment(tenant, seg.id).await.is_ok(),
        "a refused delete leaves the profile"
    );

    resources(&db).delete(tenant, child.id).await.unwrap();
    segments(&db)
        .delete(tenant, seg.id, seg.version)
        .await
        .unwrap();
    assert!(matches!(
        profiles(&db).get_by_segment(tenant, seg.id).await,
        Err(AxiamError::NotFound { .. })
    ));
}

// ---------------------------------------------------------------------------
// Conditional writes (plan §10, the two-writer rule)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_conditional_write_on_a_stale_version_is_refused() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();

    let update = |version: u64, vlan: u16| NetworkSegmentUpdate {
        expected_version: version,
        vlan_id: vlan,
        filter_ids: vec!["corp-acl".into(), "guest-acl".into()],
        rank: Some(10),
        enabled: true,
        actor: Uuid::new_v4(),
    };

    // Two writers read version 1; the first wins, the second is stale.
    let first = segments(&db)
        .update(tenant, seg.id, update(1, 11))
        .await
        .unwrap();
    assert_eq!(first.version, 2);
    let stale = segments(&db)
        .update(tenant, seg.id, update(1, 12))
        .await
        .unwrap_err();
    assert!(is_conflict(&stale), "{stale:?}");
    assert_eq!(
        segments(&db).get(tenant, seg.id).await.unwrap().vlan_id,
        11,
        "the stale write changed nothing"
    );
    // The same for delete.
    let stale = segments(&db).delete(tenant, seg.id, 1).await.unwrap_err();
    assert!(is_conflict(&stale), "{stale:?}");
    assert!(segments(&db).get(tenant, seg.id).await.is_ok());

    // A profile is written under the segment's version it read...
    let stale = profiles(&db)
        .create(tenant, seg.id, new_profile(1, profile()))
        .await
        .unwrap_err();
    assert!(is_conflict(&stale), "{stale:?}");
    let created = profiles(&db)
        .create(tenant, seg.id, new_profile(2, profile()))
        .await
        .unwrap();

    // ...and under its own.
    let replace = |version: u64, segment_version: u64, timeout: u32| {
        let mut p = profile();
        p.session_timeout_secs = timeout;
        ReplyProfileReplace {
            expected_version: version,
            expected_segment_version: segment_version,
            profile: p,
            actor: Uuid::new_v4(),
        }
    };
    let ok = profiles(&db)
        .replace(tenant, seg.id, replace(1, 2, 1000))
        .await
        .unwrap();
    assert_eq!(ok.version, created.version + 1);
    let stale = profiles(&db)
        .replace(tenant, seg.id, replace(1, 2, 2000))
        .await
        .unwrap_err();
    assert!(is_conflict(&stale), "{stale:?}");
    let stale_segment = profiles(&db)
        .replace(tenant, seg.id, replace(2, 1, 2000))
        .await
        .unwrap_err();
    assert!(is_conflict(&stale_segment), "{stale_segment:?}");
    let stale = profiles(&db).delete(tenant, seg.id, 1).await.unwrap_err();
    assert!(is_conflict(&stale), "{stale:?}");
    assert_eq!(
        profiles(&db)
            .get_by_segment(tenant, seg.id)
            .await
            .unwrap()
            .session_timeout_secs,
        1000
    );

    // The tenant policy too: 0 is "never written".
    let set = |cap: u32, version: u64| SetNetworkPolicy {
        session_timeout_max_secs: cap,
        expected_version: version,
        actor: Uuid::new_v4(),
    };
    policies(&db).set(tenant, set(1800, 0)).await.unwrap();
    for stale in [set(2000, 0), set(2000, 5)] {
        let err = policies(&db).set(tenant, stale).await.unwrap_err();
        assert!(is_conflict(&err), "{err:?}");
    }
    assert_eq!(
        policies(&db)
            .set(tenant, set(2400, 1))
            .await
            .unwrap()
            .version,
        2
    );
}

#[tokio::test]
async fn a_segment_write_cannot_strand_its_profile() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();
    profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap();

    let without_the_profiles_acl = |version: u64| NetworkSegmentUpdate {
        expected_version: version,
        vlan_id: 10,
        filter_ids: vec!["guest-acl".into()],
        rank: Some(10),
        enabled: true,
        actor: Uuid::new_v4(),
    };
    let err = segments(&db)
        .update(tenant, seg.id, without_the_profiles_acl(seg.version))
        .await
        .unwrap_err();
    assert!(is_conflict(&err), "{err:?}");
    assert_eq!(
        segments(&db).get(tenant, seg.id).await.unwrap().filter_ids,
        ["corp-acl", "guest-acl"]
    );

    // Dropping the profile first makes the same write fine, and widening the
    // envelope never strands anything.
    let profile_version = profiles(&db)
        .get_by_segment(tenant, seg.id)
        .await
        .unwrap()
        .version;
    profiles(&db)
        .delete(tenant, seg.id, profile_version)
        .await
        .unwrap();
    segments(&db)
        .update(tenant, seg.id, without_the_profiles_acl(seg.version))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Uniqueness per site
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_site_cannot_repeat_a_name_a_vlan_or_a_rank() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    segments(&db).create(corp(tenant)).await.unwrap();

    let at = |name: &str, vlan: u16, rank: u32| {
        let mut s = corp(tenant);
        s.path = format!("/network/zones/hq/{name}");
        s.vlan_id = vlan;
        s.rank = Some(rank);
        s
    };
    for (what, dup) in [
        ("name", at("corp", 11, 11)),
        ("vlan", at("other", 10, 11)),
        ("rank", at("other", 11, 10)),
    ] {
        let err = segments(&db).create(dup).await.unwrap_err();
        assert!(
            matches!(err, AxiamError::AlreadyExists { .. }),
            "a repeated {what}: {err:?}"
        );
    }
    // A refused create leaves no resource node behind: three reserved nodes and
    // the one segment.
    assert_eq!(resource_count(&db, tenant).await, 4);

    // VLAN numbers are per-site facts: the same numbers at another site are fine.
    let mut branch_office = corp(tenant);
    branch_office.path = "/network/zones/branch/corp".into();
    segments(&db).create(branch_office).await.unwrap();

    // So is a quarantine segment of the same name: its branch is its own.
    let mut quarantine = corp(tenant);
    quarantine.path = "/network/quarantine/hq/corp".into();
    quarantine.kind = NetworkSegmentKind::Quarantine;
    quarantine.vlan_id = 999;
    quarantine.rank = None;
    segments(&db).create(quarantine.clone()).await.unwrap();
    // Two quarantine segments at one site have no rank to collide on.
    quarantine.path = "/network/quarantine/hq/other".into();
    quarantine.vlan_id = 998;
    segments(&db).create(quarantine).await.unwrap();
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn another_tenants_segment_is_invisible() {
    let db = setup().await;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let seg = segments(&db).create(corp(a)).await.unwrap();
    let stored = profiles(&db)
        .create(a, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap();

    let not_found = |e: AxiamError| matches!(e, AxiamError::NotFound { .. });
    assert!(not_found(segments(&db).get(b, seg.id).await.unwrap_err()));
    assert!(not_found(
        segments(&db)
            .get_by_path(b, "/network/zones/hq/corp")
            .await
            .unwrap_err()
    ));
    assert_eq!(
        segments(&db)
            .list_page(b, None, page())
            .await
            .unwrap()
            .total,
        0
    );
    assert!(not_found(
        segments(&db)
            .update(
                b,
                seg.id,
                NetworkSegmentUpdate {
                    expected_version: seg.version,
                    vlan_id: 99,
                    filter_ids: vec![],
                    rank: Some(1),
                    enabled: true,
                    actor: Uuid::new_v4(),
                },
            )
            .await
            .unwrap_err()
    ));
    assert!(not_found(
        segments(&db)
            .delete(b, seg.id, seg.version)
            .await
            .unwrap_err()
    ));
    assert!(not_found(
        profiles(&db).get_by_segment(b, seg.id).await.unwrap_err()
    ));
    assert!(not_found(
        profiles(&db)
            .create(b, seg.id, new_profile(seg.version, profile()))
            .await
            .unwrap_err()
    ));
    assert!(not_found(
        profiles(&db)
            .delete(b, seg.id, stored.version)
            .await
            .unwrap_err()
    ));

    // Nothing of tenant A changed.
    assert_eq!(segments(&db).get(a, seg.id).await.unwrap(), seg);
    assert_eq!(
        profiles(&db).get_by_segment(a, seg.id).await.unwrap(),
        stored
    );

    // Tenant B has its own `/network`, and may use the very same path, VLAN and
    // site key: site keys are tenant-scoped strings (design note §7).
    let mine = segments(&db).create(corp(b)).await.unwrap();
    assert_ne!(mine.id, seg.id);
    assert_eq!(resource_count(&db, a).await, 4);
    assert_eq!(resource_count(&db, b).await, 4);

    // The cap is per tenant.
    policies(&db)
        .set(
            a,
            SetNetworkPolicy {
                session_timeout_max_secs: 600,
                expected_version: 0,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        policies(&db).get(b).await.unwrap().session_timeout_max_secs,
        3600
    );
}

// ---------------------------------------------------------------------------
// The session cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_cap_defaults_to_an_hour_and_is_bounded() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let policy = policies(&db).get(tenant).await.unwrap();
    assert_eq!(policy.session_timeout_max_secs, 3600);
    assert_eq!(policy.version, 0);
    assert!(policy.updated_by.is_none());

    for out_of_range in [0, 299, 86_401] {
        let err = policies(&db)
            .set(
                tenant,
                SetNetworkPolicy {
                    session_timeout_max_secs: out_of_range,
                    expected_version: 0,
                    actor: Uuid::new_v4(),
                },
            )
            .await
            .unwrap_err();
        assert!(is_validation(&err), "{out_of_range}: {err:?}");
    }
    let set = policies(&db)
        .set(
            tenant,
            SetNetworkPolicy {
                session_timeout_max_secs: 86_400,
                expected_version: 0,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    assert_eq!((set.session_timeout_max_secs, set.version), (86_400, 1));
    assert!(set.updated_by.is_some() && set.updated_at.is_some());
}

#[tokio::test]
async fn session_timeout_is_clamped_at_read_to_the_tenants_current_cap() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();

    // Above the default cap of 3600: refused at write.
    let mut high = profile();
    high.session_timeout_secs = 7200;
    high.idle_timeout_secs = Some(3000);
    let err = profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, high.clone()))
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");

    // The tenant raises its cap, and the same profile is accepted as written.
    policies(&db)
        .set(
            tenant,
            SetNetworkPolicy {
                session_timeout_max_secs: 7200,
                expected_version: 0,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    let stored = profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, high))
        .await
        .unwrap();
    assert_eq!(stored.session_timeout_secs, 7200);
    assert!(!stored.session_timeout_clamped);

    // The tenant lowers its cap. Nothing is rewritten, and the next read is
    // already narrower: the timeout and the idle timeout that rode with it.
    policies(&db)
        .set(
            tenant,
            SetNetworkPolicy {
                session_timeout_max_secs: 600,
                expected_version: 1,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    let read = profiles(&db).get_by_segment(tenant, seg.id).await.unwrap();
    assert_eq!(read.session_timeout_secs, 600);
    assert!(read.session_timeout_clamped);
    assert_eq!(read.idle_timeout_secs, Some(600), "never above the timeout");
    assert_eq!(read.version, stored.version, "a read writes nothing");

    // Raised again: the stored value was never touched, so it comes back.
    policies(&db)
        .set(
            tenant,
            SetNetworkPolicy {
                session_timeout_max_secs: 7200,
                expected_version: 2,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    let read = profiles(&db).get_by_segment(tenant, seg.id).await.unwrap();
    assert_eq!(read.session_timeout_secs, 7200);
    assert!(!read.session_timeout_clamped);
    assert_eq!(read.idle_timeout_secs, Some(3000));
}

#[tokio::test]
async fn the_datastore_bounds_the_cap_and_the_timeout_itself() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();
    profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap();
    // The schema's own ASSERT refuses a cap past a day...
    let refused = db
        .query(
            "CREATE type::record('network_policy', $t) SET tenant_id = $t, \
             session_timeout_max_secs = 604800, version = 1, updated_by = $t",
        )
        .bind(("t", tenant.to_string()))
        .await
        .unwrap()
        .check();
    assert!(refused.is_err(), "the datastore bounds the cap as well");
    // ...and a stored profile past the floor is refused the same way.
    let refused = db
        .query("UPDATE type::record('reply_profile', $s) SET session_timeout_secs = 0")
        .bind(("s", seg.id.to_string()))
        .await
        .unwrap()
        .check();
    assert!(
        refused.is_err(),
        "the datastore refuses a zero Session-Timeout"
    );
}

// ---------------------------------------------------------------------------
// Two writers racing for a node that does not exist yet
// ---------------------------------------------------------------------------

/// Run on the storage engine production deploys (`common::serialising_db`):
/// two callers that both find `/network` missing both try to make it, and the
/// engine's key conflict, retried, must leave exactly one.
#[tokio::test]
async fn two_first_writers_make_one_network_root() {
    let fixture = common::serialising_db().await;
    let db = fixture.handle();
    let tenant = Uuid::new_v4();
    let a = segments(&db);
    let b = segments(&db);

    let mut first = corp(tenant);
    first.path = "/network/zones/hq/corp".into();
    let mut second = corp(tenant);
    second.path = "/network/zones/hq/iot".into();
    second.vlan_id = 20;
    second.rank = Some(20);

    let (r1, r2) = tokio::join!(a.create(first), b.create(second));
    r1.unwrap();
    r2.unwrap();

    let nodes = resources(&db).list(tenant, page()).await.unwrap().items;
    let count = |t: &str| nodes.iter().filter(|r| r.resource_type == t).count();
    assert_eq!(count(RESOURCE_TYPE_NETWORK_ROOT), 1);
    assert_eq!(count(RESOURCE_TYPE_NETWORK_BRANCH), 1);
    assert_eq!(count(RESOURCE_TYPE_NETWORK_SITE), 1);
    assert_eq!(count(RESOURCE_TYPE_NETWORK_SEGMENT), 2);
}

/// The T-416 lesson (design note §3.5): a profile is checked against the
/// envelope of the row it is written under. A segment write that removes the
/// profile's `Filter-Id` racing the profile's creation must leave one of two
/// worlds, never a stored profile whose `filter_id` the segment no longer
/// declares. Run on the engine production deploys.
#[tokio::test]
async fn a_profile_and_an_envelope_change_racing_never_leave_a_stranded_profile() {
    let fixture = common::serialising_db().await;
    let db = fixture.handle();
    let tenant = Uuid::new_v4();

    for round in 0..8u16 {
        let mut input = corp(tenant);
        input.path = format!("/network/zones/hq/seg{round}");
        input.vlan_id = 100 + round;
        input.rank = Some(100 + u32::from(round));
        let seg = segments(&db).create(input).await.unwrap();

        let (segment_repo, profile_repo) = (segments(&db), profiles(&db));
        let drop_the_acl = NetworkSegmentUpdate {
            expected_version: seg.version,
            vlan_id: seg.vlan_id,
            filter_ids: vec!["guest-acl".into()],
            rank: seg.rank,
            enabled: true,
            actor: Uuid::new_v4(),
        };
        let (updated, created) = tokio::join!(
            segment_repo.update(tenant, seg.id, drop_the_acl),
            profile_repo.create(tenant, seg.id, new_profile(seg.version, profile())),
        );

        let envelope = segments(&db).get(tenant, seg.id).await.unwrap().filter_ids;
        if let Ok(stored) = profiles(&db).get_by_segment(tenant, seg.id).await {
            let used = stored.filter_id.expect("the profile names an ACL");
            assert!(
                envelope.contains(&used),
                "round {round}: profile uses {used:?}, envelope is {envelope:?} \
                 (update {updated:?}, create {created:?})"
            );
        }
        assert!(
            updated.is_ok() || created.is_ok(),
            "round {round}: at least one writer wins: {updated:?} / {created:?}"
        );
    }
}

/// R110W6-03, the datastore's half: a replace the gate cleared without
/// `network:grant` (a frozen clearance) does not change `vlan_id`, `rank` or
/// `enabled` of a segment that has a profile **when the write runs** — the gate's
/// read is not trusted for it — and changes everything else.
#[tokio::test]
async fn a_frozen_replace_does_not_move_a_profiled_segments_placement() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let seg = segments(&db).create(corp(tenant)).await.unwrap();
    // The stored envelope, as a replace that changes nothing.
    let same = |seg: &NetworkSegment| NetworkSegmentUpdate {
        expected_version: seg.version,
        vlan_id: seg.vlan_id,
        filter_ids: seg.filter_ids.clone(),
        rank: seg.rank,
        enabled: seg.enabled,
        actor: Uuid::new_v4(),
    };

    // No profile: every field moves under a frozen clearance.
    let mut moved = same(&seg);
    moved.vlan_id = 11;
    let seg = segments(&db)
        .update_frozen(tenant, seg.id, moved)
        .await
        .unwrap();
    assert_eq!(seg.vlan_id, 11);

    // A profile appears (the gate's read is now stale).
    profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap();

    // Each placement field: 409, nothing written.
    let mut vlan = same(&seg);
    vlan.vlan_id = 12;
    let mut rank = same(&seg);
    rank.rank = Some(5);
    let mut disabled = same(&seg);
    disabled.enabled = false;
    for update in [vlan.clone(), rank, disabled] {
        let err = segments(&db)
            .update_frozen(tenant, seg.id, update)
            .await
            .unwrap_err();
        assert!(is_conflict(&err), "{err:?}");
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
    }
    assert_eq!(segments(&db).get(tenant, seg.id).await.unwrap(), seg);

    // A non-placement field still moves under a frozen clearance...
    let mut acl = same(&seg);
    acl.filter_ids.push("iot-acl".into());
    let seg = segments(&db)
        .update_frozen(tenant, seg.id, acl)
        .await
        .unwrap();
    assert_eq!(seg.filter_ids.len(), 3);

    // ...and a clearance the gate checked the grant for moves the VLAN.
    vlan.expected_version = seg.version;
    let seg = segments(&db).update(tenant, seg.id, vlan).await.unwrap();
    assert_eq!(seg.vlan_id, 12);

    // A quarantine segment (no rank) is compared as stored: an unchanged
    // replace is not a move.
    let mut q = corp(tenant);
    q.path = "/network/quarantine/hq/q".into();
    q.kind = NetworkSegmentKind::Quarantine;
    q.vlan_id = 999;
    q.rank = None;
    let q = segments(&db).create(q).await.unwrap();
    profiles(&db)
        .create(tenant, q.id, new_profile(q.version, profile()))
        .await
        .unwrap();
    let mut unchanged = same(&q);
    unchanged.filter_ids.push("q-acl".into());
    segments(&db)
        .update_frozen(tenant, q.id, unchanged)
        .await
        .unwrap();
}

/// R110W6-03 under the engine production runs: a profile created while a
/// frozen replace moves the VLAN never leaves the profiled segment on a VLAN
/// no `network:grant` holder chose.
#[tokio::test]
async fn a_profile_racing_a_frozen_vlan_change_never_lands_both() {
    let fixture = common::serialising_db().await;
    let db = fixture.handle();
    let tenant = Uuid::new_v4();

    for round in 0..8u16 {
        let mut input = corp(tenant);
        input.path = format!("/network/zones/hq/race{round}");
        input.vlan_id = 200 + round;
        input.rank = Some(200 + u32::from(round));
        let seg = segments(&db).create(input).await.unwrap();

        let (segment_repo, profile_repo) = (segments(&db), profiles(&db));
        let move_the_vlan = NetworkSegmentUpdate {
            expected_version: seg.version,
            vlan_id: 300 + round,
            filter_ids: seg.filter_ids.clone(),
            rank: seg.rank,
            enabled: true,
            actor: Uuid::new_v4(),
        };
        let (updated, created) = tokio::join!(
            segment_repo.update_frozen(tenant, seg.id, move_the_vlan),
            profile_repo.create(tenant, seg.id, new_profile(seg.version, profile())),
        );
        assert!(
            !(updated.is_ok() && created.is_ok()),
            "round {round}: a profile and a frozen VLAN change both landed"
        );
        let vlan = segments(&db).get(tenant, seg.id).await.unwrap().vlan_id;
        if profiles(&db).get_by_segment(tenant, seg.id).await.is_ok() {
            assert_eq!(vlan, 200 + round, "round {round}: the profiled VLAN moved");
        }
    }
}

/// The decision of 2026-10-16, the datastore's half: a delete the gate cleared
/// without `network:grant` (a frozen clearance) does not remove a segment that
/// has a profile **when the write runs**, and removes one that has none.
#[tokio::test]
async fn a_frozen_delete_does_not_remove_a_profiled_segment() {
    let db = setup().await;
    let tenant = Uuid::new_v4();

    // No profile: a frozen delete removes it.
    let bare = segments(&db).create(corp(tenant)).await.unwrap();
    segments(&db)
        .delete_frozen(tenant, bare.id, bare.version)
        .await
        .unwrap();
    assert!(segments(&db).get(tenant, bare.id).await.is_err());

    // A profile appears after the gate's read: 409, nothing removed.
    let seg = segments(&db).create(corp(tenant)).await.unwrap();
    profiles(&db)
        .create(tenant, seg.id, new_profile(seg.version, profile()))
        .await
        .unwrap();
    let err = segments(&db)
        .delete_frozen(tenant, seg.id, seg.version)
        .await
        .unwrap_err();
    assert!(is_conflict(&err), "{err:?}");
    assert!(
        err.to_string().contains("changed since it was read"),
        "{err}"
    );
    assert_eq!(segments(&db).get(tenant, seg.id).await.unwrap(), seg);
    assert!(profiles(&db).get_by_segment(tenant, seg.id).await.is_ok());

    // A clearance the gate checked the grant for removes both.
    segments(&db)
        .delete(tenant, seg.id, seg.version)
        .await
        .unwrap();
    assert!(segments(&db).get(tenant, seg.id).await.is_err());
    assert!(profiles(&db).get_by_segment(tenant, seg.id).await.is_err());
}

/// The decision of 2026-10-16 under the engine production runs: a profile
/// created while a frozen delete runs never leaves a profiled segment removed
/// by a writer no one asked `network:grant` of.
#[tokio::test]
async fn a_profile_racing_a_frozen_delete_never_lands_both() {
    let fixture = common::serialising_db().await;
    let db = fixture.handle();
    let tenant = Uuid::new_v4();

    for round in 0..8u16 {
        let mut input = corp(tenant);
        input.path = format!("/network/zones/hq/del{round}");
        input.vlan_id = 400 + round;
        input.rank = Some(400 + u32::from(round));
        let seg = segments(&db).create(input).await.unwrap();

        let (segment_repo, profile_repo) = (segments(&db), profiles(&db));
        let (deleted, created) = tokio::join!(
            segment_repo.delete_frozen(tenant, seg.id, seg.version),
            profile_repo.create(tenant, seg.id, new_profile(seg.version, profile())),
        );
        assert!(
            !(deleted.is_ok() && created.is_ok()),
            "round {round}: a profile and a frozen delete both landed"
        );
        if created.is_ok() {
            assert!(
                segments(&db).get(tenant, seg.id).await.is_ok(),
                "round {round}: the profiled segment was removed"
            );
            assert!(profiles(&db).get_by_segment(tenant, seg.id).await.is_ok());
        }
    }
}

/// The type-level half of the §5.1 enumeration (W6.2): a clearance the
/// authorization function issued for one write does not carry another. Each
/// mismatch is refused before the datastore is touched, and nothing is written.
#[tokio::test]
async fn the_repository_refuses_a_clearance_for_another_write() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let raw = SurrealNetworkSegmentRepository::new(db.clone());
    let input = corp(tenant);

    // Another path, another tenant, another actor, another kind of write.
    for wrong in [
        cleared(
            tenant,
            input.actor,
            NetworkWriteTarget::SegmentCreate {
                path: "/network/zones/hq/iot".into(),
            },
        ),
        cleared(
            Uuid::new_v4(),
            input.actor,
            NetworkWriteTarget::SegmentCreate {
                path: input.path.clone(),
            },
        ),
        cleared(
            tenant,
            Uuid::new_v4(),
            NetworkWriteTarget::SegmentCreate {
                path: input.path.clone(),
            },
        ),
        cleared(
            tenant,
            input.actor,
            NetworkWriteTarget::SegmentDelete {
                segment_id: Uuid::new_v4(),
            },
        ),
    ] {
        let err = raw.create(input.clone(), &wrong).await.unwrap_err();
        assert!(
            matches!(err, AxiamError::AuthorizationDenied { .. }),
            "{err:?}"
        );
    }
    assert_eq!(resource_count(&db, tenant).await, 0, "nothing was written");

    // The profile side: a clearance for the segment's delete does not write
    // its profile.
    let seg = segments(&db).create(corp(tenant)).await.unwrap();
    let raw_profiles = SurrealReplyProfileRepository::new(db.clone());
    let input = new_profile(seg.version, profile());
    let wrong = cleared(
        tenant,
        input.actor,
        NetworkWriteTarget::SegmentDelete { segment_id: seg.id },
    );
    let err = raw_profiles
        .create(tenant, seg.id, input, &wrong)
        .await
        .unwrap_err();
    assert!(matches!(err, AxiamError::AuthorizationDenied { .. }));
    assert!(profiles(&db).get_by_segment(tenant, seg.id).await.is_err());
}

/// The tenant's cap is written like a segment: only with the clearance the
/// gate issues for this tenant, this actor and a policy write (plan 13.6).
#[tokio::test]
async fn the_policy_refuses_a_clearance_for_another_write() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let raw = SurrealNetworkPolicyRepository::new(db.clone());
    let input = || SetNetworkPolicy {
        session_timeout_max_secs: 600,
        expected_version: 0,
        actor,
    };
    for wrong in [
        cleared(Uuid::new_v4(), actor, NetworkWriteTarget::PolicyWrite),
        cleared(tenant, Uuid::new_v4(), NetworkWriteTarget::PolicyWrite),
        cleared(
            tenant,
            actor,
            NetworkWriteTarget::SegmentDelete {
                segment_id: Uuid::new_v4(),
            },
        ),
    ] {
        let err = raw.set(tenant, input(), &wrong).await.unwrap_err();
        assert!(
            matches!(err, AxiamError::AuthorizationDenied { .. }),
            "{err:?}"
        );
    }
    let stored = policies(&db).get(tenant).await.unwrap();
    assert_eq!(
        (stored.session_timeout_max_secs, stored.version),
        (3600, 0),
        "nothing was written"
    );
    // The matching one writes.
    let ok = cleared(tenant, actor, NetworkWriteTarget::PolicyWrite);
    assert_eq!(
        raw.set(tenant, input(), &ok)
            .await
            .unwrap()
            .session_timeout_max_secs,
        600
    );
}

/// The profile list (W6.3): a tenant's own effective profiles, paged, searchable
/// by `filter_id` and segment id, and clamped to the current cap like a single
/// read.
#[tokio::test]
async fn profiles_list_is_the_tenants_own_paged_and_clamped() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();

    let mut made = Vec::new();
    for (name, vlan, rank) in [("corp", 10u16, 10u32), ("iot", 20, 20), ("guest", 30, 30)] {
        let mut input = corp(tenant);
        input.path = format!("/network/zones/hq/{name}");
        input.vlan_id = vlan;
        input.rank = Some(rank);
        let seg = segments(&db).create(input).await.unwrap();
        // `guest` stays without a profile.
        if name != "guest" {
            let mut p = profile();
            p.filter_id = Some(
                if name == "corp" {
                    "corp-acl"
                } else {
                    "guest-acl"
                }
                .into(),
            );
            profiles(&db)
                .create(tenant, seg.id, new_profile(seg.version, p))
                .await
                .unwrap();
        }
        made.push(seg);
    }
    // Another tenant's profile is never listed.
    let foreign = segments(&db).create(corp(other)).await.unwrap();
    profiles(&db)
        .create(other, foreign.id, new_profile(foreign.version, profile()))
        .await
        .unwrap();

    let all = profiles(&db).list_page(tenant, page()).await.unwrap();
    assert_eq!(all.total, 2, "a segment without a profile is not listed");
    assert_eq!(all.items.len(), 2);
    assert!(all.items.iter().all(|p| p.tenant_id == tenant));

    let first = profiles(&db)
        .list_page(
            tenant,
            Pagination {
                offset: 0,
                limit: 1,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!((first.items.len(), first.total), (1, 2));
    let second = profiles(&db)
        .list_page(
            tenant,
            Pagination {
                offset: 1,
                limit: 1,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!((second.items.len(), second.total), (1, 2));
    assert_ne!(first.items[0].segment_id, second.items[0].segment_id);

    let searched = profiles(&db)
        .list_page(
            tenant,
            Pagination {
                offset: 0,
                limit: 10,
                search: Some("corp-acl".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(searched.total, 1);
    assert_eq!(searched.items[0].filter_id.as_deref(), Some("corp-acl"));

    // The list reads under the tenant's current cap, like a single read.
    policies(&db)
        .set(
            tenant,
            SetNetworkPolicy {
                session_timeout_max_secs: 600,
                expected_version: 0,
                actor: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    let clamped = profiles(&db).list_page(tenant, page()).await.unwrap();
    assert!(
        clamped
            .items
            .iter()
            .all(|p| p.session_timeout_secs == 600 && p.session_timeout_clamped)
    );
}

/// The decision path's read of a site (W6.4): every segment of the site, both
/// branches, ordered by kind then rank; and the stored profiles of those
/// segments **as stored** — a row edited behind the API (an administrative
/// `Service-Type`, which the write path refuses) comes back as it is, for the
/// decision to re-validate, rather than failing the read or reading as
/// something it was never validated as. Another tenant's rows and another
/// site's are never in either.
#[tokio::test]
async fn the_decision_reads_a_site_and_its_profiles_as_stored() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();

    let mut made = Vec::new();
    for (path, kind, vlan, rank) in [
        (
            "/network/zones/hq/iot",
            NetworkSegmentKind::Access,
            20u16,
            Some(20u32),
        ),
        (
            "/network/quarantine/hq/q",
            NetworkSegmentKind::Quarantine,
            999,
            None,
        ),
        (
            "/network/zones/hq/corp",
            NetworkSegmentKind::Access,
            10,
            Some(10),
        ),
        (
            "/network/zones/branch/corp",
            NetworkSegmentKind::Access,
            10,
            Some(10),
        ),
    ] {
        let mut input = corp(tenant);
        input.path = path.into();
        input.kind = kind;
        input.vlan_id = vlan;
        input.rank = rank;
        made.push(segments(&db).create(input).await.unwrap());
    }
    segments(&db).create(corp(other)).await.unwrap();

    let site = segments(&db).0.list_site(tenant, "hq").await.unwrap();
    let names: Vec<_> = site.iter().map(|s| (s.kind, s.name.as_str())).collect();
    assert_eq!(
        names,
        [
            (NetworkSegmentKind::Access, "corp"),
            (NetworkSegmentKind::Access, "iot"),
            (NetworkSegmentKind::Quarantine, "q"),
        ]
    );
    assert!(
        segments(&db)
            .0
            .list_site(tenant, "nowhere")
            .await
            .unwrap()
            .is_empty()
    );

    // Profiles on `corp` (hq) and `q`; `iot` has none.
    let hq_corp = &made[2];
    let q = &made[1];
    for seg in [hq_corp, q] {
        profiles(&db)
            .create(tenant, seg.id, new_profile(seg.version, profile()))
            .await
            .unwrap();
    }
    db.query("UPDATE type::record('reply_profile', $id) SET service_type = 'administrative_user'")
        .bind(("id", q.id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();

    let ids: Vec<Uuid> = site.iter().map(|s| s.id).collect();
    let stored = profiles(&db).0.list_stored(tenant, &ids).await.unwrap();
    assert_eq!(stored.len(), 2, "a segment without a profile is absent");
    let edited = stored.iter().find(|p| p.segment_id == q.id).unwrap();
    assert_eq!(edited.service_type.as_deref(), Some("administrative_user"));
    assert_eq!(edited.session_timeout_secs, 900);
    assert_eq!(edited.version, 1);
    // Another tenant asking for the same ids gets nothing.
    assert!(
        profiles(&db)
            .0
            .list_stored(other, &ids)
            .await
            .unwrap()
            .is_empty()
    );
}
