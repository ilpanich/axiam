//! §4.2 rule 2 inside the write (R110W6-04, #701): a role carrying a
//! `network:` permission never ends up held by a group, even when a `network:`
//! grant to the role and a group assignment of it race past the network gate.
//!
//! The gate (`axiam_authz::network_gate`) reads before the write; these tests
//! are the datastore's half. The sequential ones run on `kv-mem` (they assert
//! what a transaction does); the race runs on `surrealkv`, the engine
//! production deploys (`common/mod.rs` says why `kv-mem` cannot judge "only one
//! wins").

mod common;

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::{CreatePermission, PermissionEffect};
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, PermissionRepository, RoleRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealRoleRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tokio::sync::Barrier;
use uuid::Uuid;

const ALLOW: PermissionEffect = PermissionEffect::Allow;

struct World {
    db: Surreal<Db>,
    tenant: Uuid,
    join: Uuid,
    other: Uuid,
}

impl World {
    async fn on(db: Surreal<Db>) -> Self {
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Org".into(),
                slug: format!("org-{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "Tenant".into(),
                slug: format!("t-{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap()
            .id;
        let perms = SurrealPermissionRepository::new(db.clone());
        let make = |action: &'static str| {
            let perms = perms.clone();
            async move {
                perms
                    .create(CreatePermission {
                        tenant_id: tenant,
                        action: action.into(),
                        description: String::new(),
                    })
                    .await
                    .unwrap()
                    .id
            }
        };
        let join = make("network:join").await;
        let other = make("documents:read").await;
        Self {
            db,
            tenant,
            join,
            other,
        }
    }

    async fn mem() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        Self::on(db).await
    }

    fn roles(&self) -> SurrealRoleRepository<Db> {
        SurrealRoleRepository::new(self.db.clone())
    }

    fn perms(&self) -> SurrealPermissionRepository<Db> {
        SurrealPermissionRepository::new(self.db.clone())
    }

    async fn role(&self) -> Uuid {
        self.roles()
            .create(CreateRole {
                tenant_id: self.tenant,
                name: format!("r-{}", Uuid::new_v4().simple()),
                description: String::new(),
                is_global: false,
            })
            .await
            .unwrap()
            .id
    }

    async fn group(&self) -> Uuid {
        SurrealGroupRepository::new(self.db.clone())
            .create(CreateGroup {
                tenant_id: self.tenant,
                name: format!("g-{}", Uuid::new_v4().simple()),
                description: String::new(),
                metadata: None,
            })
            .await
            .unwrap()
            .id
    }

    async fn grant(&self, role: Uuid, permission: Uuid) -> Result<(), AxiamError> {
        self.perms()
            .grant_to_role_with_effect(self.tenant, role, permission, vec![], ALLOW)
            .await
    }

    async fn assign(&self, role: Uuid, group: Uuid) -> Result<(), AxiamError> {
        self.roles()
            .assign_to_group(self.tenant, group, role, AssignmentScope::from(None))
            .await
    }

    /// The two facts rule 2 forbids together, read after the fact.
    async fn state(&self, role: Uuid) -> (bool, bool) {
        let network = self
            .perms()
            .get_role_permission_grants(self.tenant, role)
            .await
            .unwrap()
            .iter()
            .any(|g| g.permission.action.starts_with("network:"));
        let grouped = !self
            .roles()
            .get_role_group_assignments(self.tenant, role)
            .await
            .unwrap()
            .is_empty();
        (network, grouped)
    }
}

/// The refusal a write that lost the race gets: `409`, read by the REST layer
/// as `stale_version` ("changed since it was read").
#[track_caller]
fn assert_raced(result: Result<(), AxiamError>) {
    match result {
        Err(AxiamError::Conflict { reason }) => assert!(
            reason.contains("the role changed since it was read"),
            "{reason}"
        ),
        other => panic!("expected the rule-2 conflict, got {other:?}"),
    }
}

/// Granted first, then assigned to a group: the assignment's transaction sees
/// the grant and refuses, writing nothing.
#[tokio::test]
async fn a_group_assignment_of_a_role_that_carries_a_network_grant_is_refused() {
    let w = World::mem().await;
    let (role, group) = (w.role().await, w.group().await);
    w.grant(role, w.join).await.unwrap();
    assert_raced(w.assign(role, group).await);
    assert_eq!(w.state(role).await, (true, false));
}

/// Assigned to a group first, then granted: the grant's transaction sees the
/// group edge and refuses, writing nothing.
#[tokio::test]
async fn a_network_grant_to_a_group_held_role_is_refused() {
    let w = World::mem().await;
    let (role, group) = (w.role().await, w.group().await);
    w.assign(role, group).await.unwrap();
    assert_raced(w.grant(role, w.join).await);
    assert_eq!(w.state(role).await, (false, true));
}

/// The rule reads the namespace as the gate does: leading whitespace skipped,
/// the prefix compared ASCII case-insensitively (`is_network_action`).
#[tokio::test]
async fn the_rule_reads_the_namespace_as_the_gate_does() {
    let w = World::mem().await;
    let perms = w.perms();
    for (action, network) in [
        ("  NETWORK:decide", true),
        ("Network:Join", true),
        // U+212A KELVIN SIGN: not an ASCII `k`, so not the namespace — for
        // the gate (`eq_ignore_ascii_case`) and for the transaction alike.
        ("networ\u{212a}:join", false),
        ("networking:read", false),
    ] {
        let permission = perms
            .create(CreatePermission {
                tenant_id: w.tenant,
                action: action.into(),
                description: String::new(),
            })
            .await
            .unwrap()
            .id;
        assert_eq!(
            axiam_core::models::network::is_network_action(action),
            network,
            "{action}"
        );
        let (role, group) = (w.role().await, w.group().await);
        w.assign(role, group).await.unwrap();
        let granted = w.grant(role, permission).await;
        if network {
            assert_raced(granted);
        } else {
            granted.unwrap_or_else(|e| panic!("{action}: {e:?}"));
        }
    }
}

/// Everything else is as it was: a grant outside the namespace to a
/// group-held role, a group assignment of a role with none, a network role to
/// a user, and the duplicate and cross-tenant answers.
#[tokio::test]
async fn writes_outside_the_rule_are_unchanged() {
    let w = World::mem().await;
    let (role, group) = (w.role().await, w.group().await);
    w.grant(role, w.other).await.unwrap();
    w.assign(role, group).await.unwrap();
    assert!(matches!(
        w.assign(role, group).await,
        Err(AxiamError::AlreadyExists { .. })
    ));
    assert!(matches!(
        w.grant(role, w.other).await,
        Err(AxiamError::AlreadyExists { .. })
    ));
    assert_eq!(w.state(role).await, (false, true));

    // A network role to a user is not the group path: written as before.
    let network_role = w.role().await;
    w.grant(network_role, w.join).await.unwrap();
    let user = SurrealUserRepository::new(w.db.clone())
        .create(CreateUser {
            tenant_id: w.tenant,
            username: format!("u{}", Uuid::new_v4().simple()),
            email: format!("{}@example.com", Uuid::new_v4().simple()),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    w.roles()
        .assign_to_user(w.tenant, user, network_role, AssignmentScope::from(None))
        .await
        .unwrap();
    assert_eq!(w.state(network_role).await, (true, false));

    // Another tenant's group or role: refused as before, nothing written.
    let elsewhere = World::on(w.db.clone()).await;
    let foreign_group = elsewhere.group().await;
    assert!(matches!(
        w.assign(role, foreign_group).await,
        Err(AxiamError::AuthorizationDenied { .. })
    ));
    assert!(matches!(
        w.perms()
            .grant_to_role_with_effect(w.tenant, role, elsewhere.join, vec![], ALLOW)
            .await,
        Err(AxiamError::AuthorizationDenied { .. })
    ));
}

/// The race of R110W6-04 on the engine production runs. Each side first makes
/// the gate's reads — the role's grants (no `network:` one) and the role's
/// group holders (none) — and both wait at a barrier until both have read, so
/// each write is issued on a state the other is about to change. Then both
/// write at once, on two runtime workers.
///
/// These writes make no claim (the seeder's reconcile is such a writer; the
/// REST handlers' claimed writes are raced in `axiam-api-rest`'s
/// `network_gate_test`): rule 2's in-transaction re-read and the role-row
/// epoch write are what decide. At least one must be refused (`409`), and the
/// role must never end up both network-permissioned and group-held. With
/// either the re-read or the role-row write removed, both land (measured:
/// without the shared write, snapshot isolation lets two transactions that
/// write disjoint edges both commit).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_network_grant_racing_a_group_assignment_never_lands_both() {
    let fixture = common::serialising_db().await;
    let w = Arc::new(World::on(fixture.handle()).await);

    let mut grant_won = 0;
    let mut assign_won = 0;
    for round in 0..16 {
        let (role, group) = (w.role().await, w.group().await);
        let barrier = Arc::new(Barrier::new(2));

        let granting = {
            let (w, barrier) = (Arc::clone(&w), Arc::clone(&barrier));
            tokio::spawn(async move {
                // The gate's read for a grant: does a group hold the role?
                let holders = w
                    .roles()
                    .get_role_group_assignments(w.tenant, role)
                    .await
                    .unwrap();
                assert!(holders.is_empty(), "round {round}: setup");
                barrier.wait().await;
                w.grant(role, w.join).await
            })
        };
        let assigning = {
            let (w, barrier) = (Arc::clone(&w), Arc::clone(&barrier));
            tokio::spawn(async move {
                // The gate's read for a group assignment: any network grant?
                let grants = w
                    .perms()
                    .get_role_permission_grants(w.tenant, role)
                    .await
                    .unwrap();
                assert!(grants.is_empty(), "round {round}: setup");
                barrier.wait().await;
                w.assign(role, group).await
            })
        };
        let (granted, assigned) = (granting.await.unwrap(), assigning.await.unwrap());

        assert!(
            granted.is_err() || assigned.is_err(),
            "round {round}: a network grant and a group assignment of one role both landed"
        );
        for refused in [&granted, &assigned].into_iter().filter(|r| r.is_err()) {
            assert!(
                matches!(refused, Err(AxiamError::Conflict { reason })
                    if reason.contains("the role changed since it was read")),
                "round {round}: the loser is the rule-2 409, got {refused:?}"
            );
        }
        let (network, grouped) = w.state(role).await;
        assert!(
            !(network && grouped),
            "round {round}: the role is network-permissioned and group-held"
        );
        assert_eq!(
            (network, grouped),
            (granted.is_ok(), assigned.is_ok()),
            "round {round}: what landed is what answered success"
        );
        grant_won += usize::from(granted.is_ok());
        assign_won += usize::from(assigned.is_ok());
    }
    // Not asserted (scheduling decides), but printed so a run shows that both
    // orders were exercised.
    println!("grant won {grant_won}, group assignment won {assign_won}");
}
