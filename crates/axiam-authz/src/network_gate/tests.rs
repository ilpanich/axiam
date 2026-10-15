//! The function's decisions, against hand-built facts.
//!
//! The access oracle here answers from a fixed set of `(subject, action, node)`
//! triples, so these tests pin **what the function asks and what it does with
//! the answer**: which permission, on which node, for which subject. That the
//! engine answers those questions with deny-override and the hierarchy cascade
//! is the engine's own test suite's; the handler tests in `axiam-api-rest`
//! (`network_gate_test.rs`) run the function against the real engine.

use std::collections::{BTreeSet, HashMap};

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::network::{
    NETWORK_ADMIN, NETWORK_DECIDE, NETWORK_GRANT, NETWORK_GRANT_ADMIN, NETWORK_JOIN,
    NETWORK_PROFILES_WRITE, NETWORK_READ, NETWORK_SEGMENTS_WRITE, NetworkSegment,
    NetworkSegmentKind, NetworkSegmentUpdate, NetworkWriteTarget, NewNetworkSegment,
    RESOURCE_TYPE_NETWORK_SEGMENT, RESOURCE_TYPE_NETWORK_SITE, ReplyProfile, network_root_id,
    site_node_id,
};
use axiam_core::models::permission::{Permission, PermissionEffect, PermissionGrant};
use axiam_core::models::radius_reply::{
    REPLY_DICTIONARY_V1, ReplyProfileInput, ServiceType, TerminationAction,
};
use axiam_core::models::resource::Resource;
use axiam_core::models::role::{Role, RoleAssignment, RoleSubjectAssignment};
use chrono::Utc;
use uuid::Uuid;

use super::*;

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/// Allows exactly the listed `(subject, action, node)` triples.
#[derive(Default)]
struct Oracle {
    allowed: BTreeSet<(Uuid, String, Uuid)>,
    asked: std::sync::Mutex<Vec<(Uuid, String, Uuid)>>,
}

impl Oracle {
    fn allow(mut self, subject: Uuid, action: &str, node: Uuid) -> Self {
        self.allowed.insert((subject, action.to_owned(), node));
        self
    }
}

impl WriteTimeAccess for Oracle {
    async fn check_at_write_time(&self, request: &AccessRequest) -> AxiamResult<AccessDecision> {
        let key = (
            request.subject_id,
            request.action.clone(),
            request.resource_id,
        );
        self.asked.lock().unwrap().push(key.clone());
        Ok(if self.allowed.contains(&key) {
            AccessDecision::Allow
        } else {
            AccessDecision::Deny("no grant".into())
        })
    }
}

#[derive(Default)]
struct Store {
    roles: HashMap<Uuid, Role>,
    grants: HashMap<Uuid, Vec<PermissionGrant>>,
    holders: HashMap<Uuid, RoleHolders>,
    assignments: HashMap<Uuid, Vec<RoleAssignment>>,
    permissions: HashMap<Uuid, Permission>,
    resources: HashMap<Uuid, Resource>,
    segments: HashMap<Uuid, NetworkSegment>,
    profiles: HashMap<Uuid, ReplyProfile>,
    cap: u32,
    bindings: HashMap<Uuid, Uuid>,
}

fn not_found(what: &str) -> AxiamError {
    AxiamError::NotFound {
        entity: what.into(),
        id: String::new(),
    }
}

impl NetworkGateStore for Store {
    async fn role(&self, _t: Uuid, id: Uuid) -> AxiamResult<Role> {
        self.roles
            .get(&id)
            .cloned()
            .ok_or_else(|| not_found("role"))
    }
    async fn role_grants(&self, _t: Uuid, id: Uuid) -> AxiamResult<Vec<PermissionGrant>> {
        Ok(self.grants.get(&id).cloned().unwrap_or_default())
    }
    async fn role_holders(&self, _t: Uuid, id: Uuid) -> AxiamResult<RoleHolders> {
        Ok(self.holders.get(&id).cloned().unwrap_or_default())
    }
    async fn subject_assignments(&self, _t: Uuid, id: Uuid) -> AxiamResult<Vec<RoleAssignment>> {
        Ok(self.assignments.get(&id).cloned().unwrap_or_default())
    }
    async fn group_assignments(&self, _t: Uuid, id: Uuid) -> AxiamResult<Vec<RoleAssignment>> {
        Ok(self.assignments.get(&id).cloned().unwrap_or_default())
    }
    async fn permission(&self, _t: Uuid, id: Uuid) -> AxiamResult<Permission> {
        self.permissions
            .get(&id)
            .cloned()
            .ok_or_else(|| not_found("permission"))
    }
    async fn resource(&self, _t: Uuid, id: Uuid) -> AxiamResult<Option<Resource>> {
        Ok(self.resources.get(&id).cloned())
    }
    async fn segment(&self, _t: Uuid, id: Uuid) -> AxiamResult<NetworkSegment> {
        self.segments
            .get(&id)
            .cloned()
            .ok_or_else(|| not_found("network_segment"))
    }
    async fn profile(&self, _t: Uuid, id: Uuid) -> AxiamResult<Option<ReplyProfile>> {
        Ok(self.profiles.get(&id).cloned())
    }
    async fn session_timeout_cap(&self, _t: Uuid) -> AxiamResult<u32> {
        Ok(self.cap)
    }
    async fn bound_service_account(&self, cert: Uuid) -> AxiamResult<Option<Uuid>> {
        Ok(self.bindings.get(&cert).copied())
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

struct World {
    tenant: Uuid,
    writer: Uuid,
    store: Store,
}

impl World {
    fn new() -> Self {
        Self {
            tenant: Uuid::new_v4(),
            writer: Uuid::new_v4(),
            store: Store {
                cap: 3600,
                ..Store::default()
            },
        }
    }

    fn gate_writer(&self) -> GateWriter {
        GateWriter {
            tenant_id: self.tenant,
            subject_id: self.writer,
            subject_scope: SubjectScope::Tenant,
        }
    }

    fn root(&self) -> Uuid {
        network_root_id(self.tenant)
    }

    fn permission(&mut self, action: &str) -> Uuid {
        let id = Uuid::new_v4();
        self.store.permissions.insert(
            id,
            Permission {
                id,
                tenant_id: self.tenant,
                action: action.to_owned(),
                description: String::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        );
        id
    }

    /// A role carrying `grants` (action, effect).
    fn role(&mut self, is_global: bool, grants: &[(&str, PermissionEffect)]) -> Uuid {
        let id = Uuid::new_v4();
        self.store.roles.insert(
            id,
            Role {
                id,
                tenant_id: self.tenant,
                name: format!("role-{}", id.simple()),
                description: String::new(),
                is_global,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        );
        let list = grants
            .iter()
            .map(|(action, effect)| {
                let pid = self.permission(action);
                PermissionGrant {
                    permission: self.store.permissions[&pid].clone(),
                    scope_ids: Vec::new(),
                    effect: *effect,
                }
            })
            .collect();
        self.store.grants.insert(id, list);
        id
    }

    fn assign(&mut self, subject: Uuid, role: Uuid, resource_id: Option<Uuid>, inherit: bool) {
        let assignment = RoleAssignment {
            role: self.store.roles[&role].clone(),
            resource_id,
            tenant_scope: None,
            inherit,
        };
        self.store
            .assignments
            .entry(subject)
            .or_default()
            .push(assignment);
    }

    fn holder(&mut self, role: Uuid, group: bool, inherit: bool) {
        let h = RoleSubjectAssignment {
            subject_id: Uuid::new_v4(),
            resource_id: Some(Uuid::new_v4()),
            tenant_scope: None,
            inherit,
        };
        let entry = self.store.holders.entry(role).or_default();
        if group {
            entry.groups.push(h);
        } else {
            entry.service_accounts.push(h);
        }
    }

    fn segment(&mut self, kind: NetworkSegmentKind) -> NetworkSegment {
        let id = Uuid::new_v4();
        let seg = NetworkSegment {
            id,
            tenant_id: self.tenant,
            name: "iot".into(),
            site_key: "hq".into(),
            kind,
            vlan_id: 20,
            filter_ids: vec!["iot-acl".into()],
            rank: (kind == NetworkSegmentKind::Access).then_some(20),
            enabled: true,
            version: 3,
            created_by: Uuid::new_v4(),
            updated_by: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.store.segments.insert(id, seg.clone());
        seg
    }

    fn resource(&mut self, id: Uuid, resource_type: &str) {
        self.store.resources.insert(
            id,
            Resource {
                id,
                tenant_id: self.tenant,
                name: "n".into(),
                resource_type: resource_type.to_owned(),
                parent_id: None,
                metadata: serde_json::Value::Null,
                uma_registered_by: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        );
    }

    async fn decide(&self, oracle: &Oracle, write: NetworkWrite<'_>) -> GateVerdict {
        authorize_network_write(oracle, &self.store, self.gate_writer(), write)
            .await
            .expect("no infrastructure error")
    }
}

fn profile_input() -> ReplyProfileInput {
    ReplyProfileInput {
        dictionary: REPLY_DICTIONARY_V1.into(),
        session_timeout_secs: 900,
        termination_action: TerminationAction::RadiusRequest,
        idle_timeout_secs: None,
        filter_id: Some("iot-acl".into()),
        service_type: Some(ServiceType::FramedUser),
    }
}

const ALLOW: PermissionEffect = PermissionEffect::Allow;
const DENY: PermissionEffect = PermissionEffect::Deny;

#[track_caller]
fn refused(v: GateVerdict, rule: &str) -> GateRefusal {
    match v {
        Err(r) => {
            assert_eq!(r.rule, rule, "{r:?}");
            r
        }
        Ok(c) => panic!("expected a refusal under {rule}, got {c:?}"),
    }
}

#[track_caller]
fn passes(v: GateVerdict) {
    drop(cleared(v));
}

#[track_caller]
fn cleared(v: GateVerdict) -> GateClearance {
    match v {
        Ok(c) => c,
        Err(r) => panic!("expected a clearance, got {r:?}"),
    }
}

// ---------------------------------------------------------------------------
// H1–H6: a positive and a negative case each
// ---------------------------------------------------------------------------

/// Everything a profile writer needs on an access segment.
fn profile_writer(w: &World, seg: &NetworkSegment) -> Oracle {
    Oracle::default()
        .allow(w.writer, NETWORK_PROFILES_WRITE, seg.id)
        .allow(w.writer, NETWORK_GRANT, seg.id)
}

#[tokio::test]
async fn a_profile_writer_holding_h1_to_h6_is_cleared_with_a_matching_token() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Access);
    let input = profile_input();
    let c = cleared(
        w.decide(
            &profile_writer(&w, &seg),
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &input,
            },
        )
        .await,
    );
    assert!(c.is_network_sensitive());
    let token = c
        .into_write_clearance()
        .expect("a profile write carries a token");
    token
        .check(
            w.tenant,
            w.writer,
            &NetworkWriteTarget::ProfileWrite { segment_id: seg.id },
        )
        .unwrap();
}

#[tokio::test]
async fn h1_without_profiles_write_is_403_naming_it() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Access);
    let input = profile_input();
    let oracle = Oracle::default().allow(w.writer, NETWORK_GRANT, seg.id);
    let r = refused(
        w.decide(
            &oracle,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &input,
            },
        )
        .await,
        "H1",
    );
    assert_eq!(r.status, RefusalStatus::Forbidden);
    assert_eq!(
        r.missing,
        Some(MissingPermission {
            action: NETWORK_PROFILES_WRITE.into(),
            node: seg.id
        })
    );
    assert_eq!(r.audit_action, AUDIT_PROFILE_WRITE_REFUSED);
    // Before and after values for the audit row (§5.4).
    assert!(r.before.iter().any(|(k, v)| *k == "vlan_id" && v == "20"));
    assert!(
        r.after
            .iter()
            .any(|(k, v)| *k == "filter_id" && v == "iot-acl")
    );
}

#[tokio::test]
async fn h2_without_network_grant_is_403_even_with_profiles_write() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Access);
    let input = profile_input();
    let oracle = Oracle::default().allow(w.writer, NETWORK_PROFILES_WRITE, seg.id);
    let r = refused(
        w.decide(
            &oracle,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &input,
            },
        )
        .await,
        "H2",
    );
    assert_eq!(r.missing.unwrap().action, NETWORK_GRANT);
}

#[tokio::test]
async fn h3_a_filter_id_outside_the_envelope_or_above_the_cap_is_refused() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Access);
    let oracle = profile_writer(&w, &seg);

    let mut outside = profile_input();
    outside.filter_id = Some("corp-acl".into());
    refused(
        w.decide(
            &oracle,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &outside,
            },
        )
        .await,
        "H3:envelope:filter_id",
    );

    w.store.cap = 600;
    refused(
        w.decide(
            &oracle,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &profile_input(),
            },
        )
        .await,
        "H3:envelope:session_timeout",
    );

    // Positive: inside both.
    let mut inside = profile_input();
    inside.session_timeout_secs = 600;
    passes(
        w.decide(
            &oracle,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &inside,
            },
        )
        .await,
    );
}

#[tokio::test]
async fn h4_the_admin_class_needs_grant_admin_and_admin() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Access);
    let mut admin = profile_input();
    admin.service_type = Some(ServiceType::AdministrativeUser);

    let r = refused(
        w.decide(
            &profile_writer(&w, &seg),
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &admin,
            },
        )
        .await,
        "H4",
    );
    assert_eq!(r.missing.unwrap().action, NETWORK_GRANT_ADMIN);

    // Holding grant_admin alone is not holding the class itself.
    let half = profile_writer(&w, &seg).allow(w.writer, NETWORK_GRANT_ADMIN, seg.id);
    let r = refused(
        w.decide(
            &half,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &admin,
            },
        )
        .await,
        "H4",
    );
    assert_eq!(r.missing.unwrap().action, NETWORK_ADMIN);

    // Positive (option A's case; the repository still refuses the class
    // under option B).
    let both = half.allow(w.writer, NETWORK_ADMIN, seg.id);
    passes(
        w.decide(
            &both,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &admin,
            },
        )
        .await,
    );
}

#[tokio::test]
async fn h5_a_quarantine_profile_needs_grant_on_the_quarantine_site() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Quarantine);
    let input = profile_input();
    let site = site_node_id(w.tenant, NetworkSegmentKind::Quarantine, "hq");

    let r = refused(
        w.decide(
            &profile_writer(&w, &seg),
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &input,
            },
        )
        .await,
        "H5",
    );
    assert_eq!(r.missing.unwrap().node, site);

    let oracle = profile_writer(&w, &seg).allow(w.writer, NETWORK_GRANT, site);
    passes(
        w.decide(
            &oracle,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &input,
            },
        )
        .await,
    );
}

#[tokio::test]
async fn h6_a_writer_that_may_join_the_segment_cannot_write_its_profile() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Access);
    let input = profile_input();
    let oracle = profile_writer(&w, &seg).allow(w.writer, NETWORK_JOIN, seg.id);
    let r = refused(
        w.decide(
            &oracle,
            NetworkWrite::ProfileWrite {
                segment_id: seg.id,
                input: &input,
            },
        )
        .await,
        "H6",
    );
    assert_eq!(r.status, RefusalStatus::Forbidden);
    // Positive: the same writer, not join-able, is the first test's case.
}

#[tokio::test]
async fn a_profile_delete_needs_h1_only() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Quarantine);
    refused(
        w.decide(
            &Oracle::default(),
            NetworkWrite::ProfileDelete { segment_id: seg.id },
        )
        .await,
        "H1",
    );
    let oracle = Oracle::default().allow(w.writer, NETWORK_PROFILES_WRITE, seg.id);
    let c = cleared(
        w.decide(&oracle, NetworkWrite::ProfileDelete { segment_id: seg.id })
            .await,
    );
    assert!(c.into_write_clearance().is_some());
}

// ---------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_segment_is_created_under_segments_write_at_the_nearest_existing_parent() {
    let mut w = World::new();
    let input = NewNetworkSegment {
        tenant_id: w.tenant,
        path: "/network/zones/hq/iot".into(),
        kind: NetworkSegmentKind::Access,
        vlan_id: 20,
        filter_ids: vec![],
        rank: Some(20),
        enabled: true,
        actor: w.writer,
    };
    // No node exists yet: the check is at /network.
    let r = refused(
        w.decide(
            &Oracle::default(),
            NetworkWrite::SegmentCreate { input: &input },
        )
        .await,
        "4.2:segments_write",
    );
    assert_eq!(r.missing.unwrap().node, w.root());

    // Once the site exists, it is the parent.
    let site = site_node_id(w.tenant, NetworkSegmentKind::Access, "hq");
    w.resource(site, RESOURCE_TYPE_NETWORK_SITE);
    let oracle = Oracle::default().allow(w.writer, NETWORK_SEGMENTS_WRITE, site);
    let c = cleared(
        w.decide(&oracle, NetworkWrite::SegmentCreate { input: &input })
            .await,
    );
    c.into_write_clearance()
        .unwrap()
        .check(
            w.tenant,
            w.writer,
            &NetworkWriteTarget::SegmentCreate {
                path: input.path.clone(),
            },
        )
        .unwrap();

    let mut outside = input.clone();
    outside.path = "/elsewhere/hq/iot".into();
    let r = refused(
        w.decide(&oracle, NetworkWrite::SegmentCreate { input: &outside })
            .await,
        "4.1:reserved-subtree",
    );
    assert_eq!(r.status, RefusalStatus::Invalid);
}

#[tokio::test]
async fn a_segment_update_needs_segments_write_at_the_node_and_not_joinable() {
    let mut w = World::new();
    let seg = w.segment(NetworkSegmentKind::Access);
    let update = NetworkSegmentUpdate {
        expected_version: seg.version,
        vlan_id: 99,
        filter_ids: vec![],
        rank: Some(20),
        enabled: true,
        actor: w.writer,
    };
    let write = NetworkWrite::SegmentUpdate {
        segment_id: seg.id,
        update: &update,
    };
    let r = refused(
        w.decide(&Oracle::default(), write).await,
        "4.2:segments_write",
    );
    // VLAN 20 became VLAN 99, visible in the refusal's values.
    assert!(r.before.iter().any(|(k, v)| *k == "vlan_id" && v == "20"));
    assert!(r.after.iter().any(|(k, v)| *k == "vlan_id" && v == "99"));

    let oracle = Oracle::default().allow(w.writer, NETWORK_SEGMENTS_WRITE, seg.id);
    passes(w.decide(&oracle, write).await);
    let joinable = oracle.allow(w.writer, NETWORK_JOIN, seg.id);
    refused(w.decide(&joinable, write).await, "H6");
}

// ---------------------------------------------------------------------------
// Role assignment (§5.3, §4.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn assigning_a_join_allow_at_n_needs_network_grant_at_n() {
    let mut w = World::new();
    let role = w.role(false, &[(NETWORK_JOIN, ALLOW)]);
    let device = Uuid::new_v4();
    let n = Uuid::new_v4();
    let write = NetworkWrite::RoleAssign {
        role_id: role,
        grantee: Grantee::ServiceAccount(device),
        resource_id: Some(n),
        inherit: true,
    };

    let r = refused(w.decide(&Oracle::default(), write).await, "5.3:assign");
    assert_eq!(r.status, RefusalStatus::Forbidden);
    assert_eq!(
        r.missing,
        Some(MissingPermission {
            action: NETWORK_GRANT.into(),
            node: n
        })
    );
    assert_eq!(r.audit_action, AUDIT_ROLE_ASSIGN_REFUSED);

    // Holding it elsewhere is not holding it at N.
    let elsewhere = Oracle::default().allow(w.writer, NETWORK_GRANT, Uuid::new_v4());
    refused(w.decide(&elsewhere, write).await, "5.3:assign");

    let at_n = Oracle::default().allow(w.writer, NETWORK_GRANT, n);
    assert!(cleared(w.decide(&at_n, write).await).is_network_sensitive());
}

#[tokio::test]
async fn a_tenant_wide_or_global_assignment_is_checked_at_network() {
    let mut w = World::new();
    let local = w.role(false, &[(NETWORK_JOIN, DENY)]);
    let global = w.role(true, &[(NETWORK_GRANT, ALLOW)]);
    let oracle = Oracle::default().allow(w.writer, NETWORK_GRANT, w.root());
    for (role, resource_id) in [(local, None), (global, Some(Uuid::new_v4()))] {
        let write = NetworkWrite::RoleAssign {
            role_id: role,
            grantee: Grantee::User(Uuid::new_v4()),
            resource_id,
            inherit: true,
        };
        let r = refused(w.decide(&Oracle::default(), write).await, "5.3:assign");
        assert_eq!(r.missing.unwrap().node, w.root());
        passes(w.decide(&oracle, write).await);
    }
}

#[tokio::test]
async fn a_quarantine_deny_is_assigned_only_by_a_network_administrator() {
    let mut w = World::new();
    let quarantine = w.role(false, &[(NETWORK_JOIN, DENY)]);
    let zones = Uuid::new_v4();
    let write = NetworkWrite::RoleAssign {
        role_id: quarantine,
        grantee: Grantee::ServiceAccount(Uuid::new_v4()),
        resource_id: Some(zones),
        inherit: true,
    };
    refused(w.decide(&Oracle::default(), write).await, "5.3:assign");
    passes(
        w.decide(
            &Oracle::default().allow(w.writer, NETWORK_GRANT, zones),
            write,
        )
        .await,
    );
}

#[tokio::test]
async fn a_meta_permission_is_delegated_only_by_its_holder() {
    let mut w = World::new();
    let role = w.role(false, &[(NETWORK_GRANT, ALLOW), (NETWORK_DECIDE, ALLOW)]);
    let n = Uuid::new_v4();
    let write = NetworkWrite::RoleAssign {
        role_id: role,
        grantee: Grantee::User(Uuid::new_v4()),
        resource_id: Some(n),
        inherit: true,
    };
    let only_grant = Oracle::default().allow(w.writer, NETWORK_GRANT, n);
    let r = refused(w.decide(&only_grant, write).await, "5.3:assign");
    assert_eq!(r.missing.unwrap().action, NETWORK_DECIDE);
    passes(
        w.decide(&only_grant.allow(w.writer, NETWORK_DECIDE, n), write)
            .await,
    );
}

#[tokio::test]
async fn rule_2_a_network_role_is_never_assigned_to_a_group() {
    let mut w = World::new();
    let role = w.role(false, &[(NETWORK_READ, ALLOW)]);
    let n = Uuid::new_v4();
    let everything = Oracle::default().allow(w.writer, NETWORK_GRANT, n);
    let r = refused(
        w.decide(
            &everything,
            NetworkWrite::RoleAssign {
                role_id: role,
                grantee: Grantee::Group(Uuid::new_v4()),
                resource_id: Some(n),
                inherit: true,
            },
        )
        .await,
        "4.2:rule-2",
    );
    assert_eq!(r.status, RefusalStatus::Invalid);
    // Positive: the same role to a service account.
    passes(
        w.decide(
            &everything,
            NetworkWrite::RoleAssign {
                role_id: role,
                grantee: Grantee::ServiceAccount(Uuid::new_v4()),
                resource_id: Some(n),
                inherit: true,
            },
        )
        .await,
    );
}

#[tokio::test]
async fn rule_3_a_network_deny_is_never_assigned_with_inherit_false() {
    let mut w = World::new();
    let role = w.role(false, &[(NETWORK_JOIN, DENY)]);
    let n = Uuid::new_v4();
    let oracle = Oracle::default().allow(w.writer, NETWORK_GRANT, n);
    let write = |inherit| NetworkWrite::RoleAssign {
        role_id: role,
        grantee: Grantee::ServiceAccount(Uuid::nil()),
        resource_id: Some(n),
        inherit,
    };
    refused(w.decide(&oracle, write(false)).await, "4.2:rule-3");
    passes(w.decide(&oracle, write(true)).await);
    // An allow with inherit: false is a narrowing, and allowed.
    let allow = w.role(false, &[(NETWORK_JOIN, ALLOW)]);
    passes(
        w.decide(
            &oracle,
            NetworkWrite::RoleAssign {
                role_id: allow,
                grantee: Grantee::ServiceAccount(Uuid::nil()),
                resource_id: Some(n),
                inherit: false,
            },
        )
        .await,
    );
}

#[tokio::test]
async fn a_role_without_network_grants_is_not_the_functions_business() {
    let mut w = World::new();
    let role = w.role(false, &[("users:list", ALLOW)]);
    let c = cleared(
        w.decide(
            &Oracle::default(),
            NetworkWrite::RoleAssign {
                role_id: role,
                grantee: Grantee::Group(Uuid::new_v4()),
                resource_id: None,
                inherit: true,
            },
        )
        .await,
    );
    assert!(!c.is_network_sensitive());
}

#[tokio::test]
async fn releasing_a_quarantine_needs_network_grant_where_the_deny_was() {
    let mut w = World::new();
    let quarantine = w.role(false, &[(NETWORK_JOIN, DENY)]);
    let zones = Uuid::new_v4();
    let write = NetworkWrite::RoleUnassign {
        role_id: quarantine,
        grantee: Grantee::ServiceAccount(Uuid::new_v4()),
        resource_id: Some(zones),
    };
    let r = refused(w.decide(&Oracle::default(), write).await, "5.3:unassign");
    assert_eq!(r.missing.unwrap().node, zones);
    assert_eq!(r.audit_action, AUDIT_ROLE_UNASSIGN_REFUSED);
    passes(
        w.decide(
            &Oracle::default().allow(w.writer, NETWORK_GRANT, zones),
            write,
        )
        .await,
    );

    // Removing an allow only narrows.
    let allow = w.role(false, &[(NETWORK_JOIN, ALLOW)]);
    passes(
        w.decide(
            &Oracle::default(),
            NetworkWrite::RoleUnassign {
                role_id: allow,
                grantee: Grantee::ServiceAccount(Uuid::new_v4()),
                resource_id: Some(zones),
            },
        )
        .await,
    );
}

#[tokio::test]
async fn rule_1_a_network_role_is_not_made_global_and_a_deny_role_is_deleted_at_network() {
    let mut w = World::new();
    let role = w.role(false, &[(NETWORK_JOIN, DENY)]);
    refused(
        w.decide(
            &Oracle::default(),
            NetworkWrite::RoleUpdate {
                role_id: role,
                is_global: Some(true),
            },
        )
        .await,
        "4.2:rule-1",
    );
    passes(
        w.decide(
            &Oracle::default(),
            NetworkWrite::RoleUpdate {
                role_id: role,
                is_global: Some(false),
            },
        )
        .await,
    );

    let r = refused(
        w.decide(
            &Oracle::default(),
            NetworkWrite::RoleDelete { role_id: role },
        )
        .await,
        "5.3:role-delete",
    );
    assert_eq!(r.missing.unwrap().node, w.root());
    passes(
        w.decide(
            &Oracle::default().allow(w.writer, NETWORK_GRANT, w.root()),
            NetworkWrite::RoleDelete { role_id: role },
        )
        .await,
    );
}

// ---------------------------------------------------------------------------
// Grants on a role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn granting_a_network_permission_follows_rules_1_to_3_and_5_3() {
    let mut w = World::new();
    let join = w.permission(NETWORK_JOIN);
    let decide = w.permission(NETWORK_DECIDE);
    let admin = w.permission(NETWORK_ADMIN);
    let root = w.root();
    let grantor = Oracle::default().allow(w.writer, NETWORK_GRANT, root);
    let grant =
        |role, permission_id, effect, scope_ids: &'static [Uuid]| NetworkWrite::PermissionGrant {
            role_id: role,
            permission_id,
            effect,
            scope_ids,
        };

    let plain = w.role(false, &[]);
    // Without network:grant at /network.
    let r = refused(
        w.decide(&Oracle::default(), grant(plain, join, ALLOW, &[]))
            .await,
        "5.3:permission",
    );
    assert_eq!(r.missing.unwrap().node, root);
    passes(w.decide(&grantor, grant(plain, join, ALLOW, &[])).await);
    // A meta permission needs holding it.
    let r = refused(
        w.decide(&grantor, grant(plain, decide, ALLOW, &[])).await,
        "5.3:permission",
    );
    assert_eq!(r.missing.unwrap().action, NETWORK_DECIDE);
    // The administrative class is not grantable at all under option B.
    refused(
        w.decide(&grantor, grant(plain, admin, ALLOW, &[])).await,
        "4.2:not-grantable",
    );
    // A scoped network grant is refused.
    static SCOPES: [Uuid; 1] = [Uuid::nil()];
    refused(
        w.decide(&grantor, grant(plain, join, DENY, &SCOPES)).await,
        "4.2:scoped-grant",
    );

    // Rule 1: a global role.
    let global = w.role(true, &[]);
    refused(
        w.decide(&grantor, grant(global, join, ALLOW, &[])).await,
        "4.2:rule-1",
    );
    // Rule 2: a role a group holds.
    let grouped = w.role(false, &[]);
    w.holder(grouped, true, true);
    refused(
        w.decide(&grantor, grant(grouped, join, ALLOW, &[])).await,
        "4.2:rule-2",
    );
    // Rule 3: a deny on a role assigned with inherit: false; an allow is fine.
    let narrow = w.role(false, &[]);
    w.holder(narrow, false, false);
    refused(
        w.decide(&grantor, grant(narrow, join, DENY, &[])).await,
        "4.2:rule-3",
    );
    passes(w.decide(&grantor, grant(narrow, join, ALLOW, &[])).await);

    // Revoking either effect needs network:grant at /network.
    refused(
        w.decide(
            &Oracle::default(),
            NetworkWrite::PermissionRevoke {
                role_id: plain,
                permission_id: join,
            },
        )
        .await,
        "5.3:permission",
    );
    passes(
        w.decide(
            &grantor,
            NetworkWrite::PermissionRevoke {
                role_id: plain,
                permission_id: join,
            },
        )
        .await,
    );

    // An ordinary permission is not the function's business.
    let other = w.permission("users:list");
    assert!(
        !cleared(
            w.decide(&Oracle::default(), grant(global, other, ALLOW, &[]))
                .await
        )
        .is_network_sensitive()
    );
}

#[tokio::test]
async fn the_reserved_namespace_is_not_created_renamed_or_deleted() {
    let mut w = World::new();
    let oracle = Oracle::default();
    for action in ["network:join", "Network:join", "network:new"] {
        refused(
            w.decide(&oracle, NetworkWrite::PermissionCreate { action })
                .await,
            "4.2:reserved-namespace",
        );
    }
    passes(
        w.decide(
            &oracle,
            NetworkWrite::PermissionCreate {
                action: "invoices:read",
            },
        )
        .await,
    );

    let join = w.permission(NETWORK_JOIN);
    let mine = w.permission("invoices:read");
    for (id, action) in [
        (join, Some("invoices:join")),
        (join, None),
        (mine, Some("network:join")),
    ] {
        refused(
            w.decide(
                &oracle,
                NetworkWrite::PermissionUpdate {
                    permission_id: id,
                    action,
                },
            )
            .await,
            "4.2:reserved-namespace",
        );
    }
    passes(
        w.decide(
            &oracle,
            NetworkWrite::PermissionUpdate {
                permission_id: mine,
                action: Some("invoices:write"),
            },
        )
        .await,
    );
    refused(
        w.decide(
            &oracle,
            NetworkWrite::PermissionDelete {
                permission_id: join,
            },
        )
        .await,
        "4.2:reserved-namespace",
    );
    passes(
        w.decide(
            &oracle,
            NetworkWrite::PermissionDelete {
                permission_id: mine,
            },
        )
        .await,
    );
}

// ---------------------------------------------------------------------------
// Certificate binding (§5.3 binding rows, H6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn binding_to_an_account_with_joins_needs_grant_at_every_join_node() {
    let mut w = World::new();
    let device = Uuid::new_v4();
    let (n1, n2) = (Uuid::new_v4(), Uuid::new_v4());
    let join = w.role(false, &[(NETWORK_JOIN, ALLOW)]);
    w.assign(device, join, Some(n1), true);
    let join2 = w.role(false, &[(NETWORK_JOIN, ALLOW)]);
    w.assign(device, join2, Some(n2), true);
    let cert = Uuid::new_v4();
    let previous = Uuid::new_v4();
    w.store.bindings.insert(cert, previous);
    let write = NetworkWrite::CertificateBind {
        certificate_id: cert,
        service_account_id: device,
    };
    let device_joins =
        Oracle::default()
            .allow(device, NETWORK_JOIN, n1)
            .allow(device, NETWORK_JOIN, n2);

    // Holding grant at one of the two is not enough.
    let r = refused(
        w.decide(&device_joins.allow(w.writer, NETWORK_GRANT, n1), write)
            .await,
        "5.3:bind",
    );
    assert_eq!(r.missing.unwrap().node, n2);
    assert_eq!(r.audit_action, AUDIT_BINDING_REFUSED);
    assert!(
        r.before
            .iter()
            .any(|(k, v)| *k == "service_account_id" && *v == previous.to_string())
    );

    let both = Oracle::default()
        .allow(device, NETWORK_JOIN, n1)
        .allow(device, NETWORK_JOIN, n2)
        .allow(w.writer, NETWORK_GRANT, n1)
        .allow(w.writer, NETWORK_GRANT, n2);
    assert!(cleared(w.decide(&both, write).await).is_network_sensitive());
}

#[tokio::test]
async fn an_allow_a_deny_already_beats_asks_nothing_and_no_join_asks_nothing() {
    let mut w = World::new();
    let device = Uuid::new_v4();
    let n = Uuid::new_v4();
    let join = w.role(false, &[(NETWORK_JOIN, ALLOW)]);
    w.assign(device, join, Some(n), true);
    // The engine answers "not allowed" for the device at N (a quarantine deny
    // beats the allow): the binder needs nothing there.
    let write = NetworkWrite::CertificateBind {
        certificate_id: Uuid::new_v4(),
        service_account_id: device,
    };
    passes(w.decide(&Oracle::default(), write).await);

    let bare = Uuid::new_v4();
    passes(
        w.decide(
            &Oracle::default(),
            NetworkWrite::CertificateBind {
                certificate_id: Uuid::new_v4(),
                service_account_id: bare,
            },
        )
        .await,
    );
}

#[tokio::test]
async fn h6_a_service_account_cannot_bind_a_certificate_to_itself() {
    let w = World::new();
    // Whatever it holds.
    let oracle = Oracle::default().allow(w.writer, NETWORK_GRANT, w.root());
    let r = refused(
        w.decide(
            &oracle,
            NetworkWrite::CertificateBind {
                certificate_id: Uuid::new_v4(),
                service_account_id: w.writer,
            },
        )
        .await,
        "H6",
    );
    assert_eq!(r.status, RefusalStatus::Forbidden);
    assert_eq!(r.audit_action, AUDIT_BINDING_REFUSED);
}

// ---------------------------------------------------------------------------
// Generic resources (§4.1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_generic_resource_routes_do_not_reach_the_reserved_subtree() {
    let mut w = World::new();
    let oracle = Oracle::default();
    let seg = Uuid::new_v4();
    w.resource(seg, RESOURCE_TYPE_NETWORK_SEGMENT);
    let plain = Uuid::new_v4();
    w.resource(plain, "project");

    for write in [
        NetworkWrite::ResourceCreate {
            resource_type: "network_segment",
            parent_id: None,
        },
        NetworkWrite::ResourceCreate {
            resource_type: "project",
            parent_id: Some(seg),
        },
        NetworkWrite::ResourceUpdate {
            resource_id: seg,
            resource_type: None,
            parent_id: Some(None),
        },
        NetworkWrite::ResourceUpdate {
            resource_id: plain,
            resource_type: Some("network_root"),
            parent_id: None,
        },
        NetworkWrite::ResourceUpdate {
            resource_id: plain,
            resource_type: None,
            parent_id: Some(Some(seg)),
        },
        NetworkWrite::ResourceDelete { resource_id: seg },
    ] {
        let r = refused(w.decide(&oracle, write).await, "4.1:reserved-subtree");
        assert_eq!(r.status, RefusalStatus::Invalid);
        assert_eq!(r.audit_action, AUDIT_RESOURCE_WRITE_REFUSED);
    }
    for write in [
        NetworkWrite::ResourceCreate {
            resource_type: "project",
            parent_id: Some(plain),
        },
        NetworkWrite::ResourceUpdate {
            resource_id: plain,
            resource_type: Some("service"),
            parent_id: Some(None),
        },
        NetworkWrite::ResourceDelete { resource_id: plain },
    ] {
        assert!(!cleared(w.decide(&oracle, write).await).is_network_sensitive());
    }
}

/// Every check the function makes is about the writer, with the writer's
/// subject scope, except the device's own `network:join` the binding rows read.
#[tokio::test]
async fn the_writer_is_checked_with_its_own_subject_scope() {
    struct ScopeProbe(std::sync::Mutex<Vec<SubjectScope>>);
    impl WriteTimeAccess for ScopeProbe {
        async fn check_at_write_time(&self, r: &AccessRequest) -> AxiamResult<AccessDecision> {
            self.0.lock().unwrap().push(r.subject_scope);
            Ok(AccessDecision::DeniedByRule("deny".into()))
        }
    }
    let mut w = World::new();
    let role = w.role(false, &[(NETWORK_JOIN, ALLOW)]);
    let org = SubjectScope::Organization {
        tenant_id: Uuid::new_v4(),
    };
    let probe = ScopeProbe(std::sync::Mutex::new(Vec::new()));
    let writer = GateWriter {
        subject_scope: org,
        ..w.gate_writer()
    };
    let v = authorize_network_write(
        &probe,
        &w.store,
        writer,
        NetworkWrite::RoleAssign {
            role_id: role,
            grantee: Grantee::ServiceAccount(Uuid::new_v4()),
            resource_id: None,
            inherit: true,
        },
    )
    .await
    .unwrap();
    // A deny-by-rule is "does not hold", exactly as no grant is.
    refused(v, "5.3:assign");
    assert_eq!(*probe.0.lock().unwrap(), vec![org]);
}

/// A role or permission that is not the tenant's is the repository's to
/// refuse, with the answer it always gave (`404`, or CQ-B07's cross-tenant
/// `403`); the function clears it as conferring nothing.
#[tokio::test]
async fn an_unknown_role_or_permission_is_left_to_the_repository() {
    let w = World::new();
    for write in [
        NetworkWrite::RoleAssign {
            role_id: Uuid::new_v4(),
            grantee: Grantee::Group(Uuid::new_v4()),
            resource_id: None,
            inherit: false,
        },
        NetworkWrite::RoleDelete {
            role_id: Uuid::new_v4(),
        },
        NetworkWrite::PermissionRevoke {
            role_id: Uuid::new_v4(),
            permission_id: Uuid::new_v4(),
        },
        NetworkWrite::PermissionDelete {
            permission_id: Uuid::new_v4(),
        },
    ] {
        assert!(!cleared(w.decide(&Oracle::default(), write).await).is_network_sensitive());
    }
    // A segment that is not the tenant's is a 404 from the function itself:
    // the segment routes have no older answer to keep.
    let input = profile_input();
    let err = authorize_network_write(
        &Oracle::default(),
        &w.store,
        w.gate_writer(),
        NetworkWrite::ProfileWrite {
            segment_id: Uuid::new_v4(),
            input: &input,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AxiamError::NotFound { .. }));
}

// ---------------------------------------------------------------------------
// The tenant's Session-Timeout cap (plan 13.6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_policy_write_needs_network_admin_at_the_root_and_carries_a_matching_token() {
    let w = World::new();
    let oracle = Oracle::default().allow(w.writer, NETWORK_ADMIN, w.root());
    let c = cleared(
        w.decide(
            &oracle,
            NetworkWrite::PolicyWrite {
                session_timeout_max_secs: 1800,
            },
        )
        .await,
    );
    assert!(c.is_network_sensitive());
    c.into_write_clearance()
        .expect("a policy write carries a token")
        .check(w.tenant, w.writer, &NetworkWriteTarget::PolicyWrite)
        .unwrap();
}

#[tokio::test]
async fn a_policy_write_without_network_admin_is_403_naming_it_with_the_values() {
    let w = World::new();
    // Everything a profile writer holds, and every meta permission: none of
    // it writes the cap.
    let oracle = Oracle::default()
        .allow(w.writer, NETWORK_PROFILES_WRITE, w.root())
        .allow(w.writer, NETWORK_GRANT, w.root())
        .allow(w.writer, NETWORK_SEGMENTS_WRITE, w.root());
    let r = refused(
        w.decide(
            &oracle,
            NetworkWrite::PolicyWrite {
                session_timeout_max_secs: 7200,
            },
        )
        .await,
        "4.2:policy_write",
    );
    assert_eq!(r.status, RefusalStatus::Forbidden);
    assert_eq!(r.audit_action, AUDIT_POLICY_WRITE_REFUSED);
    let missing = r.missing.expect("a 403 names the permission");
    assert_eq!(
        (missing.action.as_str(), missing.node),
        (NETWORK_ADMIN, w.root())
    );
    // The audit row can show the cap and which way the write meant to move it.
    assert!(
        r.before
            .contains(&("session_timeout_max_secs", "3600".to_owned()))
    );
    assert!(
        r.after
            .contains(&("session_timeout_max_secs", "7200".to_owned()))
    );
    assert!(r.after.contains(&("direction", "raised".to_owned())));
}

/// The decision the commit records: a raise asks no more than a lowering. The
/// cap changes no stored profile (a read renders `min(stored, cap)`), and the
/// split between whoever writes profiles and whoever writes the envelope is
/// the note's own (§5.2 H3), so a raise does not also ask for
/// `network:profiles_write` or `network:grant`.
#[tokio::test]
async fn a_raise_asks_no_more_than_a_lowering() {
    let w = World::new();
    let oracle = Oracle::default().allow(w.writer, NETWORK_ADMIN, w.root());
    for cap in [300, 3600, 86_400] {
        passes(
            w.decide(
                &oracle,
                NetworkWrite::PolicyWrite {
                    session_timeout_max_secs: cap,
                },
            )
            .await,
        );
    }
    // And the only thing asked, at any of them, is network:admin at /network.
    let asked = oracle.asked.lock().unwrap();
    assert!(
        asked
            .iter()
            .all(|(_, action, node)| action == NETWORK_ADMIN && *node == w.root()),
        "{asked:?}"
    );
}

#[tokio::test]
async fn a_deny_of_network_admin_at_the_root_refuses_the_policy_write() {
    // The oracle answers deny for anything not listed, which is what
    // deny-override gives a writer with an explicit deny: "does not hold".
    let w = World::new();
    let r = refused(
        w.decide(
            &Oracle::default(),
            NetworkWrite::PolicyWrite {
                session_timeout_max_secs: 600,
            },
        )
        .await,
        "4.2:policy_write",
    );
    assert!(r.after.contains(&("direction", "lowered".to_owned())));
}
