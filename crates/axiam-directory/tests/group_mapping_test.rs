//! Directory group mapping end to end (T23.3.4, G-3, D-30): the real sign-in
//! path (`AuthService`), the real repositories (in-memory SurrealDB), the real
//! authorization engine, and the in-process TLS directory in `tests/support`.
//!
//! What is pinned here, and where the rest is pinned:
//!
//! * a directory user's groups — direct and nested — become AXIAM memberships at
//!   sign-in, and a role on the mapped AXIAM group is effective for them through
//!   the authorization engine, then **gone after the directory removes them and
//!   they sign in again**;
//! * the mapping owns only what it wrote: a manual membership (of the same
//!   group, or another) is never touched, and an unmapped directory group — even
//!   one named like an AXIAM group — grants nothing;
//! * **fail closed**: a lookup that fails or hits the cap refuses the sign-in,
//!   for an existing account and for a just-provisioned one, changes nothing and
//!   leaves a row that names no person;
//! * the resolution itself (filters, depth, cycles, cap, referrals) is pinned in
//!   `group_lookup_test.rs`, the DN comparison in `dn.rs`, the storage in
//!   `axiam-db`'s `directory_group_mapping_test.rs`.
//!
//! No assertion message formats a credential, a DN or an identifier.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axiam_auth::config::AuthConfig;
use axiam_auth::error::AuthError;
use axiam_auth::service::{
    AUDIT_GROUP_MAPPING_REFUSED, AUDIT_GROUPS_MAPPED, AuthService, LoginInput, LoginResult,
    RepositoryDirectoryAuditSink,
};
use axiam_authz::types::SubjectScope;
use axiam_authz::{AccessDecision, AccessRequest, AuthorizationEngine};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryGroupMapper, DirectoryKind, GroupMapping, NewDirectoryConfig,
    UserAttributeMap,
};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, DirectoryConfigRepository, GroupRepository, Pagination,
    PermissionRepository, ResourceRepository, RoleRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealDirectoryConfigRepository, SurrealFederationLinkRepository,
    SurrealGroupRepository, SurrealPermissionRepository, SurrealRefreshTokenRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealSessionRepository, SurrealUserRepository,
};
use axiam_directory::config::validate;
use axiam_directory::{ClientLimits, RepositoryDirectoryAuthenticator};
use axiam_directory::{MembershipChangeSlot, RepositoryGroupMapper, mapper::apply_backed_groups};
use ldap3_proto::proto::LdapResultCode;
use support::{
    BASE_DN, Entry, GROUP_BASE_DN, SERVICE_DN, Script, TestServer, alice_password, group_dn,
    service_secret,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

const ALICE_UUID: &str = "00000000-0000-4000-8000-00000000a11c";
const ALICE_DN: &str = "uid=alice,ou=people,dc=example,dc=com";

type Svc = AuthService<
    SurrealUserRepository<Db>,
    SurrealSessionRepository<Db>,
    SurrealFederationLinkRepository<Db>,
    SurrealRefreshTokenRepository<Db>,
>;
type Engine = AuthorizationEngine<
    SurrealRoleRepository<Db>,
    SurrealPermissionRepository<Db>,
    SurrealResourceRepository<Db>,
    SurrealScopeRepository<Db>,
    SurrealGroupRepository<Db>,
>;
type ConfigRepo = SurrealDirectoryConfigRepository<Db>;

/// An Ed25519 key pair minted per process: no key literal in the source.
fn jwt_keys() -> &'static (String, String) {
    static KEYS: OnceLock<(String, String)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

fn directory_key() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(|| {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes
    })
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: jwt_keys().0.clone(),
        jwt_public_key_pem: jwt_keys().1.clone(),
        jwt_issuer: "axiam-test".into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 3600,
        hash_acquire_timeout_secs: 20,
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        email_verification_grace_period_hours: 24,
        ..AuthConfig::default()
    }
}

fn alice() -> Entry {
    Entry::person("alice", &alice_password(), ALICE_UUID)
}

/// The directory: `staff`, `eng` (which contains `staff`: one level of
/// nesting), `ops`, `admins` and `unmapped`, with alice a direct member of
/// those named in `direct`.
fn directory(direct: &[&str]) -> Vec<Entry> {
    let alice_in = |name: &str| -> Vec<&str> {
        if direct.contains(&name) {
            vec![ALICE_DN]
        } else {
            vec![]
        }
    };
    vec![
        alice(),
        Entry::group("staff", &alice_in("staff")),
        Entry::group("eng", &[&group_dn("staff")]),
        Entry::group("ops", &alice_in("ops")),
        Entry::group("admins", &alice_in("admins")),
        Entry::group("unmapped", &alice_in("unmapped")),
    ]
}

struct Harness {
    db: Surreal<Db>,
    tenant_id: Uuid,
    org_id: Uuid,
    server: TestServer,
    users: SurrealUserRepository<Db>,
    groups: SurrealGroupRepository<Db>,
    audit: SurrealAuditLogRepository<Db>,
    config_repo: ConfigRepo,
    svc: Svc,
    /// Where the mapper reports a changed membership; empty until a test sets it.
    slot: MembershipChangeSlot,
    /// The AXIAM groups of the tenant, by the name they were created under.
    staff: Uuid,
    eng: Uuid,
    ops: Uuid,
    /// An AXIAM group deliberately named like a directory group nobody mapped.
    admins: Uuid,
}

fn limits() -> ClientLimits {
    ClientLimits {
        acquire_timeout: Duration::from_millis(500),
        connect_timeout: Duration::from_secs(2),
        operation_timeout: Duration::from_secs(2),
        authentication_deadline: Duration::from_secs(8),
        ..ClientLimits::default()
    }
}

async fn axiam_group(db: &Surreal<Db>, tenant_id: Uuid, name: &str) -> Uuid {
    SurrealGroupRepository::new(db.clone())
        .create(CreateGroup {
            tenant_id,
            name: name.into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

fn config_input(
    h: &TestServer,
    tenant_id: Uuid,
    kind: DirectoryKind,
    mappings: Vec<GroupMapping>,
    depth: u8,
) -> NewDirectoryConfig {
    let reverse = kind == DirectoryKind::OpenLdap;
    NewDirectoryConfig {
        tenant_id,
        enabled: true,
        kind,
        url: format!("ldaps://localhost:{}", h.port()),
        start_tls: false,
        bind_dn: SERVICE_DN.into(),
        bind_secret: Some(Zeroizing::new(service_secret())),
        base_dn: BASE_DN.into(),
        user_filter: "(uid={username})".into(),
        // The fixture people are OpenLDAP-shaped whichever kind is tested: the
        // kind selects how groups are found, and the attribute map is explicit.
        user_attribute_map: UserAttributeMap {
            username: "uid".into(),
            email: "mail".into(),
            display_name: "displayName".into(),
            external_id: "entryUUID".into(),
        },
        group_base_dn: reverse.then(|| GROUP_BASE_DN.to_string()),
        group_filter: reverse.then(|| "(objectClass=groupOfNames)".to_string()),
        group_member_attribute: kind.default_group_member_attribute().into(),
        group_nesting_depth: depth,
        group_mappings: mappings,
        sync_interval_secs: 3600,
        jit_provisioning: true,
        trust_anchors_pem: vec![h.ca.pem.clone()],
    }
}

fn map(dn: &str, group_id: Uuid) -> GroupMapping {
    GroupMapping {
        directory_group_dn: dn.into(),
        group_id,
    }
}

/// The standard table: `staff` and `eng` and `ops` are mapped; `admins` and
/// `unmapped` are not.
fn standard_table(h: &Harness) -> Vec<GroupMapping> {
    vec![
        map(&group_dn("staff"), h.staff),
        map(&group_dn("eng"), h.eng),
        map(&group_dn("ops"), h.ops),
    ]
}

async fn harness_with(
    kind: DirectoryKind,
    entries: Vec<Entry>,
    depth: u8,
    mappings: impl FnOnce(&Harness) -> Vec<GroupMapping>,
) -> Harness {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let tenant_id = Uuid::new_v4();
    let server = TestServer::start(Script {
        entries,
        ..Script::default()
    })
    .await;

    let users = SurrealUserRepository::new(db.clone());
    let groups = SurrealGroupRepository::new(db.clone());
    let audit = SurrealAuditLogRepository::new(db.clone());
    let config_repo = SurrealDirectoryConfigRepository::new(db.clone(), Some(directory_key()));

    let authenticator = Arc::new(RepositoryDirectoryAuthenticator::with_client(
        config_repo.clone(),
        Arc::new(support::loopback_client(limits())),
    ));
    let slot = MembershipChangeSlot::new();
    let mapper = RepositoryGroupMapper::new(Arc::clone(&authenticator), groups.clone())
        .with_change_slot(slot.clone());
    let svc = AuthService::new(
        users.clone(),
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        auth_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    )
    .with_directory_authenticator(authenticator)
    .with_directory_group_mapper(Arc::new(mapper))
    .with_directory_audit(Arc::new(RepositoryDirectoryAuditSink(audit.clone())));

    let h = Harness {
        staff: axiam_group(&db, tenant_id, "ax-staff").await,
        eng: axiam_group(&db, tenant_id, "ax-eng").await,
        ops: axiam_group(&db, tenant_id, "ax-ops").await,
        admins: axiam_group(&db, tenant_id, "admins").await,
        db,
        tenant_id,
        org_id: Uuid::new_v4(),
        server,
        users,
        groups,
        audit,
        config_repo,
        svc,
        slot,
    };
    let table = mappings(&h);
    let input = config_input(&h.server, tenant_id, kind, table, depth);
    validate(&input).expect("the fixture configuration must be acceptable");
    h.config_repo.create(input).await.unwrap();
    h
}

async fn harness() -> Harness {
    harness_with(
        DirectoryKind::OpenLdap,
        directory(&["staff", "ops", "admins", "unmapped"]),
        5,
        standard_table,
    )
    .await
}

fn login(h: &Harness) -> LoginInput {
    LoginInput {
        tenant_id: h.tenant_id,
        org_id: h.org_id,
        username_or_email: "alice".into(),
        password: alice_password(),
        ip_address: None,
        user_agent: None,
        mfa_policy: None,
        lockout_policy: None,
    }
}

async fn sign_in(h: &Harness) -> Result<LoginResult, AxiamError> {
    h.svc.login(login(h)).await
}

fn is_invalid_credentials(outcome: &Result<LoginResult, AxiamError>) -> bool {
    matches!(
        outcome,
        Err(AxiamError::AuthenticationFailed { reason }) if reason == &AuthError::InvalidCredentials.to_string()
    )
}

async fn alice_id(h: &Harness) -> Uuid {
    h.users
        .get_by_username(h.tenant_id, "alice")
        .await
        .unwrap()
        .id
}

async fn group_names(h: &Harness) -> BTreeSet<String> {
    let id = alice_id(h).await;
    h.groups
        .get_user_groups(h.tenant_id, id)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.name)
        .collect()
}

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

async fn audit_rows(h: &Harness, action: &str) -> Vec<AuditLogEntry> {
    h.audit
        .list(
            h.tenant_id,
            AuditLogFilter {
                action: Some(action.to_string()),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
}

/// How many group lookups (base-object reads, or searches under the group base)
/// the directory has seen.
fn group_lookups(h: &Harness) -> usize {
    h.server
        .events()
        .iter()
        .filter(|e| match e {
            support::Event::Search { base, scope, .. } => {
                matches!(scope, ldap3_proto::proto::LdapSearchScope::Base)
                    || !base.eq_ignore_ascii_case(BASE_DN)
            }
            _ => false,
        })
        .count()
}

// ---------------------------------------------------------------------------
// The mapping applied at sign-in
// ---------------------------------------------------------------------------

/// A first sign-in provisions the account and maps its groups — the direct
/// ones and the one reached through nesting — and audits the change with
/// identifiers and counts only.
#[tokio::test]
async fn a_first_sign_in_maps_direct_and_nested_groups_and_audits_the_change() {
    let h = harness().await;
    assert!(matches!(sign_in(&h).await, Ok(LoginResult::Success(_))));

    // staff (direct) and ops (direct), and eng through staff (nested).
    assert_eq!(
        group_names(&h).await,
        names(&["ax-staff", "ax-eng", "ax-ops"])
    );
    let id = alice_id(&h).await;
    let owned: BTreeSet<Uuid> = h
        .groups
        .get_user_directory_group_ids(h.tenant_id, id)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(owned, BTreeSet::from([h.staff, h.eng, h.ops]));

    let rows = audit_rows(&h, AUDIT_GROUPS_MAPPED).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].resource_id, Some(id));
    let metadata = rows[0].metadata.clone();
    assert_eq!(metadata["added_count"], 3);
    assert_eq!(metadata["removed_count"], 0);
    // directory groups: staff, ops, admins, unmapped (direct) + eng (nested).
    assert_eq!(metadata["directory_groups_resolved"], 5);
    assert_eq!(metadata["directory_groups_mapped"], 3);
    let rendered = serde_json::to_string(&metadata).unwrap();
    for person_or_dn in ["alice", "uid=", "cn=", "example.com", ALICE_UUID] {
        assert!(
            !rendered.contains(person_or_dn),
            "the audit row must hold identifiers and counts only"
        );
    }
}

/// D-30: nothing is granted by name. The directory has a group called `admins`
/// that alice belongs to, and the tenant has an AXIAM group called `admins`;
/// nobody mapped one to the other, so alice is not in it.
#[tokio::test]
async fn unmapped_directory_groups_grant_nothing_including_one_named_like_an_axiam_group() {
    let h = harness().await;
    assert!(sign_in(&h).await.is_ok());
    let names = group_names(&h).await;
    assert!(!names.contains("admins"), "no match by name");
    let id = alice_id(&h).await;
    assert!(
        !h.groups
            .get_user_groups(h.tenant_id, id)
            .await
            .unwrap()
            .iter()
            .any(|g| g.id == h.admins)
    );
    // And no AXIAM group was created from a directory one.
    let all = h
        .groups
        .list(
            h.tenant_id,
            Pagination {
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(all.total, 4, "ax-staff, ax-eng, ax-ops and admins, no more");
}

/// Memberships follow the directory: an addition appears and a removal
/// disappears at the next sign-in, and nothing else moves.
#[tokio::test]
async fn the_mapping_applies_additions_and_removals_at_each_sign_in() {
    let h = harness().await;
    h.server.set_entries(directory(&["staff"]));
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(group_names(&h).await, names(&["ax-staff", "ax-eng"]));

    // The directory adds alice to ops and takes her out of staff.
    h.server.set_entries(directory(&["ops"]));
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(group_names(&h).await, names(&["ax-ops"]));

    let rows = audit_rows(&h, AUDIT_GROUPS_MAPPED).await;
    assert_eq!(rows.len(), 2, "one row per sign-in that changed something");
    let second = rows
        .iter()
        .find(|r| r.metadata["removed_count"] == 2)
        .expect("the second sign-in removed staff and eng");
    assert_eq!(second.metadata["added_count"], 1);

    // A sign-in that changes nothing writes nothing.
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(audit_rows(&h, AUDIT_GROUPS_MAPPED).await.len(), 2);
}

/// The acceptance case: a role on the mapped AXIAM group is effective for the
/// directory user through the authorization engine, and disappears after the
/// directory removes them from the group and they sign in again.
#[tokio::test]
async fn a_role_through_a_mapped_group_is_effective_and_gone_after_removal() {
    let h = harness().await;
    let resource = SurrealResourceRepository::new(h.db.clone())
        .create(CreateResource {
            tenant_id: h.tenant_id,
            name: "ledger".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let roles = SurrealRoleRepository::new(h.db.clone());
    let perms = SurrealPermissionRepository::new(h.db.clone());
    let role = roles
        .create(CreateRole {
            tenant_id: h.tenant_id,
            name: "ledger-reader".into(),
            description: String::new(),
            is_global: false,
        })
        .await
        .unwrap();
    let perm = perms
        .create(CreatePermission {
            tenant_id: h.tenant_id,
            action: "read".into(),
            description: String::new(),
        })
        .await
        .unwrap();
    perms
        .grant_to_role(h.tenant_id, role.id, perm.id)
        .await
        .unwrap();
    // The role is on the AXIAM group, never on the user.
    roles
        .assign_to_group(
            h.tenant_id,
            h.staff,
            role.id,
            AssignmentScope::resource(resource),
        )
        .await
        .unwrap();
    let engine: Engine = AuthorizationEngine::new(
        roles.clone(),
        perms.clone(),
        SurrealResourceRepository::new(h.db.clone()),
        SurrealScopeRepository::new(h.db.clone()),
        h.groups.clone(),
    );
    let may_read = |user_id: Uuid| {
        let engine = &engine;
        let tenant_id = h.tenant_id;
        async move {
            engine
                .check_access(&AccessRequest {
                    tenant_id,
                    subject_scope: SubjectScope::Tenant,
                    subject_id: user_id,
                    action: "read".into(),
                    resource_id: resource,
                    scope: None,
                })
                .await
                .unwrap()
        }
    };

    // Alice is in the directory's staff group: first sign-in, role effective.
    h.server.set_entries(directory(&["staff"]));
    assert!(sign_in(&h).await.is_ok());
    let id = alice_id(&h).await;
    assert_eq!(may_read(id).await, AccessDecision::Allow);

    // The directory takes her out of staff. Until she signs in again the
    // membership stands (that is the contract: a removal takes effect at the
    // next sign-in) ...
    h.server.set_entries(directory(&[]));
    assert_eq!(may_read(id).await, AccessDecision::Allow);
    // ... and at the next sign-in it is gone, and so is the role.
    assert!(sign_in(&h).await.is_ok());
    assert!(matches!(may_read(id).await, AccessDecision::Deny(_)));

    // Put back, and it is back.
    h.server.set_entries(directory(&["staff"]));
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(may_read(id).await, AccessDecision::Allow);
}

/// D-30: the mapping owns only its own memberships. A manual membership of a
/// mapped group is left as it is — no second edge, no change of owner — and the
/// directory's removal never takes it; a manual membership of an unrelated
/// group is never looked at.
#[tokio::test]
async fn a_manual_membership_is_untouched_by_every_application() {
    let h = harness().await;
    // Create the account with the mapping off, so there is a user to give a
    // membership by hand.
    let table = standard_table(&h);
    let mut off = config_input(&h.server, h.tenant_id, DirectoryKind::OpenLdap, vec![], 5);
    off.bind_secret = None;
    h.config_repo.update(off.clone()).await.unwrap();
    h.server.set_entries(directory(&["staff"]));
    assert!(sign_in(&h).await.is_ok());
    let id = alice_id(&h).await;
    assert!(
        group_names(&h).await.is_empty(),
        "an empty table maps nothing"
    );
    assert_eq!(
        group_lookups(&h),
        0,
        "an empty table asks the directory no group question"
    );

    // An administrator adds alice to ax-staff (a mapped group) and ax-ops (a
    // mapped group the directory will not back) by hand, and to admins.
    for group in [h.staff, h.ops, h.admins] {
        h.groups.add_member(h.tenant_id, id, group).await.unwrap();
    }

    // Turn the mapping on: staff is backed (and eng through it).
    off.group_mappings = table;
    h.config_repo.update(off).await.unwrap();
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(
        group_names(&h).await,
        names(&["ax-staff", "ax-eng", "ax-ops", "admins"])
    );
    let owned: BTreeSet<Uuid> = h
        .groups
        .get_user_directory_group_ids(h.tenant_id, id)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        owned,
        BTreeSet::from([h.eng]),
        "only the edge the mapping wrote is the mapping's; ax-staff stayed manual"
    );

    // The directory removes alice from staff, so neither staff nor eng is
    // backed any more: the one directory edge goes, every manual one stays.
    h.server.set_entries(directory(&[]));
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(
        group_names(&h).await,
        names(&["ax-staff", "ax-ops", "admins"])
    );
    assert!(
        h.groups
            .get_user_directory_group_ids(h.tenant_id, id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// RFC 4514 normalisation, end to end: a table written the way `ldapsearch`
/// prints a DN (upper-case types, a space after each comma) matches the group
/// the directory names in lower case without.
#[tokio::test]
async fn a_mapping_matches_whatever_the_spelling_of_the_dn() {
    let h = harness_with(DirectoryKind::OpenLdap, directory(&["staff"]), 5, |h| {
        vec![map("CN=Staff, OU=Groups, DC=Example, DC=COM", h.staff)]
    })
    .await;
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(group_names(&h).await, names(&["ax-staff"]));
}

/// The kind picks how groups are found: Active Directory reads `memberOf` off
/// the entry, and nests through the groups' own `memberOf`.
#[tokio::test]
async fn an_active_directory_user_is_mapped_through_member_of() {
    let entries = vec![
        alice().with_values("memberOf", &[&group_dn("staff")]),
        Entry::ad_group("staff", &[&group_dn("eng")]),
        Entry::ad_group("eng", &[]),
        Entry::ad_group("unmapped", &[]),
    ];
    let h = harness_with(DirectoryKind::ActiveDirectory, entries, 5, |h| {
        vec![
            map(&group_dn("staff"), h.staff),
            map(&group_dn("eng"), h.eng),
        ]
    })
    .await;
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(group_names(&h).await, names(&["ax-staff", "ax-eng"]));

    // Depth 0: no nesting, so only the direct group.
    let mut input = config_input(
        &h.server,
        h.tenant_id,
        DirectoryKind::ActiveDirectory,
        vec![
            map(&group_dn("staff"), h.staff),
            map(&group_dn("eng"), h.eng),
        ],
        0,
    );
    input.bind_secret = None;
    h.config_repo.update(input).await.unwrap();
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(group_names(&h).await, names(&["ax-staff"]));
}

/// A mapping row that outlived its group grants nothing and locks nobody out.
#[tokio::test]
async fn a_mapping_row_whose_group_was_deleted_is_skipped() {
    let h = harness().await;
    h.groups.delete(h.tenant_id, h.eng).await.unwrap();
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(group_names(&h).await, names(&["ax-staff", "ax-ops"]));
}

/// A role that arrived through a group must not outlive the sign-in that
/// noticed the directory had removed it — **even with the decision cache on**.
/// The mapper reports a changed membership through the slot the composition
/// root sets to the engine's `invalidate_subject`, as the group routes do.
/// The first half is the control: without the hook a cached allow survives.
#[tokio::test]
async fn a_membership_change_flushes_the_decision_cache_through_the_hook() {
    use axiam_authz::{DecisionCache, DecisionCacheConfig};

    let h = harness().await;
    let resource = SurrealResourceRepository::new(h.db.clone())
        .create(CreateResource {
            tenant_id: h.tenant_id,
            name: "ledger".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let roles = SurrealRoleRepository::new(h.db.clone());
    let perms = SurrealPermissionRepository::new(h.db.clone());
    let role = roles
        .create(CreateRole {
            tenant_id: h.tenant_id,
            name: "ledger-reader".into(),
            description: String::new(),
            is_global: false,
        })
        .await
        .unwrap();
    let perm = perms
        .create(CreatePermission {
            tenant_id: h.tenant_id,
            action: "read".into(),
            description: String::new(),
        })
        .await
        .unwrap();
    perms
        .grant_to_role(h.tenant_id, role.id, perm.id)
        .await
        .unwrap();
    roles
        .assign_to_group(
            h.tenant_id,
            h.staff,
            role.id,
            AssignmentScope::resource(resource),
        )
        .await
        .unwrap();
    let engine: Arc<Engine> = Arc::new(
        AuthorizationEngine::new(
            roles.clone(),
            perms.clone(),
            SurrealResourceRepository::new(h.db.clone()),
            SurrealScopeRepository::new(h.db.clone()),
            h.groups.clone(),
        )
        .with_decision_cache(Arc::new(DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(300),
            max_entries_per_tenant: 100,
        }))),
    );
    let may_read = |user_id: Uuid| {
        let engine = Arc::clone(&engine);
        let tenant_id = h.tenant_id;
        async move {
            engine
                .check_access(&AccessRequest {
                    tenant_id,
                    subject_scope: SubjectScope::Tenant,
                    subject_id: user_id,
                    action: "read".into(),
                    resource_id: resource,
                    scope: None,
                })
                .await
                .unwrap()
        }
    };

    // Control: no hook. The allow is cached, the directory removes alice, she
    // signs in, the membership is gone — and the cached allow still stands.
    h.server.set_entries(directory(&["staff"]));
    assert!(sign_in(&h).await.is_ok());
    let id = alice_id(&h).await;
    assert_eq!(may_read(id).await, AccessDecision::Allow);
    h.server.set_entries(directory(&[]));
    assert!(sign_in(&h).await.is_ok());
    assert!(group_names(&h).await.is_empty());
    assert_eq!(
        may_read(id).await,
        AccessDecision::Allow,
        "control: without the hook the cache is stale, which is what the hook is for"
    );

    // Now the hook the composition root sets.
    let flushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let engine = Arc::clone(&engine);
        let flushes = Arc::clone(&flushes);
        assert!(h.slot.set(Arc::new(move |tenant_id, user_id| {
            let engine = Arc::clone(&engine);
            let flushes = Arc::clone(&flushes);
            Box::pin(async move {
                flushes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                engine.invalidate_subject(tenant_id, user_id).await.unwrap();
            })
        })));
    }
    // Put alice back in staff: the addition flushes too (the stale deny is
    // cleared and the allow is cached).
    h.server.set_entries(directory(&["staff"]));
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(may_read(id).await, AccessDecision::Allow);
    assert_eq!(flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
    // A sign-in that changes nothing flushes nothing.
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
    // The removal is effective at once, with the cache on.
    h.server.set_entries(directory(&[]));
    assert!(sign_in(&h).await.is_ok());
    assert!(matches!(may_read(id).await, AccessDecision::Deny(_)));
    assert_eq!(flushes.load(std::sync::atomic::Ordering::SeqCst), 2);
    // The slot takes one hook.
    assert!(!h.slot.set(Arc::new(|_, _| Box::pin(async {}))));
}

// ---------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------

/// A lookup that fails refuses the sign-in — the ordinary failure, not counted
/// against the account — changes no membership, and leaves a row that names no
/// person. When the directory answers again, the next sign-in succeeds.
#[tokio::test]
async fn a_failed_group_lookup_refuses_the_sign_in_and_changes_nothing() {
    let h = harness().await;
    assert!(sign_in(&h).await.is_ok());
    let before = group_names(&h).await;
    assert!(!before.is_empty());

    // The directory has taken alice out of staff and ops — and then cannot be
    // asked about groups. The old memberships must not be what lets her in.
    h.server.set_entries(directory(&[]));
    h.server
        .set_group_search_done(Some((LdapResultCode::Busy, vec![])));
    let refused = sign_in(&h).await;
    assert!(
        is_invalid_credentials(&refused),
        "the sign-in is refused, and says nothing more than any refusal"
    );
    assert_eq!(group_names(&h).await, before, "nothing was changed");
    let user = h.users.get_by_username(h.tenant_id, "alice").await.unwrap();
    assert_eq!(
        user.failed_login_attempts, 0,
        "the user did nothing wrong, so it is not counted against the account"
    );
    let rows = audit_rows(&h, AUDIT_GROUP_MAPPING_REFUSED).await;
    assert_eq!(rows.len(), 1);
    let rendered = serde_json::to_string(&rows[0].metadata).unwrap();
    assert!(!rendered.contains("alice") && !rendered.contains("uid="));

    // Recovery: the directory answers, and the removal lands.
    h.server.set_group_search_done(None);
    assert!(sign_in(&h).await.is_ok());
    assert!(group_names(&h).await.is_empty());
}

/// The hard cap refuses, end to end: more groups than the cap is no sign-in.
#[tokio::test]
async fn a_user_in_more_groups_than_the_cap_is_refused() {
    let h = harness().await;
    assert!(sign_in(&h).await.is_ok());
    let before = group_names(&h).await;

    let mut entries = directory(&["staff"]);
    entries.extend((0..1_001).map(|i| Entry::group(&format!("bulk{i}"), &[ALICE_DN])));
    h.server.set_entries(entries);
    assert!(is_invalid_credentials(&sign_in(&h).await));
    assert_eq!(group_names(&h).await, before, "nothing was changed");
    assert_eq!(audit_rows(&h, AUDIT_GROUP_MAPPING_REFUSED).await.len(), 1);
}

/// Under JIT a just-created account whose group lookup fails is refused. It has
/// no membership, so it grants nothing; the next sign-in (the directory
/// answering) maps its groups.
#[tokio::test]
async fn a_provisioned_account_whose_group_lookup_fails_is_refused_and_holds_nothing() {
    let h = harness().await;
    h.server
        .set_group_search_done(Some((LdapResultCode::Busy, vec![])));
    assert!(is_invalid_credentials(&sign_in(&h).await));

    // The account was created (the directory vouched for the password) ...
    let id = alice_id(&h).await;
    // ... and holds nothing, by any route.
    assert!(
        h.groups
            .get_user_groups(h.tenant_id, id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        h.groups
            .get_user_directory_group_ids(h.tenant_id, id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(audit_rows(&h, AUDIT_GROUP_MAPPING_REFUSED).await.len(), 1);

    // And while the directory still cannot be asked, she still cannot sign in.
    assert!(is_invalid_credentials(&sign_in(&h).await));
    assert!(group_names(&h).await.is_empty());

    h.server.set_group_search_done(None);
    assert!(sign_in(&h).await.is_ok());
    assert_eq!(
        group_names(&h).await,
        names(&["ax-staff", "ax-eng", "ax-ops"])
    );
}

// ---------------------------------------------------------------------------
// The mapper directly (what the sync job will call)
// ---------------------------------------------------------------------------

/// The same function the sign-in uses, called without a sign-in: the sync job's
/// entry point.
#[tokio::test]
async fn the_mapper_is_callable_without_a_sign_in_and_fails_closed_the_same_way() {
    let h = harness().await;
    assert!(sign_in(&h).await.is_ok());
    let id = alice_id(&h).await;

    let authenticator = Arc::new(RepositoryDirectoryAuthenticator::with_client(
        h.config_repo.clone(),
        Arc::new(support::loopback_client(limits())),
    ));
    let mapper = RepositoryGroupMapper::new(authenticator, h.groups.clone());

    h.server.set_entries(directory(&["ops"]));
    let outcome = mapper
        .apply_for_user(h.tenant_id, id, ALICE_DN)
        .await
        .unwrap();
    assert_eq!(outcome.removed.len(), 2, "staff and eng");
    assert!(outcome.added.is_empty());
    assert_eq!(outcome.directory_groups_mapped, 1);
    assert_eq!(group_names(&h).await, names(&["ax-ops"]));

    // A tenant with no directory is NotConfigured, never an empty success that
    // would strip memberships.
    assert_eq!(
        mapper
            .apply_for_user(Uuid::new_v4(), id, ALICE_DN)
            .await
            .unwrap_err(),
        DirectoryAuthError::NotConfigured
    );
    // A lookup that fails changes nothing.
    h.server
        .set_group_search_done(Some((LdapResultCode::Busy, vec![])));
    assert_eq!(
        mapper
            .apply_for_user(h.tenant_id, id, ALICE_DN)
            .await
            .unwrap_err(),
        DirectoryAuthError::Unavailable
    );
    assert_eq!(group_names(&h).await, names(&["ax-ops"]));
}

/// The application function over a backed set alone, which is what a sync job
/// that already holds the set would call.
#[tokio::test]
async fn apply_backed_groups_reports_what_it_did_and_leaves_manual_edges() {
    let h = harness().await;
    assert!(sign_in(&h).await.is_ok());
    let id = alice_id(&h).await;
    h.groups
        .add_member(h.tenant_id, id, h.admins)
        .await
        .unwrap();

    // Back only ax-staff and admins (admins is held by hand).
    let backed = BTreeSet::from([h.staff, h.admins]);
    let outcome = apply_backed_groups(&h.groups, h.tenant_id, id, &backed)
        .await
        .unwrap();
    assert!(outcome.added.is_empty(), "staff was already the mapping's");
    assert_eq!(outcome.left_manual, vec![h.admins]);
    let removed: BTreeSet<Uuid> = outcome.removed.into_iter().collect();
    assert_eq!(removed, BTreeSet::from([h.eng, h.ops]));
    assert_eq!(group_names(&h).await, names(&["ax-staff", "admins"]));
}
