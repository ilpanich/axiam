//! The directory sync job end to end (T23.3.5, G-3, D-31): the real engine, the
//! real repositories (in-memory SurrealDB), the real group mapper and the
//! in-process TLS directory in `tests/support`.
//!
//! What is pinned here:
//!
//! * a vanished entry, an AD-disabled account (`userAccountControl` bit `0x2`)
//!   and an OpenLDAP `pwdAccountLockedTime` each make the account `Inactive`
//!   with its sessions and refresh tokens revoked, its directory memberships
//!   removed (manual ones kept), the decision cache flushed and an audit row —
//!   and `account_may_act` refuses it afterwards, which is what closes T-303's
//!   residual for passkeys and the OP cookie;
//! * **nothing re-enables**: an entry that reappears, or is enabled again, is
//!   reported once and the account stays `Inactive`;
//! * an attribute update is applied, a colliding one is skipped and audited;
//! * the incremental run acts only on entries changed since the watermark whose
//!   identifier belongs to a marked account, never concludes "vanished", and
//!   falls back to a full run when the AD server changes or gives no watermark;
//! * the safety valve trips with no change and does not trip below its
//!   thresholds;
//! * errors change nothing, including an error part-way through the reads;
//! * a tenant with no directory, or a disabled one, is skipped without a
//!   connection; a local account is never touched; no row is ever removed and
//!   no account ever becomes `Deleted`.
//!
//! No assertion message formats a credential, a DN or an identifier.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_auth::service::{RepositoryDirectoryAuditSink, account_may_act};
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryKind, GroupMapping, NewDirectoryConfig,
};
use axiam_core::models::directory_sync::{
    AUDIT_ACCOUNT_DEACTIVATED, AUDIT_ACCOUNT_REAPPEARED, AUDIT_ACCOUNT_UPDATED,
    AUDIT_GROUPS_MAPPED, AUDIT_SYNC_ATTRIBUTE_SKIPPED, AUDIT_SYNC_RUN, AUDIT_SYNC_SAFETY_VALVE,
    AUDIT_SYNC_USER_SKIPPED, DirectorySyncResult, DirectorySyncState,
};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::models::session::CreateSession;
use axiam_core::models::user::{CreateDirectoryAccount, CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, DirectoryConfigRepository, DirectorySyncStateRepository,
    GroupRepository, Pagination, RefreshTokenRepository, SessionRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealDirectoryConfigRepository,
    SurrealDirectorySyncStateRepository, SurrealGroupRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealUserRepository,
};
use axiam_directory::config::validate;
use axiam_directory::sync::{DirectorySync, RunKind, SyncError, SyncLimits, SyncSummary};
use axiam_directory::{
    ClientLimits, MembershipChangeSlot, RepositoryDirectoryAuthenticator, RepositoryGroupMapper,
};
use chrono::{Duration as Age, Utc};
use ldap3_proto::proto::{LdapFilter, LdapResultCode, LdapSearchScope};
use support::{
    BASE_DN, Entry, Event, GROUP_BASE_DN, SERVICE_DN, Script, TestServer, alice_password, group_dn,
    service_secret,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

const ALICE_UUID: &str = "00000000-0000-4000-8000-00000000a11c";
const BOB_UUID: &str = "00000000-0000-4000-8000-0000000000b0";
const CAROL_UUID: &str = "00000000-0000-4000-8000-00000000ca01";
const DAVE_UUID: &str = "00000000-0000-4000-8000-0000000da7e0";
const ALICE_DN: &str = "uid=alice,ou=people,dc=example,dc=com";

type ConfigRepo = SurrealDirectoryConfigRepository<Db>;
type Sync = DirectorySync<
    ConfigRepo,
    SurrealUserRepository<Db>,
    SurrealSessionRepository<Db>,
    SurrealRefreshTokenRepository<Db>,
    SurrealDirectorySyncStateRepository<Db>,
>;

fn directory_key() -> [u8; 32] {
    use std::sync::OnceLock;
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(|| {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes
    })
}

fn client_limits() -> ClientLimits {
    ClientLimits {
        acquire_timeout: Duration::from_millis(500),
        connect_timeout: Duration::from_secs(2),
        operation_timeout: Duration::from_secs(2),
        authentication_deadline: Duration::from_secs(8),
        ..ClientLimits::default()
    }
}

fn person(uid: &str, uuid: &str) -> Entry {
    Entry::person(uid, &alice_password(), uuid)
}

fn alice() -> Entry {
    person("alice", ALICE_UUID)
}

fn bob() -> Entry {
    person("bob", BOB_UUID)
}

struct Harness {
    tenant_id: Uuid,
    server: TestServer,
    users: SurrealUserRepository<Db>,
    groups: SurrealGroupRepository<Db>,
    audit: SurrealAuditLogRepository<Db>,
    sessions: SurrealSessionRepository<Db>,
    refresh: SurrealRefreshTokenRepository<Db>,
    states: SurrealDirectorySyncStateRepository<Db>,
    config_repo: ConfigRepo,
    sync: Sync,
    /// `(tenant, user)` for every decision-cache flush the mapper made.
    flushes: Arc<Mutex<Vec<(Uuid, Uuid)>>>,
    staff: Uuid,
    ops: Uuid,
}

struct Setup {
    kind: DirectoryKind,
    script: Script,
    /// Map the directory group `staff` onto the AXIAM group of the same name.
    mapped: bool,
    depth: u8,
    limits: SyncLimits,
}

impl Setup {
    fn open_ldap(entries: Vec<Entry>) -> Self {
        Self {
            kind: DirectoryKind::OpenLdap,
            script: Script {
                entries,
                enforce_sizelimit: true,
                ..Script::default()
            },
            mapped: false,
            depth: 5,
            limits: SyncLimits::default(),
        }
    }

    fn active_directory(entries: Vec<Entry>) -> Self {
        Self {
            kind: DirectoryKind::ActiveDirectory,
            ..Self::open_ldap(entries)
        }
    }
}

async fn build(setup: Setup) -> Harness {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let tenant_id = Uuid::new_v4();
    let server = TestServer::start(setup.script).await;

    let users = SurrealUserRepository::new(db.clone());
    let groups = SurrealGroupRepository::new(db.clone());
    let audit = SurrealAuditLogRepository::new(db.clone());
    let sessions = SurrealSessionRepository::new(db.clone());
    let refresh = SurrealRefreshTokenRepository::new(db.clone());
    let states = SurrealDirectorySyncStateRepository::new(db.clone());
    let config_repo = SurrealDirectoryConfigRepository::new(db.clone(), Some(directory_key()));

    let group = |name: &'static str| {
        let groups = groups.clone();
        async move {
            groups
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
    };
    let staff = group("ax-staff").await;
    let ops = group("ax-ops").await;

    let kind = setup.kind;
    let reverse = kind == DirectoryKind::OpenLdap;
    let input = NewDirectoryConfig {
        tenant_id,
        enabled: true,
        kind,
        url: format!("ldaps://localhost:{}", server.port()),
        start_tls: false,
        bind_dn: SERVICE_DN.into(),
        bind_secret: Some(Zeroizing::new(service_secret())),
        base_dn: BASE_DN.into(),
        user_filter: match kind {
            DirectoryKind::OpenLdap => "(uid={username})".into(),
            DirectoryKind::ActiveDirectory => "(sAMAccountName={username})".into(),
        },
        user_attribute_map: kind.default_user_attribute_map(),
        group_base_dn: reverse.then(|| GROUP_BASE_DN.to_string()),
        group_filter: reverse.then(|| "(objectClass=groupOfNames)".to_string()),
        group_member_attribute: kind.default_group_member_attribute().into(),
        group_nesting_depth: setup.depth,
        group_mappings: if setup.mapped {
            vec![GroupMapping {
                directory_group_dn: group_dn("staff"),
                group_id: staff,
            }]
        } else {
            vec![]
        },
        sync_interval_secs: 3600,
        jit_provisioning: true,
        trust_anchors_pem: vec![server.ca.pem.clone()],
    };
    validate(&input).expect("the fixture configuration must be acceptable");
    config_repo.create(input).await.unwrap();

    let authenticator = Arc::new(RepositoryDirectoryAuthenticator::with_client(
        config_repo.clone(),
        Arc::new(support::loopback_client(client_limits())),
    ));
    let flushes = Arc::new(Mutex::new(Vec::new()));
    let slot = MembershipChangeSlot::new();
    {
        let flushes = Arc::clone(&flushes);
        slot.set(Arc::new(move |tenant, user| {
            let flushes = Arc::clone(&flushes);
            Box::pin(async move {
                flushes.lock().unwrap().push((tenant, user));
            })
        }));
    }
    let mapper = RepositoryGroupMapper::new(Arc::clone(&authenticator), groups.clone())
        .with_change_slot(slot);
    let sync = DirectorySync::new(
        config_repo.clone(),
        authenticator,
        users.clone(),
        sessions.clone(),
        refresh.clone(),
        states.clone(),
        Arc::new(mapper),
        Arc::new(RepositoryDirectoryAuditSink(audit.clone())),
    )
    .with_limits(setup.limits);

    Harness {
        tenant_id,
        server,
        users,
        groups,
        audit,
        sessions,
        refresh,
        states,
        config_repo,
        sync,
        flushes,
        staff,
        ops,
    }
}

impl Harness {
    /// A directory account for `name`, marked with `external_id`, whose
    /// attributes already equal what the fixture entry carries — so a run that
    /// finds nothing to change writes nothing.
    async fn account(&self, name: &str, external_id: &str) -> Uuid {
        self.users
            .create_directory_account(CreateDirectoryAccount {
                tenant_id: self.tenant_id,
                username: name.into(),
                email: format!("{name}@example.com"),
                external_id: external_id.into(),
                metadata: serde_json::json!({ "oidc": { "name": format!("Test {name}") } }),
            })
            .await
            .unwrap()
            .id
    }

    async fn local_account(&self, name: &str) -> User {
        self.users
            .create(CreateUser {
                tenant_id: self.tenant_id,
                username: name.into(),
                email: format!("{name}@example.com"),
                password: format!("Lp1!{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap()
    }

    async fn user(&self, id: Uuid) -> User {
        self.users.get_by_id(self.tenant_id, id).await.unwrap()
    }

    async fn status(&self, id: Uuid) -> UserStatus {
        self.user(id).await.status
    }

    async fn set_status(&self, id: Uuid, status: UserStatus) {
        self.users
            .update(
                self.tenant_id,
                id,
                UpdateUser {
                    status: Some(status),
                    ..UpdateUser::default()
                },
            )
            .await
            .unwrap();
    }

    async fn rows(&self, action: &str) -> Vec<AuditLogEntry> {
        self.audit
            .list(
                self.tenant_id,
                AuditLogFilter {
                    action: Some(action.to_string()),
                    ..Default::default()
                },
                Pagination {
                    offset: 0,
                    limit: 200,
                    search: None,
                },
            )
            .await
            .unwrap()
            .items
    }

    async fn rows_for(&self, action: &str, user_id: Uuid) -> Vec<AuditLogEntry> {
        self.rows(action)
            .await
            .into_iter()
            .filter(|row| row.resource_id == Some(user_id))
            .collect()
    }

    async fn state(&self) -> DirectorySyncState {
        self.states
            .get(self.tenant_id)
            .await
            .unwrap()
            .expect("a state row")
    }

    /// Make the tenant due again: pretend the last attempt was two hours ago.
    async fn age(&self) {
        let mut state = self.state().await;
        state.last_attempt_at = Some(Utc::now() - Age::hours(2));
        self.states.save(&state).await.unwrap();
    }

    /// A state that makes the next run an incremental one from `watermark`.
    async fn resume_from(&self, watermark: &str, server_identity: Option<&str>) {
        let mut state = DirectorySyncState::new(self.tenant_id);
        state.watermark = Some(watermark.into());
        state.server_identity = server_identity.map(str::to_string);
        state.last_full_run_at = Some(Utc::now() - Age::hours(1));
        state.last_attempt_at = Some(Utc::now() - Age::hours(2));
        state.last_result = Some(DirectorySyncResult::Ok);
        self.states.save(&state).await.unwrap();
    }

    async fn run(&self) -> SyncSummary {
        self.sync.run_due().await.unwrap()
    }

    /// The one completed report of a one-tenant pass.
    async fn run_one(&self) -> axiam_directory::TenantReport {
        let mut summary = self.run().await;
        assert!(
            summary.failures.is_empty(),
            "the run was expected to complete"
        );
        assert_eq!(summary.reports.len(), 1);
        summary.reports.remove(0)
    }

    fn searches_since(&self, before: usize) -> Vec<(String, LdapSearchScope, LdapFilter)> {
        self.server
            .events()
            .into_iter()
            .skip(before)
            .filter_map(|event| match event {
                Event::Search {
                    base,
                    scope,
                    filter,
                    ..
                } => Some((base, scope, filter)),
                _ => None,
            })
            .collect()
    }

    fn event_count(&self) -> usize {
        self.server.events().len()
    }

    async fn live_session(&self, user_id: Uuid) -> (Uuid, String) {
        let token_hash = Uuid::new_v4().to_string();
        let id = self
            .sessions
            .create(CreateSession {
                tenant_id: self.tenant_id,
                user_id,
                token_hash: token_hash.clone(),
                ip_address: None,
                user_agent: None,
                expires_at: Utc::now() + Age::hours(1),
                authenticated_at: Utc::now(),
                amr: vec![],
                browser_token_hash: None,
            })
            .await
            .unwrap()
            .id;
        (id, token_hash)
    }

    async fn live_refresh_token(&self, user_id: Uuid) -> String {
        let hash = Uuid::new_v4().to_string();
        self.refresh
            .create(CreateRefreshToken {
                tenant_id: self.tenant_id,
                token_hash: hash.clone(),
                client_id: "test-client".into(),
                user_id: Some(user_id),
                scopes: vec![],
                session_id: None,
                requested_userinfo_claims: Vec::new(),
                resource: None,
                auth_time: None,
                acr: None,
                amr: Vec::new(),
                expires_at: Utc::now() + Age::days(30),
            })
            .await
            .unwrap();
        hash
    }

    async fn group_ids(&self, user_id: Uuid) -> BTreeSet<Uuid> {
        self.groups
            .get_user_groups(self.tenant_id, user_id)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect()
    }

    async fn marked_count(&self) -> usize {
        self.users
            .list_directory_accounts(self.tenant_id, None, 10_000)
            .await
            .unwrap()
            .len()
    }
}

fn ad_guid(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn ad_marker(guid: [u8; 16]) -> String {
    Uuid::from_bytes_le(guid).hyphenated().to_string()
}

fn eq(attr: &str, value: &str) -> LdapFilter {
    LdapFilter::Equality(attr.into(), value.into())
}

fn is_ge(filter: &LdapFilter, attribute: &str) -> bool {
    matches!(filter, LdapFilter::GreaterOrEqual(attr, _) if attr == attribute)
}

fn is_lookup(filter: &LdapFilter, attribute: &str) -> bool {
    matches!(filter, LdapFilter::Equality(attr, _) if attr.eq_ignore_ascii_case(attribute))
}

// ---------------------------------------------------------------------------
// A vanished entry
// ---------------------------------------------------------------------------

/// The whole of D-31 for a vanished entry, in one place: the account is
/// `Inactive` (not `Deleted`, the row and marker kept), the account may not act
/// on any session-to-principal path, sessions and refresh tokens are gone, the
/// directory membership is removed and the manual one is not, the decision cache
/// was flushed, and the audit row names the reason without naming a person.
#[tokio::test]
async fn a_vanished_entry_deactivates_the_account_and_takes_back_what_the_directory_gave() {
    let mut setup = Setup::open_ldap(vec![bob()]);
    setup.mapped = true;
    let h = build(setup).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let bob_id = h.account("bob", BOB_UUID).await;

    // What alice holds: a directory-sourced membership, a manual one, a
    // session and an OAuth2 refresh token.
    h.groups
        .add_directory_member(h.tenant_id, alice_id, h.staff)
        .await
        .unwrap();
    h.groups
        .add_member(h.tenant_id, alice_id, h.ops)
        .await
        .unwrap();
    let (session_id, _) = h.live_session(alice_id).await;
    let refresh_hash = h.live_refresh_token(alice_id).await;
    let (bob_session, _) = h.live_session(bob_id).await;
    assert!(account_may_act(&h.user(alice_id).await).is_ok());

    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Full);
    assert_eq!(report.deactivated_vanished, 1);
    assert_eq!(report.deactivated_disabled, 0);

    // Inactive, never Deleted; the row and its marker stay.
    let after = h.user(alice_id).await;
    assert_eq!(after.status, UserStatus::Inactive);
    assert_eq!(after.directory_external_id.as_deref(), Some(ALICE_UUID));
    // The rule every session-to-principal path applies — passkeys and the OP
    // cookie included — now refuses her.
    assert!(account_may_act(&after).is_err());

    // Sessions and OAuth2 refresh tokens are gone.
    assert!(h.sessions.get_by_id(h.tenant_id, session_id).await.is_err());
    assert!(
        h.refresh
            .get_by_token_hash(h.tenant_id, &refresh_hash)
            .await
            .is_err()
    );

    // The directory-sourced membership is gone, the manual one stays, and the
    // decision cache was flushed for her.
    assert_eq!(h.group_ids(alice_id).await, BTreeSet::from([h.ops]));
    assert!(h.flushes.lock().unwrap().contains(&(h.tenant_id, alice_id)));

    // Bob is in the directory and is untouched, session and all.
    assert_eq!(h.status(bob_id).await, UserStatus::Active);
    assert!(h.sessions.get_by_id(h.tenant_id, bob_session).await.is_ok());

    // One row, success, with the reason and counts and no name.
    let rows = h.rows_for(AUDIT_ACCOUNT_DEACTIVATED, alice_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["reason"], "vanished");
    assert_eq!(rows[0].metadata["run"], "full");
    assert_eq!(rows[0].metadata["directory_memberships_removed"], 1);
    let text = rows[0].metadata.to_string();
    for forbidden in ["alice", "example.com", "uid="] {
        assert!(!text.contains(forbidden), "the row must name no person");
    }
    assert!(
        h.rows_for(AUDIT_ACCOUNT_DEACTIVATED, bob_id)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_second_run_changes_and_audits_nothing_more() {
    let h = build(Setup::open_ldap(vec![bob()])).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    h.account("bob", BOB_UUID).await;
    h.run_one().await;
    assert_eq!(h.status(alice_id).await, UserStatus::Inactive);

    h.age().await;
    let report = h.run_one().await;
    assert_eq!(report.changed(), 0);
    assert_eq!(h.rows(AUDIT_ACCOUNT_DEACTIVATED).await.len(), 1);
}

/// A pending-verification and a locked directory account are deactivated too:
/// the directory's word is about the person, whatever AXIAM thought of the
/// account's state.
#[tokio::test]
async fn pending_and_locked_accounts_are_deactivated_when_their_entry_vanishes() {
    let h = build(Setup::open_ldap(vec![])).await;
    let pending = h.account("pending", ALICE_UUID).await;
    let locked = h.account("locked", BOB_UUID).await;
    h.set_status(pending, UserStatus::PendingVerification).await;
    h.set_status(locked, UserStatus::Locked).await;

    let report = h.run_one().await;
    assert_eq!(report.deactivated_vanished, 2);
    assert_eq!(h.status(pending).await, UserStatus::Inactive);
    assert_eq!(h.status(locked).await, UserStatus::Inactive);
}

// ---------------------------------------------------------------------------
// A disabled entry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_open_ldap_locked_time_deactivates_the_account_the_same_way() {
    let mut setup = Setup::open_ldap(vec![
        alice().with_values("pwdAccountLockedTime", &["000001010000Z"]),
        bob(),
    ]);
    setup.mapped = true;
    let h = build(setup).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let bob_id = h.account("bob", BOB_UUID).await;
    h.groups
        .add_directory_member(h.tenant_id, alice_id, h.staff)
        .await
        .unwrap();
    h.groups
        .add_member(h.tenant_id, alice_id, h.ops)
        .await
        .unwrap();
    let (session_id, _) = h.live_session(alice_id).await;
    let refresh_hash = h.live_refresh_token(alice_id).await;

    let report = h.run_one().await;
    assert_eq!(report.deactivated_disabled, 1);
    assert_eq!(report.deactivated_vanished, 0);

    let after = h.user(alice_id).await;
    assert_eq!(after.status, UserStatus::Inactive);
    assert!(account_may_act(&after).is_err());
    assert!(h.sessions.get_by_id(h.tenant_id, session_id).await.is_err());
    assert!(
        h.refresh
            .get_by_token_hash(h.tenant_id, &refresh_hash)
            .await
            .is_err()
    );
    assert_eq!(h.group_ids(alice_id).await, BTreeSet::from([h.ops]));
    let rows = h.rows_for(AUDIT_ACCOUNT_DEACTIVATED, alice_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["reason"], "disabled");
    assert_eq!(h.status(bob_id).await, UserStatus::Active);
}

#[tokio::test]
async fn an_active_directory_account_with_the_disabled_bit_is_deactivated() {
    let h = build(Setup::active_directory(vec![
        Entry::ad_person("alice", &alice_password(), ad_guid(0x11), 5)
            .with_values("userAccountControl", &["514"]),
        Entry::ad_person("bob", &alice_password(), ad_guid(0x22), 6)
            // Bit 0x2 clear (a normal account with "password never expires").
            .with_values("userAccountControl", &["66048"]),
    ]))
    .await;
    let alice_id = h.account("alice", &ad_marker(ad_guid(0x11))).await;
    let bob_id = h.account("bob", &ad_marker(ad_guid(0x22))).await;
    let (session_id, _) = h.live_session(alice_id).await;
    h.server.set_root_dse(&[
        ("highestCommittedUSN", "100"),
        ("dsServiceName", "CN=NTDS Settings,CN=DC1"),
    ]);

    let report = h.run_one().await;
    assert_eq!(report.deactivated_disabled, 1);
    assert_eq!(h.status(alice_id).await, UserStatus::Inactive);
    assert!(account_may_act(&h.user(alice_id).await).is_err());
    assert!(h.sessions.get_by_id(h.tenant_id, session_id).await.is_err());
    assert_eq!(h.status(bob_id).await, UserStatus::Active);
    assert_eq!(
        h.rows_for(AUDIT_ACCOUNT_DEACTIVATED, alice_id).await[0].metadata["reason"],
        "disabled"
    );
}

/// An attribute that cannot be read is not a statement that the account is
/// disabled: an AD entry with no `userAccountControl` keeps its account active.
#[tokio::test]
async fn an_unreadable_disabled_attribute_never_deactivates() {
    let h = build(Setup::active_directory(vec![
        Entry::ad_person("alice", &alice_password(), ad_guid(0x11), 5)
            .without("userAccountControl"),
    ]))
    .await;
    let alice_id = h.account("alice", &ad_marker(ad_guid(0x11))).await;
    h.run_one().await;
    assert_eq!(h.status(alice_id).await, UserStatus::Active);
}

// ---------------------------------------------------------------------------
// Nothing re-enables
// ---------------------------------------------------------------------------

/// The entry comes back; the account does not. It is reported — once.
#[tokio::test]
async fn a_reappearing_entry_leaves_the_account_inactive_and_says_so_once() {
    let h = build(Setup::open_ldap(vec![])).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    h.run_one().await;
    assert_eq!(h.status(alice_id).await, UserStatus::Inactive);

    // The directory gets her back, enabled.
    h.server.set_entries(vec![alice()]);
    h.age().await;
    let report = h.run_one().await;
    assert_eq!(report.reappeared_reported, 1);
    assert_eq!(
        h.status(alice_id).await,
        UserStatus::Inactive,
        "never re-enabled"
    );
    let rows = h.rows_for(AUDIT_ACCOUNT_REAPPEARED, alice_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["action"], "administrator action required");

    // Reported once, not nightly.
    h.age().await;
    let again = h.run_one().await;
    assert_eq!(again.reappeared_reported, 0);
    assert_eq!(
        h.rows_for(AUDIT_ACCOUNT_REAPPEARED, alice_id).await.len(),
        1
    );
    assert_eq!(h.status(alice_id).await, UserStatus::Inactive);
    assert!(account_may_act(&h.user(alice_id).await).is_err());
    assert!(h.state().await.reported_user_ids.contains(&alice_id));
}

/// An administrator suspended the account; the directory says it is fine. The
/// job neither re-enables it nor stays quiet about it.
#[tokio::test]
async fn an_account_an_administrator_made_inactive_is_reported_never_reactivated() {
    let h = build(Setup::open_ldap(vec![alice()])).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    h.set_status(alice_id, UserStatus::Inactive).await;

    let report = h.run_one().await;
    assert_eq!(report.reappeared_reported, 1);
    assert_eq!(report.changed(), 0);
    assert_eq!(h.status(alice_id).await, UserStatus::Inactive);
}

/// Once the directory disables the entry again the account no longer waits on
/// anyone, so the report is retired and would be written again if it came back.
#[tokio::test]
async fn a_report_is_retired_when_the_entry_goes_again() {
    let h = build(Setup::open_ldap(vec![alice()])).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    h.set_status(alice_id, UserStatus::Inactive).await;
    h.run_one().await;
    assert!(h.state().await.reported_user_ids.contains(&alice_id));

    h.server.set_entries(vec![]);
    h.age().await;
    h.run_one().await;
    assert!(!h.state().await.reported_user_ids.contains(&alice_id));

    h.server.set_entries(vec![alice()]);
    h.age().await;
    h.run_one().await;
    assert_eq!(
        h.rows_for(AUDIT_ACCOUNT_REAPPEARED, alice_id).await.len(),
        2
    );
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn changed_attributes_are_applied_through_the_cleaners() {
    let h = build(Setup::open_ldap(vec![
        alice()
            .with_values("uid", &["alice.renamed"])
            .with_values("mail", &["alice.renamed@example.com"])
            .with_values("displayName", &["  Alice \u{202E} Renamed  "]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;

    let report = h.run_one().await;
    assert_eq!(report.attributes_updated, 1);
    let after = h.user(alice_id).await;
    assert_eq!(after.username, "alice.renamed");
    assert_eq!(after.email, "alice.renamed@example.com");
    assert_eq!(after.metadata["oidc"]["name"], "Alice Renamed");
    assert_eq!(after.status, UserStatus::Active);
    assert_eq!(after.directory_external_id.as_deref(), Some(ALICE_UUID));

    let rows = h.rows_for(AUDIT_ACCOUNT_UPDATED, alice_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].metadata["fields"],
        serde_json::json!(["username", "email", "display_name"])
    );
    // The row names the fields, never a value.
    assert!(!rows[0].metadata.to_string().contains("renamed"));
}

#[tokio::test]
async fn a_value_that_cannot_be_cleaned_leaves_the_account_alone() {
    let h = build(Setup::open_ldap(vec![
        alice()
            .with_values("mail", &["not an address"])
            .with_values("uid", &["ali ce"]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let report = h.run_one().await;
    assert_eq!(report.attributes_updated, 0);
    let after = h.user(alice_id).await;
    assert_eq!(after.username, "alice");
    assert_eq!(after.email, "alice@example.com");
}

/// A rename that would take another account's name is skipped and audited; the
/// change that does not collide is still applied.
#[tokio::test]
async fn a_colliding_change_is_skipped_and_audited_and_the_rest_is_applied() {
    let h = build(Setup::open_ldap(vec![
        alice()
            .with_values("mail", &["carol@example.com"])
            .with_values("uid", &["dave"])
            .with_values("displayName", &["Alice Changed"]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let carol = h.local_account("carol").await;
    let dave = h.local_account("dave").await;

    let report = h.run_one().await;
    assert_eq!(report.attributes_skipped, 2);
    assert_eq!(report.attributes_updated, 1);

    let after = h.user(alice_id).await;
    assert_eq!(after.username, "alice", "dave's name was not taken");
    assert_eq!(
        after.email, "alice@example.com",
        "carol's address was not taken"
    );
    assert_eq!(after.metadata["oidc"]["name"], "Alice Changed");

    let skipped = h.rows_for(AUDIT_SYNC_ATTRIBUTE_SKIPPED, alice_id).await;
    assert_eq!(skipped.len(), 2);
    let mut by_attribute: Vec<(String, String)> = skipped
        .iter()
        .map(|row| {
            (
                row.metadata["attribute"].as_str().unwrap().to_string(),
                row.metadata["existing_user_id"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    by_attribute.sort();
    assert_eq!(
        by_attribute,
        vec![
            ("email".to_string(), carol.id.to_string()),
            ("username".to_string(), dave.id.to_string()),
        ]
    );
    // The local accounts are exactly as they were.
    assert_eq!(h.user(carol.id).await.email, "carol@example.com");
    assert_eq!(h.user(dave.id).await.username, "dave");
}

/// A name that differs from the account's only in case is the account's own, not
/// a collision with anyone.
#[tokio::test]
async fn a_case_only_change_to_ones_own_name_is_applied() {
    let h = build(Setup::open_ldap(vec![
        alice().with_values("uid", &["Alice"]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let report = h.run_one().await;
    assert_eq!(report.attributes_skipped, 0);
    assert_eq!(h.user(alice_id).await.username, "Alice");
}

// ---------------------------------------------------------------------------
// Group mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_group_mapping_follows_the_directory_on_every_run() {
    let mut setup = Setup::open_ldap(vec![alice(), Entry::group("staff", &[ALICE_DN])]);
    setup.mapped = true;
    let h = build(setup).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    h.groups
        .add_member(h.tenant_id, alice_id, h.ops)
        .await
        .unwrap();

    let report = h.run_one().await;
    assert_eq!(report.memberships_changed, 1);
    assert_eq!(
        h.group_ids(alice_id).await,
        BTreeSet::from([h.staff, h.ops])
    );
    let rows = h.rows_for(AUDIT_GROUPS_MAPPED, alice_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["source"], "sync");
    assert!(h.flushes.lock().unwrap().contains(&(h.tenant_id, alice_id)));

    // The directory takes her out of `staff`: the next run takes the
    // directory-sourced membership away and leaves the manual one.
    h.server
        .set_entries(vec![alice(), Entry::group("staff", &[])]);
    h.age().await;
    let report = h.run_one().await;
    assert_eq!(report.memberships_changed, 1);
    assert_eq!(h.group_ids(alice_id).await, BTreeSet::from([h.ops]));
}

/// One user's mapping failing skips that user — and only that user: their
/// attributes are not touched either, and the run is reported as partial with a
/// full run owed.
#[tokio::test]
async fn a_failed_mapping_skips_that_user_only() {
    let mut setup = Setup::open_ldap(vec![
        alice().with_values("displayName", &["Alice Changed"]),
        bob().with_values("displayName", &["Bob Changed"]),
        Entry::group("staff", &[]),
    ]);
    setup.mapped = true;
    setup.depth = 0;
    // Alice's group lookup fails, however often it is retried; Bob's works.
    setup.script.fail_group_searches_matching = Some("uid=alice".into());
    let h = build(setup).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let bob_id = h.account("bob", BOB_UUID).await;

    let mut summary = h.run().await;
    assert!(summary.failures.is_empty());
    let report = summary.reports.remove(0);
    assert_eq!(report.accounts_skipped, 1);
    assert_eq!(report.attributes_updated, 1);

    // Alice was skipped entirely — her attributes too; Bob was refreshed.
    assert_eq!(
        h.user(alice_id).await.metadata["oidc"]["name"],
        "Test alice"
    );
    assert_eq!(h.user(bob_id).await.metadata["oidc"]["name"], "Bob Changed");
    assert_eq!(h.status(alice_id).await, UserStatus::Active);

    let skipped = h.rows(AUDIT_SYNC_USER_SKIPPED).await;
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].resource_id, Some(alice_id));
    assert_eq!(skipped[0].metadata["reason"], "group_mapping_not_applied");

    let state = h.state().await;
    assert_eq!(state.last_result, Some(DirectorySyncResult::Partial));
    assert!(
        state.full_required,
        "the skipped account is owed a full run"
    );
}

// ---------------------------------------------------------------------------
// The incremental run
// ---------------------------------------------------------------------------

/// Only an entry changed at or after the watermark **and** owned by a marked
/// account is acted on. Carol's entry is older than the watermark, so her stale
/// account is left alone; Bob's entry changed but no account is marked with it,
/// so nothing is created, linked or marked; the watermark moves to the newest
/// timestamp read.
#[tokio::test]
async fn an_incremental_run_picks_up_a_change_and_ignores_entries_nobody_owns() {
    let h = build(Setup::open_ldap(vec![
        alice()
            .with_values("mail", &["alice.new@example.com"])
            .with_values("modifyTimestamp", &["20261003130000Z"]),
        bob().with_values("modifyTimestamp", &["20261003130500Z"]),
        person("carol", CAROL_UUID)
            .with_values("mail", &["carol.new@example.com"])
            .with_values("modifyTimestamp", &["20261003100000Z"]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let carol_id = h.account("carol", CAROL_UUID).await;
    let marked_before = h.marked_count().await;
    h.resume_from("20261003120000Z", None).await;

    let before = h.event_count();
    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Incremental);
    assert!(!report.fell_back_to_full);
    assert_eq!(report.accounts_examined, 1, "only alice's entry is owned");

    assert_eq!(h.user(alice_id).await.email, "alice.new@example.com");
    assert_eq!(
        h.user(carol_id).await.email,
        "carol@example.com",
        "an entry older than the watermark is not looked at"
    );
    assert_eq!(
        h.marked_count().await,
        marked_before,
        "nothing is created or linked"
    );
    assert!(
        h.users
            .get_by_directory_external_id(h.tenant_id, BOB_UUID)
            .await
            .unwrap()
            .is_none()
    );
    assert!(h.users.get_by_username(h.tenant_id, "bob").await.is_err());

    // One search, the `>=` filter on the stored watermark, under the base.
    let sent = h.searches_since(before);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].0.eq_ignore_ascii_case(BASE_DN));
    assert_eq!(sent[0].1, LdapSearchScope::Subtree);
    assert_eq!(
        sent[0].2,
        LdapFilter::GreaterOrEqual("modifyTimestamp".into(), "20261003120000Z".into())
    );

    // Every entry read moves the watermark, owned or not.
    let state = h.state().await;
    assert_eq!(state.watermark.as_deref(), Some("20261003130500Z"));
    assert!(!state.full_required);
    assert_eq!(state.last_result, Some(DirectorySyncResult::Ok));
}

/// Deletions are invisible to an incremental search: an account whose entry is
/// gone is **not** deactivated by it. That is the full run's conclusion alone.
#[tokio::test]
async fn an_incremental_run_never_concludes_that_an_entry_vanished() {
    let h = build(Setup::open_ldap(vec![
        bob().with_values("modifyTimestamp", &["20261003130000Z"]),
    ]))
    .await;
    let gone = h.account("alice", ALICE_UUID).await;
    h.account("bob", BOB_UUID).await;
    h.resume_from("20261003120000Z", None).await;

    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Incremental);
    assert_eq!(report.deactivated_vanished, 0);
    assert_eq!(h.status(gone).await, UserStatus::Active);
    assert!(h.rows(AUDIT_ACCOUNT_DEACTIVATED).await.is_empty());
}

/// A disabled entry is a positive statement by the directory, so an incremental
/// run acts on it.
#[tokio::test]
async fn an_incremental_run_deactivates_an_entry_the_directory_disabled() {
    let h = build(Setup::open_ldap(vec![
        alice()
            .with_values("pwdAccountLockedTime", &["000001010000Z"])
            .with_values("modifyTimestamp", &["20261003130000Z"]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    h.resume_from("20261003120000Z", None).await;

    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Incremental);
    assert_eq!(report.deactivated_disabled, 1);
    assert_eq!(h.status(alice_id).await, UserStatus::Inactive);
    assert_eq!(
        h.rows_for(AUDIT_ACCOUNT_DEACTIVATED, alice_id).await[0].metadata["run"],
        "incremental"
    );
}

/// A timed lockout (ppolicy writes a generalized time after failed binds) is not
/// a disable, in the full run: an outsider can trigger one by guessing passwords
/// against the directory, and sync never re-enables.
#[tokio::test]
async fn a_temporary_lockout_leaves_the_account_active_in_a_full_run() {
    let recent = (Utc::now() - Age::minutes(3))
        .format("%Y%m%d%H%M%SZ")
        .to_string();
    let h = build(Setup::open_ldap(vec![
        alice().with_values("pwdAccountLockedTime", &["20200101000000Z"]),
        bob().with_values("pwdAccountLockedTime", &[&recent]),
        person("carol", CAROL_UUID).with_values("pwdAccountLockedTime", &["000001010000Z"]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let bob_id = h.account("bob", BOB_UUID).await;
    let carol_id = h.account("carol", CAROL_UUID).await;
    let (alice_session, _) = h.live_session(alice_id).await;
    let (bob_session, _) = h.live_session(bob_id).await;
    let alice_before = h.user(alice_id).await;
    let bob_before = h.user(bob_id).await;

    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Full);
    assert_eq!(report.deactivated_disabled, 1, "only the permanent lock");

    for (id, before, session) in [
        (alice_id, alice_before, alice_session),
        (bob_id, bob_before, bob_session),
    ] {
        let after = h.user(id).await;
        assert_eq!(after.status, UserStatus::Active);
        assert_eq!(after.updated_at, before.updated_at, "not even written");
        assert!(account_may_act(&after).is_ok());
        assert!(h.sessions.get_by_id(h.tenant_id, session).await.is_ok());
        assert!(h.rows_for(AUDIT_ACCOUNT_DEACTIVATED, id).await.is_empty());
    }
    assert_eq!(h.status(carol_id).await, UserStatus::Inactive);
}

/// The same distinction in the incremental run.
#[tokio::test]
async fn a_temporary_lockout_leaves_the_account_active_in_an_incremental_run() {
    let recent = (Utc::now() - Age::minutes(3))
        .format("%Y%m%d%H%M%SZ")
        .to_string();
    let h = build(Setup::open_ldap(vec![
        alice()
            .with_values("pwdAccountLockedTime", &["20200101000000Z"])
            .with_values("modifyTimestamp", &["20261003130000Z"]),
        bob()
            .with_values("pwdAccountLockedTime", &[&recent])
            .with_values("modifyTimestamp", &["20261003130000Z"]),
        person("carol", CAROL_UUID)
            .with_values("pwdAccountLockedTime", &["000001010000Z"])
            .with_values("modifyTimestamp", &["20261003130000Z"]),
    ]))
    .await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let bob_id = h.account("bob", BOB_UUID).await;
    let carol_id = h.account("carol", CAROL_UUID).await;
    h.resume_from("20261003120000Z", None).await;
    let alice_before = h.user(alice_id).await;
    let bob_before = h.user(bob_id).await;

    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Incremental);
    assert_eq!(report.deactivated_disabled, 1, "only the permanent lock");
    for (id, before) in [(alice_id, alice_before), (bob_id, bob_before)] {
        let after = h.user(id).await;
        assert_eq!(after.status, UserStatus::Active);
        assert_eq!(after.updated_at, before.updated_at);
        assert!(h.rows_for(AUDIT_ACCOUNT_DEACTIVATED, id).await.is_empty());
    }
    assert_eq!(h.status(carol_id).await, UserStatus::Inactive);
}

/// The bound: what was read is applied (each entry is a positive statement),
/// the watermark does not move, and the next run is a full one.
#[tokio::test]
async fn an_incremental_run_over_the_bound_applies_the_prefix_and_owes_a_full_run() {
    let entries: Vec<Entry> = [
        ("alice", ALICE_UUID),
        ("bob", BOB_UUID),
        ("carol", CAROL_UUID),
        ("dave", DAVE_UUID),
    ]
    .into_iter()
    .map(|(uid, uuid)| {
        person(uid, uuid)
            .with_values("mail", &[&format!("{uid}.new@example.com")])
            .with_values("modifyTimestamp", &["20261003130000Z"])
    })
    .collect();
    let mut setup = Setup::open_ldap(entries);
    setup.limits.max_changed_entries = 2;
    let h = build(setup).await;
    let mut ids = Vec::new();
    for (uid, uuid) in [
        ("alice", ALICE_UUID),
        ("bob", BOB_UUID),
        ("carol", CAROL_UUID),
        ("dave", DAVE_UUID),
    ] {
        ids.push(h.account(uid, uuid).await);
    }
    h.resume_from("20261003120000Z", None).await;

    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Incremental);
    assert!(report.bound_hit);
    assert_eq!(report.attributes_updated, 2, "the prefix was applied");

    let state = h.state().await;
    assert!(state.full_required);
    assert_eq!(
        state.watermark.as_deref(),
        Some("20261003120000Z"),
        "not advanced"
    );

    // The next due run is a full one, and it brings the other two up to date.
    h.age().await;
    let next = h.run_one().await;
    assert_eq!(next.run, RunKind::Full);
    assert_eq!(next.attributes_updated, 2);
    let state = h.state().await;
    assert!(!state.full_required);
    assert!(state.last_full_run_at.is_some());
}

// ---------------------------------------------------------------------------
// Active Directory: the watermark and the server
// ---------------------------------------------------------------------------

const DC1: &str = "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Site,CN=Sites";
const DC2: &str = "CN=NTDS Settings,CN=DC2,CN=Servers,CN=Site,CN=Sites";

async fn ad_harness() -> (Harness, Uuid, Uuid) {
    let h = build(Setup::active_directory(vec![
        Entry::ad_person("alice", &alice_password(), ad_guid(0x11), 10),
        Entry::ad_person("bob", &alice_password(), ad_guid(0x22), 20),
    ]))
    .await;
    h.server
        .set_root_dse(&[("highestCommittedUSN", "100"), ("dsServiceName", DC1)]);
    let alice_id = h.account("alice", &ad_marker(ad_guid(0x11))).await;
    let bob_id = h.account("bob", &ad_marker(ad_guid(0x22))).await;
    (h, alice_id, bob_id)
}

/// The full run stores `highestCommittedUSN` from the rootDSE (read before the
/// lookups) and the server's identity; the next run is incremental on `uSNChanged`
/// from that number, and the filter the server parsed says so.
#[tokio::test]
async fn the_active_directory_watermark_is_the_root_dse_usn_of_the_same_server() {
    let (h, alice_id, bob_id) = ad_harness().await;

    let before = h.event_count();
    let first = h.run_one().await;
    assert_eq!(first.run, RunKind::Full);
    let sent = h.searches_since(before);
    // The rootDSE is read first, then one lookup per account by objectGUID.
    assert_eq!(sent[0].0, "");
    assert_eq!(sent[0].1, LdapSearchScope::Base);
    assert_eq!(
        sent.iter()
            .filter(|s| is_lookup(&s.2, "objectGUID"))
            .count(),
        2
    );
    let state = h.state().await;
    assert_eq!(state.watermark.as_deref(), Some("100"));
    assert_eq!(state.server_identity.as_deref(), Some(DC1));
    assert!(state.last_full_run_at.is_some());

    // The directory changes alice (USN 150) and the server's mark moves on.
    h.server.set_entries(vec![
        Entry::ad_person("alice", &alice_password(), ad_guid(0x11), 150)
            .with_values("mail", &["alice.new@example.com"]),
        Entry::ad_person("bob", &alice_password(), ad_guid(0x22), 20),
    ]);
    h.server
        .set_root_dse(&[("highestCommittedUSN", "160"), ("dsServiceName", DC1)]);
    h.age().await;
    let before = h.event_count();
    let second = h.run_one().await;
    assert_eq!(second.run, RunKind::Incremental);
    assert!(!second.fell_back_to_full);
    let sent = h.searches_since(before);
    assert_eq!(sent.len(), 2, "the rootDSE and one changed-since search");
    assert_eq!(
        sent[1].2,
        LdapFilter::GreaterOrEqual("uSNChanged".into(), "100".into())
    );
    assert_eq!(h.user(alice_id).await.email, "alice.new@example.com");
    assert_eq!(h.user(bob_id).await.email, "bob@example.com");
    assert_eq!(h.state().await.watermark.as_deref(), Some("160"));
}

#[tokio::test]
async fn a_different_directory_server_falls_back_to_a_full_run() {
    let (h, alice_id, _) = ad_harness().await;
    h.run_one().await;

    // Another domain controller answers: its USNs are not ours.
    h.server
        .set_root_dse(&[("highestCommittedUSN", "7"), ("dsServiceName", DC2)]);
    h.server.set_entries(vec![
        Entry::ad_person("alice", &alice_password(), ad_guid(0x11), 3)
            .with_values("mail", &["alice.moved@example.com"]),
        Entry::ad_person("bob", &alice_password(), ad_guid(0x22), 4),
    ]);
    h.age().await;
    let before = h.event_count();
    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Full);
    assert!(report.fell_back_to_full);
    let sent = h.searches_since(before);
    assert!(sent.iter().all(|s| !is_ge(&s.2, "uSNChanged")));
    assert_eq!(
        sent.iter()
            .filter(|s| is_lookup(&s.2, "objectGUID"))
            .count(),
        2
    );
    // The full run caught the change an incremental search on a stale watermark
    // (100 against USN 3) would have missed, and re-anchored the state.
    assert_eq!(h.user(alice_id).await.email, "alice.moved@example.com");
    let state = h.state().await;
    assert_eq!(state.server_identity.as_deref(), Some(DC2));
    assert_eq!(state.watermark.as_deref(), Some("7"));
}

#[tokio::test]
async fn a_root_dse_without_a_usn_falls_back_to_a_full_run_and_keeps_doing_so() {
    let (h, _, _) = ad_harness().await;
    h.run_one().await;

    h.server.set_root_dse(&[("dsServiceName", DC1)]);
    h.age().await;
    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Full);
    assert!(report.fell_back_to_full);
    // Nothing usable was read, so nothing is stored to resume from.
    assert!(h.state().await.watermark.is_none());

    h.age().await;
    let again = h.run_one().await;
    assert_eq!(again.run, RunKind::Full);
}

/// A server that hides its rootDSE cannot give a watermark: the incremental run
/// is replaced by a full one rather than trusted.
#[tokio::test]
async fn an_unreadable_root_dse_falls_back_to_a_full_run() {
    let h = build(Setup::active_directory(vec![Entry::ad_person(
        "alice",
        &alice_password(),
        ad_guid(0x11),
        10,
    )]))
    .await;
    // `set_root_dse` is never called: the server answers noSuchObject.
    let alice_id = h.account("alice", &ad_marker(ad_guid(0x11))).await;
    h.resume_from("100", Some(DC1)).await;

    let report = h.run_one().await;
    assert_eq!(report.run, RunKind::Full);
    assert!(report.fell_back_to_full);
    assert_eq!(h.status(alice_id).await, UserStatus::Active);
    assert!(h.state().await.watermark.is_none());
}

/// `objectGUID` is binary. The lookup the engine sends carries the little-endian
/// octets of the account's stored identifier, every one escaped; the server
/// parses back exactly those octets, whatever filter syntax they resemble.
#[tokio::test]
async fn an_object_guid_lookup_reaches_the_server_as_little_endian_octets() {
    let hostile: [u8; 16] = [
        0x2a, 0x28, 0x29, 0x5c, 0x00, 0x41, 0x42, 0x43, 0x44, 0x2a, 0x29, 0x28, 0x5c, 0x5c, 0x00,
        0x7f,
    ];
    let h = build(Setup::active_directory(vec![
        Entry::ad_person("alice", &alice_password(), hostile, 10),
        Entry::ad_person("bob", &alice_password(), ad_guid(0x22), 20),
    ]))
    .await;
    h.server
        .set_root_dse(&[("highestCommittedUSN", "100"), ("dsServiceName", DC1)]);
    let alice_id = h.account("alice", &ad_marker(hostile)).await;

    let before = h.event_count();
    let report = h.run_one().await;
    assert_eq!(report.accounts_examined, 1);
    assert_eq!(
        h.status(alice_id).await,
        UserStatus::Active,
        "found, not vanished"
    );
    let expected: String = hostile.iter().map(|b| char::from(*b)).collect();
    let lookups: Vec<_> = h
        .searches_since(before)
        .into_iter()
        .filter(|s| is_lookup(&s.2, "objectGUID"))
        .collect();
    assert_eq!(lookups.len(), 1);
    assert_eq!(lookups[0].2, eq("objectGUID", &expected));
}

// ---------------------------------------------------------------------------
// The safety valve
// ---------------------------------------------------------------------------

/// Ten accounts, six of them gone from the directory: 60 %, and more than five.
/// Nothing is applied — not the deactivations, not the refresh of the four that
/// are still there — and the failure is on the summary, the state and the audit
/// log, once.
#[tokio::test]
async fn the_valve_trips_and_applies_nothing() {
    let present: Vec<Entry> = (0..4)
        .map(|i| {
            person(
                &format!("p{i}"),
                &format!("00000000-0000-4000-8000-0000000000{i:02}"),
            )
            .with_values("displayName", &["Changed"])
        })
        .collect();
    let h = build(Setup::open_ldap(present)).await;
    let mut ids = Vec::new();
    for i in 0..4 {
        ids.push(
            h.account(
                &format!("p{i}"),
                &format!("00000000-0000-4000-8000-0000000000{i:02}"),
            )
            .await,
        );
    }
    for i in 0..6 {
        ids.push(
            h.account(
                &format!("gone{i}"),
                &format!("00000000-0000-4000-8000-0000000001{i:02}"),
            )
            .await,
        );
    }
    let (session_id, _) = h.live_session(ids[9]).await;

    let summary = h.run().await;
    assert!(summary.reports.is_empty());
    assert_eq!(summary.failures.len(), 1);
    assert!(matches!(
        summary.failures[0].1,
        SyncError::SafetyValve {
            would_deactivate: 6,
            directory_accounts: 10
        }
    ));
    assert_eq!(
        summary.failure_message().as_deref(),
        Some("directory sync failed for 1 of 1 tenants (safety_valve)")
    );

    // No change at all.
    for id in &ids {
        assert_eq!(h.status(*id).await, UserStatus::Active);
    }
    assert_eq!(h.user(ids[0]).await.metadata["oidc"]["name"], "Test p0");
    assert!(h.sessions.get_by_id(h.tenant_id, session_id).await.is_ok());
    assert!(h.rows(AUDIT_ACCOUNT_DEACTIVATED).await.is_empty());
    assert!(h.rows(AUDIT_ACCOUNT_UPDATED).await.is_empty());

    let rows = h.rows(AUDIT_SYNC_SAFETY_VALVE).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["would_deactivate"], 6);
    assert_eq!(rows[0].metadata["directory_accounts"], 10);
    assert_eq!(rows[0].metadata["applied"], "nothing");
    let state = h.state().await;
    assert_eq!(state.last_result, Some(DirectorySyncResult::SafetyValve));
    assert!(state.full_required);
    assert!(
        state.last_full_run_at.is_none(),
        "it was not a complete run"
    );

    // Still tripped on the next attempt, still no change, and the audit log
    // does not repeat itself.
    h.age().await;
    let again = h.run().await;
    assert_eq!(again.failures.len(), 1);
    assert_eq!(h.rows(AUDIT_SYNC_SAFETY_VALVE).await.len(), 1);
    for id in &ids {
        assert_eq!(h.status(*id).await, UserStatus::Active);
    }
}

/// The valve is for a mass disappearance, not a small one: four of ten is 40 %
/// but under the floor of five, so the run applies.
#[tokio::test]
async fn the_valve_does_not_trip_under_its_floor() {
    let h = build(Setup::open_ldap(vec![])).await;
    let mut ids = Vec::new();
    for i in 0..10 {
        ids.push(
            h.account(
                &format!("u{i}"),
                &format!("00000000-0000-4000-8000-0000000002{i:02}"),
            )
            .await,
        );
    }
    // The directory still has the last six.
    let still_there: Vec<Entry> = (4..10)
        .map(|i| {
            person(
                &format!("u{i}"),
                &format!("00000000-0000-4000-8000-0000000002{i:02}"),
            )
        })
        .collect();
    h.server.set_entries(still_there);

    let report = h.run_one().await;
    assert_eq!(report.deactivated_vanished, 4);
    for (i, id) in ids.iter().enumerate() {
        let expected = if i < 4 {
            UserStatus::Inactive
        } else {
            UserStatus::Active
        };
        assert_eq!(h.status(*id).await, expected);
    }
    assert!(h.rows(AUDIT_SYNC_SAFETY_VALVE).await.is_empty());
}

/// And not for a share at or under the percentage: with the floor lowered to
/// three and the share to 40 %, three of twelve is 25 %.
#[tokio::test]
async fn the_valve_does_not_trip_at_or_under_its_percentage() {
    let mut setup = Setup::open_ldap(vec![]);
    setup.limits.valve_percent = 40;
    setup.limits.valve_min_accounts = 3;
    let h = build(setup).await;
    let mut ids = Vec::new();
    for i in 0..12 {
        ids.push(
            h.account(
                &format!("u{i}"),
                &format!("00000000-0000-4000-8000-0000000003{i:02}"),
            )
            .await,
        );
    }
    h.server.set_entries(
        (3..12)
            .map(|i| {
                person(
                    &format!("u{i}"),
                    &format!("00000000-0000-4000-8000-0000000003{i:02}"),
                )
            })
            .collect(),
    );
    let report = h.run_one().await;
    assert_eq!(report.deactivated_vanished, 3);
    assert!(h.rows(AUDIT_SYNC_SAFETY_VALVE).await.is_empty());
}

/// An empty directory — an outage that answered, or a base DN pointed at
/// nothing — would be "every account vanished". The valve is what stands
/// between that and a disabled company.
#[tokio::test]
async fn an_empty_directory_does_not_disable_the_tenant() {
    let h = build(Setup::open_ldap(vec![])).await;
    let mut ids = Vec::new();
    for i in 0..8 {
        ids.push(
            h.account(
                &format!("u{i}"),
                &format!("00000000-0000-4000-8000-0000000004{i:02}"),
            )
            .await,
        );
    }
    let summary = h.run().await;
    assert!(matches!(
        summary.failures[0].1,
        SyncError::SafetyValve {
            would_deactivate: 8,
            directory_accounts: 8
        }
    ));
    for id in ids {
        assert_eq!(h.status(id).await, UserStatus::Active);
    }
}

// ---------------------------------------------------------------------------
// Errors change nothing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unreachable_directory_changes_nothing_and_is_a_reported_failure() {
    let h = build(Setup::open_ldap(vec![])).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let (session_id, _) = h.live_session(alice_id).await;
    // The directory goes away.
    let Harness {
        sync,
        users,
        sessions,
        states,
        tenant_id,
        server,
        ..
    } = h;
    drop(server);

    let summary = sync.run_due().await.unwrap();
    assert!(summary.reports.is_empty());
    assert_eq!(summary.failures.len(), 1);
    assert!(matches!(
        summary.failures[0].1,
        SyncError::Directory(DirectoryAuthError::Unavailable)
    ));
    assert_eq!(
        summary.failure_message().as_deref(),
        Some("directory sync failed for 1 of 1 tenants (directory_unavailable)")
    );

    // Nothing changed — an absent directory is not an empty one.
    let user = users.get_by_id(tenant_id, alice_id).await.unwrap();
    assert_eq!(user.status, UserStatus::Active);
    assert!(sessions.get_by_id(tenant_id, session_id).await.is_ok());
    let state = states.get(tenant_id).await.unwrap().unwrap();
    assert_eq!(state.last_result, Some(DirectorySyncResult::Failed));
    assert!(state.last_attempt_at.is_some());
    assert!(state.last_full_run_at.is_none());
}

/// The directory fails **part-way through the reads**. Two accounts, both gone
/// from it: the first lookup completes ("not found"), the second fails. Because
/// the run reads everything before it writes anything, the first is not
/// deactivated on its own.
#[tokio::test]
async fn a_failure_part_way_through_the_reads_applies_nothing() {
    let mut setup = Setup::open_ldap(vec![]);
    setup.script.fail_user_searches_from = Some(1);
    let h = build(setup).await;
    let a = h.account("alice", ALICE_UUID).await;
    let b = h.account("bob", BOB_UUID).await;

    let summary = h.run().await;
    assert_eq!(summary.failures.len(), 1);
    assert!(matches!(
        summary.failures[0].1,
        SyncError::Directory(DirectoryAuthError::Unavailable)
    ));
    assert_eq!(h.status(a).await, UserStatus::Active);
    assert_eq!(h.status(b).await, UserStatus::Active);
    assert!(h.rows(AUDIT_ACCOUNT_DEACTIVATED).await.is_empty());
}

/// A service account that may not search is a configuration fault, not an empty
/// directory.
#[tokio::test]
async fn a_service_account_without_read_rights_is_a_failure_not_a_vanishing() {
    let mut setup = Setup::open_ldap(vec![alice()]);
    setup.script.search_done = Some((LdapResultCode::InsufficentAccessRights, vec![]));
    let h = build(setup).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    let summary = h.run().await;
    assert!(matches!(
        summary.failures[0].1,
        SyncError::Directory(DirectoryAuthError::Misconfigured)
    ));
    assert_eq!(h.status(alice_id).await, UserStatus::Active);
}

/// Two entries with one identifier is a directory fault. The account is skipped,
/// not read as vanished, and the run is partial.
#[tokio::test]
async fn an_ambiguous_identifier_skips_the_account_and_is_not_a_vanishing() {
    let twin = Entry::person("alice-twin", &alice_password(), ALICE_UUID);
    let h = build(Setup::open_ldap(vec![alice(), twin, bob()])).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    h.account("bob", BOB_UUID).await;
    let mut summary = h.run().await;
    let report = summary.reports.remove(0);
    assert_eq!(report.accounts_skipped, 1);
    assert_eq!(h.status(alice_id).await, UserStatus::Active);
    let state = h.state().await;
    assert_eq!(state.last_result, Some(DirectorySyncResult::Partial));
    assert!(state.full_required);
}

/// An identifier that cannot be put in a filter is a question that was not
/// asked: the account is skipped and nothing is sent for it.
#[tokio::test]
async fn an_identifier_that_cannot_be_asked_for_is_skipped_not_vanished() {
    let h = build(Setup::active_directory(vec![])).await;
    h.server
        .set_root_dse(&[("highestCommittedUSN", "100"), ("dsServiceName", DC1)]);
    // An AD tenant whose marker is not a GUID (a row from another kind, say).
    let odd = h.account("odd", "not-a-guid").await;
    let before = h.event_count();
    let mut summary = h.run().await;
    let report = summary.reports.remove(0);
    assert_eq!(report.accounts_skipped, 1);
    assert_eq!(h.status(odd).await, UserStatus::Active);
    assert!(
        h.searches_since(before)
            .iter()
            .all(|s| !is_lookup(&s.2, "objectGUID")),
        "nothing was asked about it"
    );
}

// ---------------------------------------------------------------------------
// Which tenants, and which accounts
// ---------------------------------------------------------------------------

/// A tenant with no directory has no row to be listed by, and one whose
/// directory is disabled is not listed: neither costs a connection, a state row
/// or an audit row.
#[tokio::test]
async fn a_tenant_without_a_directory_or_with_it_disabled_is_skipped_without_a_connection() {
    let h = build(Setup::open_ldap(vec![])).await;
    let alice_id = h.account("alice", ALICE_UUID).await;
    // Disable the directory.
    let mut config = h
        .config_repo
        .get_by_tenant(h.tenant_id)
        .await
        .unwrap()
        .unwrap();
    config.enabled = false;
    h.config_repo
        .update(NewDirectoryConfig {
            tenant_id: config.tenant_id,
            enabled: false,
            kind: config.kind,
            url: config.url,
            start_tls: config.start_tls,
            bind_dn: config.bind_dn,
            bind_secret: None,
            base_dn: config.base_dn,
            user_filter: config.user_filter,
            user_attribute_map: config.user_attribute_map,
            group_base_dn: config.group_base_dn,
            group_filter: config.group_filter,
            group_member_attribute: config.group_member_attribute,
            group_nesting_depth: config.group_nesting_depth,
            group_mappings: config.group_mappings,
            sync_interval_secs: config.sync_interval_secs,
            jit_provisioning: config.jit_provisioning,
            trust_anchors_pem: config.trust_anchors_pem,
        })
        .await
        .unwrap();

    let summary = h.run().await;
    assert!(summary.reports.is_empty() && summary.failures.is_empty());
    assert_eq!(summary.not_due, 0);
    assert_eq!(h.server.connections(), 0);
    assert!(h.states.get(h.tenant_id).await.unwrap().is_none());
    assert_eq!(h.status(alice_id).await, UserStatus::Active);

    // And a deployment where no tenant has a directory at all.
    let none = build(Setup::open_ldap(vec![])).await;
    none.config_repo.delete(none.tenant_id).await.unwrap();
    let summary = none.run().await;
    assert!(summary.reports.is_empty() && summary.failures.is_empty());
    assert_eq!(none.server.connections(), 0);
}

#[tokio::test]
async fn a_tenant_that_is_not_yet_due_is_left_alone() {
    let h = build(Setup::open_ldap(vec![])).await;
    h.account("alice", ALICE_UUID).await;
    h.run_one().await;
    let connections = h.server.connections();

    let summary = h.run().await;
    assert_eq!(summary.not_due, 1);
    assert!(summary.reports.is_empty() && summary.failures.is_empty());
    assert_eq!(h.server.connections(), connections);
}

/// A local account is none of the job's business, whatever the directory says —
/// including when the directory holds an entry with the same address.
#[tokio::test]
async fn a_local_account_is_never_touched() {
    let h = build(Setup::open_ldap(vec![
        person("mallory", "00000000-0000-4000-8000-0000000000aa")
            .with_values("mail", &["local-admin@example.com"])
            .with_values("pwdAccountLockedTime", &["000001010000Z"]),
    ]))
    .await;
    let local = h.local_account("local-admin").await;
    let (session_id, _) = h.live_session(local.id).await;
    h.account("alice", ALICE_UUID).await;
    h.set_status(local.id, UserStatus::Active).await;
    let before = h.user(local.id).await;

    h.run_one().await;

    let after = h.user(local.id).await;
    assert_eq!(after.status, UserStatus::Active);
    assert_eq!(after.updated_at, before.updated_at, "not even written");
    assert_eq!(after.directory_external_id, None, "never linked");
    assert_eq!(after.password_hash, before.password_hash);
    assert!(h.sessions.get_by_id(h.tenant_id, session_id).await.is_ok());
}

/// Whatever the directory says, no row goes away and no account becomes
/// `Deleted`: the only status the job writes is `Inactive`.
#[tokio::test]
async fn no_row_is_removed_and_no_account_is_deleted() {
    let h = build(Setup::open_ldap(vec![
        alice().with_values("pwdAccountLockedTime", &["000001010000Z"]),
    ]))
    .await;
    let ids = vec![
        h.account("alice", ALICE_UUID).await,
        h.account("bob", BOB_UUID).await,
        h.account("carol", CAROL_UUID).await,
    ];
    let marked_before = h.marked_count().await;
    h.run_one().await;

    assert_eq!(h.marked_count().await, marked_before);
    for id in ids {
        let user = h.user(id).await;
        assert!(matches!(
            user.status,
            UserStatus::Inactive | UserStatus::Active
        ));
        assert!(user.directory_external_id.is_some(), "the marker stays");
    }
}

/// The run's own record: a full run writes one summary row with counts only.
#[tokio::test]
async fn a_full_run_writes_one_summary_row_of_counts() {
    let h = build(Setup::open_ldap(vec![alice()])).await;
    h.account("alice", ALICE_UUID).await;
    h.run_one().await;
    let rows = h.rows(AUDIT_SYNC_RUN).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["run"], "full");
    assert_eq!(rows[0].metadata["accounts_examined"], 1);
}
