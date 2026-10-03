//! Just-in-time provisioning and linking at the `AuthService` level
//! (G-3, T23.3.3, D-28), with a scripted `DirectoryAuthenticator` standing in
//! for the LDAP client and the real repositories underneath.
//!
//! What is pinned here is what the login path does around the directory:
//! the account it creates, the answer and the cost of every refusal (the same
//! as an unknown name's), the collisions it will not provision over, the race
//! between two first logins, and what linking an existing account retires.
//! The directory client, the escaping and the provisioning gate are pinned
//! against a live in-process directory in `axiam-directory`'s tests.
//!
//! Assertion messages name the case; none formats a credential, a result's
//! Debug output or an identifier.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axiam_auth::config::AuthConfig;
use axiam_auth::error::AuthError;
use axiam_auth::service::{
    AUDIT_ACCOUNT_LINKED, AUDIT_JIT_PROVISIONED, AUDIT_JIT_REFUSED, AuthService, LoginInput,
    LoginResult, RepositoryDirectoryAuditSink,
};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{AuditLogEntry, AuditOutcome};
use axiam_core::models::certificate::{CertificateStatus, CertificateType, KeyAlgorithm};
use axiam_core::models::directory::{
    DirectoryAccountRestriction, DirectoryAuthError, DirectoryAuthenticator, DirectoryFuture,
    DirectoryIdentity,
};
use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::models::opaque::{CreateOpaqueCredential, OpaqueKsf, OpaqueKsfParams, OpaqueSuite};
use axiam_core::models::session::Amr;
use axiam_core::models::settings::MfaPolicy;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::models::webauthn_credential::{CreateWebauthnCredential, WebauthnCredentialType};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, CertificateRepository, OpaqueCredentialRepository,
    Pagination, RefreshTokenRepository, SessionRepository, UserRepository,
    WebauthnCredentialRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealCertificateRepository, SurrealFederationLinkRepository,
    SurrealOpaqueCredentialRepository, SurrealRefreshTokenRepository, SurrealSessionRepository,
    SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use chrono::{Duration as ChronoDuration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key
const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

const ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";
const OTHER_ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964aa";

fn config(hash_acquire_timeout_secs: u64) -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: TEST_PRIVATE_KEY.into(),
        jwt_public_key_pem: TEST_PUBLIC_KEY.into(),
        jwt_issuer: "axiam-test".into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 3600,
        hash_acquire_timeout_secs,
        max_failed_login_attempts: 3,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        email_verification_grace_period_hours: 24,
        ..AuthConfig::default()
    }
}

// -----------------------------------------------------------------------
// The scripted directory
// -----------------------------------------------------------------------

enum Mode {
    /// The directory decides: the entry answers iff the credential matches.
    Directory,
    /// Every call fails as given.
    Fail(DirectoryAuthError),
}

struct StubDirectory {
    identity: DirectoryIdentity,
    /// What the directory holds for the entry. Generated, never a literal.
    credential: String,
    mode: Mutex<Mode>,
    lookup: Mutex<Result<DirectoryIdentity, DirectoryAuthError>>,
    sign_in_calls: AtomicUsize,
    provision_calls: AtomicUsize,
    lookup_calls: AtomicUsize,
    /// Both provisioning binds are held until both have arrived.
    rendezvous: Option<tokio::sync::Barrier>,
}

impl StubDirectory {
    fn new(identity: DirectoryIdentity, credential: String) -> Self {
        Self {
            lookup: Mutex::new(Ok(identity.clone())),
            identity,
            credential,
            mode: Mutex::new(Mode::Directory),
            sign_in_calls: AtomicUsize::new(0),
            provision_calls: AtomicUsize::new(0),
            lookup_calls: AtomicUsize::new(0),
            rendezvous: None,
        }
    }

    fn arc(identity: DirectoryIdentity, credential: &str) -> Arc<Self> {
        Arc::new(Self::new(identity, credential.to_string()))
    }

    fn failing(identity: DirectoryIdentity, failure: DirectoryAuthError) -> Arc<Self> {
        let stub = Self::new(identity, fresh_credential());
        *stub.mode.lock().unwrap() = Mode::Fail(failure);
        Arc::new(stub)
    }

    fn answer(&self, presented: &str) -> Result<DirectoryIdentity, DirectoryAuthError> {
        match &*self.mode.lock().unwrap() {
            Mode::Fail(failure) => Err(*failure),
            Mode::Directory if presented == self.credential => Ok(self.identity.clone()),
            Mode::Directory => Err(DirectoryAuthError::InvalidCredentials),
        }
    }

    fn provision_calls(&self) -> usize {
        self.provision_calls.load(Ordering::SeqCst)
    }
}

fn fresh_credential() -> String {
    axiam_test_support::other_password()
}

fn identity(external_id: &str, username: &str, email: &str) -> DirectoryIdentity {
    DirectoryIdentity {
        external_id: external_id.into(),
        dn: format!("uid={username},ou=people,dc=example,dc=com"),
        username: Some(username.into()),
        email: Some(email.into()),
        display_name: Some("Alice Example".into()),
    }
}

impl DirectoryAuthenticator for StubDirectory {
    fn authenticate<'a>(
        &'a self,
        _tenant_id: Uuid,
        _login_name: &'a str,
        presented: &'a str,
    ) -> DirectoryFuture<'a, Result<DirectoryIdentity, DirectoryAuthError>> {
        self.sign_in_calls.fetch_add(1, Ordering::SeqCst);
        let outcome = self.answer(presented);
        Box::pin(async move { outcome })
    }

    fn authenticate_for_provisioning<'a>(
        &'a self,
        _tenant_id: Uuid,
        _login_name: &'a str,
        presented: &'a str,
    ) -> DirectoryFuture<'a, Result<DirectoryIdentity, DirectoryAuthError>> {
        self.provision_calls.fetch_add(1, Ordering::SeqCst);
        let outcome = self.answer(presented);
        Box::pin(async move {
            if let Some(barrier) = &self.rendezvous {
                barrier.wait().await;
            }
            outcome
        })
    }

    fn lookup_entry<'a>(
        &'a self,
        _tenant_id: Uuid,
        _login_name: &'a str,
    ) -> DirectoryFuture<'a, Result<DirectoryIdentity, DirectoryAuthError>> {
        self.lookup_calls.fetch_add(1, Ordering::SeqCst);
        let outcome = self.lookup.lock().unwrap().clone();
        Box::pin(async move { outcome })
    }
}

// -----------------------------------------------------------------------
// The harness
// -----------------------------------------------------------------------

type Svc = AuthService<
    SurrealUserRepository<Db>,
    SurrealSessionRepository<Db>,
    SurrealFederationLinkRepository<Db>,
    SurrealRefreshTokenRepository<Db>,
>;

struct Harness {
    users: SurrealUserRepository<Db>,
    sessions: SurrealSessionRepository<Db>,
    refresh: SurrealRefreshTokenRepository<Db>,
    webauthn: SurrealWebauthnCredentialRepository<Db>,
    certificates: SurrealCertificateRepository<Db>,
    audit: SurrealAuditLogRepository<Db>,
    db: Surreal<Db>,
    tenant_id: Uuid,
    org_id: Uuid,
    /// A local account, `bob`, active, with a known password.
    local_user: Uuid,
    local_credential: String,
}

async fn harness() -> Harness {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let users = SurrealUserRepository::new(db.clone());
    let tenant_id = Uuid::new_v4();
    let local_credential = fresh_credential();
    let local_user = users
        .create(CreateUser {
            tenant_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: local_credential.clone(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    activate(&users, tenant_id, local_user).await;
    Harness {
        sessions: SurrealSessionRepository::new(db.clone()),
        refresh: SurrealRefreshTokenRepository::new(db.clone()),
        webauthn: SurrealWebauthnCredentialRepository::new(db.clone()),
        certificates: SurrealCertificateRepository::new(db.clone()),
        audit: SurrealAuditLogRepository::new(db.clone()),
        users,
        db,
        tenant_id,
        org_id: Uuid::new_v4(),
        local_user,
        local_credential,
    }
}

async fn activate(users: &SurrealUserRepository<Db>, tenant_id: Uuid, id: Uuid) {
    users
        .update(
            tenant_id,
            id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

fn service_with(
    h: &Harness,
    directory: Option<Arc<StubDirectory>>,
    hash_acquire_timeout_secs: u64,
    permits: usize,
) -> Svc {
    let svc = AuthService::new(
        h.users.clone(),
        h.sessions.clone(),
        SurrealFederationLinkRepository::new(h.db.clone()),
        SurrealRefreshTokenRepository::new(h.db.clone()),
        config(hash_acquire_timeout_secs),
        Arc::new(tokio::sync::Semaphore::new(permits)),
    )
    .with_directory_audit(Arc::new(RepositoryDirectoryAuditSink(h.audit.clone())));
    match directory {
        Some(directory) => svc.with_directory_authenticator(directory),
        None => svc,
    }
}

fn service(h: &Harness, directory: Option<Arc<StubDirectory>>) -> Svc {
    service_with(h, directory, 5, 4)
}

fn input(h: &Harness, login: &str, presented: &str) -> LoginInput {
    LoginInput {
        tenant_id: h.tenant_id,
        org_id: h.org_id,
        username_or_email: login.into(),
        password: presented.into(),
        ip_address: None,
        user_agent: None,
        mfa_policy: None,
        lockout_policy: None,
    }
}

fn is_invalid_credentials(outcome: &Result<LoginResult, AxiamError>) -> bool {
    matches!(
        outcome,
        Err(AxiamError::AuthenticationFailed { reason }) if reason == &AuthError::InvalidCredentials.to_string()
    )
}

async fn account_count(h: &Harness) -> u64 {
    h.users
        .list(
            h.tenant_id,
            Pagination {
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .await
        .unwrap()
        .total
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

/// A row never holds what was typed: the credential strings in play are
/// searched for in the rendered row.
fn row_mentions(row: &AuditLogEntry, needle: &str) -> bool {
    serde_json::to_string(&row.metadata)
        .unwrap()
        .contains(needle)
}

/// The cost of the plain unknown-user answer on this machine: the smallest of
/// three, so the bound below is a floor and not an average.
async fn unknown_user_cost(h: &Harness) -> Duration {
    let svc = service(h, None);
    let mut least = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        let outcome = svc.login(input(h, "nobody", &fresh_credential())).await;
        assert!(is_invalid_credentials(&outcome));
        least = least.min(started.elapsed());
    }
    least
}

// -----------------------------------------------------------------------
// Just-in-time provisioning
// -----------------------------------------------------------------------

/// The happy path: an unknown name with the directory's password creates the
/// account `Active`, marked with the entry's identifier, with the attributes
/// mapped, issues a session whose `amr` is `pwd`, and writes an audit row that
/// carries no credential.
#[tokio::test]
async fn a_first_login_creates_an_active_marked_account_and_signs_in() {
    let h = harness().await;
    let directory_credential = fresh_credential();
    let directory = StubDirectory::arc(
        identity(ENTRY, "alice", "alice@example.com"),
        &directory_credential,
    );
    let svc = service(&h, Some(Arc::clone(&directory)));

    let outcome = svc.login(input(&h, "alice", &directory_credential)).await;
    let session_id = match outcome {
        Ok(LoginResult::Success(out)) => out.session_id,
        _ => panic!("a first directory login must issue a session"),
    };

    let created = h.users.get_by_username(h.tenant_id, "alice").await.unwrap();
    assert_eq!(created.status, UserStatus::Active);
    assert_eq!(created.directory_external_id.as_deref(), Some(ENTRY));
    assert_eq!(created.email, "alice@example.com");
    assert_eq!(created.metadata["oidc"]["name"], "Alice Example");
    assert!(
        !axiam_auth::password::verify_password(&directory_credential, &created.password_hash, None)
            .unwrap(),
        "the directory's password is never stored, as a hash or otherwise"
    );
    let session = h.sessions.get_by_id(h.tenant_id, session_id).await.unwrap();
    assert_eq!(session.user_id, created.id);
    assert_eq!(session.amr, vec![Amr::Pwd]);
    assert_eq!(directory.provision_calls(), 1);

    let rows = audit_rows(&h, AUDIT_JIT_PROVISIONED).await;
    assert_eq!(rows.len(), 1, "one creation, one row");
    assert_eq!(rows[0].outcome, AuditOutcome::Success);
    assert_eq!(rows[0].resource_id, Some(created.id));
    assert!(!row_mentions(&rows[0], &directory_credential));
}

/// A second login with the same name finds the account the first one made:
/// the sign-in path, not the provisioning path, and no duplicate.
#[tokio::test]
async fn a_second_login_uses_the_existing_marked_account() {
    let h = harness().await;
    let directory_credential = fresh_credential();
    let directory = StubDirectory::arc(
        identity(ENTRY, "alice", "alice@example.com"),
        &directory_credential,
    );
    let svc = service(&h, Some(Arc::clone(&directory)));
    let before = account_count(&h).await;

    assert!(matches!(
        svc.login(input(&h, "alice", &directory_credential)).await,
        Ok(LoginResult::Success(_))
    ));
    assert!(matches!(
        svc.login(input(&h, "alice", &directory_credential)).await,
        Ok(LoginResult::Success(_))
    ));
    assert_eq!(account_count(&h).await, before + 1, "one account, not two");
    assert_eq!(directory.provision_calls(), 1);
    assert_eq!(directory.sign_in_calls.load(Ordering::SeqCst), 1);
    assert_eq!(audit_rows(&h, AUDIT_JIT_PROVISIONED).await.len(), 1);

    // And the second sign-in is the directory's decision, like any other.
    let wrong = fresh_credential();
    assert!(is_invalid_credentials(
        &svc.login(input(&h, "alice", &wrong)).await
    ));
}

/// Every way a first login can fail answers exactly as an unknown name does —
/// the same error — creates nothing, and still runs the dummy verify: its cost
/// is never below half of the plain unknown-user answer's.
#[tokio::test]
async fn every_refusal_is_the_unknown_user_answer_and_pays_the_dummy_verify() {
    let h = harness().await;
    let floor = unknown_user_cost(&h).await / 2;
    let before = account_count(&h).await;
    let directory_credential = fresh_credential();
    let wrong = fresh_credential();

    let cases: Vec<(&str, Option<Arc<StubDirectory>>, &str)> = vec![
        // jit_provisioning off, a disabled directory and no directory are all
        // the gate's NotConfigured.
        (
            "gate",
            Some(StubDirectory::failing(
                identity(ENTRY, "alice", "alice@example.com"),
                DirectoryAuthError::NotConfigured,
            )),
            &directory_credential,
        ),
        (
            "wrong password",
            Some(StubDirectory::arc(
                identity(ENTRY, "alice", "alice@example.com"),
                &directory_credential,
            )),
            &wrong,
        ),
        (
            "entry not found",
            Some(StubDirectory::failing(
                identity(ENTRY, "alice", "alice@example.com"),
                DirectoryAuthError::InvalidCredentials,
            )),
            &directory_credential,
        ),
        (
            "directory unreachable",
            Some(StubDirectory::failing(
                identity(ENTRY, "alice", "alice@example.com"),
                DirectoryAuthError::Unavailable,
            )),
            &directory_credential,
        ),
        (
            "directory misconfigured",
            Some(StubDirectory::failing(
                identity(ENTRY, "alice", "alice@example.com"),
                DirectoryAuthError::Misconfigured,
            )),
            &directory_credential,
        ),
        (
            "directory refuses the account",
            Some(StubDirectory::failing(
                identity(ENTRY, "alice", "alice@example.com"),
                DirectoryAuthError::AccountRestricted(DirectoryAccountRestriction::Disabled),
            )),
            &directory_credential,
        ),
        (
            "no authenticator in the deployment",
            None,
            &directory_credential,
        ),
    ];
    for (case, directory, presented) in cases {
        let svc = service(&h, directory);
        let started = Instant::now();
        let outcome = svc.login(input(&h, "alice", presented)).await;
        let elapsed = started.elapsed();
        assert!(
            is_invalid_credentials(&outcome),
            "{case}: must be the unknown-user answer"
        );
        assert!(elapsed >= floor, "{case}: the dummy verify must have run");
    }
    // An empty password never reaches the directory at all.
    let directory = StubDirectory::arc(
        identity(ENTRY, "alice", "alice@example.com"),
        &directory_credential,
    );
    let svc = service(&h, Some(Arc::clone(&directory)));
    assert!(is_invalid_credentials(
        &svc.login(input(&h, "alice", "")).await
    ));
    assert_eq!(directory.provision_calls(), 0);

    assert_eq!(account_count(&h).await, before, "nothing may be created");
    assert!(audit_rows(&h, AUDIT_JIT_PROVISIONED).await.is_empty());
}

/// Saturation answers `503` on every unknown-name branch — the directory ones
/// included, and *before* the directory is contacted — exactly where the plain
/// unknown-user answer does. This is what pins that the directory branches run
/// under the same hash permit as the dummy verify they are timed against.
#[tokio::test]
async fn saturation_answers_the_same_503_before_the_directory_is_contacted() {
    let h = harness().await;
    let directory_credential = fresh_credential();
    let directory = StubDirectory::arc(
        identity(ENTRY, "alice", "alice@example.com"),
        &directory_credential,
    );
    // No permits at all and no patience.
    let saturated = service_with(&h, Some(Arc::clone(&directory)), 0, 0);
    let outcome = saturated
        .login(input(&h, "alice", &directory_credential))
        .await;
    assert!(matches!(outcome, Err(AxiamError::ServiceUnavailable(_))));
    assert_eq!(directory.provision_calls(), 0);

    let plain = service_with(&h, None, 0, 0);
    let plain_outcome = plain.login(input(&h, "alice", &directory_credential)).await;
    assert!(matches!(
        plain_outcome,
        Err(AxiamError::ServiceUnavailable(_))
    ));
    assert_eq!(account_count(&h).await, 1);
}

/// D-28: an entry that would collide with a local account is not provisioned
/// over it — on username or email, in any case, and across the two columns —
/// and the local account is untouched.
#[tokio::test]
async fn an_entry_that_collides_with_a_local_account_is_refused_and_audited() {
    let h = harness().await;
    let floor = unknown_user_cost(&h).await / 2;
    // Give bob something to lose: a session.
    let bob_session = match service(&h, None)
        .login(input(&h, "bob", &h.local_credential))
        .await
    {
        Ok(LoginResult::Success(out)) => out.session_id,
        _ => panic!("the local account must sign in"),
    };
    let bob_before = h.users.get_by_id(h.tenant_id, h.local_user).await.unwrap();
    let before = account_count(&h).await;

    // (login typed, the entry's username, the entry's email, which attribute)
    let cases = [
        ("BOB", "BOB", "someone@example.com", "username"),
        ("robert", "Bob", "robert@example.com", "username"),
        ("robert", "robert", "BOB@Example.COM", "email"),
        ("robert", "bob@example.com", "robert@example.com", "email"),
        ("Bob", "robert", "robert@example.com", "username"),
    ];
    for (typed, entry_username, entry_email, attribute) in cases {
        let directory_credential = fresh_credential();
        let directory = StubDirectory::arc(
            identity(ENTRY, entry_username, entry_email),
            &directory_credential,
        );
        let svc = service(&h, Some(Arc::clone(&directory)));
        let started = Instant::now();
        let outcome = svc.login(input(&h, typed, &directory_credential)).await;
        let elapsed = started.elapsed();
        assert!(
            is_invalid_credentials(&outcome),
            "{typed}/{entry_username}: a collision is the generic failure"
        );
        assert!(elapsed >= floor, "the dummy verify runs beside the bind");
        assert_eq!(directory.provision_calls(), 1, "the bind did happen");
        let rows = audit_rows(&h, AUDIT_JIT_REFUSED).await;
        let row = rows
            .iter()
            .find(|row| {
                row.metadata["attribute"] == attribute
                    && row.metadata["existing_user_id"] == h.local_user.to_string()
            })
            .unwrap_or_else(|| panic!("{typed}/{entry_username}: a collision row must exist"));
        assert_eq!(row.metadata["reason"], "collision");
        assert_eq!(row.outcome, AuditOutcome::Denied);
        assert!(!row_mentions(row, &directory_credential));
        // Written once per attempt.
        assert!(!rows.is_empty());
    }

    assert_eq!(account_count(&h).await, before, "no account was created");
    let bob_after = h.users.get_by_id(h.tenant_id, h.local_user).await.unwrap();
    assert_eq!(bob_after.password_hash, bob_before.password_hash);
    assert_eq!(bob_after.directory_external_id, None);
    assert_eq!(bob_after.failed_login_attempts, 0);
    assert_eq!(bob_after.status, UserStatus::Active);
    assert!(
        h.sessions.get_by_id(h.tenant_id, bob_session).await.is_ok(),
        "the local account's session is untouched"
    );
    // And the local account still signs in with its own password.
    assert!(matches!(
        service(&h, None)
            .login(input(&h, "bob", &h.local_credential))
            .await,
        Ok(LoginResult::Success(_))
    ));
}

/// An entry with no usable e-mail address cannot become an account (a local
/// account must have one): refused as the generic failure, with a row saying
/// why, and nothing created.
#[tokio::test]
async fn an_entry_without_a_usable_address_is_refused_and_audited() {
    let h = harness().await;
    let directory_credential = fresh_credential();
    let mut entry = identity(ENTRY, "alice", "alice@example.com");
    entry.email = None;
    let directory = StubDirectory::arc(entry, &directory_credential);
    let svc = service(&h, Some(directory));
    let before = account_count(&h).await;
    assert!(is_invalid_credentials(
        &svc.login(input(&h, "alice", &directory_credential)).await
    ));
    assert_eq!(account_count(&h).await, before);
    let rows = audit_rows(&h, AUDIT_JIT_REFUSED).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["reason"], "unusable_attributes");
}

/// Attributes the directory supplies are bounded and cleaned before they are
/// stored: a display name loses bidirectional overrides and control
/// characters.
#[tokio::test]
async fn directory_supplied_attributes_are_cleaned_before_they_are_stored() {
    let h = harness().await;
    let directory_credential = fresh_credential();
    let mut entry = identity(ENTRY, "alice", "alice@example.com");
    entry.display_name = Some("Al\u{202E}ice\u{0}\n  Example".into());
    let svc = service(&h, Some(StubDirectory::arc(entry, &directory_credential)));
    assert!(matches!(
        svc.login(input(&h, "alice", &directory_credential)).await,
        Ok(LoginResult::Success(_))
    ));
    let created = h.users.get_by_username(h.tenant_id, "alice").await.unwrap();
    assert_eq!(created.metadata["oidc"]["name"], "Alice Example");
}

/// Two first logins for one new entry at the same moment: exactly one account
/// exists afterwards, and each login either signs in (as that account) or
/// gets the generic failure — never a 500, never a duplicate.
#[tokio::test]
async fn two_concurrent_first_logins_yield_exactly_one_account() {
    let h = harness().await;
    let directory_credential = fresh_credential();
    let mut stub = StubDirectory::new(
        identity(ENTRY, "alice", "alice@example.com"),
        directory_credential.clone(),
    );
    stub.rendezvous = Some(tokio::sync::Barrier::new(2));
    let directory = Arc::new(stub);
    let before = account_count(&h).await;

    let first = {
        let svc = service(&h, Some(Arc::clone(&directory)));
        let request = input(&h, "alice", &directory_credential);
        tokio::spawn(async move { svc.login(request).await })
    };
    let second = {
        let svc = service(&h, Some(Arc::clone(&directory)));
        let request = input(&h, "alice", &directory_credential);
        tokio::spawn(async move { svc.login(request).await })
    };
    let outcomes = [first.await.unwrap(), second.await.unwrap()];

    assert_eq!(directory.provision_calls(), 2, "both binds were in flight");
    let signed_in = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(LoginResult::Success(_))))
        .count();
    assert!(signed_in >= 1, "the winner signs in");
    for outcome in &outcomes {
        assert!(
            matches!(outcome, Ok(LoginResult::Success(_))) || is_invalid_credentials(outcome),
            "the loser signs in or gets the generic failure"
        );
    }
    assert_eq!(account_count(&h).await, before + 1, "exactly one account");
}

/// MFA policy applies to a provisioned account exactly as to a local one: a
/// tenant that enforces MFA puts the new user into enrolment, no session yet.
#[tokio::test]
async fn a_tenant_that_requires_mfa_puts_the_new_user_into_enrolment() {
    let h = harness().await;
    let directory_credential = fresh_credential();
    let directory = StubDirectory::arc(
        identity(ENTRY, "alice", "alice@example.com"),
        &directory_credential,
    );
    let svc = service(&h, Some(directory));
    let mut request = input(&h, "alice", &directory_credential);
    request.mfa_policy = Some(MfaPolicy {
        mfa_enforced: true,
        mfa_challenge_lifetime_secs: 300,
    });
    assert!(matches!(
        svc.login(request).await,
        Ok(LoginResult::MfaSetupRequired(_))
    ));
    // The account exists and is active; the next sign-in is a directory
    // sign-in and meets the same policy.
    let created = h.users.get_by_username(h.tenant_id, "alice").await.unwrap();
    assert_eq!(created.status, UserStatus::Active);
    let mut again = input(&h, "alice", &directory_credential);
    again.mfa_policy = Some(MfaPolicy {
        mfa_enforced: true,
        mfa_challenge_lifetime_secs: 300,
    });
    assert!(matches!(
        svc.login(again).await,
        Ok(LoginResult::MfaSetupRequired(_))
    ));
}

/// The names a tenant already uses are untouched by a tenant without a
/// directory: a local account signs in, a wrong name is the unknown answer.
#[tokio::test]
async fn a_tenant_without_a_directory_observes_nothing_new() {
    let h = harness().await;
    let directory = StubDirectory::failing(
        identity(ENTRY, "alice", "alice@example.com"),
        DirectoryAuthError::NotConfigured,
    );
    let svc = service(&h, Some(Arc::clone(&directory)));
    assert!(matches!(
        svc.login(input(&h, "bob", &h.local_credential)).await,
        Ok(LoginResult::Success(_))
    ));
    assert_eq!(directory.provision_calls(), 0, "a local account never asks");
    assert!(is_invalid_credentials(
        &svc.login(input(&h, "nobody", &fresh_credential())).await
    ));
    assert!(audit_rows(&h, AUDIT_JIT_REFUSED).await.is_empty());
}

// -----------------------------------------------------------------------
// Linking an existing account (D-28)
// -----------------------------------------------------------------------

/// Everything a local account can hold, set up on `bob`.
struct Held {
    session: Uuid,
    refresh_hash: String,
    passkey: Uuid,
    by_metadata: Uuid,
    by_subject: Uuid,
    service_cert: Uuid,
    other_users_cert: Uuid,
}

async fn give_bob_everything(h: &Harness) -> Held {
    let svc = service(h, None);
    let session = match svc.login(input(h, "bob", &h.local_credential)).await {
        Ok(LoginResult::Success(out)) => out.session_id,
        _ => panic!("the local account must sign in"),
    };
    let refresh_hash = format!("refresh-{}", Uuid::new_v4().simple());
    h.refresh
        .create(CreateRefreshToken {
            tenant_id: h.tenant_id,
            token_hash: refresh_hash.clone(),
            client_id: "client-1".into(),
            user_id: Some(h.local_user),
            scopes: vec![],
            session_id: None,
            requested_userinfo_claims: vec![],
            resource: None,
            auth_time: None,
            acr: None,
            amr: vec![Amr::Pwd],
            expires_at: Utc::now() + ChronoDuration::hours(1),
        })
        .await
        .unwrap();
    let passkey = h
        .webauthn
        .create(CreateWebauthnCredential {
            tenant_id: h.tenant_id,
            user_id: h.local_user,
            credential_id: format!("cred-{}", Uuid::new_v4().simple()),
            name: "laptop".into(),
            credential_type: WebauthnCredentialType::Passkey,
            passkey_json: r#"{"stub":"passkey"}"#.into(),
            aaguid: None,
            attestation_format: None,
            attested: false,
            authenticator_name: None,
        })
        .await
        .unwrap()
        .id;
    let certificate = |fingerprint: &str, subject: &str, cert_type, metadata| {
        axiam_core::models::certificate::StoreCertificate {
            tenant_id: h.tenant_id,
            issuer_ca_id: Uuid::new_v4(),
            subject: subject.into(),
            public_cert_pem: "not-a-parsed-certificate".into(),
            fingerprint: fingerprint.into(),
            cert_type,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - ChronoDuration::minutes(1),
            not_after: Utc::now() + ChronoDuration::days(30),
            metadata,
        }
    };
    let by_metadata = h
        .certificates
        .create(certificate(
            "fp-by-metadata",
            "device-9",
            CertificateType::User,
            serde_json::json!({ "user_id": h.local_user.to_string() }),
        ))
        .await
        .unwrap()
        .id;
    let by_subject = h
        .certificates
        .create(certificate(
            "fp-by-subject",
            "bob@example.com",
            CertificateType::User,
            serde_json::json!({}),
        ))
        .await
        .unwrap()
        .id;
    let service_cert = h
        .certificates
        .create(certificate(
            "fp-service",
            "bob",
            CertificateType::Service,
            serde_json::json!({ "user_id": h.local_user.to_string() }),
        ))
        .await
        .unwrap()
        .id;
    let other_users_cert = h
        .certificates
        .create(certificate(
            "fp-someone-else",
            "carol",
            CertificateType::User,
            serde_json::json!({ "user_id": Uuid::new_v4().to_string() }),
        ))
        .await
        .unwrap()
        .id;
    // OPAQUE registration and TOTP enrolment.
    SurrealOpaqueCredentialRepository::new(h.db.clone())
        .upsert(CreateOpaqueCredential {
            tenant_id: h.tenant_id,
            user_id: h.local_user,
            credential_identifier: "00".repeat(32),
            suite: OpaqueSuite::default(),
            ksf_params: OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id),
            record: "11".repeat(192),
        })
        .await
        .unwrap();
    h.users
        .update(
            h.tenant_id,
            h.local_user,
            UpdateUser {
                mfa_enabled: Some(true),
                mfa_secret: Some(Some(format!("ct-{}", Uuid::new_v4().simple()))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    Held {
        session,
        refresh_hash,
        passkey,
        by_metadata,
        by_subject,
        service_cert,
        other_users_cert,
    }
}

async fn link(h: &Harness, svc: &Svc) -> AxiamResult<axiam_auth::service::DirectoryLinkOutcome> {
    svc.link_local_account_to_directory(
        h.tenant_id,
        h.local_user,
        Uuid::new_v4(),
        None,
        &h.webauthn,
        &h.certificates,
    )
    .await
}

/// Linking marks the account and retires everything that authenticates without
/// the directory deciding — sessions, refresh tokens, passkeys, `User`
/// certificates and the OPAQUE record — keeps TOTP, audits it, and from then on
/// the local password is refused and the directory's is accepted.
#[tokio::test]
async fn linking_marks_the_account_and_retires_what_the_directory_does_not_decide() {
    let h = harness().await;
    let held = give_bob_everything(&h).await;
    let directory_credential = fresh_credential();
    let directory = StubDirectory::arc(
        identity(OTHER_ENTRY, "bob", "bob@example.com"),
        &directory_credential,
    );
    let svc = service(&h, Some(Arc::clone(&directory)));

    let outcome = link(&h, &svc).await.expect("linking must succeed");
    assert!(!outcome.was_already_linked);
    assert_eq!(outcome.webauthn_credentials_deleted, 1);
    assert_eq!(outcome.certificates_revoked, 2);
    assert_eq!(directory.lookup_calls.load(Ordering::SeqCst), 1);

    // Marked, TOTP kept, no usable local credential.
    let bob = h.users.get_by_id(h.tenant_id, h.local_user).await.unwrap();
    assert_eq!(bob.directory_external_id.as_deref(), Some(OTHER_ENTRY));
    assert!(bob.mfa_enabled && bob.mfa_secret.is_some(), "TOTP is kept");
    assert!(
        !axiam_auth::password::verify_password(&h.local_credential, &bob.password_hash, None)
            .unwrap()
    );
    assert!(matches!(
        SurrealOpaqueCredentialRepository::new(h.db.clone())
            .get_by_user(h.tenant_id, h.local_user)
            .await,
        Err(AxiamError::NotFound { .. })
    ));

    // Sessions, refresh tokens, passkeys: gone.
    assert!(matches!(
        h.sessions.get_by_id(h.tenant_id, held.session).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        h.refresh
            .get_by_token_hash(h.tenant_id, &held.refresh_hash)
            .await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(
        h.webauthn
            .count_by_user(h.tenant_id, h.local_user)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        h.webauthn.get_by_id(h.tenant_id, held.passkey).await,
        Err(AxiamError::NotFound { .. })
    ));

    // `User` certificates that belong to the account: revoked. The rest: not.
    for (id, expected) in [
        (held.by_metadata, CertificateStatus::Revoked),
        (held.by_subject, CertificateStatus::Revoked),
        (held.service_cert, CertificateStatus::Active),
        (held.other_users_cert, CertificateStatus::Active),
    ] {
        assert_eq!(
            h.certificates
                .get_by_id(h.tenant_id, id)
                .await
                .unwrap()
                .status,
            expected
        );
    }

    // The audit row names the actor, the counts and the entry, never a credential.
    let rows = audit_rows(&h, AUDIT_ACCOUNT_LINKED).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, AuditOutcome::Success);
    assert_eq!(rows[0].resource_id, Some(h.local_user));
    assert_eq!(rows[0].metadata["webauthn_credentials_deleted"], 1);
    assert_eq!(rows[0].metadata["certificates_revoked"], 2);
    assert!(!row_mentions(&rows[0], &h.local_credential));
    assert!(!row_mentions(&rows[0], &directory_credential));

    // After linking: the local password no longer works, the directory's does.
    assert!(is_invalid_credentials(
        &svc.login(input(&h, "bob", &h.local_credential)).await
    ));
    assert!(matches!(
        svc.login(input(&h, "bob", &directory_credential)).await,
        Ok(LoginResult::MfaRequired(_)),
    ));
}

/// An entry already linked to another account is refused, and nothing the
/// account holds is touched.
#[tokio::test]
async fn an_entry_already_linked_elsewhere_is_refused_and_nothing_is_revoked() {
    let h = harness().await;
    let held = give_bob_everything(&h).await;
    let carol = h
        .users
        .create(CreateUser {
            tenant_id: h.tenant_id,
            username: "carol".into(),
            email: "carol@example.com".into(),
            password: fresh_credential(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    h.users
        .mark_directory_account(h.tenant_id, carol, OTHER_ENTRY)
        .await
        .unwrap();
    let directory = StubDirectory::arc(
        identity(OTHER_ENTRY, "bob", "bob@example.com"),
        &fresh_credential(),
    );
    let svc = service(&h, Some(directory));

    assert!(matches!(
        link(&h, &svc).await,
        Err(AxiamError::Conflict { .. })
    ));
    let bob = h.users.get_by_id(h.tenant_id, h.local_user).await.unwrap();
    assert_eq!(bob.directory_external_id, None, "not marked");
    assert!(
        h.sessions
            .get_by_id(h.tenant_id, held.session)
            .await
            .is_ok()
    );
    assert_eq!(
        h.webauthn
            .count_by_user(h.tenant_id, h.local_user)
            .await
            .unwrap(),
        1
    );
    assert!(audit_rows(&h, AUDIT_ACCOUNT_LINKED).await.is_empty());
}

/// The entry is resolved by the directory: none found, no directory and a
/// directory that cannot answer each refuse, and revoke nothing.
#[tokio::test]
async fn an_entry_that_cannot_be_resolved_refuses_the_link_and_revokes_nothing() {
    let h = harness().await;
    let held = give_bob_everything(&h).await;
    for (failure, expected) in [
        (DirectoryAuthError::InvalidCredentials, "not found"),
        (DirectoryAuthError::NotConfigured, "conflict"),
        (DirectoryAuthError::Unavailable, "unavailable"),
        (DirectoryAuthError::Misconfigured, "unavailable"),
    ] {
        let directory = StubDirectory::new(
            identity(OTHER_ENTRY, "bob", "bob@example.com"),
            fresh_credential(),
        );
        *directory.lookup.lock().unwrap() = Err(failure);
        let svc = service(&h, Some(Arc::new(directory)));
        let outcome = link(&h, &svc).await;
        let matched = match expected {
            "not found" => matches!(outcome, Err(AxiamError::NotFound { .. })),
            "conflict" => matches!(outcome, Err(AxiamError::Conflict { .. })),
            _ => matches!(outcome, Err(AxiamError::ServiceUnavailable(_))),
        };
        assert!(matched, "{expected}: the wrong refusal");
    }
    // A deployment with no authenticator at all.
    assert!(matches!(
        link(&h, &service(&h, None)).await,
        Err(AxiamError::ServiceUnavailable(_))
    ));

    let bob = h.users.get_by_id(h.tenant_id, h.local_user).await.unwrap();
    assert_eq!(bob.directory_external_id, None);
    assert!(
        h.sessions
            .get_by_id(h.tenant_id, held.session)
            .await
            .is_ok()
    );
    assert!(
        axiam_auth::password::verify_password(&h.local_credential, &bob.password_hash, None)
            .unwrap(),
        "the local password still works"
    );
}

/// The caller cannot name the entry: the one the directory returns is the one
/// linked, and an account already linked to a *different* entry is refused.
#[tokio::test]
async fn an_account_linked_to_a_different_entry_is_refused() {
    let h = harness().await;
    h.users
        .mark_directory_account(h.tenant_id, h.local_user, ENTRY)
        .await
        .unwrap();
    let directory = StubDirectory::arc(
        identity(OTHER_ENTRY, "bob", "bob@example.com"),
        &fresh_credential(),
    );
    let svc = service(&h, Some(directory));
    assert!(matches!(
        link(&h, &svc).await,
        Err(AxiamError::Conflict { .. })
    ));
    let bob = h.users.get_by_id(h.tenant_id, h.local_user).await.unwrap();
    assert_eq!(bob.directory_external_id.as_deref(), Some(ENTRY));
}

/// A deleted account cannot be linked.
#[tokio::test]
async fn a_deleted_account_cannot_be_linked() {
    let h = harness().await;
    h.users
        .update(
            h.tenant_id,
            h.local_user,
            UpdateUser {
                status: Some(UserStatus::Deleted),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let directory = StubDirectory::arc(
        identity(OTHER_ENTRY, "bob", "bob@example.com"),
        &fresh_credential(),
    );
    let svc = service(&h, Some(Arc::clone(&directory)));
    assert!(matches!(
        link(&h, &svc).await,
        Err(AxiamError::Validation { .. })
    ));
    assert_eq!(directory.lookup_calls.load(Ordering::SeqCst), 0);
}

/// Linking is a unit of work by order, safe to stop in and to retry: when a
/// revocation fails the account is already marked (so no local password opens
/// a new session), a failure row says where, and calling again re-runs the
/// revocations and completes.
#[tokio::test]
async fn an_interrupted_link_is_retryable_and_the_retry_completes_it() {
    let h = harness().await;
    let held = give_bob_everything(&h).await;
    let directory = StubDirectory::arc(
        identity(OTHER_ENTRY, "bob", "bob@example.com"),
        &fresh_credential(),
    );
    let svc = service(&h, Some(directory));

    let failing = FailingFirstDelete::new(h.webauthn.clone());
    let interrupted = svc
        .link_local_account_to_directory(
            h.tenant_id,
            h.local_user,
            Uuid::new_v4(),
            None,
            &failing,
            &h.certificates,
        )
        .await;
    assert!(interrupted.is_err());
    let bob = h.users.get_by_id(h.tenant_id, h.local_user).await.unwrap();
    assert_eq!(bob.directory_external_id.as_deref(), Some(OTHER_ENTRY));
    assert!(
        !axiam_auth::password::verify_password(&h.local_credential, &bob.password_hash, None)
            .unwrap(),
        "the local password is already dead"
    );
    let failures = audit_rows(&h, AUDIT_ACCOUNT_LINKED).await;
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].outcome, AuditOutcome::Failure);
    assert_eq!(failures[0].metadata["stage"], "webauthn_credentials");

    let retried = link(&h, &svc).await.expect("the retry must complete");
    assert!(retried.was_already_linked);
    assert_eq!(retried.webauthn_credentials_deleted, 1);
    assert!(matches!(
        h.sessions.get_by_id(h.tenant_id, held.session).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(audit_rows(&h, AUDIT_ACCOUNT_LINKED).await.len(), 2);
}

/// A WebAuthn repository whose first `delete_by_user` fails, then behaves.
struct FailingFirstDelete {
    inner: SurrealWebauthnCredentialRepository<Db>,
    failed: AtomicUsize,
}

impl FailingFirstDelete {
    fn new(inner: SurrealWebauthnCredentialRepository<Db>) -> Self {
        Self {
            inner,
            failed: AtomicUsize::new(0),
        }
    }
}

impl WebauthnCredentialRepository for FailingFirstDelete {
    async fn create(
        &self,
        input: CreateWebauthnCredential,
    ) -> AxiamResult<axiam_core::models::webauthn_credential::WebauthnCredential> {
        self.inner.create(input).await
    }
    async fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AxiamResult<axiam_core::models::webauthn_credential::WebauthnCredential> {
        self.inner.get_by_id(tenant_id, id).await
    }
    async fn list_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<axiam_core::models::webauthn_credential::WebauthnCredential>> {
        self.inner.list_by_user(tenant_id, user_id).await
    }
    async fn update_last_used(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.inner.update_last_used(tenant_id, id).await
    }
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.inner.delete(tenant_id, id).await
    }
    async fn delete_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        if self.failed.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(AxiamError::Internal("scripted failure".into()));
        }
        self.inner.delete_by_user(tenant_id, user_id).await
    }
    async fn count_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        self.inner.count_by_user(tenant_id, user_id).await
    }
}
