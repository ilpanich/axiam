//! Directory accounts at the `AuthService` level (G-3, T23.3.2), with a stub
//! `DirectoryAuthenticator` standing in for the LDAP client.
//!
//! The client itself is tested against a live in-process directory in
//! `axiam-directory/tests/client_test.rs`; what is tested here is what the login
//! path does around it: the lockout and status gates in front of the directory,
//! the brute-force counter, the refusal to fall back to a local hash, the entry
//! binding, the `amr`, and that a local account is untouched.
//!
//! Assertion messages name the case; none formats a password, a result's Debug
//! output or an identifier.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_auth::config::AuthConfig;
use axiam_auth::error::AuthError;
use axiam_auth::service::{AuthService, LoginInput, LoginResult};
use axiam_core::error::AxiamError;
use axiam_core::models::directory::{
    DirectoryAccountRestriction, DirectoryAuthError, DirectoryAuthenticator, DirectoryIdentity,
};
use axiam_core::models::session::Amr;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{SessionRepository, UserRepository};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealRefreshTokenRepository, SurrealSessionRepository,
    SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key
const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

const ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";

fn config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: TEST_PRIVATE_KEY.into(),
        jwt_public_key_pem: TEST_PUBLIC_KEY.into(),
        jwt_issuer: "axiam-test".into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 3600,
        hash_acquire_timeout_secs: 5,
        max_failed_login_attempts: 3,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        email_verification_grace_period_hours: 24,
        ..AuthConfig::default()
    }
}

/// A scripted directory: answers every call with `outcome` and records the
/// login names it was asked about.
struct StubDirectory {
    outcome: Mutex<Result<DirectoryIdentity, DirectoryAuthError>>,
    calls: AtomicUsize,
    login_names: Mutex<Vec<String>>,
}

impl StubDirectory {
    fn answering(outcome: Result<DirectoryIdentity, DirectoryAuthError>) -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(outcome),
            calls: AtomicUsize::new(0),
            login_names: Mutex::new(Vec::new()),
        })
    }

    fn accepting(external_id: &str) -> Arc<Self> {
        Self::answering(Ok(identity(external_id)))
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn identity(external_id: &str) -> DirectoryIdentity {
    DirectoryIdentity {
        external_id: external_id.into(),
        dn: "uid=alice,ou=people,dc=example,dc=com".into(),
        username: Some("alice".into()),
        email: Some("alice@example.com".into()),
        display_name: None,
    }
}

impl DirectoryAuthenticator for StubDirectory {
    fn authenticate<'a>(
        &'a self,
        _tenant_id: Uuid,
        login_name: &'a str,
        _password: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<DirectoryIdentity, DirectoryAuthError>>
                + Send
                + 'a,
        >,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.login_names
            .lock()
            .unwrap()
            .push(login_name.to_string());
        let outcome = self.outcome.lock().unwrap().clone();
        Box::pin(async move { outcome })
    }
}

type Svc = AuthService<
    SurrealUserRepository<Db>,
    SurrealSessionRepository<Db>,
    SurrealFederationLinkRepository<Db>,
    SurrealRefreshTokenRepository<Db>,
>;

struct Harness {
    users: SurrealUserRepository<Db>,
    sessions: SurrealSessionRepository<Db>,
    db: Surreal<Db>,
    tenant_id: Uuid,
    org_id: Uuid,
    /// A directory account, marked and active.
    directory_user: Uuid,
    /// A local account with a known password.
    local_user: Uuid,
    local_password: String,
}

fn fresh_password() -> String {
    format!("Pw1!{}", Uuid::new_v4().simple())
}

async fn harness() -> Harness {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let users = SurrealUserRepository::new(db.clone());
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    let directory_user = users
        .create(CreateUser {
            tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: fresh_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    users
        .mark_directory_account(tenant_id, directory_user, ENTRY)
        .await
        .unwrap();
    // T23.3.3 creates directory accounts `Active`: the directory has vouched
    // for the account, so the email-verification grace rule is not theirs.
    activate(&users, tenant_id, directory_user).await;

    let local_password = fresh_password();
    let local_user = users
        .create(CreateUser {
            tenant_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: local_password.clone(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    activate(&users, tenant_id, local_user).await;

    Harness {
        sessions: SurrealSessionRepository::new(db.clone()),
        users,
        db,
        tenant_id,
        org_id,
        directory_user,
        local_user,
        local_password,
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

fn service(h: &Harness, directory: Option<Arc<StubDirectory>>) -> Svc {
    let svc = AuthService::new(
        h.users.clone(),
        h.sessions.clone(),
        SurrealFederationLinkRepository::new(h.db.clone()),
        SurrealRefreshTokenRepository::new(h.db.clone()),
        config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    match directory {
        Some(directory) => svc.with_directory_authenticator(directory),
        None => svc,
    }
}

fn input(h: &Harness, login: &str, password: &str) -> LoginInput {
    LoginInput {
        tenant_id: h.tenant_id,
        org_id: h.org_id,
        username_or_email: login.into(),
        password: password.into(),
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

async fn failed_attempts(h: &Harness, id: Uuid) -> u32 {
    h.users
        .get_by_id(h.tenant_id, id)
        .await
        .unwrap()
        .failed_login_attempts
}

/// The directory decides: a bind that succeeds as the account's own entry
/// signs in, resets the counter, and the session records `pwd` — a directory
/// password is a password (RFC 8176), and AXIAM received it.
#[tokio::test]
async fn a_successful_bind_signs_in_resets_the_counter_and_records_pwd() {
    let h = harness().await;
    h.users
        .update(
            h.tenant_id,
            h.directory_user,
            UpdateUser {
                failed_login_attempts: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let directory = StubDirectory::accepting(ENTRY);
    let svc = service(&h, Some(Arc::clone(&directory)));

    // Signed in by email: the directory is asked about the account's local
    // login name, the one provisioning copied from the directory.
    let outcome = svc
        .login(input(&h, "alice@example.com", "the-directory-password"))
        .await;
    let session_id = match outcome {
        Ok(LoginResult::Success(out)) => out.session_id,
        _ => panic!("a successful directory bind must issue a session"),
    };
    assert_eq!(directory.calls(), 1);
    assert_eq!(directory.login_names.lock().unwrap().as_slice(), ["alice"]);
    assert_eq!(failed_attempts(&h, h.directory_user).await, 0);
    let session = h.sessions.get_by_id(h.tenant_id, session_id).await.unwrap();
    assert_eq!(session.amr, vec![Amr::Pwd]);
}

/// A locked account is refused without the directory hearing anything, so
/// AXIAM cannot be used to lock the account in Active Directory.
#[tokio::test]
async fn a_locked_account_is_refused_before_the_directory_is_called() {
    let h = harness().await;
    h.users
        .update(
            h.tenant_id,
            h.directory_user,
            UpdateUser {
                locked_until: Some(Some(Utc::now() + Duration::minutes(5))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let directory = StubDirectory::accepting(ENTRY);
    let svc = service(&h, Some(Arc::clone(&directory)));
    let outcome = svc.login(input(&h, "alice", "any-password")).await;
    assert!(is_invalid_credentials(&outcome));
    assert_eq!(directory.calls(), 0, "the directory must not be contacted");
}

/// A failed bind moves the same counter a wrong local password does; at the
/// threshold the account locks, and from then on the directory is not called.
#[tokio::test]
async fn failed_binds_count_and_lock_and_then_stop_reaching_the_directory() {
    let h = harness().await;
    let directory = StubDirectory::answering(Err(DirectoryAuthError::InvalidCredentials));
    let svc = service(&h, Some(Arc::clone(&directory)));
    for expected in 1..=3u32 {
        let outcome = svc.login(input(&h, "alice", "wrong")).await;
        assert!(is_invalid_credentials(&outcome));
        assert_eq!(failed_attempts(&h, h.directory_user).await, expected);
    }
    let locked = h
        .users
        .get_by_id(h.tenant_id, h.directory_user)
        .await
        .unwrap();
    assert!(locked.locked_until.is_some_and(|t| t > Utc::now()));
    let outcome = svc.login(input(&h, "alice", "wrong")).await;
    assert!(is_invalid_credentials(&outcome));
    assert_eq!(
        directory.calls(),
        3,
        "the locked account must not reach the directory"
    );
}

/// No fallback to a local hash. Even when a usable local hash is written
/// behind the directory path's back, a directory account signs in only through
/// the directory: unavailable, misconfigured, not configured, restricted, or
/// no authenticator at all — each refuses the correct local password, and none
/// counts against the account.
#[tokio::test]
async fn there_is_no_fallback_to_a_local_hash() {
    let h = harness().await;
    let local = fresh_password();
    let hash = axiam_auth::password::hash_password(&local, None).unwrap();
    h.users
        .update(
            h.tenant_id,
            h.directory_user,
            UpdateUser {
                password_hash: Some(hash),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    for failure in [
        DirectoryAuthError::Unavailable,
        DirectoryAuthError::Misconfigured,
        DirectoryAuthError::NotConfigured,
        DirectoryAuthError::AccountRestricted(DirectoryAccountRestriction::Disabled),
        DirectoryAuthError::AccountRestricted(DirectoryAccountRestriction::Locked),
    ] {
        let svc = service(&h, Some(StubDirectory::answering(Err(failure))));
        let outcome = svc.login(input(&h, "alice", &local)).await;
        assert!(
            is_invalid_credentials(&outcome),
            "a directory failure must never fall back to the local hash"
        );
    }
    let outcome = service(&h, None).login(input(&h, "alice", &local)).await;
    assert!(
        is_invalid_credentials(&outcome),
        "without an authenticator a directory account cannot sign in"
    );
    assert_eq!(
        failed_attempts(&h, h.directory_user).await,
        0,
        "an unusable directory is not the user's failure"
    );
}

/// The directory must answer as the entry this account is bound to: a login
/// name that resolves to a different entry is refused, and counted.
#[tokio::test]
async fn an_answer_from_another_entry_is_refused_and_counted() {
    let h = harness().await;
    let directory = StubDirectory::accepting("00000000-0000-4000-8000-0000000000ff");
    let svc = service(&h, Some(directory));
    let outcome = svc
        .login(input(&h, "alice", "someone-elses-password"))
        .await;
    assert!(is_invalid_credentials(&outcome));
    assert_eq!(failed_attempts(&h, h.directory_user).await, 1);

    // Case differences in the identifier are not a different entry.
    let svc = service(
        &h,
        Some(StubDirectory::accepting(&ENTRY.to_ascii_uppercase())),
    );
    assert!(matches!(
        svc.login(input(&h, "alice", "the-password")).await,
        Ok(LoginResult::Success(_))
    ));
}

/// An empty password is an RFC 4513 unauthenticated bind: refused without the
/// directory, and counted as the wrong password it is.
#[tokio::test]
async fn an_empty_password_never_reaches_the_directory() {
    let h = harness().await;
    let directory = StubDirectory::accepting(ENTRY);
    let svc = service(&h, Some(Arc::clone(&directory)));
    let outcome = svc.login(input(&h, "alice", "")).await;
    assert!(is_invalid_credentials(&outcome));
    assert_eq!(directory.calls(), 0);
    assert_eq!(failed_attempts(&h, h.directory_user).await, 1);
}

/// An account whose status refuses sign-in is refused before the directory is
/// contacted, with the generic failure.
#[tokio::test]
async fn an_inactive_directory_account_is_refused_before_the_directory() {
    let h = harness().await;
    h.users
        .update(
            h.tenant_id,
            h.directory_user,
            UpdateUser {
                status: Some(UserStatus::Inactive),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let directory = StubDirectory::accepting(ENTRY);
    let svc = service(&h, Some(Arc::clone(&directory)));
    let outcome = svc.login(input(&h, "alice", "the-password")).await;
    assert!(is_invalid_credentials(&outcome));
    assert_eq!(directory.calls(), 0);
}

/// Invariant I1: a local account signs in exactly as before, with the
/// authenticator attached and never consulted.
#[tokio::test]
async fn a_local_account_is_unchanged() {
    let h = harness().await;
    let directory = StubDirectory::accepting(ENTRY);
    let svc = service(&h, Some(Arc::clone(&directory)));
    assert!(matches!(
        svc.login(input(&h, "bob", &h.local_password)).await,
        Ok(LoginResult::Success(_))
    ));
    let outcome = svc.login(input(&h, "bob", "wrong")).await;
    assert!(is_invalid_credentials(&outcome));
    assert_eq!(failed_attempts(&h, h.local_user).await, 1);
    assert_eq!(
        directory.calls(),
        0,
        "a local account never reaches the directory"
    );
}

/// No local account: answered exactly as an unknown user is today, and the
/// directory is not consulted (just-in-time provisioning is T23.3.3's seam).
#[tokio::test]
async fn an_unknown_name_is_answered_as_today_without_the_directory() {
    let h = harness().await;
    let directory = StubDirectory::accepting(ENTRY);
    let svc = service(&h, Some(Arc::clone(&directory)));
    let outcome = svc.login(input(&h, "nobody", "anything")).await;
    assert!(is_invalid_credentials(&outcome));
    assert_eq!(directory.calls(), 0);
}
