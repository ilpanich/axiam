//! `RepositoryDirectoryAuthenticator`: the stored configuration, the bind
//! secret and the client, put together per tenant — and failing closed at each
//! of the three.

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryAuthenticator, DirectoryConfig, DirectoryKind, NewDirectoryConfig,
};
use axiam_core::repository::DirectoryConfigRepository;
use axiam_directory::{ClientLimits, DirectoryClient, RepositoryDirectoryAuthenticator};
use chrono::Utc;
use support::{BASE_DN, Entry, SERVICE_DN, Script, TestServer, alice_password, service_secret};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
struct FakeRepo {
    configs: Arc<Mutex<HashMap<Uuid, DirectoryConfig>>>,
    /// `None` makes `decrypt_bind_secret` answer as a deployment without the
    /// `directory_encryption_key` does.
    secret: Option<String>,
}

impl DirectoryConfigRepository for FakeRepo {
    async fn create(&self, _input: NewDirectoryConfig) -> AxiamResult<DirectoryConfig> {
        unimplemented!("not used by the bind path")
    }
    async fn update(&self, _input: NewDirectoryConfig) -> AxiamResult<DirectoryConfig> {
        unimplemented!("not used by the bind path")
    }
    async fn get_by_tenant(&self, tenant_id: Uuid) -> AxiamResult<Option<DirectoryConfig>> {
        Ok(self.configs.lock().unwrap().get(&tenant_id).cloned())
    }
    async fn decrypt_bind_secret(&self, tenant_id: Uuid) -> AxiamResult<Zeroizing<String>> {
        if !self.configs.lock().unwrap().contains_key(&tenant_id) {
            return Err(AxiamError::NotFound {
                entity: "directory_config".into(),
                id: tenant_id.to_string(),
            });
        }
        match &self.secret {
            Some(secret) => Ok(Zeroizing::new(secret.clone())),
            None => Err(AxiamError::ServiceUnavailable(
                "directory_encryption_key is not configured".into(),
            )),
        }
    }
    async fn delete(&self, _tenant_id: Uuid) -> AxiamResult<()> {
        Ok(())
    }
    async fn list_enabled(&self) -> AxiamResult<Vec<DirectoryConfig>> {
        Ok(vec![])
    }
}

fn config_for(server: &TestServer, tenant_id: Uuid) -> DirectoryConfig {
    DirectoryConfig {
        id: Uuid::new_v4(),
        tenant_id,
        enabled: true,
        kind: DirectoryKind::OpenLdap,
        url: format!("ldaps://localhost:{}", server.port()),
        start_tls: false,
        bind_dn: SERVICE_DN.into(),
        base_dn: BASE_DN.into(),
        user_filter: "(uid={username})".into(),
        user_attribute_map: DirectoryKind::OpenLdap.default_user_attribute_map(),
        group_base_dn: None,
        group_filter: None,
        group_member_attribute: "member".into(),
        group_nesting_depth: 5,
        sync_interval_secs: 3600,
        jit_provisioning: false,
        trust_anchors_pem: vec![server.ca.pem.clone()],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn client() -> Arc<DirectoryClient> {
    Arc::new(DirectoryClient::new(ClientLimits {
        connect_timeout: Duration::from_millis(500),
        operation_timeout: Duration::from_millis(500),
        authentication_deadline: Duration::from_secs(3),
        ..ClientLimits::default()
    }))
}

async fn server() -> TestServer {
    TestServer::start(Script {
        entries: vec![Entry::person(
            "alice",
            &alice_password(),
            "00000000-0000-4000-8000-00000000a11c",
        )],
        ..Script::default()
    })
    .await
}

#[tokio::test]
async fn an_enabled_configuration_authenticates_end_to_end() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let repo = FakeRepo {
        secret: Some(service_secret()),
        ..FakeRepo::default()
    };
    repo.configs
        .lock()
        .unwrap()
        .insert(tenant, config_for(&server, tenant));
    let authenticator = RepositoryDirectoryAuthenticator::with_client(repo, client());
    let identity = authenticator
        .authenticate(tenant, "alice", &alice_password())
        .await
        .expect("the configured directory must authenticate");
    assert_eq!(identity.external_id, "00000000-0000-4000-8000-00000000a11c");
}

#[tokio::test]
async fn no_configuration_or_a_disabled_one_is_not_configured() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let repo = FakeRepo {
        secret: Some(service_secret()),
        ..FakeRepo::default()
    };
    let authenticator = RepositoryDirectoryAuthenticator::with_client(repo.clone(), client());
    assert_eq!(
        authenticator
            .authenticate(tenant, "alice", &alice_password())
            .await,
        Err(DirectoryAuthError::NotConfigured)
    );
    let mut disabled = config_for(&server, tenant);
    disabled.enabled = false;
    repo.configs.lock().unwrap().insert(tenant, disabled);
    assert_eq!(
        authenticator
            .authenticate(tenant, "alice", &alice_password())
            .await,
        Err(DirectoryAuthError::NotConfigured)
    );
    assert_eq!(server.connections(), 0);
}

/// Cross-tenant confusion: tenant B has no directory, and a sign-in to B is
/// never answered by tenant A's.
#[tokio::test]
async fn one_tenant_is_never_answered_by_another_tenants_directory() {
    let server = server().await;
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let repo = FakeRepo {
        secret: Some(service_secret()),
        ..FakeRepo::default()
    };
    repo.configs
        .lock()
        .unwrap()
        .insert(tenant_a, config_for(&server, tenant_a));
    let authenticator = RepositoryDirectoryAuthenticator::with_client(repo, client());
    assert!(
        authenticator
            .authenticate(tenant_a, "alice", &alice_password())
            .await
            .is_ok()
    );
    assert_eq!(
        authenticator
            .authenticate(tenant_b, "alice", &alice_password())
            .await,
        Err(DirectoryAuthError::NotConfigured)
    );
}

/// D-15: without the optional key the directory is unavailable — not
/// insecure, and no connection is opened.
#[tokio::test]
async fn a_missing_encryption_key_is_unavailable_with_no_connection() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let repo = FakeRepo::default();
    repo.configs
        .lock()
        .unwrap()
        .insert(tenant, config_for(&server, tenant));
    let authenticator = RepositoryDirectoryAuthenticator::with_client(repo, client());
    assert_eq!(
        authenticator
            .authenticate(tenant, "alice", &alice_password())
            .await,
        Err(DirectoryAuthError::Unavailable)
    );
    assert_eq!(server.connections(), 0);
}

/// A stored row that skipped validation — a plaintext URL — never reaches a
/// socket.
#[tokio::test]
async fn a_stored_plaintext_url_is_refused_before_any_connection() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let repo = FakeRepo {
        secret: Some(service_secret()),
        ..FakeRepo::default()
    };
    let mut plaintext = config_for(&server, tenant);
    plaintext.url = format!("ldap://localhost:{}", server.port());
    plaintext.start_tls = false;
    repo.configs.lock().unwrap().insert(tenant, plaintext);
    let authenticator = RepositoryDirectoryAuthenticator::with_client(repo, client());
    assert_eq!(
        authenticator
            .authenticate(tenant, "alice", &alice_password())
            .await,
        Err(DirectoryAuthError::Misconfigured)
    );
    assert_eq!(server.connections(), 0);
}

#[tokio::test]
async fn unusable_stored_anchors_are_a_misconfiguration() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let repo = FakeRepo {
        secret: Some(service_secret()),
        ..FakeRepo::default()
    };
    let mut broken = config_for(&server, tenant);
    broken.trust_anchors_pem = vec!["not a certificate".into()];
    repo.configs.lock().unwrap().insert(tenant, broken);
    let authenticator = RepositoryDirectoryAuthenticator::with_client(repo, client());
    assert_eq!(
        authenticator
            .authenticate(tenant, "alice", &alice_password())
            .await,
        Err(DirectoryAuthError::Misconfigured)
    );
    assert_eq!(server.connections(), 0);
}

#[tokio::test]
async fn an_empty_password_is_refused_before_the_configuration_is_read() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let repo = FakeRepo {
        secret: Some(service_secret()),
        ..FakeRepo::default()
    };
    repo.configs
        .lock()
        .unwrap()
        .insert(tenant, config_for(&server, tenant));
    let authenticator = RepositoryDirectoryAuthenticator::with_client(repo, client());
    let empty = String::new();
    assert_eq!(
        authenticator.authenticate(tenant, "alice", &empty).await,
        Err(DirectoryAuthError::InvalidCredentials)
    );
    assert_eq!(server.connections(), 0);
}

// -----------------------------------------------------------------------
// Provisioning and lookup (T23.3.3)
// -----------------------------------------------------------------------

fn repo_with(server: &TestServer, tenant: Uuid, jit: bool, enabled: bool) -> FakeRepo {
    let repo = FakeRepo {
        secret: Some(service_secret()),
        ..FakeRepo::default()
    };
    let mut config = config_for(server, tenant);
    config.jit_provisioning = jit;
    config.enabled = enabled;
    repo.configs.lock().unwrap().insert(tenant, config);
    repo
}

/// With `jit_provisioning` on, the provisioning call is the sign-in call: the
/// directory authenticates and the identity comes back with the mapped
/// attributes.
#[tokio::test]
async fn provisioning_authenticates_when_the_tenant_asked_for_it() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let authenticator = RepositoryDirectoryAuthenticator::with_client(
        repo_with(&server, tenant, true, true),
        client(),
    );
    let identity = authenticator
        .authenticate_for_provisioning(tenant, "alice", &alice_password())
        .await
        .expect("a tenant with jit_provisioning must authenticate");
    assert_eq!(identity.external_id, "00000000-0000-4000-8000-00000000a11c");
    assert_eq!(identity.username.as_deref(), Some("alice"));
    assert_eq!(server.user_binds(), 1);
}

/// The gate sits in front of the bind: without `jit_provisioning`, a disabled
/// directory or no directory, the provisioning call is `NotConfigured` and not
/// one packet reaches the server — so a name the tenant never asked to
/// provision cannot run up failed binds in the directory.
#[tokio::test]
async fn provisioning_is_refused_before_any_connection_unless_the_tenant_asked() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    for (jit, enabled) in [(false, true), (true, false), (false, false)] {
        let authenticator = RepositoryDirectoryAuthenticator::with_client(
            repo_with(&server, tenant, jit, enabled),
            client(),
        );
        assert_eq!(
            authenticator
                .authenticate_for_provisioning(tenant, "alice", &alice_password())
                .await,
            Err(DirectoryAuthError::NotConfigured)
        );
    }
    let nobody = RepositoryDirectoryAuthenticator::with_client(FakeRepo::default(), client());
    assert_eq!(
        nobody
            .authenticate_for_provisioning(tenant, "alice", &alice_password())
            .await,
        Err(DirectoryAuthError::NotConfigured)
    );
    assert_eq!(server.connections(), 0, "no socket may be opened");
}

/// An empty password is refused first, as for sign-in, and a wrong one is the
/// ordinary invalid-credentials answer.
#[tokio::test]
async fn provisioning_refuses_an_empty_and_a_wrong_password() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let authenticator = RepositoryDirectoryAuthenticator::with_client(
        repo_with(&server, tenant, true, true),
        client(),
    );
    assert_eq!(
        authenticator
            .authenticate_for_provisioning(tenant, "alice", "")
            .await,
        Err(DirectoryAuthError::InvalidCredentials)
    );
    assert_eq!(server.connections(), 0);
    let wrong = format!("{}-not", alice_password());
    assert_eq!(
        authenticator
            .authenticate_for_provisioning(tenant, "alice", &wrong)
            .await,
        Err(DirectoryAuthError::InvalidCredentials)
    );
    assert_eq!(
        authenticator
            .authenticate_for_provisioning(tenant, "nobody", &alice_password())
            .await,
        Err(DirectoryAuthError::InvalidCredentials)
    );
}

/// Lookup finds the entry through the filter and binds nothing as it: only the
/// service account binds. It is not gated on `jit_provisioning`, but it does
/// need an enabled directory.
#[tokio::test]
async fn lookup_resolves_the_entry_without_a_user_bind() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let authenticator = RepositoryDirectoryAuthenticator::with_client(
        repo_with(&server, tenant, false, true),
        client(),
    );
    let identity = authenticator
        .lookup_entry(tenant, "alice")
        .await
        .expect("lookup is not gated on jit_provisioning");
    assert_eq!(identity.external_id, "00000000-0000-4000-8000-00000000a11c");
    assert_eq!(server.service_binds(), 1);
    assert_eq!(server.user_binds(), 0, "a lookup binds as nobody");

    assert_eq!(
        authenticator.lookup_entry(tenant, "nobody").await,
        Err(DirectoryAuthError::InvalidCredentials)
    );
}

/// The lookup escapes the login name like every other path: a filter-injection
/// attempt is data and matches nothing (the filter itself is pinned in
/// `client_test.rs`; this is the lookup's own door).
#[tokio::test]
async fn lookup_escapes_the_login_name() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let authenticator = RepositoryDirectoryAuthenticator::with_client(
        repo_with(&server, tenant, false, true),
        client(),
    );
    assert_eq!(
        authenticator.lookup_entry(tenant, "*)(uid=*").await,
        Err(DirectoryAuthError::InvalidCredentials)
    );
    assert_eq!(server.user_binds(), 0);
}

#[tokio::test]
async fn lookup_without_an_enabled_directory_is_not_configured() {
    let server = server().await;
    let tenant = Uuid::new_v4();
    let disabled = RepositoryDirectoryAuthenticator::with_client(
        repo_with(&server, tenant, true, false),
        client(),
    );
    assert_eq!(
        disabled.lookup_entry(tenant, "alice").await,
        Err(DirectoryAuthError::NotConfigured)
    );
    assert_eq!(server.connections(), 0);
}
