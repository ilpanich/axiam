//! The LDAP client against the in-process test directory (`tests/support`).
//!
//! Every security property of T23.3.2's client is asserted on what reached the
//! server, not on what the client reports: the filter the server parsed, the
//! binds it received and whether each arrived encrypted, the connections it
//! saw. Test names say which property each one pins; assertion messages name
//! the case and never carry a password, a secret or a DN from a fixture.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axiam_core::models::directory::{
    DirectoryAccountRestriction, DirectoryAuthError, DirectoryKind,
};
use axiam_directory::client::{ClientLimits, DirectoryClient, DirectoryTarget};
use axiam_directory::tls::client_config;
use ldap3_proto::proto::{LdapDerefAliases, LdapFilter, LdapResultCode};
use support::{
    BASE_DN, Entry, Event, SERVICE_DN, Script, TestCa, TestServer, Transport, alice_password,
    service_secret,
};
use uuid::Uuid;

const ALICE_UUID: &str = "6F9619FF-8B86-D011-B42D-00C04FC964FF";

fn alice() -> Entry {
    Entry::person("alice", &alice_password(), ALICE_UUID)
}

fn target_for(server: &TestServer, tenant_id: Uuid) -> DirectoryTarget {
    DirectoryTarget {
        tenant_id,
        generation: "g1".into(),
        url: format!("ldaps://localhost:{}", server.port()),
        start_tls: false,
        bind_dn: SERVICE_DN.into(),
        base_dn: BASE_DN.into(),
        user_filter: "(&(objectClass=person)(uid={username}))".into(),
        attributes: DirectoryKind::OpenLdap.default_user_attribute_map(),
        tls: client_config(std::slice::from_ref(&server.ca.pem)).unwrap(),
    }
}

fn starttls_target(server: &TestServer) -> DirectoryTarget {
    DirectoryTarget {
        url: format!("ldap://localhost:{}", server.port()),
        start_tls: true,
        ..target_for(server, Uuid::new_v4())
    }
}

fn fast_limits() -> ClientLimits {
    ClientLimits {
        acquire_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(500),
        operation_timeout: Duration::from_millis(500),
        authentication_deadline: Duration::from_secs(3),
        ..ClientLimits::default()
    }
}

async fn auth(
    client: &DirectoryClient,
    target: &DirectoryTarget,
    login: &str,
    password: &str,
) -> Result<axiam_core::models::directory::DirectoryIdentity, DirectoryAuthError> {
    client
        .authenticate(target, &service_secret(), login, password)
        .await
}

/// The whole flow over `ldaps://`: service bind, one search with the escaped
/// filter, user bind as the returned DN, identity back.
#[tokio::test]
async fn bind_as_user_succeeds_over_ldaps() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let target = target_for(&server, Uuid::new_v4());

    let identity = auth(&client, &target, "alice", &alice_password())
        .await
        .expect("a correct directory password must authenticate");
    // entryUUID normalised to lowercase hyphenated form.
    assert_eq!(identity.external_id, ALICE_UUID.to_ascii_lowercase());
    assert_eq!(identity.username.as_deref(), Some("alice"));
    assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
    assert_eq!(identity.dn, alice().dn);

    let binds = server.binds();
    assert_eq!(binds.len(), 2, "one service bind, one user bind");
    assert_eq!(binds[0].0, SERVICE_DN);
    assert_eq!(binds[1].0, alice().dn);
    assert!(binds.iter().all(|(_, encrypted, _)| *encrypted));
    assert!(binds.iter().all(|(_, _, empty)| !*empty));

    let events = server.events();
    let search = events
        .iter()
        .find_map(|e| match e {
            Event::Search {
                base,
                sizelimit,
                deref,
                attrs,
                encrypted,
                ..
            } => Some((
                base.clone(),
                *sizelimit,
                deref.clone(),
                attrs.clone(),
                *encrypted,
            )),
            _ => None,
        })
        .expect("a search");
    assert_eq!(search.0, BASE_DN);
    assert_eq!(search.1, 2, "size limit 2 on the user lookup");
    assert_eq!(search.2, LdapDerefAliases::Never);
    assert_eq!(search.3, vec!["entryUUID", "uid", "mail", "displayName"]);
    assert!(search.4);
}

/// StartTLS: the upgrade happens before anything else, and every bind is
/// encrypted.
#[tokio::test]
async fn bind_as_user_succeeds_over_starttls_and_nothing_precedes_the_upgrade() {
    let server = TestServer::start(Script {
        transport: Transport::StartTls,
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let target = starttls_target(&server);

    auth(&client, &target, "alice", &alice_password())
        .await
        .expect("StartTLS sign-in must succeed");

    let binds = server.binds();
    assert_eq!(binds.len(), 2);
    assert!(
        binds.iter().all(|(_, encrypted, _)| *encrypted),
        "no bind may arrive before the TLS upgrade"
    );
    // On each connection, StartTLS is the first thing the server hears.
    let events = server.events();
    let mut expect_starttls = false;
    for event in &events {
        match event {
            Event::Connected => expect_starttls = true,
            Event::StartTlsRequested => expect_starttls = false,
            other => assert!(
                !expect_starttls,
                "an operation preceded StartTLS: {other:?}"
            ),
        }
    }
}

/// TLS 1.2 is the floor, and it is accepted.
#[tokio::test]
async fn a_tls_1_2_only_directory_is_accepted() {
    let server = TestServer::start(Script {
        tls12_only: true,
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    assert!(
        auth(
            &client,
            &target_for(&server, Uuid::new_v4()),
            "alice",
            &alice_password()
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn a_wrong_password_is_invalid_credentials() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &axiam_test_support::other_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::InvalidCredentials);
    assert_eq!(server.user_binds(), 1, "the directory decided");
}

/// A certificate that does not chain to the tenant's anchors: refused at the
/// handshake, before any bind.
#[tokio::test]
async fn a_certificate_outside_the_tenant_anchors_is_refused_before_any_bind() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let mut target = target_for(&server, Uuid::new_v4());
    target.tls = client_config(&[TestCa::new().pem]).unwrap();

    let outcome = auth(&client, &target, "alice", &alice_password()).await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(
        server.binds().is_empty(),
        "no bind may be sent to an untrusted server"
    );
    assert!(!server.events().contains(&Event::TlsEstablished));
}

/// The public bundle does not vouch for a private CA either: an empty anchor
/// list is not "trust anything".
#[tokio::test]
async fn the_public_bundle_does_not_trust_a_private_ca() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let mut target = target_for(&server, Uuid::new_v4());
    target.tls = client_config(&[]).unwrap();
    let outcome = auth(&client, &target, "alice", &alice_password()).await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(server.binds().is_empty());
}

/// A certificate from the right CA for the wrong name: refused, no bind.
#[tokio::test]
async fn a_server_name_mismatch_is_refused_before_any_bind() {
    let server = TestServer::start(Script {
        cert_names: vec!["directory.other.example".into()],
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(
        server.binds().is_empty(),
        "no bind may be sent to a mis-named server"
    );
}

/// A server that refuses StartTLS — and would accept a bind in the clear —
/// receives no bind at all.
#[tokio::test]
async fn a_refused_starttls_fails_closed_with_no_bind_in_the_clear() {
    let server = TestServer::start(Script {
        transport: Transport::StartTlsRefused,
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &starttls_target(&server),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(server.events().contains(&Event::StartTlsRequested));
    assert!(
        server.binds().is_empty(),
        "no bind may follow a refused StartTLS"
    );
    assert!(server.search_filters().is_empty());
}

/// A plaintext target never reaches a socket, whatever the caller built.
#[tokio::test]
async fn a_plaintext_target_is_refused_with_zero_connections() {
    let server = TestServer::start(Script {
        transport: Transport::StartTlsRefused,
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let mut target = starttls_target(&server);
    target.start_tls = false; // ldap:// without StartTLS
    let outcome = auth(&client, &target, "alice", &alice_password()).await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Misconfigured);
    assert_eq!(server.connections(), 0);
}

/// Search result references point elsewhere; they are skipped, never chased,
/// and never counted as a match. A second server stands in for the referred
/// host and must see no connection.
#[tokio::test]
async fn search_references_are_neither_followed_nor_matched() {
    let elsewhere = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let referral = format!("ldaps://localhost:{}/{BASE_DN}", elsewhere.port());

    // References only, no entry: the generic failure.
    let server = TestServer::start(Script {
        search_references: vec![referral.clone(), referral.clone()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::InvalidCredentials);
    assert_eq!(server.user_binds(), 0);

    // References beside one real entry: the reference is ignored, the entry is
    // the single match.
    let server = TestServer::start(Script {
        search_references: vec![referral],
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    assert!(
        auth(
            &client,
            &target_for(&server, Uuid::new_v4()),
            "alice",
            &alice_password()
        )
        .await
        .is_ok()
    );
    assert_eq!(
        elsewhere.connections(),
        0,
        "a reference must never be chased"
    );
}

/// A search that ends in a `referral` result is a misconfiguration, never a
/// redirect.
#[tokio::test]
async fn a_referral_result_is_not_followed() {
    let elsewhere = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let server = TestServer::start(Script {
        search_done: Some((
            LdapResultCode::Referral,
            vec![format!("ldaps://localhost:{}/{BASE_DN}", elsewhere.port())],
        )),
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Misconfigured);
    assert_eq!(
        elsewhere.connections(),
        0,
        "a referral must never be chased"
    );
    assert_eq!(server.user_binds(), 0);
}

#[tokio::test]
async fn zero_matches_is_the_generic_failure_without_a_user_bind() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "nobody",
        &axiam_test_support::other_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::InvalidCredentials);
    assert_eq!(server.user_binds(), 0);
}

#[tokio::test]
async fn two_matches_is_the_generic_failure_without_a_user_bind() {
    let mut twin = Entry::person(
        "alice",
        &alice_password(),
        "00000000-0000-4000-8000-000000000002",
    );
    twin.dn = format!("uid=alice,ou=contractors,{BASE_DN}");
    let server = TestServer::start(Script {
        entries: vec![alice(), twin],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::InvalidCredentials);
    assert_eq!(
        server.user_binds(),
        0,
        "an ambiguous match must never be bound"
    );
}

/// The filter-injection attempt. The server parses what it received; it must
/// be the tenant's template with a single equality assertion whose value is
/// the literal login name — never a widened filter. The server would match
/// `(uid=*)` against everyone, so a widened filter would also have shown up as
/// a match (and a user bind).
#[tokio::test]
async fn filter_injection_reaches_the_server_as_a_literal_value() {
    let server = TestServer::start(Script {
        entries: vec![
            alice(),
            Entry::person(
                "bob",
                &axiam_test_support::other_password(),
                "00000000-0000-4000-8000-0000000000b0",
            ),
        ],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let target = target_for(&server, Uuid::new_v4());

    let hostile = [
        "*",
        ")(uid=*",
        "*)(|(objectClass=*",
        "admin)(&",
        "\\",
        "al*",
    ];
    for login in hostile {
        let outcome = auth(&client, &target, login, &alice_password()).await;
        assert_eq!(
            outcome.unwrap_err(),
            DirectoryAuthError::InvalidCredentials,
            "an injection attempt must not authenticate"
        );
    }
    assert_eq!(
        server.user_binds(),
        0,
        "no injection attempt may reach a user bind"
    );

    let filters = server.search_filters();
    assert_eq!(filters.len(), hostile.len());
    for (filter, login) in filters.iter().zip(hostile) {
        assert_eq!(
            filter,
            &LdapFilter::And(vec![
                LdapFilter::Equality("objectClass".into(), "person".into()),
                LdapFilter::Equality("uid".into(), login.into()),
            ]),
            "the server must see the template with the login as one literal value"
        );
    }
}

/// UTF-8 survives the octet-by-octet escaping and is matched as itself.
#[tokio::test]
async fn a_utf8_login_name_is_matched_as_itself() {
    let jose_password = axiam_test_support::other_password();
    let server = TestServer::start(Script {
        entries: vec![Entry::person(
            "josé",
            &jose_password,
            "00000000-0000-4000-8000-00000000000e",
        )],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    assert!(
        auth(
            &client,
            &target_for(&server, Uuid::new_v4()),
            "josé",
            &jose_password
        )
        .await
        .is_ok()
    );
}

/// An empty password would be an RFC 4513 unauthenticated bind, which this
/// server (like many) accepts as success. It is refused with zero packets.
#[tokio::test]
async fn an_empty_password_is_refused_with_zero_packets() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let empty = String::new();
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &empty,
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::InvalidCredentials);
    assert_eq!(server.connections(), 0, "no connection may be opened");
}

/// Active Directory reports a disabled account as `invalidCredentials` with
/// `data 533` in the diagnostic.
#[tokio::test]
async fn an_active_directory_disabled_account_is_refused() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        user_bind_result: Some((
            LdapResultCode::InvalidCredentials,
            "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 533, v4563"
                .into(),
        )),
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(
        outcome.unwrap_err(),
        DirectoryAuthError::AccountRestricted(DirectoryAccountRestriction::Disabled)
    );
}

/// An Active Directory entry: `sAMAccountName` and a binary `objectGUID`,
/// decoded the way AD displays it.
#[tokio::test]
async fn an_active_directory_object_guid_is_decoded() {
    let guid_bytes = vec![
        0xff, 0x19, 0x96, 0x6f, 0x86, 0x8b, 0x11, 0xd0, 0xb4, 0x2d, 0x00, 0xc0, 0x4f, 0xc9, 0x64,
        0xff,
    ];
    let entry = Entry {
        dn: format!("CN=Alice,CN=Users,{BASE_DN}"),
        password: alice_password(),
        attrs: vec![
            ("objectClass".into(), vec![b"person".to_vec()]),
            ("sAMAccountName".into(), vec![b"alice".to_vec()]),
            ("objectGUID".into(), vec![guid_bytes]),
        ],
    };
    let server = TestServer::start(Script {
        entries: vec![entry],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let mut target = target_for(&server, Uuid::new_v4());
    target.attributes = DirectoryKind::ActiveDirectory.default_user_attribute_map();
    target.user_filter = "(&(objectClass=person)(sAMAccountName={username}))".into();
    let identity = auth(&client, &target, "alice", &alice_password())
        .await
        .unwrap();
    assert_eq!(identity.external_id, "6f9619ff-8b86-d011-b42d-00c04fc964ff");
    assert_eq!(identity.email, None);
}

/// The pool reuses a service-bound connection and never a user-bound one: the
/// second sign-in performs no second service bind, and its search succeeds —
/// which this server allows only on a connection bound as the service account.
#[tokio::test]
async fn the_pool_reuses_service_connections_and_never_user_bound_ones() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let tenant = Uuid::new_v4();
    let target = target_for(&server, tenant);

    for _ in 0..3 {
        auth(&client, &target, "alice", &alice_password())
            .await
            .unwrap();
    }
    assert_eq!(
        server.service_binds(),
        1,
        "the service connection is pooled"
    );
    assert_eq!(
        server.user_binds(),
        3,
        "each user bind is its own connection"
    );
    assert_eq!(client.idle_connections(tenant), 1);
    // Each user bind connection was unbound and closed. The server records the
    // unbind on its own task, so allow it a moment to catch up.
    let unbinds = || {
        server
            .events()
            .iter()
            .filter(|e| **e == Event::Unbind)
            .count()
    };
    let started = Instant::now();
    while unbinds() < 3 && started.elapsed() < Duration::from_secs(2) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(unbinds(), 3);

    // A new configuration generation discards the pooled connection.
    let mut changed = target.clone();
    changed.generation = "g2".into();
    auth(&client, &changed, "alice", &alice_password())
        .await
        .unwrap();
    assert_eq!(server.service_binds(), 2);
}

/// Pool bounds: with two connections per tenant and one idle, a burst of
/// concurrent sign-ins against a slow directory never has more than three
/// sockets open at once, and the overflow fails fast instead of queueing.
#[tokio::test]
async fn the_pool_bounds_concurrent_connections_per_tenant() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        bind_delay: Some(Duration::from_millis(200)),
        ..Script::default()
    })
    .await;
    let limits = ClientLimits {
        max_connections_per_tenant: 2,
        max_idle_per_tenant: 1,
        acquire_timeout: Duration::from_millis(100),
        connect_timeout: Duration::from_secs(2),
        operation_timeout: Duration::from_secs(2),
        authentication_deadline: Duration::from_secs(5),
        ..ClientLimits::default()
    };
    let client = Arc::new(DirectoryClient::new(limits));
    let target = target_for(&server, Uuid::new_v4());

    let mut tasks = Vec::new();
    for _ in 0..12 {
        let client = Arc::clone(&client);
        let target = target.clone();
        tasks.push(tokio::spawn(async move {
            client
                .authenticate(&target, &service_secret(), "alice", &alice_password())
                .await
        }));
    }
    let mut ok = 0;
    let mut unavailable = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => ok += 1,
            Err(DirectoryAuthError::Unavailable) => unavailable += 1,
            Err(other) => panic!("unexpected outcome under load: {other:?}"),
        }
    }
    assert!(ok >= 1, "some sign-ins must complete");
    assert!(unavailable >= 1, "the overflow must be refused, not queued");
    assert!(
        server.max_concurrent_connections() <= 3,
        "at most max_connections_per_tenant + max_idle_per_tenant sockets"
    );
    assert!(client.idle_connections(target.tenant_id) <= 1);
}

/// One tenant's exhausted pool does not starve another's.
#[tokio::test]
async fn pools_are_partitioned_by_tenant() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let limits = ClientLimits {
        max_connections_per_tenant: 1,
        ..fast_limits()
    };
    let client = DirectoryClient::new(limits);
    let a = target_for(&server, Uuid::new_v4());
    let b = target_for(&server, Uuid::new_v4());
    auth(&client, &a, "alice", &alice_password()).await.unwrap();
    auth(&client, &b, "alice", &alice_password()).await.unwrap();
    assert_eq!(client.idle_connections(a.tenant_id), 1);
    assert_eq!(client.idle_connections(b.tenant_id), 1);
    assert_eq!(
        server.service_binds(),
        2,
        "no connection is shared across tenants"
    );
}

/// A server that accepts TCP and never speaks: the connect timeout fires.
#[tokio::test]
async fn a_silent_directory_times_out_at_connect() {
    let server = TestServer::start(Script {
        transport: Transport::Silent,
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let started = Instant::now();
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// A server that stalls on bind: the operation timeout fires.
#[tokio::test]
async fn a_stalling_directory_times_out_per_operation() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        bind_delay: Some(Duration::from_secs(10)),
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let started = Instant::now();
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// The end-to-end deadline bounds the whole flow even when each step is
/// individually within its own timeout.
#[tokio::test]
async fn the_authentication_deadline_bounds_the_whole_flow() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        bind_delay: Some(Duration::from_millis(400)),
        ..Script::default()
    })
    .await;
    let limits = ClientLimits {
        operation_timeout: Duration::from_secs(2),
        authentication_deadline: Duration::from_millis(600),
        ..fast_limits()
    };
    let client = DirectoryClient::new(limits);
    let started = Instant::now();
    let outcome = auth(
        &client,
        &target_for(&server, Uuid::new_v4()),
        "alice",
        &alice_password(),
    )
    .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(started.elapsed() < Duration::from_millis(1500));
}

/// A wrong service secret is the operator's problem, not the user's: it is a
/// misconfiguration and no user bind follows.
#[tokio::test]
async fn a_refused_service_bind_is_a_misconfiguration() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(fast_limits());
    let outcome = client
        .authenticate(
            &target_for(&server, Uuid::new_v4()),
            &axiam_test_support::other_password(),
            "alice",
            &alice_password(),
        )
        .await;
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Misconfigured);
    assert_eq!(server.user_binds(), 0);
}
