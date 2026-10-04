//! The connector's two guards against the in-process test directory
//! (T23.3.7, D-19): the address guard that closes T-300 — every refused class,
//! the operator's allow-list, AXIAM's own listeners, DNS rebinding, the pinned
//! address with the URL's host as the TLS name — and the frame guard that
//! closes P23W2-10 (T-295, T-331): an over-long declared length, nesting past
//! any stack and an envelope `ldap3` would panic on, each ending the
//! connection at once.
//!
//! The host name used throughout, `directory.test`, is one the system resolver
//! cannot answer: a connection that reached the server through it used the
//! address the test's resolver gave, and nothing else resolved the name.

mod support;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axiam_core::models::directory::{DirectoryAuthError, DirectoryIdentity, DirectoryKind};
use axiam_directory::address::{AddressPolicy, GuardError, parse_allowed_networks};
use axiam_directory::client::{ClientLimits, DirectoryClient, DirectoryTarget};
use axiam_directory::tls::client_config;
use support::{
    BASE_DN, Entry, Event, SERVICE_DN, Script, ScriptedResolver, TestServer, Transport,
    alice_password, service_secret,
};
use uuid::Uuid;

const HOST: &str = "directory.test";
const ALICE_UUID: &str = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";

fn alice() -> Entry {
    Entry::person("alice", &alice_password(), ALICE_UUID)
}

fn ip(literal: &str) -> IpAddr {
    literal.parse().expect("literal parses")
}

fn limits() -> ClientLimits {
    ClientLimits {
        acquire_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_secs(1),
        operation_timeout: Duration::from_secs(3),
        authentication_deadline: Duration::from_secs(6),
        ..ClientLimits::default()
    }
}

fn target(server: &TestServer, url: String, start_tls: bool) -> DirectoryTarget {
    DirectoryTarget {
        tenant_id: Uuid::new_v4(),
        generation: "g1".into(),
        url,
        start_tls,
        bind_dn: SERVICE_DN.into(),
        base_dn: BASE_DN.into(),
        user_filter: "(&(objectClass=person)(uid={username}))".into(),
        attributes: DirectoryKind::OpenLdap.default_user_attribute_map(),
        tls: client_config(std::slice::from_ref(&server.ca.pem)).unwrap(),
    }
}

fn ldaps_by_name(server: &TestServer) -> DirectoryTarget {
    target(server, format!("ldaps://{HOST}:{}", server.port()), false)
}

/// The production policy (strict) with a scripted resolver.
fn strict(resolver: Arc<ScriptedResolver>) -> DirectoryClient {
    DirectoryClient::new(limits()).with_resolver(resolver)
}

/// The test seam (loopback admitted, everything else strict) with a scripted
/// resolver.
fn seam(resolver: Arc<ScriptedResolver>) -> DirectoryClient {
    support::loopback_client(limits()).with_resolver(resolver)
}

async fn sign_in(
    client: &DirectoryClient,
    target: &DirectoryTarget,
) -> Result<DirectoryIdentity, DirectoryAuthError> {
    client
        .authenticate(target, &service_secret(), "alice", &alice_password())
        .await
}

async fn server_for_host() -> TestServer {
    TestServer::start(Script {
        cert_names: vec![HOST.into()],
        entries: vec![alice()],
        ..Script::default()
    })
    .await
}

/// Every class D-19 names, in both families and in the IPv4-mapped spelling,
/// reached through a name: refused by `guard` (what the management routes call
/// before saving) and again at connect, with no connection opened.
#[tokio::test]
async fn each_refused_class_is_refused_at_guard_and_at_connect_with_no_connection() {
    let server = server_for_host().await;
    let cases: &[(&str, GuardError)] = &[
        ("127.0.0.1", GuardError::Loopback),
        ("::1", GuardError::Loopback),
        ("::ffff:127.0.0.1", GuardError::Loopback),
        ("169.254.169.254", GuardError::LinkLocal),
        ("::ffff:169.254.169.254", GuardError::LinkLocal),
        ("fe80::1", GuardError::LinkLocal),
        ("0.0.0.0", GuardError::Unspecified),
        ("::", GuardError::Unspecified),
        ("224.0.0.1", GuardError::Multicast),
        ("ff02::1", GuardError::Multicast),
        ("10.0.0.1", GuardError::PrivateNotAllowed),
        ("fd00::1", GuardError::PrivateNotAllowed),
        ("100.64.0.1", GuardError::PrivateNotAllowed),
    ];
    for (address, expected) in cases {
        let resolver = ScriptedResolver::new(HOST, vec![vec![ip(address)]]);
        let client = strict(Arc::clone(&resolver));
        let target = ldaps_by_name(&server);
        assert_eq!(
            client.guard(&target.url).await.unwrap_err(),
            *expected,
            "{address} at guard"
        );
        assert_eq!(
            sign_in(&client, &target).await.unwrap_err(),
            DirectoryAuthError::Misconfigured,
            "{address} at connect"
        );
    }
    // The same through literal URLs, which never reach a resolver.
    let resolver = ScriptedResolver::new(HOST, vec![]);
    let client = strict(Arc::clone(&resolver));
    for (url, expected) in [
        (
            format!("ldaps://127.0.0.1:{}", server.port()),
            GuardError::Loopback,
        ),
        ("ldaps://169.254.169.254".to_string(), GuardError::LinkLocal),
        ("ldaps://0.0.0.0".to_string(), GuardError::Unspecified),
        ("ldaps://[::1]".to_string(), GuardError::Ipv6Literal),
    ] {
        assert_eq!(client.guard(&url).await.unwrap_err(), expected, "{url}");
        let literal = target(&server, url.clone(), false);
        assert_eq!(
            sign_in(&client, &literal).await.unwrap_err(),
            DirectoryAuthError::Misconfigured,
            "{url} at connect"
        );
    }
    assert_eq!(resolver.questions(), 0, "a literal host is never resolved");
    assert_eq!(
        server.connections(),
        0,
        "no refused address was ever dialled"
    );
}

/// `localhost` itself, through the system resolver: the production policy
/// refuses a name that resolves to loopback.
#[tokio::test]
async fn a_hostname_that_resolves_to_loopback_is_refused() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let client = DirectoryClient::new(limits());
    let localhost = target(
        &server,
        format!("ldaps://localhost:{}", server.port()),
        false,
    );
    assert_eq!(
        client.guard(&localhost.url).await.unwrap_err(),
        GuardError::Loopback
    );
    assert_eq!(
        sign_in(&client, &localhost).await.unwrap_err(),
        DirectoryAuthError::Misconfigured
    );
    assert_eq!(server.connections(), 0);
}

/// AXIAM's own listener ports are refused on this host's addresses — even
/// where the address itself is admitted (here, loopback through the seam) —
/// and an unrelated port on the same address is not.
#[tokio::test]
async fn an_own_listener_port_is_refused_and_another_port_is_not() {
    let server = server_for_host().await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    let listening_here = DirectoryClient::new(limits())
        .with_resolver(Arc::clone(&resolver) as _)
        .with_address_policy(Arc::new(
            AddressPolicy::new()
                .admitting_loopback_for_tests()
                .with_listener_ports([server.port()]),
        ));
    let target = ldaps_by_name(&server);
    assert_eq!(
        listening_here.guard(&target.url).await.unwrap_err(),
        GuardError::OwnListener
    );
    assert_eq!(
        sign_in(&listening_here, &target).await.unwrap_err(),
        DirectoryAuthError::Misconfigured
    );
    assert_eq!(server.connections(), 0);

    let listening_elsewhere = DirectoryClient::new(limits())
        .with_resolver(resolver as _)
        .with_address_policy(Arc::new(
            AddressPolicy::new()
                .admitting_loopback_for_tests()
                .with_listener_ports([server.port().wrapping_add(1)]),
        ));
    let identity = sign_in(&listening_elsewhere, &target).await.unwrap();
    assert_eq!(identity.username.as_deref(), Some("alice"));
}

/// A private address is refused by the production policy and admitted when
/// the operator's allow-list covers it — and only then.
#[tokio::test]
async fn a_private_address_is_refused_without_the_allow_list_and_admitted_with_it() {
    let server = server_for_host().await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("10.255.255.1")]]);
    let target = ldaps_by_name(&server);

    let without = strict(Arc::clone(&resolver));
    assert_eq!(
        without.guard(&target.url).await.unwrap_err(),
        GuardError::PrivateNotAllowed
    );
    assert_eq!(
        sign_in(&without, &target).await.unwrap_err(),
        DirectoryAuthError::Misconfigured
    );

    let (elsewhere, _) = parse_allowed_networks("192.168.0.0/16");
    let wrong_network = strict(Arc::clone(&resolver)).with_address_policy(Arc::new(
        AddressPolicy::new().with_allowed_private_networks(elsewhere),
    ));
    assert_eq!(
        wrong_network.guard(&target.url).await.unwrap_err(),
        GuardError::PrivateNotAllowed
    );

    let (corporate, rejected) = parse_allowed_networks("10.0.0.0/8");
    assert!(rejected.is_empty());
    let with = strict(Arc::clone(&resolver)).with_address_policy(Arc::new(
        AddressPolicy::new().with_allowed_private_networks(corporate),
    ));
    let admitted = with.guard(&target.url).await.unwrap();
    assert_eq!(admitted.host, HOST);
    assert_eq!(
        admitted.addresses,
        vec![std::net::SocketAddr::new(ip("10.255.255.1"), server.port())]
    );
    // Past the guard, the connection is attempted (and this unroutable test
    // address does not answer): the directory is unavailable, not refused.
    assert_eq!(
        sign_in(&with, &target).await.unwrap_err(),
        DirectoryAuthError::Unavailable
    );
}

/// A public address passes the production policy untouched.
#[tokio::test]
async fn a_public_address_is_admitted() {
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("93.184.216.34")]]);
    let client = strict(Arc::clone(&resolver));
    let admitted = client.guard(&format!("ldaps://{HOST}")).await.unwrap();
    assert_eq!(admitted.port, 636);
    assert_eq!(admitted.addresses.len(), 1);
}

/// DNS rebinding: the name answers a public address when the configuration is
/// checked and loopback when the connector comes to connect. The connect-time
/// guard refuses it; the loopback directory never hears from AXIAM.
#[tokio::test]
async fn dns_rebinding_between_check_and_connect_never_reaches_loopback() {
    let server = server_for_host().await;
    let resolver =
        ScriptedResolver::new(HOST, vec![vec![ip("93.184.216.34")], vec![ip("127.0.0.1")]]);
    let client = strict(Arc::clone(&resolver));
    let target = ldaps_by_name(&server);
    assert!(
        client.guard(&target.url).await.is_ok(),
        "the check sees a public address"
    );
    assert_eq!(
        sign_in(&client, &target).await.unwrap_err(),
        DirectoryAuthError::Misconfigured
    );
    assert_eq!(
        resolver.questions(),
        2,
        "one answer for the check, one for the connect"
    );
    assert_eq!(
        server.connections(),
        0,
        "the rebound address was never dialled"
    );
}

/// The pinned address is the one used: the name is unresolvable by anything
/// but the test's resolver, the sign-in succeeds, and the resolver was asked
/// exactly once per connection the server saw — nothing resolved it again
/// between the check and the connect.
#[tokio::test]
async fn the_connection_uses_the_pinned_address_and_resolves_once_per_connection() {
    let server = server_for_host().await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    let client = seam(Arc::clone(&resolver));
    let identity = sign_in(&client, &ldaps_by_name(&server)).await.unwrap();
    assert_eq!(identity.username.as_deref(), Some("alice"));
    assert!(server.connections() >= 2, "a service and a user connection");
    assert_eq!(resolver.questions(), server.connections());
}

/// The TLS server name stays the URL's host over a pinned address, for
/// `ldaps://` and for StartTLS.
#[tokio::test]
async fn the_tls_name_checked_is_the_hostname_over_a_pinned_address() {
    let ldaps = server_for_host().await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    let client = seam(Arc::clone(&resolver));
    assert!(sign_in(&client, &ldaps_by_name(&ldaps)).await.is_ok());

    let starttls = TestServer::start(Script {
        transport: Transport::StartTls,
        cert_names: vec![HOST.into()],
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let over_starttls = target(
        &starttls,
        format!("ldap://{HOST}:{}", starttls.port()),
        true,
    );
    assert!(sign_in(&client, &over_starttls).await.is_ok());
    assert!(
        starttls
            .events()
            .iter()
            .position(|e| *e == Event::TlsEstablished)
            < starttls
                .events()
                .iter()
                .position(|e| matches!(e, Event::Bind { .. })),
        "the upgrade completes before any bind"
    );
    assert!(starttls.binds().iter().all(|(_, encrypted, _)| *encrypted));
}

/// A certificate naming only the address is not a certificate for the host,
/// and a certificate for the host is not one for a literal address: the name
/// checked is what the URL says, as T23.3.2 pinned it.
#[tokio::test]
async fn a_certificate_for_the_address_alone_does_not_pass_for_the_hostname() {
    let ip_only = TestServer::start(Script {
        cert_names: vec!["127.0.0.1".into()],
        entries: vec![alice()],
        ..Script::default()
    })
    .await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    let client = seam(Arc::clone(&resolver));
    assert_eq!(
        sign_in(&client, &ldaps_by_name(&ip_only))
            .await
            .unwrap_err(),
        DirectoryAuthError::Unavailable
    );
    assert!(ip_only.binds().is_empty(), "no bind to a mis-named server");

    let host_only = server_for_host().await;
    let by_address = target(
        &host_only,
        format!("ldaps://127.0.0.1:{}", host_only.port()),
        false,
    );
    assert_eq!(
        sign_in(&client, &by_address).await.unwrap_err(),
        DirectoryAuthError::Unavailable
    );
    assert!(host_only.binds().is_empty());
}

/// A server that answers the user search with `raw` and then holds the
/// connection open, saying nothing more.
async fn hostile(raw: Vec<u8>) -> TestServer {
    TestServer::start(Script {
        cert_names: vec![HOST.into()],
        entries: vec![alice()],
        raw_user_search_reply: Some(raw),
        ..Script::default()
    })
    .await
}

/// Sign in against `server` and assert the frame guard ended it: the
/// directory unavailable, long before the operation timeout `ldap3` would
/// otherwise have waited out, and the connection closed by AXIAM.
async fn assert_aborted_promptly(server: &TestServer, client: &DirectoryClient) {
    let started = Instant::now();
    let outcome = sign_in(client, &ldaps_by_name(server)).await;
    let elapsed = started.elapsed();
    assert_eq!(outcome.unwrap_err(), DirectoryAuthError::Unavailable);
    assert!(
        elapsed < Duration::from_millis(1500),
        "aborted at once, not after the 3 s operation timeout (took {elapsed:?})"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while !server.events().contains(&Event::ClosedByClient) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(server.events().contains(&Event::RawReplySent));
    assert!(
        server.events().contains(&Event::ClosedByClient),
        "AXIAM closed the connection"
    );
    assert_eq!(
        server.user_binds(),
        0,
        "nothing was bound after the refusal"
    );
}

/// P23W2-10: a header declaring a two-gigabyte message ends the connection on
/// the spot. Before the guard, `ldap3` would have buffered whatever followed
/// until the operation timeout.
#[tokio::test]
async fn an_over_long_declared_length_aborts_the_connection_without_waiting_for_it() {
    let server = hostile(vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01]).await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    assert_aborted_promptly(&server, &seam(resolver)).await;
}

/// T-331: nesting deep enough to overflow `lber`'s recursive parser — which
/// would abort the whole process — is refused by the iterative walk instead.
#[tokio::test]
async fn nesting_past_any_stack_is_refused_and_the_process_survives() {
    let levels: usize = 20_000;
    let inner_len = |k: usize| u32::try_from(2 + 6 * (k - 1)).unwrap();
    let op_len = u32::try_from(2 + 6 * levels).unwrap();
    let mut raw = vec![0x30, 0x84];
    raw.extend_from_slice(&(3 + 6 + op_len).to_be_bytes());
    raw.extend_from_slice(&[0x02, 0x01, 0x02, 0x64, 0x84]);
    raw.extend_from_slice(&op_len.to_be_bytes());
    for k in (1..=levels).rev() {
        raw.extend_from_slice(&[0x30, 0x84]);
        raw.extend_from_slice(&inner_len(k).to_be_bytes());
    }
    raw.extend_from_slice(&[0x04, 0x00]);
    let server = hostile(raw).await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    assert_aborted_promptly(&server, &seam(resolver)).await;
}

/// T-331: a message id with no operation, which `ldap3`'s decoder `expect`s.
#[tokio::test]
async fn an_envelope_ldap3_would_panic_on_is_refused() {
    let server = hostile(vec![0x30, 0x03, 0x02, 0x01, 0x02]).await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    assert_aborted_promptly(&server, &seam(resolver)).await;
}

/// The cap is the deployment's: an entry larger than a lowered cap is
/// refused, and the same entry passes under the default.
#[tokio::test]
async fn the_cap_is_configurable_and_ordinary_traffic_passes_under_the_default() {
    let large = "x".repeat(100_000);
    let server = TestServer::start(Script {
        cert_names: vec![HOST.into()],
        entries: vec![alice().with_values("displayName", &[&large])],
        ..Script::default()
    })
    .await;
    let resolver = ScriptedResolver::new(HOST, vec![vec![ip("127.0.0.1")]]);
    let tight = seam(Arc::clone(&resolver)).with_max_message_bytes(64 * 1024);
    assert_eq!(tight.max_message_bytes(), 64 * 1024);
    assert_eq!(
        sign_in(&tight, &ldaps_by_name(&server)).await.unwrap_err(),
        DirectoryAuthError::Unavailable
    );
    let default = seam(resolver);
    let identity = sign_in(&default, &ldaps_by_name(&server)).await.unwrap();
    assert_eq!(identity.username.as_deref(), Some("alice"));
}
