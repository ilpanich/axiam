//! The sync job's three directory questions against the in-process TLS
//! directory (T23.3.5, G-3, D-31): look an account's entry up by its immutable
//! identifier, find what changed since a watermark, read the rootDSE.
//!
//! As for the bind flow and the group lookups, every property that is about
//! what reaches the wire is asserted on what the **server** parsed — the filter,
//! the base and scope, the bind that carried it — not on what the client says it
//! sent. Assertion messages name the case; they never carry a credential, a DN
//! or an identifier.

mod support;

use std::sync::Arc;
use std::time::Duration;

use axiam_core::models::directory::{DirectoryAuthError, DirectoryConfig, DirectoryKind};
use axiam_directory::client::{ClientLimits, DirectoryClient, DirectoryTarget};
use axiam_directory::sync_lookup::{DirectorySession, EntryLookup};
use axiam_directory::tls::client_config;
use chrono::Utc;
use ldap3_proto::proto::{LdapFilter, LdapResultCode, LdapSearchScope};
use support::{
    BASE_DN, Entry, Event, SERVICE_DN, Script, TestServer, alice_password, service_secret,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const ALICE_UUID: &str = "00000000-0000-4000-8000-00000000a11c";
const BOB_UUID: &str = "00000000-0000-4000-8000-0000000000b0";

/// Sixteen octets in the ASCII range, each of them one RFC 4515 has to escape
/// or a printable that must pass through the binary escaper as `\XX` anyway:
/// `*`, `(`, `)`, `\`, NUL. (The test directory's codec holds filter values as
/// UTF-8 text, so the fixture stays below `0x80`; the escaper's behaviour on
/// the high half is pinned by its unit tests.)
const HOSTILE_GUID_BYTES: [u8; 16] = [
    0x2a, 0x28, 0x29, 0x5c, 0x00, 0x41, 0x42, 0x43, 0x44, 0x2a, 0x29, 0x28, 0x5c, 0x5c, 0x00, 0x7f,
];

fn alice() -> Entry {
    Entry::person("alice", &alice_password(), ALICE_UUID)
}

fn config(server: &TestServer, kind: DirectoryKind) -> DirectoryConfig {
    let now = Utc::now();
    DirectoryConfig {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        enabled: true,
        kind,
        url: format!("ldaps://localhost:{}", server.port()),
        start_tls: false,
        bind_dn: SERVICE_DN.into(),
        base_dn: BASE_DN.into(),
        user_filter: match kind {
            DirectoryKind::OpenLdap => "(uid={username})".into(),
            DirectoryKind::ActiveDirectory => "(sAMAccountName={username})".into(),
        },
        user_attribute_map: kind.default_user_attribute_map(),
        group_base_dn: None,
        group_filter: None,
        group_member_attribute: kind.default_group_member_attribute().into(),
        group_nesting_depth: 5,
        group_mappings: vec![],
        sync_interval_secs: 3600,
        jit_provisioning: true,
        trust_anchors_pem: vec![server.ca.pem.clone()],
        created_at: now,
        updated_at: now,
    }
}

fn session_with(
    server: &TestServer,
    kind: DirectoryKind,
    limits: ClientLimits,
) -> DirectorySession {
    let config = config(server, kind);
    let target = DirectoryTarget {
        tenant_id: config.tenant_id,
        generation: "g1".into(),
        url: config.url.clone(),
        start_tls: false,
        bind_dn: config.bind_dn.clone(),
        base_dn: config.base_dn.clone(),
        user_filter: config.user_filter.clone(),
        attributes: config.user_attribute_map.clone(),
        tls: client_config(std::slice::from_ref(&server.ca.pem)).unwrap(),
    };
    DirectorySession::new(
        config,
        target,
        Zeroizing::new(service_secret()),
        Arc::new(DirectoryClient::new(limits)),
    )
}

fn limits() -> ClientLimits {
    ClientLimits {
        acquire_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(500),
        operation_timeout: Duration::from_millis(500),
        authentication_deadline: Duration::from_secs(3),
        ..ClientLimits::default()
    }
}

fn session(server: &TestServer, kind: DirectoryKind) -> DirectorySession {
    session_with(server, kind, limits())
}

async fn start(entries: Vec<Entry>) -> TestServer {
    TestServer::start(Script {
        entries,
        enforce_sizelimit: true,
        ..Script::default()
    })
    .await
}

fn searches(server: &TestServer) -> Vec<(String, LdapSearchScope, LdapFilter, i32, Vec<String>)> {
    server
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Search {
                base,
                scope,
                filter,
                sizelimit,
                attrs,
                ..
            } => Some((base, scope, filter, sizelimit, attrs)),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// By external id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_entry_is_found_by_its_entry_uuid_under_the_base_with_the_service_account() {
    let server = start(vec![alice()]).await;
    let found = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await
        .unwrap();
    let EntryLookup::Found(entry) = found else {
        panic!("the entry must be found");
    };
    assert_eq!(entry.identity.external_id, ALICE_UUID);
    assert_eq!(entry.identity.username.as_deref(), Some("alice"));
    assert_eq!(entry.identity.email.as_deref(), Some("alice@example.com"));
    assert!(!entry.disabled);

    let sent = searches(&server);
    assert_eq!(sent.len(), 1);
    let (base, scope, filter, sizelimit, attrs) = &sent[0];
    assert!(base.eq_ignore_ascii_case(BASE_DN));
    assert_eq!(*scope, LdapSearchScope::Subtree);
    assert_eq!(
        *filter,
        LdapFilter::Equality("entryUUID".into(), ALICE_UUID.into())
    );
    assert_eq!(*sizelimit, 2, "exactly-one needs one entry more than one");
    for wanted in [
        "entryUUID",
        "uid",
        "mail",
        "displayName",
        "modifyTimestamp",
        "pwdAccountLockedTime",
    ] {
        assert!(attrs.iter().any(|a| a == wanted), "{wanted} is requested");
    }
    // The service account only: no user bind, no password anywhere.
    assert_eq!(server.user_binds(), 0);
    assert_eq!(server.service_binds(), 1);
}

#[tokio::test]
async fn a_completed_search_that_matches_nothing_is_not_found() {
    let server = start(vec![alice()]).await;
    let lookup = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(BOB_UUID)
        .await
        .unwrap();
    assert_eq!(lookup, EntryLookup::NotFound);
}

#[tokio::test]
async fn two_matches_are_ambiguous_never_not_found() {
    let twin = Entry::person("alice-twin", &alice_password(), ALICE_UUID);
    let server = start(vec![alice(), twin]).await;
    let lookup = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await
        .unwrap();
    assert_eq!(lookup, EntryLookup::Ambiguous);
}

/// An entry the filter matched but whose identifier cannot be read as exactly
/// one value is an error: the answer to "does it exist" is not "no", and the
/// account is not read as vanished.
#[tokio::test]
async fn a_match_with_no_readable_identifier_is_an_error_not_a_vanished_account() {
    // Two values of the identifier attribute, one of them the one asked for: the
    // filter matches, the entry cannot be read as having a single identifier.
    let server = start(vec![
        alice().with_values("entryUUID", &[ALICE_UUID, BOB_UUID]),
    ])
    .await;
    let outcome = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await;
    assert_eq!(outcome, Err(DirectoryAuthError::Misconfigured));
}

#[tokio::test]
async fn an_identifier_that_cannot_be_asked_for_is_misconfigured_and_sends_nothing() {
    let server = start(vec![alice()]).await;
    let ad = session(&server, DirectoryKind::ActiveDirectory);
    let outcome = ad.lookup_by_external_id("not-a-guid").await;
    assert_eq!(outcome, Err(DirectoryAuthError::Misconfigured));
    assert!(searches(&server).is_empty(), "nothing is asked");
    assert_eq!(server.connections(), 0, "no connection is opened");
}

/// `objectGUID` is binary and the directory matches the raw octets in the
/// mixed-endian layout: the identifier's text is parsed and written back
/// little-endian, every octet escaped, and the server parses exactly those
/// octets back. `*`, `(`, `)`, `\` and NUL among them neither widen nor break
/// the filter.
#[tokio::test]
async fn an_object_guid_reaches_the_server_as_its_little_endian_octets() {
    let guid = Uuid::from_bytes_le(HOSTILE_GUID_BYTES);
    let entry = Entry::ad_person("alice", &alice_password(), HOSTILE_GUID_BYTES, 100);
    let decoy = Entry::ad_person("decoy", &alice_password(), [0x41; 16], 101);
    let server = start(vec![entry, decoy]).await;

    let found = session(&server, DirectoryKind::ActiveDirectory)
        .lookup_by_external_id(&guid.hyphenated().to_string())
        .await
        .unwrap();
    let EntryLookup::Found(entry) = found else {
        panic!("the entry must be found by its GUID");
    };
    assert_eq!(entry.identity.username.as_deref(), Some("alice"));
    assert_eq!(entry.identity.external_id, guid.hyphenated().to_string());

    let sent = searches(&server);
    assert_eq!(sent.len(), 1);
    let expected: String = HOSTILE_GUID_BYTES.iter().map(|b| char::from(*b)).collect();
    assert_eq!(
        sent[0].2,
        LdapFilter::Equality("objectGUID".into(), expected),
        "the server parsed the very octets, in little-endian order"
    );
}

#[tokio::test]
async fn an_unescaped_guid_would_have_matched_everything_and_this_one_matches_one() {
    // The decoy's identifier is the literal text of a wildcard-bearing GUID; were
    // the octets put in the filter raw, `*` would widen it. Two entries, one hit.
    let server = start(vec![
        Entry::ad_person("alice", &alice_password(), HOSTILE_GUID_BYTES, 1),
        Entry::ad_person("bob", &alice_password(), [0x2a; 16], 2),
        Entry::ad_person("carol", &alice_password(), [0x43; 16], 3),
    ])
    .await;
    let guid = Uuid::from_bytes_le(HOSTILE_GUID_BYTES)
        .hyphenated()
        .to_string();
    let lookup = session(&server, DirectoryKind::ActiveDirectory)
        .lookup_by_external_id(&guid)
        .await
        .unwrap();
    assert!(
        matches!(lookup, EntryLookup::Found(_)),
        "exactly one, not Ambiguous"
    );
}

#[tokio::test]
async fn an_ad_entry_with_the_disabled_bit_reads_as_disabled() {
    let guid = [0x11; 16];
    let server = start(vec![
        Entry::ad_person("alice", &alice_password(), guid, 5)
            .with_values("userAccountControl", &["514"]),
    ])
    .await;
    let EntryLookup::Found(entry) = session(&server, DirectoryKind::ActiveDirectory)
        .lookup_by_external_id(&Uuid::from_bytes_le(guid).hyphenated().to_string())
        .await
        .unwrap()
    else {
        panic!("found");
    };
    assert!(entry.disabled);
    assert_eq!(entry.change_value.as_deref(), Some("5"));
}

#[tokio::test]
async fn an_open_ldap_entry_with_a_locked_time_reads_as_disabled() {
    let server = start(vec![
        alice()
            .with_values("pwdAccountLockedTime", &["000001010000Z"])
            .with_values("modifyTimestamp", &["20261003120000Z"]),
    ])
    .await;
    let EntryLookup::Found(entry) = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await
        .unwrap()
    else {
        panic!("found");
    };
    assert!(entry.disabled);
    assert_eq!(entry.change_value.as_deref(), Some("20261003120000Z"));
}

#[tokio::test]
async fn a_malformed_change_value_is_dropped_not_trusted() {
    let server = start(vec![
        alice().with_values("modifyTimestamp", &["yesterday)(x"]),
    ])
    .await;
    let EntryLookup::Found(entry) = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await
        .unwrap()
    else {
        panic!("found");
    };
    assert!(entry.change_value.is_none());
}

#[tokio::test]
async fn a_referral_is_never_followed_and_is_not_not_found() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        search_done: Some((
            LdapResultCode::Referral,
            vec!["ldap://elsewhere.invalid/".into()],
        )),
        ..Script::default()
    })
    .await;
    let outcome = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await;
    assert_eq!(outcome, Err(DirectoryAuthError::Misconfigured));
    assert_eq!(
        server.connections(),
        1,
        "no second connection to the referral target"
    );
}

#[tokio::test]
async fn a_search_reference_is_skipped_neither_chased_nor_counted() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        search_references: vec!["ldap://elsewhere.invalid/dc=x".into()],
        ..Script::default()
    })
    .await;
    let lookup = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await
        .unwrap();
    assert!(matches!(lookup, EntryLookup::Found(_)));
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn a_busy_directory_is_unavailable_never_not_found() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        search_done: Some((LdapResultCode::Busy, vec![])),
        ..Script::default()
    })
    .await;
    let outcome = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await;
    assert_eq!(outcome, Err(DirectoryAuthError::Unavailable));
}

#[tokio::test]
async fn a_service_account_that_may_not_search_is_misconfigured_not_not_found() {
    let server = TestServer::start(Script {
        entries: vec![alice()],
        search_done: Some((LdapResultCode::InsufficentAccessRights, vec![])),
        ..Script::default()
    })
    .await;
    let outcome = session(&server, DirectoryKind::OpenLdap)
        .lookup_by_external_id(ALICE_UUID)
        .await;
    assert_eq!(outcome, Err(DirectoryAuthError::Misconfigured));
}

#[tokio::test]
async fn an_unreachable_directory_is_unavailable() {
    let server = start(vec![alice()]).await;
    let session = session(&server, DirectoryKind::OpenLdap);
    drop(server);
    assert_eq!(
        session.lookup_by_external_id(ALICE_UUID).await,
        Err(DirectoryAuthError::Unavailable)
    );
}

#[tokio::test]
async fn lookups_reuse_one_pooled_service_connection() {
    let server = start(vec![alice()]).await;
    let session = session(&server, DirectoryKind::OpenLdap);
    for _ in 0..4 {
        assert!(matches!(
            session.lookup_by_external_id(ALICE_UUID).await.unwrap(),
            EntryLookup::Found(_)
        ));
    }
    assert_eq!(server.connections(), 1);
    assert_eq!(server.service_binds(), 1);
}

// ---------------------------------------------------------------------------
// Changed since a watermark
// ---------------------------------------------------------------------------

fn bob() -> Entry {
    Entry::person("bob", &alice_password(), BOB_UUID)
}

#[tokio::test]
async fn open_ldap_changes_are_those_at_or_after_the_generalized_time() {
    let server = start(vec![
        alice().with_values("modifyTimestamp", &["20261003110000Z"]),
        bob().with_values("modifyTimestamp", &["20261003130000Z"]),
    ])
    .await;
    let changed = session(&server, DirectoryKind::OpenLdap)
        .search_changed("20261003120000Z", 100)
        .await
        .unwrap();
    assert!(changed.complete);
    assert_eq!(changed.entries.len(), 1);
    assert_eq!(changed.entries[0].identity.external_id, BOB_UUID);

    let sent = searches(&server);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].0.eq_ignore_ascii_case(BASE_DN));
    assert_eq!(sent[0].1, LdapSearchScope::Subtree);
    assert_eq!(
        sent[0].2,
        LdapFilter::GreaterOrEqual("modifyTimestamp".into(), "20261003120000Z".into())
    );
}

#[tokio::test]
async fn active_directory_changes_compare_the_usn_as_a_number() {
    let server = start(vec![
        Entry::ad_person("alice", &alice_password(), [0x11; 16], 99),
        Entry::ad_person("bob", &alice_password(), [0x22; 16], 100),
        Entry::ad_person("carol", &alice_password(), [0x33; 16], 1000),
    ])
    .await;
    let changed = session(&server, DirectoryKind::ActiveDirectory)
        .search_changed("100", 100)
        .await
        .unwrap();
    let mut names: Vec<_> = changed
        .entries
        .iter()
        .map(|e| e.identity.username.clone().unwrap())
        .collect();
    names.sort();
    // 99 < 100 <= 100 <= 1000: numerically, not as strings ("1000" < "99").
    assert_eq!(names, vec!["bob", "carol"]);
    assert_eq!(
        searches(&server)[0].2,
        LdapFilter::GreaterOrEqual("uSNChanged".into(), "100".into())
    );
}

#[tokio::test]
async fn a_watermark_that_is_not_one_builds_no_filter_and_sends_nothing() {
    let server = start(vec![alice()]).await;
    let session = session(&server, DirectoryKind::OpenLdap);
    for bad in ["", "*", "1)(uid=*", "yesterday"] {
        assert_eq!(
            session.search_changed(bad, 10).await,
            Err(DirectoryAuthError::Misconfigured),
            "{bad:?}"
        );
    }
    assert!(searches(&server).is_empty());
    assert_eq!(server.connections(), 0);
}

/// The bound: the client asks for one more than it will read, and reports a
/// prefix as incomplete — by its own count or by the server's size limit.
#[tokio::test]
async fn a_result_set_over_the_bound_is_a_prefix_and_says_so() {
    let people: Vec<Entry> = (0..6)
        .map(|i| {
            Entry::person(
                &format!("u{i}"),
                &alice_password(),
                &format!("00000000-0000-4000-8000-00000000000{i}"),
            )
            .with_values("modifyTimestamp", &["20261003130000Z"])
        })
        .collect();
    let server = start(people).await;
    let changed = session(&server, DirectoryKind::OpenLdap)
        .search_changed("20261003120000Z", 4)
        .await
        .unwrap();
    assert!(!changed.complete);
    assert_eq!(changed.entries.len(), 4);
    assert_eq!(
        searches(&server)[0].3,
        5,
        "the server is asked for bound + 1"
    );
}

#[tokio::test]
async fn a_server_that_ignores_the_size_limit_is_cut_off_by_the_client() {
    let people: Vec<Entry> = (0..6)
        .map(|i| {
            Entry::person(
                &format!("u{i}"),
                &alice_password(),
                &format!("00000000-0000-4000-8000-00000000000{i}"),
            )
            .with_values("modifyTimestamp", &["20261003130000Z"])
        })
        .collect();
    // `enforce_sizelimit` off: the server sends everything it has.
    let server = TestServer::start(Script {
        entries: people,
        ..Script::default()
    })
    .await;
    let changed = session(&server, DirectoryKind::OpenLdap)
        .search_changed("20261003120000Z", 3)
        .await
        .unwrap();
    assert!(!changed.complete);
    assert_eq!(changed.entries.len(), 3);
}

#[tokio::test]
async fn exactly_the_bound_is_complete() {
    let people: Vec<Entry> = (0..3)
        .map(|i| {
            Entry::person(
                &format!("u{i}"),
                &alice_password(),
                &format!("00000000-0000-4000-8000-00000000000{i}"),
            )
            .with_values("modifyTimestamp", &["20261003130000Z"])
        })
        .collect();
    let server = start(people).await;
    let changed = session(&server, DirectoryKind::OpenLdap)
        .search_changed("20261003120000Z", 3)
        .await
        .unwrap();
    assert!(changed.complete);
    assert_eq!(changed.entries.len(), 3);
}

#[tokio::test]
async fn entries_without_a_readable_identifier_are_passed_over_and_counted() {
    let server = start(vec![
        alice().with_values("modifyTimestamp", &["20261003130000Z"]),
        Entry::group("staff", &[]).with_values("modifyTimestamp", &["20261003130000Z"]),
    ])
    .await;
    let changed = session(&server, DirectoryKind::OpenLdap)
        .search_changed("20261003120000Z", 100)
        .await
        .unwrap();
    assert!(changed.complete);
    assert_eq!(changed.entries.len(), 1);
    assert_eq!(changed.unidentified, 1);
}

// ---------------------------------------------------------------------------
// The rootDSE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_root_dse_gives_the_usn_and_the_server_identity() {
    let server = start(vec![alice()]).await;
    server.set_root_dse(&[
        ("highestCommittedUSN", "4242"),
        (
            "dsServiceName",
            "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Site,CN=Sites",
        ),
        ("unrelated", "x"),
    ]);
    let dse = session(&server, DirectoryKind::ActiveDirectory)
        .read_root_dse()
        .await
        .unwrap();
    assert_eq!(dse.highest_committed_usn.as_deref(), Some("4242"));
    assert_eq!(
        dse.server_identity.as_deref(),
        Some("CN=NTDS Settings,CN=DC1,CN=Servers,CN=Site,CN=Sites")
    );

    let sent = searches(&server);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "", "the rootDSE is the empty DN");
    assert_eq!(sent[0].1, LdapSearchScope::Base);
    assert_eq!(sent[0].4.len(), 2, "only the two attributes are requested");
}

#[tokio::test]
async fn a_missing_or_malformed_root_dse_value_is_none_not_trusted() {
    let server = start(vec![alice()]).await;
    server.set_root_dse(&[("highestCommittedUSN", "not-a-number")]);
    let dse = session(&server, DirectoryKind::ActiveDirectory)
        .read_root_dse()
        .await
        .unwrap();
    assert!(dse.highest_committed_usn.is_none());
    assert!(dse.server_identity.is_none());
}

#[tokio::test]
async fn a_directory_that_hides_its_root_dse_is_an_error_the_caller_can_tell() {
    let server = start(vec![alice()]).await;
    // `set_root_dse` never called: the server answers noSuchObject.
    let outcome = session(&server, DirectoryKind::ActiveDirectory)
        .read_root_dse()
        .await;
    assert_eq!(outcome, Err(DirectoryAuthError::Misconfigured));
}
