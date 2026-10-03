//! Group resolution against the in-process test directory (T23.3.4, G-3, D-30).
//!
//! As for the bind flow, every property is asserted on what reached the server —
//! the filter it parsed, the scope and base of each search, the binds it saw and
//! the connections it counted — not on what the client reports. Assertion
//! messages name the case; they never carry a password, a secret or a DN.

mod support;

use std::time::Duration;

use axiam_core::models::directory::{DirectoryAuthError, DirectoryKind, GroupStrategy};
use axiam_directory::client::{ClientLimits, DirectoryClient, DirectoryTarget};
use axiam_directory::groups::{GroupLookup, MAX_GROUPS_PER_USER};
use axiam_directory::tls::client_config;
use ldap3_proto::proto::{LdapFilter, LdapResultCode, LdapSearchScope};
use support::{
    BASE_DN, Entry, Event, GROUP_BASE_DN, SERVICE_DN, Script, TestServer, alice_password, group_dn,
    service_secret,
};
use uuid::Uuid;

const ALICE_UUID: &str = "00000000-0000-4000-8000-00000000a11c";
const ALICE_DN: &str = "uid=alice,ou=people,dc=example,dc=com";

fn alice() -> Entry {
    Entry::person("alice", &alice_password(), ALICE_UUID)
}

fn target_for(server: &TestServer) -> DirectoryTarget {
    DirectoryTarget {
        tenant_id: Uuid::new_v4(),
        generation: "g1".into(),
        url: format!("ldaps://localhost:{}", server.port()),
        start_tls: false,
        bind_dn: SERVICE_DN.into(),
        base_dn: BASE_DN.into(),
        user_filter: "(uid={username})".into(),
        attributes: DirectoryKind::OpenLdap.default_user_attribute_map(),
        tls: client_config(std::slice::from_ref(&server.ca.pem)).unwrap(),
    }
}

fn client() -> DirectoryClient {
    DirectoryClient::new(ClientLimits {
        acquire_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(500),
        operation_timeout: Duration::from_millis(500),
        authentication_deadline: Duration::from_secs(3),
        ..ClientLimits::default()
    })
}

fn reverse(depth: u8) -> GroupLookup {
    GroupLookup {
        strategy: GroupStrategy::ReverseMember,
        base_dn: Some(GROUP_BASE_DN.into()),
        filter: Some("(objectClass=groupOfNames)".into()),
        member_attribute: "member".into(),
        max_depth: depth,
    }
}

fn member_of(depth: u8) -> GroupLookup {
    GroupLookup {
        strategy: GroupStrategy::MemberOf,
        base_dn: None,
        filter: None,
        member_attribute: "memberOf".into(),
        max_depth: depth,
    }
}

async fn start(entries: Vec<Entry>) -> TestServer {
    TestServer::start(Script {
        entries,
        ..Script::default()
    })
    .await
}

async fn resolve(
    server: &TestServer,
    user_dn: &str,
    lookup: &GroupLookup,
) -> Result<Vec<String>, DirectoryAuthError> {
    client()
        .resolve_groups(&target_for(server), &service_secret(), user_dn, lookup)
        .await
        .map(|found| found.dns)
}

fn names(dns: &[String]) -> Vec<String> {
    let mut names: Vec<String> = dns
        .iter()
        .map(|dn| dn.split(',').next().unwrap().to_string())
        .collect();
    names.sort();
    names
}

fn searches(server: &TestServer) -> Vec<(String, LdapSearchScope, LdapFilter, Vec<String>)> {
    server
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Search {
                base,
                scope,
                filter,
                attrs,
                ..
            } => Some((base, scope, filter, attrs)),
            _ => None,
        })
        .collect()
}

fn eq(attr: &str, value: &str) -> LdapFilter {
    LdapFilter::Equality(attr.into(), value.into())
}

/// A chain `alice -> g1 -> g2 -> g3 -> g4` in reverse-`member` form: each
/// group lists the one below it as a member.
fn member_chain() -> Vec<Entry> {
    vec![
        alice(),
        Entry::group("g1", &[ALICE_DN]),
        Entry::group("g2", &[&group_dn("g1")]),
        Entry::group("g3", &[&group_dn("g2")]),
        Entry::group("g4", &[&group_dn("g3")]),
    ]
}

/// The same chain in `memberOf` form.
fn member_of_chain() -> Vec<Entry> {
    vec![
        alice().with_values("memberOf", &[&group_dn("g1")]),
        Entry::ad_group("g1", &[&group_dn("g2")]),
        Entry::ad_group("g2", &[&group_dn("g3")]),
        Entry::ad_group("g3", &[&group_dn("g4")]),
        Entry::ad_group("g4", &[]),
    ]
}

// ---------------------------------------------------------------------------
// OpenLDAP: the reverse `member` search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_reverse_search_asks_for_exactly_the_documented_filter() {
    let server = start(vec![
        alice(),
        Entry::group("staff", &[ALICE_DN]),
        Entry::group("others", &["uid=bob,ou=people,dc=example,dc=com"]),
    ])
    .await;
    let found = resolve(&server, ALICE_DN, &reverse(5)).await.unwrap();
    assert_eq!(names(&found), ["cn=staff"]);

    let sent = searches(&server);
    // Level 0 finds `staff`; level 1 asks who contains it; level 2 stops.
    assert_eq!(sent.len(), 2);
    let (base, scope, filter, attrs) = &sent[0];
    assert_eq!(base, GROUP_BASE_DN);
    assert!(matches!(scope, LdapSearchScope::Subtree));
    assert_eq!(
        *filter,
        LdapFilter::And(vec![
            eq("objectClass", "groupOfNames"),
            eq("member", ALICE_DN)
        ])
    );
    assert_eq!(attrs, &["1.1".to_string()], "DNs only, no attributes");
    // The user's own bind is never used for this: one connection, the service
    // account, over TLS.
    assert_eq!(server.user_binds(), 0);
    assert_eq!(server.service_binds(), 1);
    assert!(server.binds().iter().all(|(_, encrypted, _)| *encrypted));
}

#[tokio::test]
async fn nesting_is_followed_to_depth_n_and_n_plus_one_is_not_asked() {
    for depth in 0u8..=3 {
        let server = start(member_chain()).await;
        let found = resolve(&server, ALICE_DN, &reverse(depth)).await.unwrap();
        let want: Vec<String> = (1..=usize::from(depth) + 1)
            .map(|n| format!("cn=g{n}"))
            .collect();
        assert_eq!(names(&found), want, "depth {depth}");
        assert_eq!(
            searches(&server).len(),
            usize::from(depth) + 1,
            "depth {depth}: one search per level and none beyond"
        );
    }
}

#[tokio::test]
async fn a_cycle_terminates() {
    // g1 and g2 contain each other, and g1 contains alice.
    let server = start(vec![
        alice(),
        Entry::group("g1", &[ALICE_DN, &group_dn("g2")]),
        Entry::group("g2", &[&group_dn("g1")]),
    ])
    .await;
    let found = resolve(&server, ALICE_DN, &reverse(10)).await.unwrap();
    assert_eq!(names(&found), ["cn=g1", "cn=g2"]);
    assert!(
        searches(&server).len() <= 3,
        "no group is asked about twice"
    );
}

#[tokio::test]
async fn the_hard_cap_of_one_thousand_groups_refuses() {
    let many = |n: usize| {
        let mut entries = vec![alice()];
        entries.extend((0..n).map(|i| Entry::group(&format!("g{i}"), &[ALICE_DN])));
        entries
    };
    // Exactly the cap is fine ...
    let server = start(many(MAX_GROUPS_PER_USER)).await;
    let found = resolve(&server, ALICE_DN, &reverse(0)).await.unwrap();
    assert_eq!(found.len(), MAX_GROUPS_PER_USER);
    // ... one more is refused, as unavailable, not as a truncated answer.
    let server = start(many(MAX_GROUPS_PER_USER + 1)).await;
    assert_eq!(
        resolve(&server, ALICE_DN, &reverse(0)).await,
        Err(DirectoryAuthError::Unavailable)
    );
}

/// A server that honours the size limit says `sizeLimitExceeded` at the cap we
/// asked for; that is the cap too, and the client never trusts it to be the
/// last word.
#[tokio::test]
async fn a_server_that_enforces_the_size_limit_is_the_cap_too() {
    let mut entries = vec![alice()];
    entries
        .extend((0..MAX_GROUPS_PER_USER + 50).map(|i| Entry::group(&format!("g{i}"), &[ALICE_DN])));
    let server = TestServer::start(Script {
        entries,
        enforce_sizelimit: true,
        ..Script::default()
    })
    .await;
    assert_eq!(
        resolve(&server, ALICE_DN, &reverse(0)).await,
        Err(DirectoryAuthError::Unavailable)
    );
    let sent = server
        .events()
        .into_iter()
        .find_map(|e| match e {
            Event::Search { sizelimit, .. } => Some(sizelimit),
            _ => None,
        })
        .unwrap();
    assert_eq!(sent, i32::try_from(MAX_GROUPS_PER_USER + 1).unwrap());
}

#[tokio::test]
async fn the_cap_counts_nested_groups_across_levels() {
    // alice in a, b; each has two parents: 6 groups in all.
    let server = start(vec![
        alice(),
        Entry::group("a", &[ALICE_DN]),
        Entry::group("b", &[ALICE_DN]),
        Entry::group("a1", &[&group_dn("a")]),
        Entry::group("a2", &[&group_dn("a")]),
        Entry::group("b1", &[&group_dn("b")]),
        Entry::group("b2", &[&group_dn("b")]),
    ])
    .await;
    let target = target_for(&server);
    let ok = client()
        .resolve_groups_capped(&target, &service_secret(), ALICE_DN, &reverse(3), 6)
        .await
        .unwrap();
    assert_eq!(ok.len(), 6);
    assert_eq!(
        client()
            .resolve_groups_capped(&target, &service_secret(), ALICE_DN, &reverse(3), 5)
            .await
            .map(|g| g.len()),
        Err(DirectoryAuthError::Unavailable)
    );
}

/// An injection attempt in a user DN: every metacharacter reaches the server as
/// data inside one equality assertion, so the filter it parsed is the documented
/// shape, and the entry that a widened filter would have matched is not found.
#[tokio::test]
async fn a_hostile_user_dn_is_escaped_in_the_filter_the_server_parsed() {
    let hostile = "uid=a*)(uid=*\\,ou=\u{0}x,dc=example,dc=com";
    let server = start(vec![alice(), Entry::group("staff", &[ALICE_DN])]).await;
    let found = resolve(&server, hostile, &reverse(0)).await.unwrap();
    assert!(
        found.is_empty(),
        "a widened filter would have matched staff"
    );

    let sent = searches(&server);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].2,
        LdapFilter::And(vec![
            eq("objectClass", "groupOfNames"),
            eq("member", hostile)
        ]),
        "one equality assertion carrying the DN verbatim, nothing else"
    );
    fn has_widening(filter: &LdapFilter) -> bool {
        match filter {
            LdapFilter::Present(_) | LdapFilter::Substring(..) | LdapFilter::Or(_) => true,
            LdapFilter::And(parts) => parts.iter().any(has_widening),
            LdapFilter::Not(inner) => has_widening(inner),
            _ => false,
        }
    }
    assert!(!has_widening(&sent[0].2));
}

#[tokio::test]
async fn nested_levels_batch_into_one_or_filter_with_every_dn_escaped() {
    // Twenty groups under alice, each with a parent: the second level asks
    // about twenty DNs in two searches (16 + 4).
    let mut entries = vec![alice()];
    for i in 0..20 {
        entries.push(Entry::group(&format!("c{i}"), &[ALICE_DN]));
        entries.push(Entry::group(
            &format!("p{i}"),
            &[&group_dn(&format!("c{i}"))],
        ));
    }
    let server = start(entries).await;
    let found = resolve(&server, ALICE_DN, &reverse(1)).await.unwrap();
    assert_eq!(found.len(), 40);
    let sent = searches(&server);
    assert_eq!(sent.len(), 3, "one for alice, two for the twenty children");
    let LdapFilter::And(parts) = &sent[1].2 else {
        panic!("expected the group filter and a membership clause");
    };
    let LdapFilter::Or(clauses) = &parts[1] else {
        panic!("expected an OR of memberships");
    };
    assert_eq!(clauses.len(), 16);
    assert!(
        clauses
            .iter()
            .all(|c| matches!(c, LdapFilter::Equality(a, _) if a == "member"))
    );
}

#[tokio::test]
async fn search_references_are_ignored_and_never_followed() {
    let server = TestServer::start(Script {
        entries: vec![alice(), Entry::group("staff", &[ALICE_DN])],
        search_references: vec!["ldaps://localhost:1/ou=elsewhere,dc=example,dc=com".into()],
        ..Script::default()
    })
    .await;
    let found = resolve(&server, ALICE_DN, &reverse(0)).await.unwrap();
    assert_eq!(
        names(&found),
        ["cn=staff"],
        "the reference is neither a group nor a match"
    );
    assert_eq!(
        server.connections(),
        1,
        "no connection was opened to the referral"
    );
}

#[tokio::test]
async fn a_referral_result_fails_the_lookup_closed() {
    let server = TestServer::start(Script {
        entries: vec![alice(), Entry::group("staff", &[ALICE_DN])],
        group_search_done: Some((
            LdapResultCode::Referral,
            vec!["ldaps://localhost:1/ou=groups,dc=example,dc=com".into()],
        )),
        ..Script::default()
    })
    .await;
    assert_eq!(
        resolve(&server, ALICE_DN, &reverse(0)).await,
        Err(DirectoryAuthError::Unavailable)
    );
    assert_eq!(server.connections(), 1, "never followed");
}

#[tokio::test]
async fn every_failure_of_the_search_is_unavailable() {
    for code in [
        LdapResultCode::InsufficentAccessRights,
        LdapResultCode::Busy,
        LdapResultCode::Unavailable,
        LdapResultCode::NoSuchObject,
        LdapResultCode::Other,
    ] {
        let server = TestServer::start(Script {
            entries: vec![alice(), Entry::group("staff", &[ALICE_DN])],
            group_search_done: Some((code.clone(), vec![])),
            ..Script::default()
        })
        .await;
        assert_eq!(
            resolve(&server, ALICE_DN, &reverse(0)).await,
            Err(DirectoryAuthError::Unavailable),
            "result {code:?}"
        );
    }
}

#[tokio::test]
async fn a_failure_at_a_nested_level_fails_the_whole_lookup() {
    // Level 0 answers and finds g1; the search for g1's parents is refused.
    // No prefix of the groups is returned.
    for (chain, lookup) in [
        (member_chain(), reverse(3)),
        (member_of_chain(), member_of(3)),
    ] {
        let server = TestServer::start(Script {
            entries: chain,
            fail_group_searches_from: Some(1),
            ..Script::default()
        })
        .await;
        assert_eq!(
            resolve(&server, ALICE_DN, &lookup).await,
            Err(DirectoryAuthError::Unavailable)
        );
    }
}

#[tokio::test]
async fn a_lookup_that_never_reaches_the_failing_level_still_succeeds() {
    let server = TestServer::start(Script {
        entries: member_chain(),
        fail_group_searches_from: Some(1),
        ..Script::default()
    })
    .await;
    assert_eq!(
        names(&resolve(&server, ALICE_DN, &reverse(0)).await.unwrap()),
        ["cn=g1"]
    );
}

#[tokio::test]
async fn a_slow_directory_is_unavailable_within_the_deadline() {
    let server = TestServer::start(Script {
        entries: member_chain(),
        group_search_delay: Some(Duration::from_secs(5)),
        ..Script::default()
    })
    .await;
    let started = std::time::Instant::now();
    assert_eq!(
        resolve(&server, ALICE_DN, &reverse(3)).await,
        Err(DirectoryAuthError::Unavailable)
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "bounded by the deadlines"
    );
}

#[tokio::test]
async fn the_pooled_service_connection_is_reused_and_nothing_user_bound_is_pooled() {
    let server = start(member_chain()).await;
    let client = client();
    let target = target_for(&server);
    for _ in 0..3 {
        client
            .resolve_groups(&target, &service_secret(), ALICE_DN, &reverse(1))
            .await
            .unwrap();
    }
    assert_eq!(server.connections(), 1);
    assert_eq!(server.service_binds(), 1);
    assert_eq!(server.user_binds(), 0);
    assert_eq!(client.idle_connections(target.tenant_id), 1);
}

#[tokio::test]
async fn an_unusable_configuration_is_refused_before_any_packet() {
    let server = start(member_chain()).await;
    let target = target_for(&server);
    let client = client();
    let no_base = GroupLookup {
        base_dn: None,
        ..reverse(1)
    };
    assert_eq!(
        client
            .resolve_groups(&target, &service_secret(), ALICE_DN, &no_base)
            .await
            .map(|g| g.dns),
        Err(DirectoryAuthError::Misconfigured)
    );
    assert_eq!(
        client
            .resolve_groups(&target, "", ALICE_DN, &reverse(1))
            .await
            .map(|g| g.dns),
        Err(DirectoryAuthError::Misconfigured)
    );
    let plaintext = DirectoryTarget {
        url: format!("ldap://localhost:{}", server.port()),
        start_tls: false,
        ..target
    };
    assert_eq!(
        client
            .resolve_groups(&plaintext, &service_secret(), ALICE_DN, &reverse(1))
            .await
            .map(|g| g.dns),
        Err(DirectoryAuthError::Misconfigured)
    );
    assert_eq!(server.connections(), 0);
}

// ---------------------------------------------------------------------------
// Active Directory: `memberOf`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn member_of_is_read_off_the_user_entry_by_a_base_object_read() {
    let server = start(vec![
        alice().with_values("memberOf", &[&group_dn("g1"), &group_dn("g2")]),
    ])
    .await;
    let found = resolve(&server, ALICE_DN, &member_of(0)).await.unwrap();
    assert_eq!(names(&found), ["cn=g1", "cn=g2"]);

    let sent = searches(&server);
    assert_eq!(sent.len(), 1);
    let (base, scope, filter, attrs) = &sent[0];
    assert_eq!(
        base, ALICE_DN,
        "the entry the directory returned, as the base"
    );
    assert!(matches!(scope, LdapSearchScope::Base));
    assert_eq!(*filter, LdapFilter::Present("objectClass".into()));
    assert_eq!(attrs, &["memberOf".to_string()]);
    assert_eq!(server.user_binds(), 0);
}

#[tokio::test]
async fn member_of_nesting_is_followed_to_depth_n_and_n_plus_one_is_not_read() {
    for depth in 0u8..=3 {
        let server = start(member_of_chain()).await;
        let found = resolve(&server, ALICE_DN, &member_of(depth)).await.unwrap();
        let want: Vec<String> = (1..=usize::from(depth) + 1)
            .map(|n| format!("cn=g{n}"))
            .collect();
        assert_eq!(names(&found), want, "depth {depth}");
        assert_eq!(
            searches(&server).len(),
            usize::from(depth) + 1,
            "depth {depth}"
        );
    }
}

#[tokio::test]
async fn a_member_of_cycle_terminates() {
    let server = start(vec![
        alice().with_values("memberOf", &[&group_dn("g1")]),
        Entry::ad_group("g1", &[&group_dn("g2")]),
        Entry::ad_group("g2", &[&group_dn("g1")]),
    ])
    .await;
    let found = resolve(&server, ALICE_DN, &member_of(10)).await.unwrap();
    assert_eq!(names(&found), ["cn=g1", "cn=g2"]);
    assert_eq!(searches(&server).len(), 3);
}

#[tokio::test]
async fn a_dangling_group_has_no_parents_but_a_missing_user_entry_is_a_failure() {
    // g1 is named but has no entry: a dangling reference, skipped.
    let server = start(vec![alice().with_values("memberOf", &[&group_dn("g1")])]).await;
    let found = resolve(&server, ALICE_DN, &member_of(3)).await.unwrap();
    assert_eq!(names(&found), ["cn=g1"]);
    // The user's own entry cannot be missing right after it authenticated.
    let server = start(vec![alice()]).await;
    assert_eq!(
        resolve(
            &server,
            "uid=ghost,ou=people,dc=example,dc=com",
            &member_of(3)
        )
        .await,
        Err(DirectoryAuthError::Unavailable)
    );
}

#[tokio::test]
async fn member_of_beyond_the_cap_or_in_ranged_form_refuses() {
    let many: Vec<String> = (0..MAX_GROUPS_PER_USER + 1).map(group_name).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let server = start(vec![alice().with_values("memberOf", &refs)]).await;
    assert_eq!(
        resolve(&server, ALICE_DN, &member_of(0)).await,
        Err(DirectoryAuthError::Unavailable)
    );
    // The server truncated the values and offered the rest in ranges: not a
    // complete answer, so not an answer.
    let server = start(vec![
        alice().with_values("memberOf;range=0-1499", &[&group_dn("g1")]),
    ])
    .await;
    assert_eq!(
        resolve(&server, ALICE_DN, &member_of(0)).await,
        Err(DirectoryAuthError::Unavailable)
    );
}

fn group_name(i: usize) -> String {
    group_dn(&format!("g{i}"))
}

#[tokio::test]
async fn member_of_search_references_are_ignored_and_a_referral_result_fails() {
    let server = TestServer::start(Script {
        entries: vec![alice().with_values("memberOf", &[&group_dn("g1")])],
        search_references: vec!["ldaps://localhost:1/dc=elsewhere".into()],
        ..Script::default()
    })
    .await;
    let found = resolve(&server, ALICE_DN, &member_of(0)).await.unwrap();
    assert_eq!(names(&found), ["cn=g1"]);
    assert_eq!(server.connections(), 1);

    let server = TestServer::start(Script {
        entries: vec![alice().with_values("memberOf", &[&group_dn("g1")])],
        group_search_done: Some((LdapResultCode::Referral, vec!["ldaps://localhost:1".into()])),
        ..Script::default()
    })
    .await;
    assert_eq!(
        resolve(&server, ALICE_DN, &member_of(0)).await,
        Err(DirectoryAuthError::Unavailable)
    );
}

#[tokio::test]
async fn an_unreadable_group_dn_is_skipped_not_traversed() {
    let server = start(vec![alice().with_values(
        "memberOf",
        &[&group_dn("g1"), "not a dn", "cn=bad\\zz,dc=x"],
    )])
    .await;
    let target = target_for(&server);
    let found = client()
        .resolve_groups(&target, &service_secret(), ALICE_DN, &member_of(3))
        .await
        .unwrap();
    assert_eq!(names(&found.dns), ["cn=g1"]);
    assert_eq!(found.skipped_unreadable, 2);
}
