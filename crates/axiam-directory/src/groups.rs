//! Which directory groups a user is in, and which AXIAM groups that maps to
//! (G-3, T23.3.4, D-30).
//!
//! This module is the **pure half**: the nested walk over an abstract
//! [`GroupParents`] source, and the pass of the mapping table over what the
//! walk found. The LDAP half — the two sources, `memberOf` for Active
//! Directory and the reverse `member` search for OpenLDAP — is
//! [`crate::client::DirectoryClient::resolve_groups`]; applying the result to
//! AXIAM's memberships is [`crate::mapper`].
//!
//! # The walk
//!
//! Level 0 is the user's own groups (their entry's `memberOf`, or the groups
//! that list the user's DN as a member). Each further level is the groups that
//! contain a group found at the previous one, to
//! [`DirectoryConfig::group_nesting_depth`]
//! levels: depth `0` follows no nesting, depth `N` follows `N` levels, and
//! level `N + 1` is never read.
//!
//! * **A cycle terminates.** A group is expanded once, whatever it is named
//!   as: groups are keyed by their [normalised DN](crate::dn::normalize), so a
//!   group that contains itself, or two that contain each other, or one that
//!   contains the user, adds nothing the second time round.
//! * **A hard cap of [`MAX_GROUPS_PER_USER`] distinct groups.** One more is
//!   [`ResolveError::CapExceeded`], not a truncated answer: a user in more
//!   groups than that is either a hostile directory or one this feature was not
//!   sized for, and the answer to both is to refuse the sign-in rather than map
//!   a prefix of the groups.
//! * **A DN that cannot be read is skipped** — not traversed, not counted, and
//!   unmappable anyway, since a mapping DN must parse.
//!
//! # Fail closed
//!
//! Every error here ends the whole resolution. A partial set is never
//! returned: the caller removes memberships the directory no longer backs, and
//! "no longer backs" read off half a walk would be wrong in the dangerous
//! direction (a lost removal keeps access; a lost addition only withholds it,
//! but the walk cannot tell which it is looking at).
//!
//! [`DirectoryConfig::group_nesting_depth`]: axiam_core::models::directory::DirectoryConfig::group_nesting_depth

use std::collections::BTreeSet;
use std::future::Future;

use axiam_core::models::directory::{GroupMapping, GroupStrategy};
use uuid::Uuid;

use crate::dn::normalize;

/// Most distinct directory groups one user may belong to, nesting included.
pub const MAX_GROUPS_PER_USER: usize = 1_000;

/// Why a resolution produced no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The user is in more than [`MAX_GROUPS_PER_USER`] groups.
    #[error("the user belongs to more directory groups than the cap allows")]
    CapExceeded,
    /// The directory could not be asked, or answered something unusable. The
    /// reason is fixed text, safe for a log line.
    #[error("the directory group lookup failed: {0}")]
    Lookup(&'static str),
}

/// What the directory says about the groups containing a set of entries.
pub trait GroupParents {
    /// The DNs of the groups that **directly** contain any entry of `of` (the
    /// user's DN, then group DNs), as the directory wrote them. May repeat a
    /// DN; the walk deduplicates.
    ///
    /// # Errors
    ///
    /// Any [`ResolveError`]; the walk stops at the first.
    fn parents_of<'a>(
        &'a mut self,
        of: &'a [String],
    ) -> impl Future<Output = Result<Vec<String>, ResolveError>> + Send + 'a;
}

/// The groups a user belongs to, as the walk found them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedGroups {
    /// Each distinct group's DN as the directory wrote it, in the order found.
    pub dns: Vec<String>,
    /// The same groups as [normalised](crate::dn::normalize) comparison keys.
    pub keys: BTreeSet<String>,
    /// DNs the directory returned that could not be read as DNs and were
    /// skipped.
    pub skipped_unreadable: usize,
}

impl ResolvedGroups {
    /// How many distinct groups were found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.dns.len()
    }

    /// Whether no group was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dns.is_empty()
    }
}

/// Walk the nesting above `user_dn` through `source`.
///
/// `max_depth` is the tenant's `group_nesting_depth`; `cap` is
/// [`MAX_GROUPS_PER_USER`] (a parameter so the tests can state the boundary
/// without a thousand fixtures).
///
/// # Errors
///
/// [`ResolveError::CapExceeded`] when more than `cap` distinct groups turn up,
/// and whatever `source` returns.
pub async fn resolve_nested<S: GroupParents>(
    source: &mut S,
    user_dn: &str,
    max_depth: u8,
    cap: usize,
) -> Result<ResolvedGroups, ResolveError> {
    let mut found = ResolvedGroups::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    // The user is never a group of themselves, however a loop reaches them.
    if let Ok(key) = normalize(user_dn) {
        seen.insert(key);
    }
    let mut frontier = vec![user_dn.to_string()];
    for _level in 0..=max_depth {
        let parents = source.parents_of(&frontier).await?;
        let mut next = Vec::new();
        for dn in parents {
            let Ok(key) = normalize(&dn) else {
                found.skipped_unreadable += 1;
                continue;
            };
            if !seen.insert(key.clone()) {
                continue;
            }
            if found.dns.len() >= cap {
                return Err(ResolveError::CapExceeded);
            }
            found.keys.insert(key);
            found.dns.push(dn.clone());
            next.push(dn);
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    Ok(found)
}

/// The AXIAM groups the mapping table puts a member of `resolved` into.
///
/// A row matches when its DN, [normalised](crate::dn::normalize), is one of the
/// resolved groups' keys — and in no other way: not by name, not by prefix, not
/// by a parent, not by a wildcard. A row whose DN cannot be read matches
/// nothing (validation refuses such a row at write; this is the read path not
/// trusting that it did).
#[must_use]
pub fn mapped_group_ids(mappings: &[GroupMapping], resolved: &ResolvedGroups) -> BTreeSet<Uuid> {
    mappings
        .iter()
        .filter(|mapping| {
            normalize(&mapping.directory_group_dn).is_ok_and(|key| resolved.keys.contains(&key))
        })
        .map(|mapping| mapping.group_id)
        .collect()
}

/// What [`crate::client::DirectoryClient::resolve_groups`] needs to know about
/// a tenant's group layout. Resolved from the stored configuration by the
/// caller, like [`crate::client::DirectoryTarget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLookup {
    /// How groups are discovered: off the entry (`memberOf`) or by a reverse
    /// search (`member`).
    pub strategy: GroupStrategy,
    /// Where the reverse search runs. Required for
    /// [`GroupStrategy::ReverseMember`], unused for `MemberOf`.
    pub base_dn: Option<String>,
    /// The tenant's static group filter, if it set one.
    pub filter: Option<String>,
    /// `memberOf` or `member` (or `uniqueMember`, `isMemberOf`, ...).
    pub member_attribute: String,
    /// The tenant's `group_nesting_depth`.
    pub max_depth: u8,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// A directory as a map: entry (normalised DN) to the groups that directly
    /// contain it. Counts the calls, so the depth bound is observable.
    struct Fixture {
        parents: HashMap<String, Vec<String>>,
        calls: Vec<Vec<String>>,
        fail_on_call: Option<usize>,
    }

    impl Fixture {
        fn new(edges: &[(&str, &[&str])]) -> Self {
            Self {
                parents: edges
                    .iter()
                    .map(|(child, parents)| {
                        (
                            normalize(child).unwrap(),
                            parents.iter().map(|p| (*p).to_string()).collect(),
                        )
                    })
                    .collect(),
                calls: vec![],
                fail_on_call: None,
            }
        }
    }

    impl GroupParents for Fixture {
        async fn parents_of(&mut self, of: &[String]) -> Result<Vec<String>, ResolveError> {
            {
                self.calls.push(of.to_vec());
                if self.fail_on_call == Some(self.calls.len()) {
                    return Err(ResolveError::Lookup("the fixture failed on purpose"));
                }
                Ok(of
                    .iter()
                    .flat_map(|dn| {
                        self.parents
                            .get(&normalize(dn).unwrap())
                            .cloned()
                            .unwrap_or_default()
                    })
                    .collect())
            }
        }
    }

    const USER: &str = "uid=alice,ou=people,dc=x";

    /// user -> g1 -> g2 -> g3 -> g4
    fn chain() -> Fixture {
        Fixture::new(&[
            (USER, &["cn=g1,ou=groups,dc=x"]),
            ("cn=g1,ou=groups,dc=x", &["cn=g2,ou=groups,dc=x"]),
            ("cn=g2,ou=groups,dc=x", &["cn=g3,ou=groups,dc=x"]),
            ("cn=g3,ou=groups,dc=x", &["cn=g4,ou=groups,dc=x"]),
        ])
    }

    fn names(found: &ResolvedGroups) -> Vec<&str> {
        found
            .dns
            .iter()
            .map(|dn| dn.split(',').next().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn depth_zero_follows_no_nesting() {
        let mut source = chain();
        let found = resolve_nested(&mut source, USER, 0, 1000).await.unwrap();
        assert_eq!(names(&found), ["cn=g1"]);
        assert_eq!(source.calls.len(), 1, "only the user's own groups are read");
    }

    #[tokio::test]
    async fn nesting_is_followed_to_depth_n_and_level_n_plus_one_is_not_read() {
        for depth in 0u8..=3 {
            let mut source = chain();
            let found = resolve_nested(&mut source, USER, depth, 1000)
                .await
                .unwrap();
            let want: Vec<String> = (1..=usize::from(depth) + 1)
                .map(|n| format!("cn=g{n}"))
                .collect();
            assert_eq!(names(&found), want, "depth {depth}");
            assert!(
                !found
                    .dns
                    .iter()
                    .any(|dn| dn.starts_with(&format!("cn=g{},", depth + 2))),
                "the group at level {} must not be found at depth {depth}",
                depth + 1
            );
            // One read for the user's groups, one per nesting level, none more.
            assert_eq!(source.calls.len(), usize::from(depth) + 1, "depth {depth}");
        }
    }

    #[tokio::test]
    async fn a_cycle_terminates_and_each_group_is_found_once() {
        // user -> a -> b -> a, and c contains itself.
        let mut source = Fixture::new(&[
            (USER, &["cn=a,dc=x", "cn=c,dc=x"]),
            ("cn=a,dc=x", &["cn=b,dc=x"]),
            ("cn=b,dc=x", &["cn=a,dc=x"]),
            ("cn=c,dc=x", &["CN=C,DC=X"]),
        ]);
        let found = resolve_nested(&mut source, USER, 10, 1000).await.unwrap();
        assert_eq!(found.len(), 3);
        assert!(source.calls.len() <= 4, "no group is expanded twice");
    }

    #[tokio::test]
    async fn a_loop_back_to_the_user_adds_nothing() {
        let mut source = Fixture::new(&[
            (USER, &["cn=a,dc=x"]),
            ("cn=a,dc=x", &["UID=Alice, OU=People, DC=X"]),
        ]);
        let found = resolve_nested(&mut source, USER, 5, 1000).await.unwrap();
        assert_eq!(names(&found), ["cn=a"]);
    }

    #[tokio::test]
    async fn one_group_under_two_spellings_is_one_group() {
        let mut source =
            Fixture::new(&[(USER, &["cn=staff,dc=x", "CN=Staff, DC=X", "cn=STAFF,dc=x"])]);
        let found = resolve_nested(&mut source, USER, 0, 1000).await.unwrap();
        assert_eq!(found.len(), 1);
    }

    #[tokio::test]
    async fn the_cap_is_exact() {
        let build = |n: usize| {
            let groups: Vec<String> = (0..n).map(|i| format!("cn=g{i},dc=x")).collect();
            let refs: Vec<&str> = groups.iter().map(String::as_str).collect();
            Fixture::new(&[(USER, &refs)])
        };
        let found = resolve_nested(
            &mut build(MAX_GROUPS_PER_USER),
            USER,
            0,
            MAX_GROUPS_PER_USER,
        )
        .await
        .unwrap();
        assert_eq!(found.len(), MAX_GROUPS_PER_USER);
        assert_eq!(
            resolve_nested(
                &mut build(MAX_GROUPS_PER_USER + 1),
                USER,
                0,
                MAX_GROUPS_PER_USER
            )
            .await,
            Err(ResolveError::CapExceeded)
        );
    }

    /// The cap counts nested groups too: a wide, deep tree cannot be walked
    /// past it a level at a time.
    #[tokio::test]
    async fn the_cap_counts_nested_groups() {
        let mut source = Fixture::new(&[
            (USER, &["cn=a,dc=x", "cn=b,dc=x"]),
            ("cn=a,dc=x", &["cn=a1,dc=x", "cn=a2,dc=x"]),
            ("cn=b,dc=x", &["cn=b1,dc=x", "cn=b2,dc=x"]),
        ]);
        assert_eq!(
            resolve_nested(&mut source, USER, 3, 5).await,
            Err(ResolveError::CapExceeded)
        );
        let mut source = Fixture::new(&[
            (USER, &["cn=a,dc=x", "cn=b,dc=x"]),
            ("cn=a,dc=x", &["cn=a1,dc=x", "cn=a2,dc=x"]),
            ("cn=b,dc=x", &["cn=b1,dc=x", "cn=b2,dc=x"]),
        ]);
        assert_eq!(
            resolve_nested(&mut source, USER, 3, 6).await.unwrap().len(),
            6
        );
    }

    #[tokio::test]
    async fn an_unreadable_dn_is_skipped_and_counted_not_traversed() {
        let mut source = Fixture::new(&[(USER, &["cn=ok,dc=x", "not a dn", "cn=bad\\zz,dc=x"])]);
        let found = resolve_nested(&mut source, USER, 3, 1000).await.unwrap();
        assert_eq!(names(&found), ["cn=ok"]);
        assert_eq!(found.skipped_unreadable, 2);
    }

    /// A failure at any level is the failure of the whole walk: no prefix of
    /// the groups is ever returned.
    #[tokio::test]
    async fn a_failure_at_any_level_fails_the_whole_walk() {
        for failing_call in 1..=3 {
            let mut source = chain();
            source.fail_on_call = Some(failing_call);
            assert_eq!(
                resolve_nested(&mut source, USER, 5, 1000).await,
                Err(ResolveError::Lookup("the fixture failed on purpose")),
                "call {failing_call}"
            );
        }
    }

    fn mapping(dn: &str, id: Uuid) -> GroupMapping {
        GroupMapping {
            directory_group_dn: dn.into(),
            group_id: id,
        }
    }

    fn resolved(dns: &[&str]) -> ResolvedGroups {
        ResolvedGroups {
            dns: dns.iter().map(|d| (*d).to_string()).collect(),
            keys: dns.iter().map(|d| normalize(d).unwrap()).collect(),
            skipped_unreadable: 0,
        }
    }

    #[test]
    fn only_a_row_naming_a_resolved_group_matches() {
        let (staff, ops, other) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let table = [
            mapping("CN=Staff, OU=Groups, DC=x", staff),
            mapping("cn=ops,ou=groups,dc=x", ops),
            mapping("cn=elsewhere,ou=groups,dc=x", other),
        ];
        let got = mapped_group_ids(&table, &resolved(&["cn=staff,ou=groups,dc=x"]));
        assert_eq!(got, BTreeSet::from([staff]));
    }

    /// D-30: no match by name, prefix, parent, or on an unreadable row.
    #[test]
    fn nothing_matches_by_name_prefix_parent_or_garbage() {
        let g = Uuid::new_v4();
        let table = [
            mapping("admins", g),
            mapping("ou=groups,dc=x", g),
            mapping("cn=admins", g),
            mapping("cn=*,ou=groups,dc=x", g),
            mapping("garbage\\zz", g),
        ];
        let got = mapped_group_ids(&table, &resolved(&["cn=admins,ou=groups,dc=x"]));
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn two_rows_for_one_directory_group_map_to_both_axiam_groups() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let table = [mapping("cn=staff,dc=x", a), mapping("CN=STAFF,DC=X", b)];
        assert_eq!(
            mapped_group_ids(&table, &resolved(&["cn=staff,dc=x"])),
            BTreeSet::from([a, b])
        );
    }
}
