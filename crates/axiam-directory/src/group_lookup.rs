//! The LDAP half of group resolution (G-3, T23.3.4, D-30): the two ways a
//! directory says which groups contain an entry, over the **service-bound**
//! pooled connection.
//!
//! * **`memberOf`** (Active Directory, [`GroupStrategy::MemberOf`]): a
//!   base-object read of the entry — the user's, then each group found — asking
//!   for the one attribute. The values are the DNs of the groups that directly
//!   contain it.
//! * **Reverse `member`** (OpenLDAP, [`GroupStrategy::ReverseMember`]): a
//!   subtree search under `group_base_dn` for
//!   `(&<group_filter>(<attribute>=<escaped DN>))`. **The DN enters the filter
//!   only through [`crate::escape::reverse_member_filter`]**, which is the RFC
//!   4515 escape and nothing else: a user DN is a string the directory
//!   supplied, and a `*`, `(`, `)`, `\` or NUL in it cannot widen the search.
//!   Nested levels batch up to [`REVERSE_MEMBER_BATCH`] group DNs into one `(|…)`
//!   filter, each escaped the same way.
//!
//! # Rules shared by both
//!
//! * **The user's own bind connection is never used.** The service connection
//!   comes from the same bounded pool the user lookup uses, under the same
//!   permits, and goes back to it afterwards.
//! * **Referrals are never followed.** A search result reference is skipped,
//!   neither chased nor counted; a referral *result* is a failure.
//! * **Entries are parsed by AXIAM's own fallible parser**
//!   ([`crate::client::parse_entry`]); `ldap3`'s panics on malformed BER.
//! * **Deadlines.** Each operation runs under `operation_timeout` and the whole
//!   resolution under `authentication_deadline`: the existing bounds, no new
//!   ones.
//! * **Size.** A search asks the server for at most `cap + 1` entries and
//!   stops reading at the cap whatever the server says; an entry with more
//!   than `cap` values, or with the values of a ranged retrieval
//!   (`memberOf;range=…`, which means the server truncated them), is the cap
//!   too. A truncated answer is never used.
//! * **Fail closed.** Every failure — transport, TLS, timeout, a refused
//!   search, a referral, a malformed entry, the cap — is
//!   [`DirectoryAuthError::Unavailable`] and ends the resolution.

use axiam_core::models::directory::{DirectoryAuthError, GroupStrategy};
use ldap3::{DerefAliases, Scope, SearchOptions};

use crate::client::{
    DirectoryClient, DirectoryTarget, Failure, Lease, debug_diagnostic, parse_entry,
    transport_failure, transport_is_encrypted,
};
use crate::escape::{REVERSE_MEMBER_BATCH, reverse_member_filter};
use crate::groups::{
    GroupLookup, GroupParents, MAX_GROUPS_PER_USER, ResolveError, ResolvedGroups, resolve_nested,
};

/// What a failed attempt was, so a stale pooled connection is retried once and
/// the cap never is.
enum Attempt {
    Cap,
    Failed(Failure),
}

impl DirectoryClient {
    /// The groups `user_dn` belongs to in `target`'s directory, nested to
    /// `lookup.max_depth` levels. See the module documentation for the rules.
    ///
    /// # Errors
    ///
    /// [`DirectoryAuthError::Unavailable`] for every failure of the lookup,
    /// including the cap; [`DirectoryAuthError::Misconfigured`] when the stored
    /// configuration cannot be used for it (no group base for a reverse search,
    /// a bind secret that is empty, a URL that is not encrypted).
    pub async fn resolve_groups(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
        user_dn: &str,
        lookup: &GroupLookup,
    ) -> Result<ResolvedGroups, DirectoryAuthError> {
        self.resolve_groups_capped(target, bind_secret, user_dn, lookup, MAX_GROUPS_PER_USER)
            .await
    }

    /// [`Self::resolve_groups`] with the cap as a parameter, so a test can state
    /// the boundary with a handful of entries.
    #[doc(hidden)]
    pub async fn resolve_groups_capped(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
        user_dn: &str,
        lookup: &GroupLookup,
        cap: usize,
    ) -> Result<ResolvedGroups, DirectoryAuthError> {
        let misconfigured = |reason| Failure::new(DirectoryAuthError::Misconfigured, reason);
        if bind_secret.is_empty() {
            return Err(self.log(target, misconfigured("the stored bind secret is empty")));
        }
        if !transport_is_encrypted(&target.url, target.start_tls) {
            return Err(self.log(
                target,
                misconfigured("the stored URL is not ldaps:// or ldap:// with StartTLS"),
            ));
        }
        if lookup.strategy == GroupStrategy::ReverseMember && lookup.base_dn.is_none() {
            return Err(self.log(
                target,
                misconfigured("a reverse group search needs group_base_dn"),
            ));
        }
        if user_dn.is_empty() {
            return Err(self.log(
                target,
                Failure::new(DirectoryAuthError::Unavailable, "the user has no DN"),
            ));
        }

        let flow = self.group_flow(target, bind_secret, user_dn, lookup, cap);
        match tokio::time::timeout(self.limits().authentication_deadline, flow).await {
            Ok(Ok(found)) => Ok(found),
            Ok(Err(Attempt::Cap)) => Err(self.log(
                target,
                Failure::new(
                    DirectoryAuthError::Unavailable,
                    "the user belongs to more directory groups than the cap allows",
                ),
            )),
            Ok(Err(Attempt::Failed(failure))) => Err(self.log(target, failure)),
            Err(_) => Err(self.log(
                target,
                Failure::new(
                    DirectoryAuthError::Unavailable,
                    "the group lookup deadline elapsed",
                ),
            )),
        }
    }

    async fn group_flow(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
        user_dn: &str,
        lookup: &GroupLookup,
        cap: usize,
    ) -> Result<ResolvedGroups, Attempt> {
        // As for the user search: a pooled connection the server closed while
        // it sat idle is ordinary, and costs one retry on a fresh one — never
        // more, and never for the cap.
        let mut lease = self
            .service_connection(target, bind_secret)
            .await
            .map_err(Attempt::Failed)?;
        let mut outcome = self.walk(&mut lease, user_dn, lookup, cap).await;
        if let Err(Attempt::Failed(failure)) = &outcome
            && lease.reused
            && failure.error == DirectoryAuthError::Unavailable
        {
            self.discard(lease).await;
            lease = self
                .fresh_service_connection(target, bind_secret)
                .await
                .map_err(Attempt::Failed)?;
            outcome = self.walk(&mut lease, user_dn, lookup, cap).await;
        }
        match outcome {
            Ok(found) => {
                self.release(target, lease).await;
                Ok(found)
            }
            // Any failure closes the connection rather than pooling it.
            Err(attempt) => {
                self.discard(lease).await;
                Err(attempt)
            }
        }
    }

    async fn walk(
        &self,
        lease: &mut Lease,
        user_dn: &str,
        lookup: &GroupLookup,
        cap: usize,
    ) -> Result<ResolvedGroups, Attempt> {
        let mut source = LdapParents {
            client: self,
            lease,
            lookup,
            user_dn,
            cap,
            reads: 0,
        };
        resolve_nested(&mut source, user_dn, lookup.max_depth, cap)
            .await
            .map_err(|error| match error {
                ResolveError::CapExceeded => Attempt::Cap,
                ResolveError::Lookup(reason) => {
                    Attempt::Failed(Failure::new(DirectoryAuthError::Unavailable, reason))
                }
            })
    }
}

/// The directory as a [`GroupParents`] source, over one leased connection.
struct LdapParents<'a> {
    client: &'a DirectoryClient,
    lease: &'a mut Lease,
    lookup: &'a GroupLookup,
    user_dn: &'a str,
    cap: usize,
    /// How many `parents_of` calls have run; the first is the user's own.
    reads: usize,
}

impl GroupParents for LdapParents<'_> {
    async fn parents_of(&mut self, of: &[String]) -> Result<Vec<String>, ResolveError> {
        {
            let first = self.reads == 0;
            self.reads += 1;
            match self.lookup.strategy {
                GroupStrategy::MemberOf => {
                    let mut parents = Parents::new(self.cap);
                    for dn in of {
                        // The user's own entry must be there to read; a *group*
                        // that has since gone is a dangling reference and has
                        // no parents.
                        let must_exist = first && dn == self.user_dn;
                        parents.extend(self.member_of(dn, must_exist).await?)?;
                    }
                    Ok(parents.into_vec())
                }
                GroupStrategy::ReverseMember => {
                    let mut parents = Parents::new(self.cap);
                    for chunk in of.chunks(REVERSE_MEMBER_BATCH) {
                        let dns: Vec<&str> = chunk.iter().map(String::as_str).collect();
                        parents.extend(self.reverse_member(&dns).await?)?;
                    }
                    Ok(parents.into_vec())
                }
            }
        }
    }
}

/// The parents found in one `parents_of` call, deduplicated as written.
///
/// Bounded at twice the cap: the groups already seen (at most `cap`) and the
/// new ones (at most `cap`) are the most a legitimate answer can name, so more
/// distinct names than that is the cap, and memory stays proportional to it.
struct Parents {
    seen: std::collections::BTreeSet<String>,
    ordered: Vec<String>,
    bound: usize,
}

impl Parents {
    fn new(cap: usize) -> Self {
        Self {
            seen: std::collections::BTreeSet::new(),
            ordered: Vec::new(),
            bound: cap.saturating_mul(2),
        }
    }

    fn extend(&mut self, dns: Vec<String>) -> Result<(), ResolveError> {
        for dn in dns {
            if self.seen.insert(dn.clone()) {
                self.ordered.push(dn);
                if self.ordered.len() > self.bound {
                    return Err(ResolveError::CapExceeded);
                }
            }
        }
        Ok(())
    }

    fn into_vec(self) -> Vec<String> {
        self.ordered
    }
}

impl LdapParents<'_> {
    fn options(&self, sizelimit: i32) -> SearchOptions {
        let limits = self.client.limits();
        SearchOptions::new()
            .sizelimit(sizelimit)
            .timelimit(i32::try_from(limits.operation_timeout.as_secs().max(1)).unwrap_or(5))
            .deref(DerefAliases::Never)
    }

    /// `memberOf` off one entry, by a base-object read.
    async fn member_of(&mut self, dn: &str, must_exist: bool) -> Result<Vec<String>, ResolveError> {
        let attribute = self.lookup.member_attribute.clone();
        let limits = self.client.limits();
        let options = self.options(2);
        let mut stream = self
            .lease
            .ldap
            .with_search_options(options)
            .with_timeout(limits.operation_timeout)
            .streaming_search(dn, Scope::Base, "(objectClass=*)", vec![attribute.clone()])
            .await
            .map_err(failure_of)?;

        let mut entries = Vec::with_capacity(1);
        loop {
            match stream.next().await.map_err(failure_of)? {
                None => break,
                // A reference or an intermediate response: never followed.
                Some(entry) if entry.is_ref() || entry.is_intermediate() => continue,
                Some(entry) => {
                    let parsed = parse_entry(entry.0)
                        .ok_or(ResolveError::Lookup("the directory sent a malformed entry"))?;
                    entries.push(parsed);
                    if entries.len() > 1 {
                        return Err(ResolveError::Lookup(
                            "a base-object read returned more than one entry",
                        ));
                    }
                }
            }
        }
        let done = stream.finish().await;
        match done.rc {
            0 => {}
            // noSuchObject: the entry is gone (or invisible to the service
            // account).
            32 if !must_exist => return Ok(Vec::new()),
            _ => return Err(result_failure("group read", &done)),
        }
        let Some(entry) = entries.pop() else {
            return if must_exist {
                Err(ResolveError::Lookup("the user's entry could not be read"))
            } else {
                Ok(Vec::new())
            };
        };
        if entry.has_ranged(&attribute) {
            return Err(ResolveError::CapExceeded);
        }
        let values = entry.values(&attribute).map(Vec::as_slice).unwrap_or(&[]);
        if values.len() > self.cap {
            return Err(ResolveError::CapExceeded);
        }
        // A value that is not UTF-8 is not a DN anything can be mapped from.
        Ok(values
            .iter()
            .filter_map(|v| String::from_utf8(v.clone()).ok())
            .collect())
    }

    /// The groups that name any of `dns` as a member, by one subtree search.
    async fn reverse_member(&mut self, dns: &[&str]) -> Result<Vec<String>, ResolveError> {
        let Some(base) = self.lookup.base_dn.clone() else {
            return Err(ResolveError::Lookup(
                "a reverse group search needs group_base_dn",
            ));
        };
        let Some(filter) = reverse_member_filter(
            self.lookup.filter.as_deref(),
            &self.lookup.member_attribute,
            dns,
        ) else {
            return Err(ResolveError::Lookup("the member attribute is not usable"));
        };
        let limits = self.client.limits();
        let sizelimit = i32::try_from(self.cap.saturating_add(1)).unwrap_or(i32::MAX);
        let options = self.options(sizelimit);
        let mut stream = self
            .lease
            .ldap
            .with_search_options(options)
            .with_timeout(limits.operation_timeout)
            // `1.1`: no attributes, only the DNs.
            .streaming_search(&base, Scope::Subtree, &filter, vec!["1.1"])
            .await
            .map_err(failure_of)?;

        let mut groups = Vec::new();
        loop {
            match stream.next().await.map_err(failure_of)? {
                None => break,
                Some(entry) if entry.is_ref() || entry.is_intermediate() => continue,
                Some(entry) => {
                    let parsed = parse_entry(entry.0)
                        .ok_or(ResolveError::Lookup("the directory sent a malformed entry"))?;
                    groups.push(parsed.dn);
                    if groups.len() > self.cap {
                        // The server's own limit is not trusted either.
                        return Err(ResolveError::CapExceeded);
                    }
                }
            }
        }
        let done = stream.finish().await;
        match done.rc {
            0 => Ok(groups),
            // sizeLimitExceeded: the server stopped at the cap we asked for.
            4 => Err(ResolveError::CapExceeded),
            _ => Err(result_failure("reverse group search", &done)),
        }
    }
}

fn failure_of(error: ldap3::LdapError) -> ResolveError {
    ResolveError::Lookup(transport_failure(error).reason)
}

/// A search that ended with a result code other than success: the reason is
/// fixed text and the directory's own words go to `debug` only.
fn result_failure(operation: &'static str, done: &ldap3::LdapResult) -> ResolveError {
    debug_diagnostic(operation, done);
    ResolveError::Lookup(match done.rc {
        10 => "the directory answered a group search with a referral, which is never followed",
        3 | 51 | 52 | 80 => "the directory is busy or unavailable",
        50 => "the service account may not read the group data",
        32 => "the group search base does not exist",
        _ => "the directory refused the group search",
    })
}
