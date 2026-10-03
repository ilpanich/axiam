//! The directory half of the sync job (G-3, T23.3.5, D-31): three read-only
//! questions asked over the **service-bound pooled connection**.
//!
//! * [`DirectorySession::lookup_by_external_id`] — the entry whose immutable
//!   identifier is the one a directory account carries: a subtree search under
//!   `base_dn` for `(entryUUID=<uuid>)` or `(objectGUID=<binary-escaped 16
//!   bytes>)`, **exactly one** entry or [`EntryLookup::NotFound`] /
//!   [`EntryLookup::Ambiguous`].
//! * [`DirectorySession::search_changed`] — every entry whose change attribute
//!   (`modifyTimestamp`, `uSNChanged`) is at or after a watermark, bounded.
//! * [`DirectorySession::read_root_dse`] — Active Directory's
//!   `highestCommittedUSN` and `dsServiceName`, from the rootDSE of the very
//!   server the connection reached.
//!
//! # Rules shared with the rest of the connector
//!
//! * **Filters only through `escape`.** [`crate::escape::external_id_filter`]
//!   and [`crate::escape::changed_since_filter`] are the only way a value
//!   reaches these filters; an identifier or watermark that cannot be put in
//!   one is [`DirectoryAuthError::Misconfigured`] — "cannot ask", never "not
//!   found". **A question that was not asked must never read as a negative
//!   answer**, because "not found" is what deactivates an account.
//! * **Referrals are never followed**; search result references are skipped,
//!   neither chased nor counted. Entries are parsed by AXIAM's fallible parser.
//! * **Bounded.** Each operation runs under `operation_timeout`, the whole
//!   query under `authentication_deadline`; a lookup asks the server for two
//!   entries and stops reading at the second; a changed-since search asks for
//!   `max_entries + 1`, stops reading beyond `max_entries` whatever the server
//!   says, and reports that it did.
//! * **Read-only.** Nothing here binds as anyone but the service account, and
//!   nothing writes.
//! * **What the directory said never leaves in a log line above `debug`.**

use std::sync::Arc;

use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryConfig, DirectoryIdentity, DirectoryKind, UserAttributeMap,
};
use ldap3::{DerefAliases, Scope, SearchOptions};
use zeroize::Zeroizing;

use crate::client::{
    DirectoryClient, DirectoryTarget, Failure, Lease, RawEntry, debug_diagnostic, parse_entry,
    transport_failure, transport_is_encrypted,
};
use crate::escape::{changed_since_filter, external_id_filter, is_generalized_time, is_usn};

/// `userAccountControl` bit `ACCOUNTDISABLE` (`0x2`): Active Directory's mark
/// for an administratively disabled account.
pub const UAC_ACCOUNT_DISABLED: u64 = 0x2;

/// The attribute that says a directory has disabled an account: Active
/// Directory's `userAccountControl`, or OpenLDAP's ppolicy
/// `pwdAccountLockedTime`.
#[must_use]
pub const fn disabled_attribute(kind: DirectoryKind) -> &'static str {
    match kind {
        DirectoryKind::ActiveDirectory => "userAccountControl",
        DirectoryKind::OpenLdap => "pwdAccountLockedTime",
    }
}

/// Whether the values of [`disabled_attribute`] mean "disabled" (D-31).
///
/// * Active Directory: `userAccountControl` carries bit `0x2`. An attribute that
///   is absent or does not parse as a number is **not** a statement that the
///   account is disabled — an account is never deactivated on a value that
///   could not be read.
/// * OpenLDAP: `pwdAccountLockedTime` is **present**. (ppolicy writes it for an
///   administrative lock and for a lockout after failed attempts alike; D-31
///   takes presence.)
#[must_use]
pub fn is_disabled(kind: DirectoryKind, values: Option<&Vec<Vec<u8>>>) -> bool {
    match kind {
        DirectoryKind::ActiveDirectory => values
            .and_then(|values| values.first())
            .and_then(|raw| std::str::from_utf8(raw).ok())
            .and_then(|text| text.trim().parse::<u64>().ok())
            .is_some_and(|flags| flags & UAC_ACCOUNT_DISABLED != 0),
        DirectoryKind::OpenLdap => {
            values.is_some_and(|values| values.iter().any(|v| !v.is_empty()))
        }
    }
}

/// What one entry tells the sync job.
#[derive(Clone, PartialEq, Eq)]
pub struct SyncEntry {
    /// The identifier, DN and mapped attributes, as for a sign-in. The DN is
    /// the one the directory returned and is only ever used as a value.
    pub identity: DirectoryIdentity,
    /// The directory has disabled the account ([`is_disabled`]).
    pub disabled: bool,
    /// The entry's value of the change attribute, when it was readable and is
    /// well formed (a generalized time or a USN).
    pub change_value: Option<String>,
}

impl std::fmt::Debug for SyncEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncEntry")
            .field("identity", &self.identity)
            .field("disabled", &self.disabled)
            .field("has_change_value", &self.change_value.is_some())
            .finish()
    }
}

/// The answer to "which entry has this identifier".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryLookup {
    /// Exactly one entry.
    Found(Box<SyncEntry>),
    /// The search completed and matched nothing under `base_dn`.
    NotFound,
    /// More than one entry matched. Identifiers are unique, so this is a
    /// directory fault; the caller skips the account and does **not** read it
    /// as vanished.
    Ambiguous,
}

/// What an incremental search returned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangedEntries {
    /// The entries read, at most the bound.
    pub entries: Vec<SyncEntry>,
    /// `false` when the bound was hit — by the server's own size limit or by
    /// the client's count — so the list is a prefix of the full answer.
    pub complete: bool,
    /// Entries that carried no usable identifier (and so can match no account)
    /// and were passed over.
    pub unidentified: usize,
}

/// What the rootDSE says about the server the connection reached.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RootDse {
    /// Active Directory's `dsServiceName`: the DN of the domain controller's
    /// NTDS Settings object. `highestCommittedUSN` counts *this* server's
    /// changes, so a watermark is only meaningful against the same value.
    pub server_identity: Option<String>,
    /// `highestCommittedUSN`, a decimal number.
    pub highest_committed_usn: Option<String>,
}

/// One tenant's directory, ready to be asked: the stored configuration, the
/// decrypted bind secret (held only until the session is dropped) and the
/// shared bounded client. Built by
/// [`crate::RepositoryDirectoryAuthenticator::open_sync`].
pub struct DirectorySession {
    pub(crate) config: DirectoryConfig,
    pub(crate) target: DirectoryTarget,
    pub(crate) secret: Zeroizing<String>,
    pub(crate) client: Arc<DirectoryClient>,
}

impl std::fmt::Debug for DirectorySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectorySession")
            .field("tenant_id", &self.config.tenant_id)
            .finish_non_exhaustive()
    }
}

/// The attributes a sync search asks for: the mapped ones, the identifier, the
/// change attribute and the one that says "disabled", each once.
fn requested(map: &UserAttributeMap, kind: DirectoryKind) -> Vec<String> {
    let mut attrs: Vec<String> = Vec::with_capacity(6);
    for name in [
        map.external_id.as_str(),
        map.username.as_str(),
        map.email.as_str(),
        map.display_name.as_str(),
        kind.change_attribute(),
        disabled_attribute(kind),
    ] {
        if !attrs.iter().any(|a| a.eq_ignore_ascii_case(name)) {
            attrs.push(name.to_string());
        }
    }
    attrs
}

/// What the three queries have in common: a search and how many entries to read.
struct Query<'a> {
    base: &'a str,
    scope: Scope,
    filter: &'a str,
    attrs: Vec<String>,
    /// The most entries read. The server is asked for one more, so hitting the
    /// bound is observable; `sizeLimitExceeded` is the same observation.
    max_entries: usize,
}

/// What a search read.
struct Read {
    entries: Vec<RawEntry>,
    truncated: bool,
}

impl DirectorySession {
    /// A session over parts the caller has assembled. The composition root uses
    /// [`crate::RepositoryDirectoryAuthenticator::open_sync`], which reads the
    /// stored configuration and decrypts the secret itself; this exists for
    /// callers that already hold both (the client's own tests).
    #[must_use]
    pub fn new(
        config: DirectoryConfig,
        target: DirectoryTarget,
        secret: Zeroizing<String>,
        client: Arc<DirectoryClient>,
    ) -> Self {
        Self {
            config,
            target,
            secret,
            client,
        }
    }

    /// The configuration the session was opened from (no secret in it).
    #[must_use]
    pub fn config(&self) -> &DirectoryConfig {
        &self.config
    }

    fn attributes(&self) -> Vec<String> {
        requested(&self.config.user_attribute_map, self.config.kind)
    }

    fn entry_from(&self, raw: RawEntry) -> Result<SyncEntry, Failure> {
        let kind = self.config.kind;
        let change_value = raw
            .text(kind.change_attribute())
            .filter(|value| is_generalized_time(value) || is_usn(value));
        let disabled = is_disabled(kind, raw.values(disabled_attribute(kind)));
        let identity = raw.into_identity(&self.config.user_attribute_map)?;
        Ok(SyncEntry {
            identity,
            disabled,
            change_value,
        })
    }

    /// The entry whose identifier is `external_id`, under `base_dn`.
    ///
    /// # Errors
    ///
    /// [`DirectoryAuthError::Misconfigured`] when the identifier cannot be put
    /// in a filter or the directory refuses the search;
    /// [`DirectoryAuthError::Unavailable`] for every transport failure, timeout
    /// and busy answer. **No error is "not found"**: only a completed search
    /// that matched nothing is.
    pub async fn lookup_by_external_id(
        &self,
        external_id: &str,
    ) -> Result<EntryLookup, DirectoryAuthError> {
        let Some(filter) =
            external_id_filter(&self.config.user_attribute_map.external_id, external_id)
        else {
            return Err(self.client.log(
                &self.target,
                Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the stored identifier cannot be turned into a filter",
                ),
            ));
        };
        let query = Query {
            base: &self.target.base_dn,
            scope: Scope::Subtree,
            filter: &filter,
            attrs: self.attributes(),
            max_entries: 1,
        };
        let read = self.run(&query).await?;
        match (read.entries.len(), read.truncated) {
            (0, false) => Ok(EntryLookup::NotFound),
            (1, false) => {
                let raw = read
                    .entries
                    .into_iter()
                    .next()
                    .ok_or(DirectoryAuthError::Unavailable)?;
                // An entry whose identifier cannot be read is not a match for
                // anything: the account is skipped, never read as vanished.
                let entry = self
                    .entry_from(raw)
                    .map_err(|failure| self.client.log(&self.target, failure))?;
                Ok(EntryLookup::Found(Box::new(entry)))
            }
            _ => Ok(EntryLookup::Ambiguous),
        }
    }

    /// Entries changed at or after `watermark`, at most `max_entries` of them.
    ///
    /// # Errors
    ///
    /// As [`Self::lookup_by_external_id`]; a watermark that is neither a
    /// generalized time nor a USN is `Misconfigured`.
    pub async fn search_changed(
        &self,
        watermark: &str,
        max_entries: usize,
    ) -> Result<ChangedEntries, DirectoryAuthError> {
        let Some(filter) = changed_since_filter(self.config.kind.change_attribute(), watermark)
        else {
            return Err(self.client.log(
                &self.target,
                Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the stored watermark cannot be turned into a filter",
                ),
            ));
        };
        let query = Query {
            base: &self.target.base_dn,
            scope: Scope::Subtree,
            filter: &filter,
            attrs: self.attributes(),
            max_entries,
        };
        let read = self.run(&query).await?;
        let mut out = ChangedEntries {
            entries: Vec::with_capacity(read.entries.len()),
            complete: !read.truncated,
            unidentified: 0,
        };
        for raw in read.entries {
            match self.entry_from(raw) {
                Ok(entry) => out.entries.push(entry),
                // Not every entry the filter matches is a person with an
                // identifier the bind account may read (an OU, a group): such an
                // entry can match no account and is passed over.
                Err(_) => out.unidentified += 1,
            }
        }
        Ok(out)
    }

    /// The rootDSE's `dsServiceName` and `highestCommittedUSN`.
    ///
    /// Values that are missing, or malformed (a USN that is not a number), are
    /// `None`: the caller falls back to a full run rather than trusting them.
    ///
    /// # Errors
    ///
    /// As [`Self::lookup_by_external_id`].
    pub async fn read_root_dse(&self) -> Result<RootDse, DirectoryAuthError> {
        let query = Query {
            base: "",
            scope: Scope::Base,
            filter: "(objectClass=*)",
            attrs: vec!["dsServiceName".into(), "highestCommittedUSN".into()],
            max_entries: 1,
        };
        let read = self.run(&query).await?;
        let Some(raw) = read.entries.into_iter().next() else {
            return Ok(RootDse::default());
        };
        Ok(RootDse {
            server_identity: raw
                .text("dsServiceName")
                .filter(|value| value.len() <= 1024),
            highest_committed_usn: raw.text("highestCommittedUSN").filter(|v| is_usn(v)),
        })
    }

    /// Run one query under the whole-flow deadline, on a pooled service
    /// connection, retrying once on a fresh one when a pooled connection the
    /// server closed fails at the transport level.
    async fn run(&self, query: &Query<'_>) -> Result<Read, DirectoryAuthError> {
        let client = &self.client;
        if self.secret.is_empty() {
            return Err(client.log(
                &self.target,
                Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the stored bind secret is empty",
                ),
            ));
        }
        if !transport_is_encrypted(&self.target.url, self.target.start_tls) {
            return Err(client.log(
                &self.target,
                Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the stored URL is not ldaps:// or ldap:// with StartTLS",
                ),
            ));
        }
        let flow = self.flow(query);
        match tokio::time::timeout(client.limits().authentication_deadline, flow).await {
            Ok(Ok(read)) => Ok(read),
            Ok(Err(failure)) => Err(client.log(&self.target, failure)),
            Err(_) => Err(client.log(
                &self.target,
                Failure::new(
                    DirectoryAuthError::Unavailable,
                    "the sync query deadline elapsed",
                ),
            )),
        }
    }

    async fn flow(&self, query: &Query<'_>) -> Result<Read, Failure> {
        let client = &self.client;
        let mut lease = client
            .service_connection(&self.target, &self.secret)
            .await?;
        let mut outcome = self.search(&mut lease, query).await;
        if let Err(failure) = &outcome
            && lease.reused
            && failure.error == DirectoryAuthError::Unavailable
        {
            client.discard(lease).await;
            lease = client
                .fresh_service_connection(&self.target, &self.secret)
                .await?;
            outcome = self.search(&mut lease, query).await;
        }
        match outcome {
            Ok((read, reusable)) => {
                if reusable {
                    client.release(&self.target, lease).await;
                } else {
                    // Reading stopped before the server finished: the stream
                    // still holds replies, so the connection is not pooled.
                    client.discard(lease).await;
                }
                Ok(read)
            }
            Err(failure) => {
                client.discard(lease).await;
                Err(failure)
            }
        }
    }

    /// One search. The `bool` is whether the connection may go back to the
    /// pool (the search ran to its end).
    async fn search(&self, lease: &mut Lease, query: &Query<'_>) -> Result<(Read, bool), Failure> {
        let limits = self.client.limits();
        let sizelimit = i32::try_from(query.max_entries.saturating_add(1)).unwrap_or(i32::MAX);
        let options = SearchOptions::new()
            .sizelimit(sizelimit)
            .timelimit(i32::try_from(limits.operation_timeout.as_secs().max(1)).unwrap_or(5))
            .deref(DerefAliases::Never);
        let mut stream = lease
            .ldap
            .with_search_options(options)
            .with_timeout(limits.operation_timeout)
            .streaming_search(query.base, query.scope, query.filter, query.attrs.clone())
            .await
            .map_err(transport_failure)?;

        let mut entries = Vec::new();
        loop {
            match stream.next().await.map_err(transport_failure)? {
                None => break,
                // A reference or an intermediate response: never followed.
                Some(entry) if entry.is_ref() || entry.is_intermediate() => continue,
                Some(entry) => {
                    let parsed = parse_entry(entry.0).ok_or_else(|| {
                        Failure::new(
                            DirectoryAuthError::Unavailable,
                            "the directory sent a malformed search entry",
                        )
                    })?;
                    entries.push(parsed);
                    if entries.len() > query.max_entries {
                        // The server's own limit is not trusted: stop here.
                        // The bound is hit; what was read is a prefix.
                        entries.pop();
                        return Ok((
                            Read {
                                entries,
                                truncated: true,
                            },
                            false,
                        ));
                    }
                }
            }
        }
        let done = stream.finish().await;
        match done.rc {
            0 => Ok((
                Read {
                    entries,
                    truncated: false,
                },
                true,
            )),
            // sizeLimitExceeded: the server stopped at the bound we asked for.
            4 => Ok((
                Read {
                    entries,
                    truncated: true,
                },
                true,
            )),
            10 => {
                debug_diagnostic("sync search", &done);
                Err(Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the directory answered the sync search with a referral, which is never followed",
                ))
            }
            3 | 51 | 52 | 80 => {
                debug_diagnostic("sync search", &done);
                Err(Failure::new(
                    DirectoryAuthError::Unavailable,
                    "the directory is busy or unavailable",
                ))
            }
            _ => {
                debug_diagnostic("sync search", &done);
                Err(Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the directory refused the sync search (check base_dn and the bind account's read rights)",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str) -> Vec<Vec<u8>> {
        vec![text.as_bytes().to_vec()]
    }

    #[test]
    fn active_directory_disabled_is_bit_two_of_user_account_control() {
        let ad = DirectoryKind::ActiveDirectory;
        // 512 = NORMAL_ACCOUNT; 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE;
        // 66050 = ... | DONT_EXPIRE_PASSWORD | ACCOUNTDISABLE.
        assert!(!is_disabled(ad, Some(&values("512"))));
        assert!(is_disabled(ad, Some(&values("514"))));
        assert!(is_disabled(ad, Some(&values("66050"))));
        assert!(!is_disabled(ad, Some(&values("66048"))));
        assert!(is_disabled(ad, Some(&values(" 2 "))));
    }

    #[test]
    fn a_value_that_cannot_be_read_never_disables_an_account() {
        let ad = DirectoryKind::ActiveDirectory;
        assert!(!is_disabled(ad, None));
        assert!(!is_disabled(ad, Some(&vec![])));
        assert!(!is_disabled(ad, Some(&values(""))));
        assert!(!is_disabled(ad, Some(&values("disabled"))));
        assert!(!is_disabled(ad, Some(&values("-2"))));
        assert!(!is_disabled(ad, Some(&vec![vec![0xff, 0xfe]])));
    }

    #[test]
    fn open_ldap_disabled_is_the_presence_of_the_locked_time() {
        let ol = DirectoryKind::OpenLdap;
        assert!(!is_disabled(ol, None));
        assert!(!is_disabled(ol, Some(&vec![])));
        assert!(!is_disabled(ol, Some(&values(""))));
        assert!(is_disabled(ol, Some(&values("000001010000Z"))));
        assert!(is_disabled(ol, Some(&values("20261003120000Z"))));
    }

    #[test]
    fn the_requested_attributes_are_the_mapped_ones_plus_change_and_disabled() {
        let map = DirectoryKind::OpenLdap.default_user_attribute_map();
        assert_eq!(
            requested(&map, DirectoryKind::OpenLdap),
            vec![
                "entryUUID",
                "uid",
                "mail",
                "displayName",
                "modifyTimestamp",
                "pwdAccountLockedTime"
            ]
        );
        let map = DirectoryKind::ActiveDirectory.default_user_attribute_map();
        assert_eq!(
            requested(&map, DirectoryKind::ActiveDirectory),
            vec![
                "objectGUID",
                "sAMAccountName",
                "mail",
                "displayName",
                "uSNChanged",
                "userAccountControl"
            ]
        );
    }
}
