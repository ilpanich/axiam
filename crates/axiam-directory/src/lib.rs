//! AXIAM directory identity source: LDAP and Active Directory.
//!
//! This crate is the home of competitor-gap item **G-3**: a tenant can
//! federate an existing LDAP or Active Directory directory, so its users sign
//! in with their directory password, are provisioned just in time, and have
//! their directory groups mapped onto AXIAM groups (roles and permissions keep
//! working through group inheritance).
//!
//! # What exists today
//!
//! * [`config`] validates a directory configuration before it is stored
//!   (T23.3.1).
//! * [`escape`] is RFC 4515 filter-value escaping and the only function that
//!   puts a login name into a filter; [`tls`] builds the verified rustls client
//!   configuration from a tenant's anchors (T23.3.2).
//! * [`client`] is the LDAP client — `ldap3` over rustls, mandatory TLS, a
//!   bounded per-tenant pool, no referrals — and the bind-as-user flow;
//!   [`authenticator`] is the
//!   [`DirectoryAuthenticator`](axiam_core::models::directory::DirectoryAuthenticator)
//!   the composition root injects into the login path (T23.3.2).
//! * [`dn`], [`groups`], [`group_lookup`] and [`mapper`] are group mapping
//!   (T23.3.4, D-30): an explicit table of directory group DNs to AXIAM groups,
//!   nested resolution to a configured depth under a hard cap, and the
//!   application that owns only the memberships it wrote.
//!
//! * [`sync_lookup`] and [`sync`] are the sync job (T23.3.5, D-31): the
//!   read-only questions it asks the directory, and the full and incremental
//!   runs that turn the answers into `Inactive` accounts, refreshed attributes
//!   and group mappings — and never into a re-enabled, created or linked one.
//!
//! * [`address`] and [`frame`] guard the connector itself (T23.3.7, D-19):
//!   the address guard resolves a directory host once, refuses loopback,
//!   link-local, metadata, multicast and AXIAM's own listeners — and private
//!   ranges outside the operator's allow-list — and the connection is pinned
//!   to the vetted address (T-300); the frame guard measures and checks every
//!   message a directory sends before `ldap3` sees it (P23W2-10, T-295,
//!   T-331), through a relay beneath `ldap3`.
//!
//! The management routes are a later task of the same item (T23.3.8); they
//! call `config::validate` and [`DirectoryClient::guard`] on every write.
//!
//! # Boundaries that bind every later task
//!
//! * **Read-only.** AXIAM never writes to a directory. The bind account it is
//!   given should hold read-only rights, and the documentation says so; nothing
//!   here may add an LDAP add, modify, delete or password-change operation.
//! * **No Kerberos.** SPNEGO / Kerberos single sign-on is out of scope for this
//!   phase (decision D-1), so nothing Kerberos-shaped appears in the model.
//! * **Encrypted transport only.** A plaintext `ldap://` URL is refused at
//!   configuration time; the only accepted shapes are `ldaps://` and `ldap://`
//!   with StartTLS.
//! * **The bind secret is write-only.** It is encrypted at rest under a key
//!   held by the secret provider, never returned by any API and never logged.
//!
//! # Placement
//!
//! Layer 3 of the workspace, beside `axiam-federation`: a federation protocol
//! with the same dependency shape (domain types below it, protocol code in it,
//! nothing above allowed to be reached back into). See
//! `claude_dev/crate-layering.md` for why, and
//! `scripts/check-crate-layering.py` for the gate that holds it.

pub mod address;
pub mod authenticator;
pub mod client;
pub mod config;
pub mod dn;
pub mod escape;
pub mod frame;
pub mod group_lookup;
pub mod groups;
pub mod mapper;
mod relay;
pub mod sync;
pub mod sync_lookup;
pub mod tls;

pub use address::{AddressPolicy, GuardError, GuardedTarget, Resolver, SystemResolver};
pub use authenticator::{MappedGroups, RepositoryDirectoryAuthenticator};
pub use client::{ClientLimits, DirectoryClient, DirectoryTarget};
pub use mapper::{MembershipChangeHook, MembershipChangeSlot, RepositoryGroupMapper};
pub use sync::{DirectorySync, RunKind, SyncError, SyncLimits, SyncSummary, TenantReport};
pub use sync_lookup::DirectorySession;
