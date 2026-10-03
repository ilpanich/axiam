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
//! Only the configuration surface (T23.3.1): the [`config`] module validates a
//! directory configuration before it is stored. There is no network code, no
//! authentication path and no REST route yet; the LDAP client, the
//! bind-as-user path, provisioning, group mapping and the sync job are later
//! tasks of the same item.
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

pub mod config;
pub mod escape;
pub mod tls;
