//! Outbound SCIM provisioning: AXIAM as the **client** of a downstream SCIM 2.0
//! service provider (G-6, T23.6.2; decision D-57).
//!
//! The rest of this crate is a SCIM *server*. This module is the other
//! direction: a tenant registers downstream service providers
//! ([`axiam_core::models::scim_target::ScimTarget`]) and AXIAM pushes user and
//! group lifecycle changes to them.
//!
//! # Three pieces
//!
//! * [`ScimProvisioner`] — the **source**. It implements the core
//!   [`ProvisioningSink`](axiam_core::provisioning::ProvisioningSink) the user
//!   and group repositories report every committed change to, and enqueues one
//!   *reference* (`{resource_type, axiam_id}`, nothing else) per enabled target
//!   on the shared outbound dispatcher as
//!   [`OutboundKind::ScimPush`](axiam_core::outbound::OutboundKind::ScimPush).
//! * [`ScimPushDeliverer`] — the **attempt**. It implements the core
//!   [`OutboundDeliverer`](axiam_core::outbound::OutboundDeliverer) the
//!   dispatcher's consumer calls: one attempt, classify, never decide.
//! * [`wire`] — the RFC 7643 / RFC 7644 documents the deliverer sends and the
//!   digest that lets it skip a `PATCH` that would change nothing.
//!
//! # Level-triggered delivery
//!
//! No attribute of a person ever sits in a queue or in the dead-letter queue.
//! Each attempt re-reads the target, the resource and its link, and computes
//! what the downstream **should** look like *now*; retries, reordering and
//! duplicates therefore converge on the same state.
//!
//! | The resource, at the attempt | Link | The attempt does |
//! |---|---|---|
//! | user `Active` and in scope | none | `POST /Users` (a `409` adopts by `externalId`) |
//! | user `Active` and in scope | yes | `PATCH` the mapped attributes, **skipped** when the digest is unchanged |
//! | user out of scope, or any other live status | yes | per `deprovision`: `PATCH active=false`, or `DELETE` |
//! | user out of scope, or any other live status | none | nothing (nothing is created downstream to deactivate) |
//! | user `Deleted`, `Anonymized` or gone | yes | `DELETE`, **whatever** `deprovision` says; the link is removed |
//! | group in scope (`push_groups`) | none / yes | `POST /Groups` / `PATCH` (`displayName`, `externalId`, `members`) |
//! | group out of scope or gone | yes | `DELETE`; the link is removed |
//!
//! # The way out of the process
//!
//! Every request — SCIM calls and the OAuth2 token request alike — goes through
//! `guarded_fetch_no_redirect` with `allow_private = false`: the host is
//! resolved fresh, every address must be globally routable, the validated
//! address is pinned, `https` is required, and a `3xx` is returned instead of
//! followed, so neither the credential nor a person's attributes can reach a
//! host the administrator did not name. Before the credential is sent the
//! target is read once more and its `updated_at` compared with the read the
//! attempt started from (T-406). Reasons that reach the audit log and the
//! target's state are a fixed vocabulary: never a URL, a body, a name or a
//! value.

mod client;
mod deliverer;
mod provisioner;
pub mod wire;

pub use deliverer::ScimPushDeliverer;
pub use provisioner::{ScimProvisioner, group_in_scope, reference_message};
